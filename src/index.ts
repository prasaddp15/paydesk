import crypto from 'crypto';
import express, { Express, NextFunction, Request, RequestHandler, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mysql, { ResultSetHeader, RowDataPacket } from 'mysql2/promise';

dotenv.config();

type Role = 'main_admin' | 'client_admin';

type SessionUser = {
  id: number;
  clientId: number | null;
  name: string;
  email: string;
  role: Role;
};

type AuthedRequest = Request & {
  authUser?: SessionUser;
};

type UserRow = RowDataPacket & {
  id: number;
  client_id: number | null;
  name: string;
  email: string;
  password_hash: string;
  role: Role;
};

type AdminRow = RowDataPacket & {
  id: number;
  name: string;
  email: string;
  password_hash: string;
  status: 'active' | 'paused';
};

type ClientRow = RowDataPacket & {
  id: number;
  company_name: string;
  contact_name: string;
  email: string;
  phone_number: string | null;
  business_website: string | null;
  pan_number: string | null;
  aadhaar_number: string | null;
  gst_number: string | null;
  business_category: string | null;
  business_address: string | null;
  city: string | null;
  state: string | null;
  pincode: string | null;
  status: 'active' | 'paused' | 'pending';
  razorpay_key_id: string | null;
  razorpay_key_secret: string | null;
  razorpay_webhook_secret: string | null;
};

type ClientApiKeyRow = RowDataPacket & {
  api_key_id: number;
  client_id: number;
  api_key: string;
  api_secret_hash: string;
  api_key_status: 'active' | 'revoked';
  company_name: string;
  contact_name: string;
  email: string;
  status: 'active' | 'paused' | 'pending';
};

type GatewayRequest = Request & {
  client?: ClientApiKeyRow;
  requestId?: string;
};

const app: Express = express();
const port = Number(process.env.PORT || 5000);
const isProduction = process.env.NODE_ENV === 'production';
const sessions = new Map<string, SessionUser>();

const requiredProductionEnv = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'ENCRYPTION_KEY'];
const missingProductionEnv = isProduction ? requiredProductionEnv.filter((key) => !process.env[key]) : [];

if (missingProductionEnv.length > 0) {
  console.error(`Missing required production environment variables: ${missingProductionEnv.join(', ')}`);
  process.exit(1);
}

app.use(cors());
app.use('/api/webhooks/razorpay/:clientId', express.raw({ type: 'application/json' }));
app.use(express.json());

const databaseConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'app_db',
};

console.log(
  `Database target: ${databaseConfig.user}@${databaseConfig.host}:${databaseConfig.port}/${databaseConfig.database}`,
);

const pool = mysql.createPool({
  ...databaseConfig,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const toSessionUser = (row: UserRow): SessionUser => ({
  id: row.id,
  clientId: row.client_id,
  name: row.name,
  email: row.email,
  role: row.role,
});

const toAdminSessionUser = (row: AdminRow): SessionUser => ({
  id: row.id,
  clientId: null,
  name: row.name,
  email: row.email,
  role: 'main_admin',
});

const hashPassword = (password: string): string => {
  const salt = crypto.randomBytes(16).toString('hex');
  const iterations = 100000;
  const hash = crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha512').toString('hex');
  return `pbkdf2$${iterations}$${salt}$${hash}`;
};

const verifyPassword = (password: string, storedHash: string): boolean => {
  const [scheme, iterationsValue, salt, hash] = storedHash.split('$');
  if (scheme !== 'pbkdf2' || !iterationsValue || !salt || !hash) {
    return false;
  }

  const iterations = Number(iterationsValue);
  const candidate = crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha512');
  const original = Buffer.from(hash, 'hex');

  return candidate.length === original.length && crypto.timingSafeEqual(candidate, original);
};

const verifyHmac = (payload: string | Buffer, signature: string | undefined, secret: string): boolean => {
  if (!signature || !secret) {
    return false;
  }

  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  const expectedBuffer = Buffer.from(expected, 'hex');
  const signatureBuffer = Buffer.from(signature, 'hex');

  return expectedBuffer.length === signatureBuffer.length && crypto.timingSafeEqual(expectedBuffer, signatureBuffer);
};

const getEncryptionKey = (): Buffer => {
  const value = process.env.ENCRYPTION_KEY || 'paydesk-development-encryption-key-change-me';
  return /^[a-f0-9]{64}$/i.test(value) ? Buffer.from(value, 'hex') : crypto.createHash('sha256').update(value).digest();
};

const encryptSecret = (value: string | null | undefined): string | null => {
  if (!value) {
    return null;
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return `enc:v1:${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
};

const decryptSecret = (value: string | null | undefined): string => {
  if (!value) {
    return '';
  }

  if (!value.startsWith('enc:v1:')) {
    return value;
  }

  try {
    const [, , ivHex, tagHex, encryptedHex] = value.split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', getEncryptionKey(), Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(encryptedHex, 'hex')), decipher.final()]).toString('utf8');
  } catch (error) {
    console.error('Secret decrypt error:', error);
    return '';
  }
};

const normalizeOptionalString = (value: unknown): string | null => {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  return trimmed || null;
};

const normalizeRequiredString = (value: unknown): string => {
  return typeof value === 'string' ? value.trim() : '';
};

const getCustomerKey = (name: string | null, email: string | null, phone: string | null): string | null => {
  if (email) {
    return `email:${email.toLowerCase()}`;
  }

  if (phone) {
    return `phone:${phone.replace(/[^\d+]/g, '')}`;
  }

  if (name) {
    return `name:${name.toLowerCase()}`;
  }

  return null;
};

const upsertCustomer = async (
  clientId: number,
  name: string | null,
  email: string | null,
  phone: string | null,
): Promise<number | null> => {
  const customerKey = getCustomerKey(name, email, phone);
  if (!customerKey) {
    return null;
  }

  const [result] = await pool.execute<ResultSetHeader>(
    `INSERT INTO customers (client_id, customer_key, name, email, phone)
     VALUES (?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
      id = LAST_INSERT_ID(id),
      name = COALESCE(VALUES(name), name),
      email = COALESCE(VALUES(email), email),
      phone = COALESCE(VALUES(phone), phone),
      updated_at = CURRENT_TIMESTAMP`,
    [clientId, customerKey, name, email, phone],
  );

  return result.insertId || null;
};

const refreshCustomerStats = async (customerId: number | null) => {
  if (!customerId) {
    return;
  }

  await pool.execute(
    `UPDATE customers c
     SET
      total_transactions = (
        SELECT COUNT(*) FROM transactions t WHERE t.customer_id = c.id
      ),
      captured_amount = (
        SELECT COALESCE(SUM(CASE WHEN t.status = 'captured' THEN t.amount ELSE 0 END), 0)
        FROM transactions t
        WHERE t.customer_id = c.id
      ),
      last_payment_at = (
        SELECT MAX(t.created_at) FROM transactions t WHERE t.customer_id = c.id
      ),
      updated_at = CURRENT_TIMESTAMP
     WHERE c.id = ?`,
    [customerId],
  );
};

const isTicketStatus = (status: unknown): status is 'open' | 'in_progress' | 'resolved' | 'closed' => {
  return typeof status === 'string' && ['open', 'in_progress', 'resolved', 'closed'].includes(status);
};

const isTicketPriority = (priority: unknown): priority is 'low' | 'normal' | 'high' | 'urgent' => {
  return typeof priority === 'string' && ['low', 'normal', 'high', 'urgent'].includes(priority);
};

const requireAuth: RequestHandler = (req: AuthedRequest, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  const authUser = token ? sessions.get(token) : undefined;

  if (!authUser) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  req.authUser = authUser;
  next();
};

const requireRole = (role: Role): RequestHandler => {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    if (req.authUser?.role !== role) {
      res.status(403).json({ error: 'You do not have access to this resource' });
      return;
    }

    next();
  };
};

const requireClientAccess: RequestHandler = (req: AuthedRequest, res: Response, next: NextFunction) => {
  const clientId = Number(req.params.clientId);

  if (!Number.isInteger(clientId)) {
    res.status(400).json({ error: 'Invalid client id' });
    return;
  }

  if (req.authUser?.role === 'main_admin' || req.authUser?.clientId === clientId) {
    next();
    return;
  }

  res.status(403).json({ error: 'You do not have access to this client' });
};

const platformSettingKeys = [
  'razorpay_key_id',
  'razorpay_key_secret',
  'razorpay_webhook_secret',
  'razorpay_last_tested_at',
  'razorpay_last_test_status',
  'razorpay_last_test_message',
];

const getPlatformSettingRows = async (keys = platformSettingKeys) => {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT setting_key, setting_value, updated_at
     FROM platform_settings
     WHERE setting_key IN (${keys.map(() => '?').join(', ')})`,
    keys,
  );

  return rows.reduce<Record<string, { value: string; updatedAt: string | null }>>((settings, row) => {
    settings[row.setting_key] = {
      value: row.setting_value || '',
      updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : null,
    };
    return settings;
  }, {});
};

const getPlatformSettings = async () => {
  const rows = await getPlatformSettingRows(['razorpay_key_id', 'razorpay_key_secret', 'razorpay_webhook_secret']);

  return Object.entries(rows).reduce<Record<string, string>>((settings, [key, row]) => {
    settings[key] = key.includes('secret') ? decryptSecret(row.value) : row.value;
    return settings;
  }, {});
};

const getPlatformRazorpayState = async () => {
  const settings = await getPlatformSettingRows();
  const credentialRows = ['razorpay_key_id', 'razorpay_key_secret', 'razorpay_webhook_secret']
    .map((key) => settings[key]?.updatedAt)
    .filter(Boolean) as string[];

  return {
    keyId: settings.razorpay_key_id?.value || '',
    keySecret: '',
    webhookSecret: '',
    keySecretConfigured: Boolean(settings.razorpay_key_secret?.value),
    webhookSecretConfigured: Boolean(settings.razorpay_webhook_secret?.value),
    updatedAt: credentialRows.length ? credentialRows.sort()[credentialRows.length - 1] || null : null,
    lastTestedAt: settings.razorpay_last_tested_at?.value || null,
    lastTestStatus: settings.razorpay_last_test_status?.value || null,
    lastTestMessage: settings.razorpay_last_test_message?.value || null,
  };
};

const getPlatformRazorpayCredentials = async () => {
  const settings = await getPlatformSettings();

  if (!settings.razorpay_key_id || !settings.razorpay_key_secret) {
    const error = new Error('Platform Razorpay credentials are not configured') as Error & { statusCode?: number };
    error.statusCode = 400;
    throw error;
  }

  return {
    keyId: settings.razorpay_key_id,
    keySecret: settings.razorpay_key_secret,
    webhookSecret: settings.razorpay_webhook_secret || '',
  };
};

const getTableColumns = async (tableName: string): Promise<Set<string>> => {
  const [rows] = await pool.query<RowDataPacket[]>(
    `SELECT COLUMN_NAME
     FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = ?`,
    [tableName],
  );

  return new Set(rows.map((row) => row.COLUMN_NAME));
};

const addColumnIfMissing = async (tableName: string, columns: Set<string>, columnName: string, definition: string) => {
  if (columns.has(columnName)) {
    return;
  }

  await pool.query(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
  columns.add(columnName);
};

const logApiCall = async (
  req: GatewayRequest,
  statusCode: number,
  message: string,
  clientId?: number | null,
  apiKeyId?: number | null,
) => {
  try {
    const requestPayload = req.body && typeof req.body === 'object' ? JSON.stringify(req.body) : null;
    const responsePayload = JSON.stringify({ statusCode, message });

    await pool.execute(
      `INSERT INTO api_logs (client_id, api_key_id, method, endpoint, status_code, message, request_payload, response_payload, request_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        clientId ?? req.client?.client_id ?? null,
        apiKeyId ?? req.client?.api_key_id ?? null,
        req.method,
        req.originalUrl,
        statusCode,
        message.slice(0, 255),
        requestPayload,
        responsePayload,
        req.requestId || crypto.randomUUID(),
      ],
    );
  } catch (error) {
    console.error('API log error:', error);
  }
};

const requireGatewayClient: RequestHandler = async (req: GatewayRequest, res: Response, next: NextFunction) => {
  req.requestId = crypto.randomUUID();
  const apiKey = String(req.headers['x-platform-key'] || '');
  const apiSecret = String(req.headers['x-platform-secret'] || '');

  if (!apiKey || !apiSecret) {
    await logApiCall(req, 401, 'Missing platform API key or secret');
    res.status(401).json({ error: 'Missing platform API key or secret', requestId: req.requestId });
    return;
  }

  try {
    const [rows] = await pool.execute<ClientApiKeyRow[]>(
      `SELECT
        k.id AS api_key_id, k.client_id, k.api_key, k.api_secret_hash, k.status AS api_key_status,
        c.company_name, c.contact_name, c.email, c.status
       FROM client_api_keys k
       JOIN clients c ON c.id = k.client_id
       WHERE k.api_key = ?
       LIMIT 1`,
      [apiKey],
    );
    const client = rows[0];

    if (!client || client.api_key_status !== 'active' || !verifyPassword(apiSecret, client.api_secret_hash)) {
      await logApiCall(req, 401, 'Invalid platform API credentials', client?.client_id, client?.api_key_id);
      res.status(401).json({ error: 'Invalid platform API credentials', requestId: req.requestId });
      return;
    }

    if (client.status !== 'active') {
      await logApiCall(req, 403, 'Client account is not active', client.client_id, client.api_key_id);
      res.status(403).json({ error: 'Client account is not active', requestId: req.requestId });
      return;
    }

    req.client = client;
    await pool.execute('UPDATE client_api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?', [client.api_key_id]);
    next();
  } catch (error) {
    console.error('Gateway auth error:', error);
    await logApiCall(req, 500, 'Gateway authentication failed');
    res.status(500).json({ error: 'Gateway authentication failed', requestId: req.requestId });
  }
};

const mapRazorpayPaymentStatus = (status: string): 'captured' | 'authorized' | 'failed' => {
  if (status === 'captured') {
    return 'captured';
  }

  if (status === 'authorized') {
    return 'authorized';
  }

  return 'failed';
};

const razorpayRequest = async <T>(
  path: string,
  method: 'GET' | 'POST',
  body?: Record<string, unknown>,
  credentials?: { keyId: string; keySecret: string },
): Promise<T> => {
  const platformKeys = credentials || (await getPlatformRazorpayCredentials());

  const response = await fetch(`https://api.razorpay.com/v1${path}`, {
    method,
    headers: {
      Authorization: `Basic ${Buffer.from(`${platformKeys.keyId}:${platformKeys.keySecret}`).toString('base64')}`,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = (await response.json().catch(() => ({}))) as T & { error?: { description?: string } };

  if (!response.ok) {
    const message =
      response.status === 401
        ? 'Razorpay authentication failed. Update the platform Razorpay Key ID and Key Secret in the main admin vault.'
        : payload.error?.description || 'Razorpay request failed';
    const error = new Error(message) as Error & { statusCode?: number };
    error.statusCode = response.status;
    throw error;
  }

  return payload;
};

const ensureRuntimeSchema = async () => {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS platform_settings (
      id INT PRIMARY KEY AUTO_INCREMENT,
      setting_key VARCHAR(120) UNIQUE NOT NULL,
      setting_value TEXT,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`,
  );

  await pool.query(
    `CREATE TABLE IF NOT EXISTS clients (
      id INT PRIMARY KEY AUTO_INCREMENT,
      company_name VARCHAR(255) NOT NULL,
      contact_name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      phone_number VARCHAR(30),
      business_website VARCHAR(255),
      pan_number VARCHAR(20),
      aadhaar_number VARCHAR(20),
      gst_number VARCHAR(30),
      business_category VARCHAR(120),
      business_address TEXT,
      city VARCHAR(120),
      state VARCHAR(120),
      pincode VARCHAR(20),
      status ENUM('active', 'paused', 'pending') NOT NULL DEFAULT 'pending',
      razorpay_key_id VARCHAR(255),
      razorpay_key_secret VARCHAR(255),
      razorpay_webhook_secret VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NULL DEFAULT NULL
    )`,
  );

  await pool.query(
    `CREATE TABLE IF NOT EXISTS admins (
      id INT PRIMARY KEY AUTO_INCREMENT,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      status ENUM('active', 'paused') NOT NULL DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NULL DEFAULT NULL
    )`,
  );

  await pool.query(
    `CREATE TABLE IF NOT EXISTS users (
      id INT PRIMARY KEY AUTO_INCREMENT,
      client_id INT NULL,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role ENUM('main_admin', 'client_admin') NOT NULL DEFAULT 'client_admin',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NULL DEFAULT NULL,
      FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    )`,
  );

  await pool.query(
    `CREATE TABLE IF NOT EXISTS customers (
      id INT PRIMARY KEY AUTO_INCREMENT,
      client_id INT NOT NULL,
      customer_key VARCHAR(255) NOT NULL,
      name VARCHAR(255),
      email VARCHAR(255),
      phone VARCHAR(40),
      total_transactions INT NOT NULL DEFAULT 0,
      captured_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
      last_payment_at TIMESTAMP NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NULL DEFAULT NULL,
      UNIQUE KEY uniq_customers_client_key (client_id, customer_key),
      FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    )`,
  );

  await pool.query(
    `CREATE TABLE IF NOT EXISTS transactions (
      id INT PRIMARY KEY AUTO_INCREMENT,
      client_id INT NOT NULL,
      customer_id INT NULL,
      razorpay_order_id VARCHAR(255) UNIQUE,
      razorpay_payment_id VARCHAR(255) UNIQUE,
      razorpay_refund_id VARCHAR(255),
      receipt VARCHAR(255),
      amount DECIMAL(12,2) NOT NULL,
      currency CHAR(3) NOT NULL DEFAULT 'INR',
      status ENUM('created', 'captured', 'authorized', 'failed', 'refunded') NOT NULL DEFAULT 'captured',
      customer_name VARCHAR(255),
      customer_email VARCHAR(255),
      customer_phone VARCHAR(40),
      notes TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NULL DEFAULT NULL,
      FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
      FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL
    )`,
  );

  await pool.query(
    `CREATE TABLE IF NOT EXISTS client_api_keys (
      id INT PRIMARY KEY AUTO_INCREMENT,
      client_id INT NOT NULL,
      name VARCHAR(120) NOT NULL DEFAULT 'Default API key',
      api_key VARCHAR(255) UNIQUE NOT NULL,
      api_secret_hash VARCHAR(255) NOT NULL,
      api_secret_encrypted TEXT,
      status ENUM('active', 'revoked') NOT NULL DEFAULT 'active',
      last_used_at TIMESTAMP NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    )`,
  );

  await pool.query(
    `CREATE TABLE IF NOT EXISTS api_key_requests (
      id INT PRIMARY KEY AUTO_INCREMENT,
      client_id INT NOT NULL,
      name VARCHAR(120) NOT NULL,
      environment_type VARCHAR(60) NOT NULL DEFAULT 'Production (Live)',
      business_justification TEXT,
      status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
      message VARCHAR(255),
      reviewed_at TIMESTAMP NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    )`,
  );

  await pool.query(
    `CREATE TABLE IF NOT EXISTS api_logs (
      id INT PRIMARY KEY AUTO_INCREMENT,
      client_id INT,
      api_key_id INT,
      method VARCHAR(12) NOT NULL,
      endpoint VARCHAR(255) NOT NULL,
      status_code INT NOT NULL,
      message VARCHAR(255),
      request_payload TEXT,
      response_payload TEXT,
      request_id VARCHAR(80) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL,
      FOREIGN KEY (api_key_id) REFERENCES client_api_keys(id) ON DELETE SET NULL
    )`,
  );

  await pool.query(
    `CREATE TABLE IF NOT EXISTS razorpay_events (
      id INT PRIMARY KEY AUTO_INCREMENT,
      client_id INT NOT NULL,
      event_id VARCHAR(255) UNIQUE,
      event_name VARCHAR(255) NOT NULL,
      payload TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    )`,
  );

  await pool.query(
    `CREATE TABLE IF NOT EXISTS support_tickets (
      id INT PRIMARY KEY AUTO_INCREMENT,
      client_id INT NOT NULL,
      created_by_user_id INT NULL,
      subject VARCHAR(255) NOT NULL,
      category VARCHAR(120) NOT NULL DEFAULT 'General support',
      priority ENUM('low', 'normal', 'high', 'urgent') NOT NULL DEFAULT 'normal',
      status ENUM('open', 'in_progress', 'resolved', 'closed') NOT NULL DEFAULT 'open',
      message TEXT NOT NULL,
      admin_reply TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NULL DEFAULT NULL,
      resolved_at TIMESTAMP NULL,
      FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
      FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
    )`,
  );

  const clientApiKeyColumns = await getTableColumns('client_api_keys');
  await addColumnIfMissing('client_api_keys', clientApiKeyColumns, 'name', "VARCHAR(120) NOT NULL DEFAULT 'Default API key'");
  await addColumnIfMissing('client_api_keys', clientApiKeyColumns, 'api_secret_encrypted', 'TEXT');
  await addColumnIfMissing('client_api_keys', clientApiKeyColumns, 'last_used_at', 'TIMESTAMP NULL');

  const customerColumns = await getTableColumns('customers');
  await addColumnIfMissing('customers', customerColumns, 'customer_key', 'VARCHAR(255) NOT NULL');
  await addColumnIfMissing('customers', customerColumns, 'total_transactions', 'INT NOT NULL DEFAULT 0');
  await addColumnIfMissing('customers', customerColumns, 'captured_amount', 'DECIMAL(12,2) NOT NULL DEFAULT 0.00');
  await addColumnIfMissing('customers', customerColumns, 'last_payment_at', 'TIMESTAMP NULL');
  await addColumnIfMissing('customers', customerColumns, 'updated_at', 'TIMESTAMP NULL DEFAULT NULL');

  const transactionColumns = await getTableColumns('transactions');
  await addColumnIfMissing('transactions', transactionColumns, 'customer_id', 'INT NULL');
  await addColumnIfMissing('transactions', transactionColumns, 'razorpay_order_id', 'VARCHAR(255) UNIQUE');
  await addColumnIfMissing('transactions', transactionColumns, 'razorpay_refund_id', 'VARCHAR(255)');
  await addColumnIfMissing('transactions', transactionColumns, 'receipt', 'VARCHAR(255)');
  await addColumnIfMissing('transactions', transactionColumns, 'customer_name', 'VARCHAR(255)');
  await addColumnIfMissing('transactions', transactionColumns, 'customer_phone', 'VARCHAR(40)');
  await addColumnIfMissing('transactions', transactionColumns, 'notes', 'TEXT');
  await addColumnIfMissing('transactions', transactionColumns, 'updated_at', 'TIMESTAMP NULL DEFAULT NULL');

  const apiRequestColumns = await getTableColumns('api_key_requests');
  await addColumnIfMissing('api_key_requests', apiRequestColumns, 'name', "VARCHAR(120) NOT NULL DEFAULT 'Default API key'");
  await addColumnIfMissing('api_key_requests', apiRequestColumns, 'environment_type', "VARCHAR(60) NOT NULL DEFAULT 'Production (Live)'");
  await addColumnIfMissing('api_key_requests', apiRequestColumns, 'business_justification', 'TEXT');
  await addColumnIfMissing('api_key_requests', apiRequestColumns, 'reviewed_at', 'TIMESTAMP NULL');

  const apiLogColumns = await getTableColumns('api_logs');
  await addColumnIfMissing('api_logs', apiLogColumns, 'api_key_id', 'INT');
  await addColumnIfMissing('api_logs', apiLogColumns, 'message', 'VARCHAR(255)');
  await addColumnIfMissing('api_logs', apiLogColumns, 'request_payload', 'TEXT');
  await addColumnIfMissing('api_logs', apiLogColumns, 'response_payload', 'TEXT');
  await addColumnIfMissing('api_logs', apiLogColumns, 'request_id', 'VARCHAR(80) NOT NULL DEFAULT ""');

  const supportTicketColumns = await getTableColumns('support_tickets');
  await addColumnIfMissing('support_tickets', supportTicketColumns, 'created_by_user_id', 'INT NULL');
  await addColumnIfMissing('support_tickets', supportTicketColumns, 'category', "VARCHAR(120) NOT NULL DEFAULT 'General support'");
  await addColumnIfMissing('support_tickets', supportTicketColumns, 'admin_reply', 'TEXT');
  await addColumnIfMissing('support_tickets', supportTicketColumns, 'updated_at', 'TIMESTAMP NULL DEFAULT NULL');
  await addColumnIfMissing('support_tickets', supportTicketColumns, 'resolved_at', 'TIMESTAMP NULL');

  await pool.query(
    `UPDATE api_key_requests
     SET environment_type = 'Sandbox (Testing)'
     WHERE LOWER(COALESCE(message, '')) LIKE '%sandbox%'
      AND environment_type = 'Production (Live)'`,
  );

  await pool.query(
    `UPDATE api_key_requests
     SET business_justification = TRIM(SUBSTRING_INDEX(message, ' | ', -1))
     WHERE business_justification IS NULL
      AND message LIKE 'Environment:% | %'`,
  );

  await pool.query(
    `INSERT INTO customers (client_id, customer_key, name, email, phone)
     SELECT
      client_id,
      CASE
        WHEN customer_email IS NOT NULL AND customer_email <> '' THEN CONCAT('email:', LOWER(customer_email))
        WHEN customer_phone IS NOT NULL AND customer_phone <> '' THEN CONCAT('phone:', customer_phone)
        ELSE CONCAT('name:', LOWER(customer_name))
      END AS customer_key,
      MAX(customer_name) AS name,
      MAX(customer_email) AS email,
      MAX(customer_phone) AS phone
     FROM transactions
     WHERE customer_email IS NOT NULL OR customer_phone IS NOT NULL OR customer_name IS NOT NULL
     GROUP BY client_id, customer_key
     ON DUPLICATE KEY UPDATE
      name = COALESCE(VALUES(name), name),
      email = COALESCE(VALUES(email), email),
      phone = COALESCE(VALUES(phone), phone),
      updated_at = CURRENT_TIMESTAMP`,
  );

  await pool.query(
    `UPDATE transactions t
     JOIN customers c
      ON c.client_id = t.client_id
      AND c.customer_key = CASE
        WHEN t.customer_email IS NOT NULL AND t.customer_email <> '' THEN CONCAT('email:', LOWER(t.customer_email))
        WHEN t.customer_phone IS NOT NULL AND t.customer_phone <> '' THEN CONCAT('phone:', t.customer_phone)
        ELSE CONCAT('name:', LOWER(t.customer_name))
      END
     SET t.customer_id = c.id
     WHERE t.customer_id IS NULL
      AND (t.customer_email IS NOT NULL OR t.customer_phone IS NOT NULL OR t.customer_name IS NOT NULL)`,
  );

  await pool.query(
    `UPDATE customers c
     SET
      total_transactions = (
        SELECT COUNT(*) FROM transactions t WHERE t.customer_id = c.id
      ),
      captured_amount = (
        SELECT COALESCE(SUM(CASE WHEN t.status = 'captured' THEN t.amount ELSE 0 END), 0)
        FROM transactions t
        WHERE t.customer_id = c.id
      ),
      last_payment_at = (
        SELECT MAX(t.created_at) FROM transactions t WHERE t.customer_id = c.id
      ),
      updated_at = CURRENT_TIMESTAMP`,
  );
};

app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ status: 'Backend is running', timestamp: new Date().toISOString() });
});

app.post('/api/auth/register', async (req: Request, res: Response) => {
  const fullName = normalizeRequiredString(req.body.fullName || req.body.name);
  const email = normalizeRequiredString(req.body.email).toLowerCase();
  const phoneNumber = normalizeRequiredString(req.body.phoneNumber);
  const businessName = normalizeRequiredString(req.body.businessName || req.body.companyName);
  const password = normalizeRequiredString(req.body.password);
  const confirmPassword = normalizeRequiredString(req.body.confirmPassword);
  const businessWebsite = normalizeOptionalString(req.body.businessWebsite);
  const panNumber = normalizeRequiredString(req.body.panNumber).toUpperCase();
  const aadhaarNumber = normalizeRequiredString(req.body.aadhaarNumber).replace(/\s+/g, '');
  const gstNumber = normalizeOptionalString(req.body.gstNumber)?.toUpperCase() || null;
  const businessCategory = normalizeRequiredString(req.body.businessCategory);
  const businessAddress = normalizeRequiredString(req.body.businessAddress);
  const city = normalizeRequiredString(req.body.city);
  const state = normalizeRequiredString(req.body.state);
  const pincode = normalizeRequiredString(req.body.pincode);

  if (!fullName || !email || !phoneNumber || !businessName || !password || !confirmPassword || !panNumber || !aadhaarNumber || !businessCategory || !businessAddress || !city || !state || !pincode) {
    res.status(400).json({ error: 'Full name, email, phone, business details, PAN, Aadhaar, password, and address are required' });
    return;
  }

  if (password !== confirmPassword) {
    res.status(400).json({ error: 'Password and confirm password must match' });
    return;
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [clientResult] = await connection.execute<ResultSetHeader>(
      `INSERT INTO clients
        (company_name, contact_name, email, phone_number, business_website, pan_number, aadhaar_number, gst_number,
         business_category, business_address, city, state, pincode, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
      [
        businessName,
        fullName,
        email,
        phoneNumber,
        businessWebsite,
        panNumber,
        aadhaarNumber,
        gstNumber,
        businessCategory,
        businessAddress,
        city,
        state,
        pincode,
      ],
    );

    const [userResult] = await connection.execute<ResultSetHeader>(
      `INSERT INTO users (client_id, name, email, password_hash, role)
       VALUES (?, ?, ?, ?, 'client_admin')`,
      [clientResult.insertId, fullName, email, hashPassword(password)],
    );

    await connection.commit();

    const user: SessionUser = {
      id: userResult.insertId,
      clientId: clientResult.insertId,
      name: fullName,
      email,
      role: 'client_admin',
    };
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, user);

    res.status(201).json({ token, user });
  } catch (error: any) {
    await connection.rollback();
    const isDuplicate = error?.code === 'ER_DUP_ENTRY';
    res.status(isDuplicate ? 409 : 500).json({
      error: isDuplicate ? 'A client or user with this email already exists' : 'Registration failed',
    });
  } finally {
    connection.release();
  }
});

app.post('/api/auth/login', async (req: Request, res: Response) => {
  const email = normalizeRequiredString(req.body.email).toLowerCase();
  const password = normalizeRequiredString(req.body.password);

  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required' });
    return;
  }

  try {
    const [adminRows] = await pool.execute<AdminRow[]>(
      'SELECT id, name, email, password_hash, status FROM admins WHERE email = ? LIMIT 1',
      [email],
    );
    const adminRow = adminRows[0];

    if (adminRow) {
      if (adminRow.status !== 'active' || !verifyPassword(password, adminRow.password_hash)) {
        res.status(401).json({ error: 'Invalid email or password' });
        return;
      }

      const user = toAdminSessionUser(adminRow);
      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, user);
      res.json({ token, user });
      return;
    }

    const [rows] = await pool.execute<UserRow[]>(
      `SELECT id, client_id, name, email, password_hash, role
       FROM users
       WHERE email = ? AND role = 'client_admin'
       LIMIT 1`,
      [email],
    );
    const userRow = rows[0];

    if (!userRow || !verifyPassword(password, userRow.password_hash)) {
      res.status(401).json({ error: 'Invalid email or password' });
      return;
    }

    const user = toSessionUser(userRow);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, user);

    res.json({ token, user });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', requireAuth, (req: Request, res: Response) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (token) {
    sessions.delete(token);
  }

  res.json({ ok: true });
});

app.get('/api/admin/dashboard', requireAuth, requireRole('main_admin'), async (_req: Request, res: Response) => {
  try {
    const [
      [clientStats],
      [transactionStats],
      [apiStats],
      [recentTransactions],
      [clients],
      [customerSummaries],
      [apiLogs],
      [apiKeyRequests],
      [supportTickets],
      [monthlyRevenue],
      [transactionStatusBreakdown],
      [clientStatusBreakdown],
      [apiStatusBreakdown],
      [ticketStatusBreakdown],
      [topClients],
      settings,
    ] = await Promise.all([
      pool.query<RowDataPacket[]>(
        `SELECT
          COUNT(*) AS totalClients,
          SUM(status = 'active') AS activeClients,
          SUM(status = 'pending') AS pendingClients
        FROM clients`,
      ),
      pool.query<RowDataPacket[]>(
        `SELECT
          COUNT(*) AS totalTransactions,
          COALESCE(SUM(CASE WHEN status = 'captured' THEN amount ELSE 0 END), 0) AS capturedAmount
        FROM transactions`,
      ),
      pool.query<RowDataPacket[]>('SELECT COUNT(*) AS totalApiCalls FROM api_logs'),
      pool.query<RowDataPacket[]>(
        `SELECT t.id, t.razorpay_order_id, t.razorpay_payment_id, t.razorpay_refund_id, t.amount, t.currency,
          t.status, t.customer_name, t.customer_email, t.customer_phone, t.created_at, c.company_name
         FROM transactions t
         JOIN clients c ON c.id = t.client_id
         ORDER BY t.created_at DESC
         LIMIT 20`,
      ),
      pool.query<RowDataPacket[]>(
        `SELECT c.id, c.company_name, c.contact_name, c.email, c.phone_number, c.business_website,
          c.pan_number, c.aadhaar_number, c.gst_number, c.business_category, c.business_address,
          c.city, c.state, c.pincode, c.status, c.razorpay_key_id,
          COALESCE(tx.transaction_count, 0) AS transaction_count,
          COALESCE(tx.captured_amount, 0) AS captured_amount,
          COALESCE(ak.api_key_count, 0) AS api_key_count
         FROM clients c
         LEFT JOIN (
          SELECT client_id,
            COUNT(*) AS transaction_count,
            COALESCE(SUM(CASE WHEN status = 'captured' THEN amount ELSE 0 END), 0) AS captured_amount
          FROM transactions
          GROUP BY client_id
         ) tx ON tx.client_id = c.id
         LEFT JOIN (
          SELECT client_id, COUNT(*) AS api_key_count
          FROM client_api_keys
          GROUP BY client_id
         ) ak ON ak.client_id = c.id
         ORDER BY c.created_at DESC`,
      ),
      pool.query<RowDataPacket[]>(
        `SELECT
          c.company_name,
          cu.name AS customer_name,
          cu.email AS customer_email,
          cu.phone AS customer_phone,
          cu.total_transactions AS transaction_count,
          cu.captured_amount,
          cu.last_payment_at
         FROM customers cu
         JOIN clients c ON c.id = cu.client_id
         ORDER BY cu.last_payment_at DESC, COALESCE(cu.updated_at, cu.created_at) DESC
         LIMIT 50`,
      ),
      pool.query<RowDataPacket[]>(
        `SELECT l.id, l.method, l.endpoint, l.status_code, l.message, l.request_id, l.created_at,
          c.company_name
         FROM api_logs l
         LEFT JOIN clients c ON c.id = l.client_id
         ORDER BY l.created_at DESC
         LIMIT 10`,
      ),
      pool.query<RowDataPacket[]>(
        `SELECT r.id, r.client_id, r.name, r.environment_type, r.business_justification,
          r.status, r.message, r.reviewed_at, r.created_at,
          c.company_name, c.email
         FROM api_key_requests r
         JOIN clients c ON c.id = r.client_id
         ORDER BY r.created_at DESC
         LIMIT 20`,
      ),
      pool.query<RowDataPacket[]>(
        `SELECT t.id, t.client_id, t.subject, t.category, t.priority, t.status, t.message,
          t.admin_reply, t.created_at, COALESCE(t.updated_at, t.created_at) AS updated_at, t.resolved_at,
          c.company_name, c.email,
          u.name AS created_by_name, u.email AS created_by_email
         FROM support_tickets t
         JOIN clients c ON c.id = t.client_id
         LEFT JOIN users u ON u.id = t.created_by_user_id
         ORDER BY FIELD(t.status, 'open', 'in_progress', 'resolved', 'closed'), COALESCE(t.updated_at, t.created_at) DESC
         LIMIT 50`,
      ),
      pool.query<RowDataPacket[]>(
        `SELECT
          DATE_FORMAT(created_at, '%Y-%m') AS label,
          COUNT(*) AS transaction_count,
          COALESCE(SUM(CASE WHEN status = 'captured' THEN amount ELSE 0 END), 0) AS captured_amount
         FROM transactions
         WHERE created_at >= DATE_SUB(CURRENT_DATE, INTERVAL 6 MONTH)
         GROUP BY DATE_FORMAT(created_at, '%Y-%m')
         ORDER BY label ASC`,
      ),
      pool.query<RowDataPacket[]>(
        `SELECT status AS label, COUNT(*) AS count, COALESCE(SUM(amount), 0) AS amount
         FROM transactions
         GROUP BY status
         ORDER BY count DESC`,
      ),
      pool.query<RowDataPacket[]>(
        `SELECT status AS label, COUNT(*) AS count
         FROM clients
         GROUP BY status
         ORDER BY count DESC`,
      ),
      pool.query<RowDataPacket[]>(
        `SELECT
          CASE
            WHEN status_code BETWEEN 200 AND 299 THEN 'success'
            WHEN status_code BETWEEN 400 AND 499 THEN 'client_error'
            WHEN status_code >= 500 THEN 'server_error'
            ELSE 'other'
          END AS label,
          COUNT(*) AS count
         FROM api_logs
         GROUP BY label
         ORDER BY count DESC`,
      ),
      pool.query<RowDataPacket[]>(
        `SELECT status AS label, COUNT(*) AS count
         FROM support_tickets
         GROUP BY status
         ORDER BY FIELD(status, 'open', 'in_progress', 'resolved', 'closed')`,
      ),
      pool.query<RowDataPacket[]>(
        `SELECT
          c.id,
          c.company_name,
          c.email,
          c.status,
          COALESCE(COUNT(t.id), 0) AS transaction_count,
          COALESCE(SUM(CASE WHEN t.status = 'captured' THEN t.amount ELSE 0 END), 0) AS captured_amount,
          COALESCE(SUM(t.status = 'failed'), 0) AS failed_transactions,
          COALESCE(COUNT(DISTINCT cu.id), 0) AS customer_count,
          COALESCE(COUNT(DISTINCT l.id), 0) AS api_call_count
         FROM clients c
         LEFT JOIN transactions t ON t.client_id = c.id
         LEFT JOIN customers cu ON cu.client_id = c.id
         LEFT JOIN api_logs l ON l.client_id = c.id
         GROUP BY c.id
         ORDER BY captured_amount DESC
         LIMIT 12`,
      ),
      getPlatformRazorpayState(),
    ]);

    res.json({
      stats: {
        totalClients: Number(clientStats[0]?.totalClients || 0),
        activeClients: Number(clientStats[0]?.activeClients || 0),
        pendingClients: Number(clientStats[0]?.pendingClients || 0),
        totalTransactions: Number(transactionStats[0]?.totalTransactions || 0),
        capturedAmount: Number(transactionStats[0]?.capturedAmount || 0),
        totalApiCalls: Number(apiStats[0]?.totalApiCalls || 0),
      },
      recentTransactions,
      clients,
      customerSummaries,
      apiLogs,
      apiKeyRequests,
      supportTickets,
      analytics: {
        monthlyRevenue,
        transactionStatusBreakdown,
        clientStatusBreakdown,
        apiStatusBreakdown,
        ticketStatusBreakdown,
        topClients,
      },
      razorpayKeys: settings,
    });
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).json({ error: 'Unable to load admin dashboard' });
  }
});

app.post('/api/admin/api-key-requests/:requestId/approve', requireAuth, requireRole('main_admin'), async (req: Request, res: Response) => {
  const requestId = Number(req.params.requestId);

  if (!Number.isInteger(requestId)) {
    res.status(400).json({ error: 'Valid request id is required' });
    return;
  }

  const connection = await pool.getConnection();
  const apiKey = `pk_${crypto.randomBytes(16).toString('hex')}`;
  const apiSecret = `sk_${crypto.randomBytes(24).toString('hex')}`;

  try {
    await connection.beginTransaction();

    const [requests] = await connection.execute<RowDataPacket[]>(
      `SELECT r.id, r.client_id, r.name, r.status, c.status AS client_status
       FROM api_key_requests r
       JOIN clients c ON c.id = r.client_id
       WHERE r.id = ?
       LIMIT 1`,
      [requestId],
    );
    const keyRequest = requests[0];

    if (!keyRequest) {
      await connection.rollback();
      res.status(404).json({ error: 'API key request not found' });
      return;
    }

    if (keyRequest.status !== 'pending') {
      await connection.rollback();
      res.status(409).json({ error: 'API key request is already reviewed' });
      return;
    }

    if (keyRequest.client_status === 'paused') {
      await connection.rollback();
      res.status(400).json({ error: 'Client is paused. Activate the client before issuing platform API keys' });
      return;
    }

    if (keyRequest.client_status === 'pending') {
      await connection.execute('UPDATE clients SET status = ? WHERE id = ?', ['active', keyRequest.client_id]);
    }

    const [result] = await connection.execute<ResultSetHeader>(
      `INSERT INTO client_api_keys (client_id, name, api_key, api_secret_hash, api_secret_encrypted)
       VALUES (?, ?, ?, ?, ?)`,
      [keyRequest.client_id, keyRequest.name || 'Approved API key', apiKey, hashPassword(apiSecret), encryptSecret(apiSecret)],
    );

    await connection.execute(
      `UPDATE api_key_requests
       SET status = 'approved', reviewed_at = CURRENT_TIMESTAMP, message = ?
       WHERE id = ?`,
      [`Approved. Issued PayDesk platform API key ${apiKey}.`, requestId],
    );

    await connection.commit();
    res.status(201).json({ id: result.insertId, clientId: keyRequest.client_id, apiKey, apiSecret });
  } catch (error) {
    await connection.rollback();
    console.error('API key approval error:', error);
    res.status(500).json({ error: 'Unable to approve API key request' });
  } finally {
    connection.release();
  }
});

app.patch('/api/admin/api-key-requests/:requestId/reject', requireAuth, requireRole('main_admin'), async (req: Request, res: Response) => {
  const requestId = Number(req.params.requestId);
  const message = String(req.body.message || 'Rejected by main admin');

  if (!Number.isInteger(requestId)) {
    res.status(400).json({ error: 'Valid request id is required' });
    return;
  }

  try {
    await pool.execute(
      `UPDATE api_key_requests
       SET status = 'rejected', reviewed_at = CURRENT_TIMESTAMP, message = ?
       WHERE id = ? AND status = 'pending'`,
      [message, requestId],
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('API key request reject error:', error);
    res.status(500).json({ error: 'Unable to reject API key request' });
  }
});

app.patch('/api/admin/support-tickets/:ticketId', requireAuth, requireRole('main_admin'), async (req: Request, res: Response) => {
  const ticketId = Number(req.params.ticketId);
  const status = req.body.status;
  const priority = req.body.priority;
  const adminReply = normalizeOptionalString(req.body.adminReply || req.body.admin_reply);

  if (!Number.isInteger(ticketId)) {
    res.status(400).json({ error: 'Valid ticket id is required' });
    return;
  }

  if (status !== undefined && !isTicketStatus(status)) {
    res.status(400).json({ error: 'Valid ticket status is required' });
    return;
  }

  if (priority !== undefined && !isTicketPriority(priority)) {
    res.status(400).json({ error: 'Valid ticket priority is required' });
    return;
  }

  try {
    const [result] = await pool.execute<ResultSetHeader>(
      `UPDATE support_tickets
       SET
        status = COALESCE(?, status),
        priority = COALESCE(?, priority),
        admin_reply = COALESCE(?, admin_reply),
        updated_at = CURRENT_TIMESTAMP,
        resolved_at = CASE
          WHEN ? IN ('resolved', 'closed') THEN COALESCE(resolved_at, CURRENT_TIMESTAMP)
          WHEN ? IN ('open', 'in_progress') THEN NULL
          ELSE resolved_at
        END
       WHERE id = ?`,
      [status || null, priority || null, adminReply, status || null, status || null, ticketId],
    );

    if (result.affectedRows === 0) {
      res.status(404).json({ error: 'Support ticket not found' });
      return;
    }

    res.json({ ok: true });
  } catch (error) {
    console.error('Support ticket update error:', error);
    res.status(500).json({ error: 'Unable to update support ticket' });
  }
});

app.put('/api/admin/razorpay-keys', requireAuth, requireRole('main_admin'), async (req: Request, res: Response) => {
  const keyId = normalizeRequiredString(req.body.keyId);
  const keySecret = normalizeOptionalString(req.body.keySecret);
  const webhookSecret = normalizeOptionalString(req.body.webhookSecret);

  if (!keyId) {
    res.status(400).json({ error: 'Razorpay Key ID is required' });
    return;
  }

  try {
    const existing = await getPlatformSettingRows(['razorpay_key_id', 'razorpay_key_secret', 'razorpay_webhook_secret']);
    const existingKeyId = existing.razorpay_key_id?.value || '';
    const existingKeySecret = existing.razorpay_key_secret?.value || '';
    const existingWebhookSecret = existing.razorpay_webhook_secret?.value || '';

    if (!keySecret && !existingKeySecret) {
      res.status(400).json({ error: 'Razorpay Key Secret is required' });
      return;
    }

    if (!keySecret && existingKeyId && existingKeyId !== keyId) {
      res.status(400).json({ error: 'Enter the matching Razorpay Key Secret when changing the Key ID' });
      return;
    }

    await pool.execute(
      `INSERT INTO platform_settings (setting_key, setting_value) VALUES
        ('razorpay_key_id', ?),
        ('razorpay_key_secret', ?),
        ('razorpay_webhook_secret', ?)
       ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)`,
      [
        keyId,
        keySecret ? encryptSecret(keySecret) : existingKeySecret,
        webhookSecret ? encryptSecret(webhookSecret) : existingWebhookSecret,
      ],
    );

    res.json({ ok: true });
  } catch (error) {
    console.error('Platform key update error:', error);
    res.status(500).json({ error: 'Unable to update platform keys' });
  }
});

const saveRazorpayTestResult = async (status: 'success' | 'failed', message: string) => {
  await pool.execute(
    `INSERT INTO platform_settings (setting_key, setting_value) VALUES
      ('razorpay_last_tested_at', ?),
      ('razorpay_last_test_status', ?),
      ('razorpay_last_test_message', ?)
     ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)`,
    [new Date().toISOString(), status, message.slice(0, 500)],
  );
};

app.post('/api/admin/razorpay-keys/test', requireAuth, requireRole('main_admin'), async (_req: Request, res: Response) => {
  try {
    await razorpayRequest<Record<string, unknown>>('/orders?count=1', 'GET');
    const message = 'Razorpay credentials authenticated successfully';
    await saveRazorpayTestResult('success', message);
    res.json({ ok: true, message });
  } catch (error: any) {
    const statusCode = error?.statusCode || 500;
    const message = error?.message || 'Unable to authenticate Razorpay credentials';
    await saveRazorpayTestResult('failed', message);
    res.status(statusCode).json({
      ok: false,
      error: message,
    });
  }
});

app.patch('/api/admin/clients/:clientId/status', requireAuth, requireRole('main_admin'), async (req: Request, res: Response) => {
  const clientId = Number(req.params.clientId);
  const { status } = req.body;

  if (!Number.isInteger(clientId) || !['active', 'paused', 'pending'].includes(status)) {
    res.status(400).json({ error: 'Valid client id and status are required' });
    return;
  }

  try {
    await pool.execute('UPDATE clients SET status = ? WHERE id = ?', [status, clientId]);
    res.json({ ok: true });
  } catch (error) {
    console.error('Client status update error:', error);
    res.status(500).json({ error: 'Unable to update client status' });
  }
});

app.post('/api/admin/clients', requireAuth, requireRole('main_admin'), async (req: Request, res: Response) => {
  const {
    companyName,
    contactName,
    email,
    phoneNumber,
    businessWebsite,
    panNumber,
    aadhaarNumber,
    gstNumber,
    businessCategory,
    businessAddress,
    city,
    state: businessState,
    pincode,
    status = 'pending',
    adminName,
    adminEmail,
    adminPassword,
  } = req.body;

  if (!companyName || !contactName || !email || !['active', 'paused', 'pending'].includes(status)) {
    res.status(400).json({ error: 'Company, contact, email, and valid status are required' });
    return;
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();
    const [clientResult] = await connection.execute<ResultSetHeader>(
      `INSERT INTO clients
        (company_name, contact_name, email, phone_number, business_website, pan_number, aadhaar_number, gst_number,
         business_category, business_address, city, state, pincode, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        companyName,
        contactName,
        email,
        normalizeOptionalString(phoneNumber),
        normalizeOptionalString(businessWebsite),
        normalizeOptionalString(panNumber)?.toUpperCase() || null,
        normalizeOptionalString(aadhaarNumber)?.replace(/\s+/g, '') || null,
        normalizeOptionalString(gstNumber)?.toUpperCase() || null,
        normalizeOptionalString(businessCategory),
        normalizeOptionalString(businessAddress),
        normalizeOptionalString(city),
        normalizeOptionalString(businessState),
        normalizeOptionalString(pincode),
        status,
      ],
    );

    if (adminName && adminEmail && adminPassword) {
      await connection.execute(
        `INSERT INTO users (client_id, name, email, password_hash, role)
         VALUES (?, ?, ?, ?, 'client_admin')`,
        [clientResult.insertId, adminName, adminEmail, hashPassword(adminPassword)],
      );
    }

    await connection.commit();
    res.status(201).json({ id: clientResult.insertId });
  } catch (error: any) {
    await connection.rollback();
    res.status(error?.code === 'ER_DUP_ENTRY' ? 409 : 500).json({
      error: error?.code === 'ER_DUP_ENTRY' ? 'Client or admin email already exists' : 'Unable to create client',
    });
  } finally {
    connection.release();
  }
});

app.put('/api/admin/clients/:clientId', requireAuth, requireRole('main_admin'), async (req: Request, res: Response) => {
  const clientId = Number(req.params.clientId);
  const {
    companyName,
    contactName,
    email,
    phoneNumber,
    businessWebsite,
    panNumber,
    aadhaarNumber,
    gstNumber,
    businessCategory,
    businessAddress,
    city,
    state: businessState,
    pincode,
    status,
  } = req.body;

  if (!Number.isInteger(clientId) || !companyName || !contactName || !email || !['active', 'paused', 'pending'].includes(status)) {
    res.status(400).json({ error: 'Client id, company, contact, email, and valid status are required' });
    return;
  }

  try {
    const [result] = await pool.execute<ResultSetHeader>(
      `UPDATE clients
       SET company_name = ?, contact_name = ?, email = ?,
        phone_number = COALESCE(?, phone_number),
        business_website = COALESCE(?, business_website),
        pan_number = COALESCE(?, pan_number),
        aadhaar_number = COALESCE(?, aadhaar_number),
        gst_number = COALESCE(?, gst_number),
        business_category = COALESCE(?, business_category),
        business_address = COALESCE(?, business_address),
        city = COALESCE(?, city),
        state = COALESCE(?, state),
        pincode = COALESCE(?, pincode),
        status = ?
       WHERE id = ?`,
      [
        companyName,
        contactName,
        email,
        normalizeOptionalString(phoneNumber),
        normalizeOptionalString(businessWebsite),
        normalizeOptionalString(panNumber)?.toUpperCase() || null,
        normalizeOptionalString(aadhaarNumber)?.replace(/\s+/g, '') || null,
        normalizeOptionalString(gstNumber)?.toUpperCase() || null,
        normalizeOptionalString(businessCategory),
        normalizeOptionalString(businessAddress),
        normalizeOptionalString(city),
        normalizeOptionalString(businessState),
        normalizeOptionalString(pincode),
        status,
        clientId,
      ],
    );

    if (result.affectedRows === 0) {
      res.status(404).json({ error: 'Client not found' });
      return;
    }

    res.json({ ok: true });
  } catch (error: any) {
    res.status(error?.code === 'ER_DUP_ENTRY' ? 409 : 500).json({
      error: error?.code === 'ER_DUP_ENTRY' ? 'A client with this email already exists' : 'Unable to update client',
    });
  }
});

app.delete('/api/admin/clients/:clientId', requireAuth, requireRole('main_admin'), async (req: Request, res: Response) => {
  const clientId = Number(req.params.clientId);

  if (!Number.isInteger(clientId)) {
    res.status(400).json({ error: 'Valid client id is required' });
    return;
  }

  try {
    const [result] = await pool.execute<ResultSetHeader>('DELETE FROM clients WHERE id = ?', [clientId]);

    if (result.affectedRows === 0) {
      res.status(404).json({ error: 'Client not found' });
      return;
    }

    res.json({ ok: true });
  } catch (error) {
    console.error('Client delete error:', error);
    res.status(500).json({ error: 'Unable to delete client' });
  }
});

app.get('/api/client/:clientId/dashboard', requireAuth, requireClientAccess, async (req: Request, res: Response) => {
  const clientId = Number(req.params.clientId);

  try {
    const [
      [clients],
      [transactionStats],
      [transactions],
      [customerSummaries],
      [apiKeys],
      [apiLogs],
      [apiKeyRequests],
      [supportTickets],
      [monthlyRevenue],
      [transactionStatusBreakdown],
      [apiStatusBreakdown],
      [ticketStatusBreakdown],
      [paymentReports],
      [settlementReports],
    ] = await Promise.all([
      pool.query<RowDataPacket[]>('SELECT * FROM clients WHERE id = ? LIMIT 1', [clientId]),
      pool.query<RowDataPacket[]>(
        `SELECT
          COUNT(*) AS totalTransactions,
          COALESCE(SUM(CASE WHEN status = 'captured' THEN amount ELSE 0 END), 0) AS capturedAmount,
          SUM(status = 'failed') AS failedTransactions
         FROM transactions
         WHERE client_id = ?`,
        [clientId],
      ),
      pool.query<RowDataPacket[]>(
        `SELECT id, razorpay_order_id, razorpay_payment_id, razorpay_refund_id, amount, currency, status,
          customer_name, customer_email, customer_phone, created_at
         FROM transactions
         WHERE client_id = ?
         ORDER BY created_at DESC
         LIMIT 12`,
        [clientId],
      ),
      pool.query<RowDataPacket[]>(
        `SELECT
          name AS customer_name,
          email AS customer_email,
          phone AS customer_phone,
          total_transactions AS transaction_count,
          captured_amount,
          last_payment_at
         FROM customers
         WHERE client_id = ?
         ORDER BY last_payment_at DESC, COALESCE(updated_at, created_at) DESC
         LIMIT 50`,
        [clientId],
      ),
      pool.query<RowDataPacket[]>(
        `SELECT id, name, api_key, api_secret_encrypted, status, last_used_at, created_at
         FROM client_api_keys
         WHERE client_id = ?
         ORDER BY created_at DESC`,
        [clientId],
      ),
      pool.query<RowDataPacket[]>(
        `SELECT id, method, endpoint, status_code, message, request_payload, response_payload, request_id, created_at
         FROM api_logs
         WHERE client_id = ?
         ORDER BY created_at DESC
         LIMIT 10`,
        [clientId],
      ),
      pool.query<RowDataPacket[]>(
        `SELECT id, name, environment_type, business_justification, status, message, reviewed_at, created_at
         FROM api_key_requests
         WHERE client_id = ?
         ORDER BY created_at DESC
         LIMIT 10`,
        [clientId],
      ),
      pool.query<RowDataPacket[]>(
        `SELECT id, client_id, subject, category, priority, status, message, admin_reply, created_at, COALESCE(updated_at, created_at) AS updated_at, resolved_at
         FROM support_tickets
         WHERE client_id = ?
         ORDER BY COALESCE(updated_at, created_at) DESC, created_at DESC
         LIMIT 30`,
        [clientId],
      ),
      pool.query<RowDataPacket[]>(
        `SELECT
          DATE_FORMAT(created_at, '%Y-%m') AS label,
          COUNT(*) AS transaction_count,
          COALESCE(SUM(CASE WHEN status = 'captured' THEN amount ELSE 0 END), 0) AS captured_amount
         FROM transactions
         WHERE client_id = ?
          AND created_at >= DATE_SUB(CURRENT_DATE, INTERVAL 6 MONTH)
         GROUP BY DATE_FORMAT(created_at, '%Y-%m')
         ORDER BY label ASC`,
        [clientId],
      ),
      pool.query<RowDataPacket[]>(
        `SELECT status AS label, COUNT(*) AS count, COALESCE(SUM(amount), 0) AS amount
         FROM transactions
         WHERE client_id = ?
         GROUP BY status
         ORDER BY count DESC`,
        [clientId],
      ),
      pool.query<RowDataPacket[]>(
        `SELECT
          CASE
            WHEN status_code BETWEEN 200 AND 299 THEN 'success'
            WHEN status_code BETWEEN 400 AND 499 THEN 'client_error'
            WHEN status_code >= 500 THEN 'server_error'
            ELSE 'other'
          END AS label,
          COUNT(*) AS count
         FROM api_logs
         WHERE client_id = ?
         GROUP BY label
         ORDER BY count DESC`,
        [clientId],
      ),
      pool.query<RowDataPacket[]>(
        `SELECT status AS label, COUNT(*) AS count
         FROM support_tickets
         WHERE client_id = ?
         GROUP BY status
         ORDER BY FIELD(status, 'open', 'in_progress', 'resolved', 'closed')`,
        [clientId],
      ),
      pool.query<RowDataPacket[]>(
        `SELECT
          DATE(created_at) AS report_date,
          COUNT(*) AS transaction_count,
          COALESCE(SUM(CASE WHEN status = 'captured' THEN amount ELSE 0 END), 0) AS captured_amount,
          COALESCE(SUM(CASE WHEN status = 'failed' THEN amount ELSE 0 END), 0) AS failed_amount,
          COALESCE(SUM(status = 'refunded'), 0) AS refunds
         FROM transactions
         WHERE client_id = ?
         GROUP BY DATE(created_at)
         ORDER BY report_date DESC
         LIMIT 30`,
        [clientId],
      ),
      pool.query<RowDataPacket[]>(
        `SELECT
          DATE(DATE_ADD(created_at, INTERVAL 2 DAY)) AS settlement_date,
          COUNT(*) AS transaction_count,
          COALESCE(SUM(CASE WHEN status = 'captured' THEN amount ELSE 0 END), 0) AS gross_amount,
          COALESCE(SUM(CASE WHEN status = 'refunded' THEN amount ELSE 0 END), 0) AS refund_amount,
          COALESCE(SUM(CASE WHEN status = 'captured' THEN amount ELSE 0 END), 0) -
            COALESCE(SUM(CASE WHEN status = 'refunded' THEN amount ELSE 0 END), 0) AS net_amount,
          CASE
            WHEN DATE(DATE_ADD(created_at, INTERVAL 2 DAY)) <= CURRENT_DATE THEN 'settled'
            ELSE 'scheduled'
          END AS status
         FROM transactions
         WHERE client_id = ?
          AND status IN ('captured', 'refunded')
         GROUP BY DATE(DATE_ADD(created_at, INTERVAL 2 DAY))
         ORDER BY settlement_date DESC
         LIMIT 30`,
        [clientId],
      ),
    ]);

    if (!clients[0]) {
      res.status(404).json({ error: 'Client not found' });
      return;
    }

    res.json({
      client: {
        ...clients[0],
        razorpay_key_secret: decryptSecret(clients[0].razorpay_key_secret),
        razorpay_webhook_secret: decryptSecret(clients[0].razorpay_webhook_secret),
      },
      stats: {
        totalTransactions: Number(transactionStats[0]?.totalTransactions || 0),
        capturedAmount: Number(transactionStats[0]?.capturedAmount || 0),
        failedTransactions: Number(transactionStats[0]?.failedTransactions || 0),
      },
      transactions,
      customerSummaries,
      apiKeys: apiKeys.map((apiKey) => ({
        ...apiKey,
        api_secret: decryptSecret(apiKey.api_secret_encrypted),
        api_secret_encrypted: undefined,
      })),
      apiLogs,
      apiKeyRequests,
      supportTickets,
      analytics: {
        monthlyRevenue,
        transactionStatusBreakdown,
        apiStatusBreakdown,
        ticketStatusBreakdown,
        paymentReports,
        settlementReports,
      },
    });
  } catch (error) {
    console.error('Client dashboard error:', error);
    res.status(500).json({ error: 'Unable to load client dashboard' });
  }
});

app.put('/api/client/:clientId/razorpay-keys', requireAuth, requireClientAccess, async (_req: Request, res: Response) => {
  res.status(403).json({ error: 'Razorpay keys are managed only in the main admin platform vault' });
});

app.post('/api/client/:clientId/api-keys', requireAuth, requireClientAccess, async (req: Request, res: Response) => {
  if ((req as AuthedRequest).authUser?.role !== 'main_admin') {
    res.status(403).json({ error: 'API keys are issued by the main admin. Request access instead.' });
    return;
  }

  const clientId = Number(req.params.clientId);
  const { name } = req.body;
  const apiKey = `pk_${crypto.randomBytes(16).toString('hex')}`;
  const apiSecret = `sk_${crypto.randomBytes(24).toString('hex')}`;

  try {
    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT INTO client_api_keys (client_id, name, api_key, api_secret_hash)
       VALUES (?, ?, ?, ?)`,
      [clientId, name || 'Default API key', apiKey, hashPassword(apiSecret)],
    );

    res.status(201).json({ id: result.insertId, apiKey, apiSecret });
  } catch (error) {
    console.error('Client API key create error:', error);
    res.status(500).json({ error: 'Unable to create client API key' });
  }
});

app.post('/api/client/:clientId/api-key-requests', requireAuth, requireClientAccess, async (req: Request, res: Response) => {
  const clientId = Number(req.params.clientId);
  const { name } = req.body;
  const environmentType = normalizeOptionalString(req.body.environmentType) || 'Production (Live)';
  const businessJustification = normalizeOptionalString(req.body.businessJustification);
  const message = normalizeOptionalString(req.body.message);

  if (!name) {
    res.status(400).json({ error: 'API key name is required' });
    return;
  }

  try {
    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT INTO api_key_requests (client_id, name, environment_type, business_justification, message)
       VALUES (?, ?, ?, ?, ?)`,
      [clientId, name, environmentType, businessJustification, message],
    );

    res.status(201).json({ id: result.insertId });
  } catch (error) {
    console.error('API key request error:', error);
    res.status(500).json({ error: 'Unable to request API key' });
  }
});

app.delete('/api/client/:clientId/api-key-requests/:requestId', requireAuth, requireClientAccess, async (req: Request, res: Response) => {
  const clientId = Number(req.params.clientId);
  const requestId = Number(req.params.requestId);

  if (!Number.isInteger(requestId)) {
    res.status(400).json({ error: 'Valid API key request id is required' });
    return;
  }

  try {
    const [result] = await pool.execute<ResultSetHeader>(
      `DELETE FROM api_key_requests
       WHERE id = ? AND client_id = ? AND status = 'pending'`,
      [requestId, clientId],
    );

    if (result.affectedRows === 0) {
      res.status(404).json({ error: 'Pending API key request not found' });
      return;
    }

    res.json({ ok: true });
  } catch (error) {
    console.error('API key request cancel error:', error);
    res.status(500).json({ error: 'Unable to cancel API key request' });
  }
});

app.post('/api/client/:clientId/support-tickets', requireAuth, requireClientAccess, async (req: AuthedRequest, res: Response) => {
  const clientId = Number(req.params.clientId);
  const subject = normalizeRequiredString(req.body.subject);
  const message = normalizeRequiredString(req.body.message);
  const category = normalizeOptionalString(req.body.category) || 'General support';
  const priority = normalizeOptionalString(req.body.priority) || 'normal';

  if (!subject || !message) {
    res.status(400).json({ error: 'Subject and message are required' });
    return;
  }

  if (!isTicketPriority(priority)) {
    res.status(400).json({ error: 'Valid ticket priority is required' });
    return;
  }

  try {
    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT INTO support_tickets (client_id, created_by_user_id, subject, category, priority, message, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
      [clientId, req.authUser?.id || null, subject, category, priority, message],
    );

    res.status(201).json({ id: result.insertId });
  } catch (error) {
    console.error('Support ticket create error:', error);
    res.status(500).json({ error: 'Unable to create support ticket' });
  }
});

app.patch('/api/client/:clientId/api-keys/:apiKeyId/revoke', requireAuth, requireClientAccess, async (req: Request, res: Response) => {
  const clientId = Number(req.params.clientId);
  const apiKeyId = Number(req.params.apiKeyId);

  if (!Number.isInteger(apiKeyId)) {
    res.status(400).json({ error: 'Valid API key id is required' });
    return;
  }

  try {
    await pool.execute('UPDATE client_api_keys SET status = ? WHERE id = ? AND client_id = ?', ['revoked', apiKeyId, clientId]);
    res.json({ ok: true });
  } catch (error) {
    console.error('Client API key revoke error:', error);
    res.status(500).json({ error: 'Unable to revoke client API key' });
  }
});

app.post('/api/client/:clientId/transactions', requireAuth, requireClientAccess, async (req: Request, res: Response) => {
  const clientId = Number(req.params.clientId);
  const {
    paymentId,
    amount,
    currency = 'INR',
    status = 'captured',
    customerName,
    customerEmail,
    customerPhone,
  } = req.body;

  if (!paymentId || !amount || !['created', 'captured', 'authorized', 'failed', 'refunded'].includes(status)) {
    res.status(400).json({ error: 'Payment id, amount, and valid status are required' });
    return;
  }

  try {
    const normalizedCustomerName = normalizeOptionalString(customerName);
    const normalizedCustomerEmail = normalizeOptionalString(customerEmail);
    const normalizedCustomerPhone = normalizeOptionalString(customerPhone);
    const customerId = await upsertCustomer(clientId, normalizedCustomerName, normalizedCustomerEmail, normalizedCustomerPhone);
    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT INTO transactions
        (client_id, customer_id, razorpay_payment_id, amount, currency, status, customer_name, customer_email, customer_phone)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        clientId,
        customerId,
        paymentId,
        amount,
        currency,
        status,
        normalizedCustomerName,
        normalizedCustomerEmail,
        normalizedCustomerPhone,
      ],
    );
    await refreshCustomerStats(customerId);

    res.status(201).json({ id: result.insertId });
  } catch (error) {
    console.error('Transaction create error:', error);
    res.status(500).json({ error: 'Unable to create transaction' });
  }
});

app.post('/api/gateway/orders', requireGatewayClient, async (req: GatewayRequest, res: Response) => {
  const client = req.client;
  const amount = Number(req.body.amount);
  const currency = String(req.body.currency || 'INR').toUpperCase();
  const receipt = String(req.body.receipt || `paydesk_${Date.now()}`);
  const customerName = normalizeOptionalString(req.body.customerName || req.body.customer_name);
  const customerEmail = normalizeOptionalString(req.body.customerEmail || req.body.customer_email);
  const customerPhone = normalizeOptionalString(req.body.customerPhone || req.body.customer_phone);
  const notes = req.body.notes && typeof req.body.notes === 'object' ? req.body.notes : {};

  if (!client) {
    res.status(401).json({ error: 'Client authentication required', requestId: req.requestId });
    return;
  }

  if (!Number.isInteger(amount) || amount <= 0 || !/^[A-Z]{3}$/.test(currency)) {
    await logApiCall(req, 400, 'Valid amount in smallest currency unit and currency are required');
    res.status(400).json({ error: 'Valid amount in smallest currency unit and currency are required', requestId: req.requestId });
    return;
  }

  try {
    const platformKeys = await getPlatformRazorpayCredentials();
    const order = await razorpayRequest<Record<string, any>>('/orders', 'POST', {
      amount,
      currency,
      receipt,
      notes: {
        ...notes,
        paydesk_client_id: String(client.client_id),
        ...(customerName ? { customer_name: customerName } : {}),
        ...(customerEmail ? { customer_email: customerEmail } : {}),
        ...(customerPhone ? { customer_phone: customerPhone } : {}),
      },
    });

    const customerId = await upsertCustomer(client.client_id, customerName, customerEmail, customerPhone);
    await pool.execute(
      `INSERT INTO transactions (client_id, customer_id, razorpay_order_id, amount, currency, status, receipt, customer_name, customer_email, customer_phone, notes)
       VALUES (?, ?, ?, ?, ?, 'created', ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
        customer_id = COALESCE(VALUES(customer_id), customer_id),
        amount = VALUES(amount),
        currency = VALUES(currency),
        receipt = VALUES(receipt),
        customer_name = COALESCE(VALUES(customer_name), customer_name),
        customer_email = COALESCE(VALUES(customer_email), customer_email),
        customer_phone = COALESCE(VALUES(customer_phone), customer_phone),
        notes = VALUES(notes)`,
      [client.client_id, customerId, order.id, amount / 100, currency, receipt, customerName, customerEmail, customerPhone, JSON.stringify(notes)],
    );
    await refreshCustomerStats(customerId);

    await logApiCall(req, 201, 'Razorpay order created');
    res.status(201).json({
      requestId: req.requestId,
      order,
      checkout: {
        keyId: platformKeys.keyId,
        orderId: order.id,
        amount: order.amount,
        currency: order.currency,
        name: client.company_name,
      },
    });
  } catch (error: any) {
    const statusCode = error?.statusCode || 500;
    await logApiCall(req, statusCode, error?.message || 'Unable to create Razorpay order');
    res.status(statusCode).json({ error: error?.message || 'Unable to create Razorpay order', requestId: req.requestId });
  }
});

app.post('/api/gateway/payments/verify', requireGatewayClient, async (req: GatewayRequest, res: Response) => {
  const client = req.client;
  const orderId = String(req.body.razorpay_order_id || req.body.orderId || '');
  const paymentId = String(req.body.razorpay_payment_id || req.body.paymentId || '');
  const signature = String(req.body.razorpay_signature || req.body.signature || '');
  const customerName = normalizeOptionalString(req.body.customerName || req.body.customer_name);
  const customerEmail = normalizeOptionalString(req.body.customerEmail || req.body.customer_email);
  const customerPhone = normalizeOptionalString(req.body.customerPhone || req.body.customer_phone);

  if (!client) {
    res.status(401).json({ error: 'Client authentication required', requestId: req.requestId });
    return;
  }

  if (!orderId || !paymentId || !signature) {
    await logApiCall(req, 400, 'Order id, payment id, and signature are required');
    res.status(400).json({ error: 'Order id, payment id, and signature are required', requestId: req.requestId });
    return;
  }

  const platformKeys = await getPlatformRazorpayCredentials();
  if (!verifyHmac(`${orderId}|${paymentId}`, String(signature), platformKeys.keySecret)) {
    await logApiCall(req, 400, 'Razorpay payment signature mismatch');
    res.status(400).json({ error: 'Razorpay payment signature mismatch', requestId: req.requestId });
    return;
  }

  try {
    const payment = await razorpayRequest<Record<string, any>>(`/payments/${paymentId}`, 'GET');
    const status = mapRazorpayPaymentStatus(String(payment.status || 'failed'));
    const amount = Number(payment.amount || 0) / 100;
    const currency = String(payment.currency || 'INR').toUpperCase();
    const paymentEmail = normalizeOptionalString(payment.email) || customerEmail;
    const paymentPhone = normalizeOptionalString(payment.contact) || customerPhone;
    const customerId = await upsertCustomer(client.client_id, customerName, paymentEmail, paymentPhone);

    await pool.execute(
      `INSERT INTO transactions (client_id, customer_id, razorpay_order_id, razorpay_payment_id, amount, currency, status, customer_name, customer_email, customer_phone)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
        customer_id = COALESCE(VALUES(customer_id), customer_id),
        razorpay_payment_id = VALUES(razorpay_payment_id),
        amount = VALUES(amount),
        currency = VALUES(currency),
        status = VALUES(status),
        customer_name = COALESCE(VALUES(customer_name), customer_name),
        customer_email = COALESCE(VALUES(customer_email), customer_email),
        customer_phone = COALESCE(VALUES(customer_phone), customer_phone)`,
      [client.client_id, customerId, orderId, paymentId, amount, currency, status, customerName, paymentEmail, paymentPhone],
    );
    await refreshCustomerStats(customerId);

    await logApiCall(req, 200, 'Razorpay payment verified');
    res.json({ requestId: req.requestId, verified: true, payment });
  } catch (error: any) {
    const statusCode = error?.statusCode || 500;
    await logApiCall(req, statusCode, error?.message || 'Unable to verify Razorpay payment');
    res.status(statusCode).json({ error: error?.message || 'Unable to verify Razorpay payment', requestId: req.requestId });
  }
});

app.post('/api/gateway/refunds', requireGatewayClient, async (req: GatewayRequest, res: Response) => {
  const client = req.client;
  const paymentId = String(req.body.paymentId || req.body.razorpay_payment_id || '');
  const amount = req.body.amount ? Number(req.body.amount) : undefined;
  const notes = req.body.notes && typeof req.body.notes === 'object' ? req.body.notes : {};

  if (!client) {
    res.status(401).json({ error: 'Client authentication required', requestId: req.requestId });
    return;
  }

  if (!paymentId || (amount !== undefined && (!Number.isInteger(amount) || amount <= 0))) {
    await logApiCall(req, 400, 'Valid payment id and optional refund amount are required');
    res.status(400).json({ error: 'Valid payment id and optional refund amount are required', requestId: req.requestId });
    return;
  }

  try {
    const refundBody: Record<string, unknown> = { notes };
    if (amount !== undefined) {
      refundBody.amount = amount;
    }

    const refund = await razorpayRequest<Record<string, any>>(`/payments/${paymentId}/refund`, 'POST', refundBody);
    const [transactions] = await pool.execute<RowDataPacket[]>(
      'SELECT customer_id FROM transactions WHERE client_id = ? AND razorpay_payment_id = ? LIMIT 1',
      [client.client_id, paymentId],
    );
    await pool.execute(
      `UPDATE transactions
       SET status = 'refunded', razorpay_refund_id = ?
       WHERE client_id = ? AND razorpay_payment_id = ?`,
      [refund.id || null, client.client_id, paymentId],
    );
    await refreshCustomerStats(transactions[0]?.customer_id || null);

    await logApiCall(req, 201, 'Razorpay refund created');
    res.status(201).json({ requestId: req.requestId, refund });
  } catch (error: any) {
    const statusCode = error?.statusCode || 500;
    await logApiCall(req, statusCode, error?.message || 'Unable to create Razorpay refund');
    res.status(statusCode).json({ error: error?.message || 'Unable to create Razorpay refund', requestId: req.requestId });
  }
});

app.post('/api/webhooks/razorpay/:clientId', async (req: Request, res: Response) => {
  const clientId = Number(req.params.clientId);
  const signature = String(req.headers['x-razorpay-signature'] || '');
  const eventId = req.headers['x-razorpay-event-id'] ? String(req.headers['x-razorpay-event-id']) : null;
  const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(JSON.stringify(req.body));

  if (!Number.isInteger(clientId)) {
    res.status(400).json({ error: 'Valid client id is required' });
    return;
  }

  try {
    const [clients] = await pool.execute<ClientRow[]>('SELECT * FROM clients WHERE id = ? LIMIT 1', [clientId]);
    const client = clients[0];

    const platformKeys = await getPlatformRazorpayCredentials();
    const webhookSecret = platformKeys.webhookSecret;
    if (!webhookSecret || !verifyHmac(rawBody, signature, webhookSecret)) {
      res.status(400).json({ error: 'Invalid Razorpay webhook signature' });
      return;
    }

    const payload = JSON.parse(rawBody.toString('utf8')) as Record<string, any>;
    const eventName = String(payload.event || 'unknown');
    await pool.execute(
      `INSERT INTO razorpay_events (client_id, event_id, event_name, payload)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE payload = VALUES(payload)`,
      [clientId, eventId, eventName, JSON.stringify(payload)],
    );

    const payment = payload.payload?.payment?.entity;
    if (payment?.id) {
      const customerName = normalizeOptionalString(payment.notes?.customer_name || payment.notes?.customerName);
      const customerEmail = normalizeOptionalString(payment.email);
      const customerPhone = normalizeOptionalString(payment.contact);
      const customerId = await upsertCustomer(clientId, customerName, customerEmail, customerPhone);
      await pool.execute(
        `INSERT INTO transactions (client_id, customer_id, razorpay_order_id, razorpay_payment_id, amount, currency, status, customer_name, customer_email, customer_phone)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
          customer_id = COALESCE(VALUES(customer_id), customer_id),
          razorpay_order_id = VALUES(razorpay_order_id),
          amount = VALUES(amount),
          currency = VALUES(currency),
          status = VALUES(status),
          customer_name = COALESCE(VALUES(customer_name), customer_name),
          customer_email = COALESCE(VALUES(customer_email), customer_email),
          customer_phone = COALESCE(VALUES(customer_phone), customer_phone)`,
        [
          clientId,
          customerId,
          payment.order_id || null,
          payment.id,
          Number(payment.amount || 0) / 100,
          payment.currency || 'INR',
          mapRazorpayPaymentStatus(String(payment.status || 'failed')),
          customerName,
          customerEmail,
          customerPhone,
        ],
      );
      await refreshCustomerStats(customerId);
    }

    const refund = payload.payload?.refund?.entity;
    if (refund?.payment_id) {
      const [transactions] = await pool.execute<RowDataPacket[]>(
        'SELECT customer_id FROM transactions WHERE client_id = ? AND razorpay_payment_id = ? LIMIT 1',
        [clientId, refund.payment_id],
      );
      await pool.execute(
        `UPDATE transactions
         SET status = 'refunded', razorpay_refund_id = ?
         WHERE client_id = ? AND razorpay_payment_id = ?`,
        [refund.id || null, clientId, refund.payment_id],
      );
      await refreshCustomerStats(transactions[0]?.customer_id || null);
    }

    res.json({ ok: true });
  } catch (error) {
    console.error('Razorpay webhook error:', error);
    res.status(500).json({ error: 'Unable to process Razorpay webhook' });
  }
});

ensureRuntimeSchema()
  .then(() => {
    app.listen(port, '0.0.0.0', () => {
      console.log(`Server running on 0.0.0.0:${port}`);
    });
  })
  .catch((error) => {
    console.error('Database schema check failed:', error);
    process.exit(1);
  });
