CREATE DATABASE IF NOT EXISTS app_db;
USE app_db;

CREATE TABLE IF NOT EXISTS clients (
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
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admins (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  status ENUM('active', 'paused') NOT NULL DEFAULT 'active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  client_id INT NULL,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('main_admin', 'client_admin') NOT NULL DEFAULT 'client_admin',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS platform_settings (
  id INT PRIMARY KEY AUTO_INCREMENT,
  setting_key VARCHAR(120) UNIQUE NOT NULL,
  setting_value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- CREATE TABLE IF NOT EXISTS customers (
--   id INT PRIMARY KEY AUTO_INCREMENT,
--   client_id INT NOT NULL,
--   customer_key VARCHAR(255) NOT NULL,
--   name VARCHAR(255),
--   email VARCHAR(255),
--   phone VARCHAR(40),
--   total_transactions INT NOT NULL DEFAULT 0,
--   captured_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
--   last_payment_at TIMESTAMP NULL,
--   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--   updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
--   UNIQUE KEY uniq_customers_client_key (client_id, customer_key),
--   FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
-- );
CREATE TABLE IF NOT EXISTS customers (
  id INT PRIMARY KEY AUTO_INCREMENT,
  client_id INT NOT NULL,
  customer_key VARCHAR(255) NOT NULL,
  name VARCHAR(255),
  email VARCHAR(255),
  phone VARCHAR(40),
  total_transactions INT NOT NULL DEFAULT 0,
  captured_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  last_payment_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:01',
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_customers_client_key (client_id, customer_key),
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS transactions (
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
  notes JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
  FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS client_api_keys (
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
);

CREATE TABLE IF NOT EXISTS api_key_requests (
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
);

CREATE TABLE IF NOT EXISTS api_logs (
  id INT PRIMARY KEY AUTO_INCREMENT,
  client_id INT,
  api_key_id INT,
  method VARCHAR(12) NOT NULL,
  endpoint VARCHAR(255) NOT NULL,
  status_code INT NOT NULL,
  message VARCHAR(255),
  request_payload JSON,
  response_payload JSON,
  request_id VARCHAR(80) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL,
  FOREIGN KEY (api_key_id) REFERENCES client_api_keys(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS razorpay_events (
  id INT PRIMARY KEY AUTO_INCREMENT,
  client_id INT NOT NULL,
  event_id VARCHAR(255) UNIQUE,
  event_name VARCHAR(255) NOT NULL,
  payload JSON NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS support_tickets (
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
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  resolved_at TIMESTAMP NULL,
  FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
  FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

ALTER TABLE clients ADD COLUMN IF NOT EXISTS razorpay_webhook_secret VARCHAR(255);
ALTER TABLE clients ADD COLUMN IF NOT EXISTS phone_number VARCHAR(30);
ALTER TABLE clients ADD COLUMN IF NOT EXISTS business_website VARCHAR(255);
ALTER TABLE clients ADD COLUMN IF NOT EXISTS pan_number VARCHAR(20);
ALTER TABLE clients ADD COLUMN IF NOT EXISTS aadhaar_number VARCHAR(20);
ALTER TABLE clients ADD COLUMN IF NOT EXISTS gst_number VARCHAR(30);
ALTER TABLE clients ADD COLUMN IF NOT EXISTS business_category VARCHAR(120);
ALTER TABLE clients ADD COLUMN IF NOT EXISTS business_address TEXT;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS city VARCHAR(120);
ALTER TABLE clients ADD COLUMN IF NOT EXISTS state VARCHAR(120);
ALTER TABLE clients ADD COLUMN IF NOT EXISTS pincode VARCHAR(20);
ALTER TABLE client_api_keys ADD COLUMN IF NOT EXISTS api_secret_encrypted TEXT;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS customer_id INT NULL;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS razorpay_order_id VARCHAR(255) UNIQUE;
ALTER TABLE transactions MODIFY COLUMN razorpay_payment_id VARCHAR(255) NULL;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS razorpay_refund_id VARCHAR(255);
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS receipt VARCHAR(255);
ALTER TABLE transactions MODIFY COLUMN status ENUM('created', 'captured', 'authorized', 'failed', 'refunded') NOT NULL DEFAULT 'captured';
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS customer_name VARCHAR(255);
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS customer_phone VARCHAR(40);
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS notes JSON;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;
ALTER TABLE api_logs ADD COLUMN IF NOT EXISTS request_payload JSON;
ALTER TABLE api_logs ADD COLUMN IF NOT EXISTS response_payload JSON;

CREATE INDEX IF NOT EXISTS idx_users_client_id ON users(client_id);
CREATE INDEX IF NOT EXISTS idx_admins_status ON admins(status);
CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status);
CREATE INDEX IF NOT EXISTS idx_clients_business_category ON clients(business_category);
CREATE INDEX IF NOT EXISTS idx_customers_client_id ON customers(client_id);
CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email);
CREATE INDEX IF NOT EXISTS idx_customers_phone ON customers(phone);
CREATE INDEX IF NOT EXISTS idx_transactions_client_id ON transactions(client_id);
CREATE INDEX IF NOT EXISTS idx_transactions_customer_id ON transactions(customer_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_order_id ON transactions(razorpay_order_id);
CREATE INDEX IF NOT EXISTS idx_transactions_customer_email ON transactions(customer_email);
CREATE INDEX IF NOT EXISTS idx_api_logs_client_id ON api_logs(client_id);
CREATE INDEX IF NOT EXISTS idx_api_logs_created_at ON api_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_api_key_requests_client_id ON api_key_requests(client_id);
CREATE INDEX IF NOT EXISTS idx_api_key_requests_status ON api_key_requests(status);
CREATE INDEX IF NOT EXISTS idx_support_tickets_client_id ON support_tickets(client_id);
CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON support_tickets(status);
CREATE INDEX IF NOT EXISTS idx_support_tickets_priority ON support_tickets(priority);
