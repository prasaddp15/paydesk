# Backend API

Node.js/Express backend server with TypeScript and MySQL integration.

## Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Create .env file:**
   ```bash
   cp .env.example .env
   ```

3. **Update environment variables:**
   Edit `.env` with your database credentials

## Development

```bash
npm run dev
```

Server runs on `http://localhost:5000`

## Building

```bash
npm run build
npm start
```

## Project Structure

```
src/
├── index.ts       # Main server file
└── [routes/]      # Add route files here
└── [controllers/] # Add business logic here
```

## API Endpoints

### Health Check
```
GET /api/health
```
Returns server status.

### Get Users
```
GET /api/users
```
Returns list of users from database.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | Server port | 5000 |
| DB_HOST | MySQL host | localhost |
| DB_USER | MySQL user | root |
| DB_PASSWORD | MySQL password | password |
| DB_NAME | Database name | app_db |

## Adding New Endpoints

1. Create a route handler in `src/`
2. Import in `src/index.ts`
3. Add route: `app.get('/api/endpoint', handler)`

## Database Queries

Using the mysql2 connection pool:

```typescript
const connection = await pool.getConnection();
const [rows] = await connection.query('SELECT * FROM users');
connection.release();
```
