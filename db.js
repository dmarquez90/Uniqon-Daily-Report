// Database access: Supabase Postgres in production (DATABASE_URL), embedded PGlite for local development
const path = require('path');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS employees (
  id SERIAL PRIMARY KEY,
  emp_number TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'employee',
  must_change BOOLEAN NOT NULL DEFAULT TRUE,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE employees ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS locations (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'Project',
  city TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL DEFAULT '',
  created_by INTEGER REFERENCES employees(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS employee_locations (
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  location_id INTEGER NOT NULL REFERENCES locations(id),
  PRIMARY KEY (employee_id, location_id)
);
CREATE TABLE IF NOT EXISTS daily_reports (
  id SERIAL PRIMARY KEY,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  report_date TEXT NOT NULL,
  data JSONB NOT NULL,
  drive_file_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (employee_id, report_date)
);
CREATE TABLE IF NOT EXISTS report_photos (
  id SERIAL PRIMARY KEY,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  report_id INTEGER REFERENCES daily_reports(id) ON DELETE CASCADE,
  mime TEXT NOT NULL,
  data BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_photos_report ON report_photos(report_id);
CREATE TABLE IF NOT EXISTS password_resets (
  token_hash TEXT PRIMARY KEY,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN NOT NULL DEFAULT FALSE
);
`;

let ready;
function connect() {
  if (ready) return ready;
  ready = (async () => {
    if (process.env.DATABASE_URL) {
      const { Pool } = require('pg');
      const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 3 });
      return (text, params) => pool.query(text, params).then(r => r.rows);
    }
    const { PGlite } = await import('@electric-sql/pglite');
    const dir = path.resolve(process.env.DATA_DIR || './data', 'pg');
    require('fs').mkdirSync(dir, { recursive: true });
    const db = new PGlite(dir);
    await db.exec(SCHEMA);
    return (text, params) => db.query(text, params).then(r => r.rows);
  })();
  return ready;
}

async function query(text, params = []) { return (await connect())(text, params); }
async function one(text, params) { return (await query(text, params))[0] || null; }

module.exports = { query, one, SCHEMA };
