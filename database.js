const Database = require('better-sqlite3');
const path = require('path');

// Always use the project folder, even when the app is started from another directory.
const db = new Database(path.join(__dirname, 'employees.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    department TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

function columns(table) {
  return db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
}
function addColumn(table, name, definition) {
  if (!columns(table).includes(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`);
}

// Additive migrations: existing employee IDs and data remain intact.
addColumn('employees', 'phone', "TEXT NOT NULL DEFAULT ''");
addColumn('employees', 'job_title', "TEXT NOT NULL DEFAULT ''");
addColumn('employees', 'joining_date', "TEXT NOT NULL DEFAULT ''");
addColumn('employees', 'status', "TEXT NOT NULL DEFAULT 'Active'");
addColumn('users', 'role', "TEXT NOT NULL DEFAULT 'admin'");
addColumn('users', 'updated_at', "TEXT NOT NULL DEFAULT ''");

db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expired INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_expired ON sessions(expired);
  CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    attendance_date TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('Present','Absent','Leave','Half Day','Work From Home')),
    notes TEXT NOT NULL DEFAULT '',
    created_by INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(employee_id, attendance_date),
    FOREIGN KEY(employee_id) REFERENCES employees(id) ON DELETE CASCADE,
    FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
  );
  CREATE TABLE IF NOT EXISTS leave_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    leave_type TEXT NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','Approved','Rejected')),
    requested_by INTEGER,
    reviewed_by INTEGER,
    reviewed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(employee_id) REFERENCES employees(id) ON DELETE CASCADE,
    FOREIGN KEY(requested_by) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY(reviewed_by) REFERENCES users(id) ON DELETE SET NULL
  );
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    details TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
  );
  CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(attendance_date);
  CREATE INDEX IF NOT EXISTS idx_leave_status ON leave_requests(status);
  CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
`);

const employeeCount = db.prepare('SELECT COUNT(*) AS count FROM employees').get().count;
if (employeeCount === 0) {
  const insert = db.prepare('INSERT INTO employees (name,email,department) VALUES (?,?,?)');
  insert.run('Aarav Sharma', 'aarav@example.com', 'Engineering');
  insert.run('Priya Kumar', 'priya@example.com', 'Human Resources');
  insert.run('Rohan Patel', 'rohan@example.com', 'Finance');
}

console.log('Database connected; additive HR schema migrations checked.');
module.exports = db;
