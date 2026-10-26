# EmployeeHub HR Management System v2

A local-first HR application built with HTML/CSS/JavaScript, Node.js, Express and SQLite. The existing EmployeeHub dashboard and employee records are preserved through additive database migrations.

## Features

- Existing employee dashboard and directory CRUD
- Admin login with bcrypt password hashes
- Roles: `admin`, `hr`, `viewer`
- SQLite-backed session store, HTTP-only session cookies, login rate limiting and CSRF tokens for state-changing API requests
- Employee profile fields: phone, job title, joining date and status
- Attendance management
- Leave requests and approval workflow (approved leave creates attendance records)
- Employee CSV reports and summary reports
- Audit log for sign-in, account, employee, attendance, leave and export actions
- Change password and logout

## Important safety note

This is a college/practical-use starter, not a fully audited commercial HR platform. Before exposing it to the public internet, deploy behind HTTPS, set `NODE_ENV=production`, configure trusted proxy settings correctly, review privacy/legal requirements, restrict network access, test backups, and obtain a professional security review. Salary/payroll, identity documents, and highly sensitive fields are intentionally not included.

## Upgrade without losing existing employee records

1. Stop the currently running app with `Control + C` in its VS Code terminal.
2. In Finder, make a copy of the current project folder before replacing files.
3. In the existing project, create a database backup while the app is stopped:

   ```bash
   cp employees.db employees-backup-before-hr-upgrade.db
   ```

   If your database is in another folder, run this command from the project folder containing `employees.db`.
4. Copy the upgraded project files into your existing project folder, but do **not** overwrite or delete `employees.db` and do not copy any database file from a ZIP. This upgrade ZIP intentionally excludes the database and `node_modules`.
5. Install dependencies:

   ```bash
   npm install
   ```
6. Create a session secret in the terminal where you will run the server:

   ```bash
   export SESSION_SECRET="$(node -e \"console.log(require('crypto').randomBytes(48).toString('hex'))\")"
   ```

7. Start the server:

   ```bash
   npm start
   ```

8. Open `http://localhost:3000/login`.

Database migrations run automatically and only add missing columns/tables. They do not drop the existing employee table or replace employee records. Keep the backup until all tests pass.

## Admin account

The existing admin account created by `create-admin.js` remains available; the new `role` column defaults existing users to `admin`. If you need to create a new administrator, stop the server and run:

```bash
npm run create-admin
```

Use a unique username and a password of at least 12 characters. The setup script masks password input when run in an interactive terminal. Never commit passwords or `.env` files. Never commit passwords or `.env` files.

## Roles

- **admin**: full access, user account/role management, audit logs, and employee deletion.
- **hr**: employee create/edit, attendance, leave approvals, and reports; cannot manage accounts, view audit logs, or delete employees.
- **viewer**: read-only access to employees, attendance, leave and reports.

Role permissions are enforced on the server; hiding a button in the browser is not relied upon for security.

## Test checklist

1. Sign in using the existing admin account.
2. Confirm the original employees are still present.
3. Add a test employee, edit it, and delete only that test record.
4. Open **HR Workspace**. Record attendance for a test employee.
5. Submit a leave request and approve it; confirm the leave dates appear in attendance.
6. Export the employee CSV report.
7. Create an HR user and a viewer user, then test their access limits in a private browser window.
8. Confirm audit entries appear for important actions.
9. Change the admin password and sign in again.
10. Stop the server, verify the backup file exists, and retain it in a safe location.

## Troubleshooting

- **Session secret missing**: set `SESSION_SECRET` in the same terminal before `npm start`.
- **Port already in use**: stop the other server with `Control + C`, then start this app once.
- **bcrypt / better-sqlite3 installation error**: use a compatible Node.js LTS version and run `npm install` again.
- **Login fails**: confirm you are using the existing admin username/password and that the app is opening the correct project folder.
- **Employee records missing**: stop immediately and restore your backup; do not run seed or delete commands against the database.
