# EmployeeHub — Enterprise HRMS

EmployeeHub is a local-first HR management application built with Node.js, Express and SQLite. This package extends the existing application while keeping its current employee, user, attendance, leave, login, reports, audit, and HR Operations modules.

## Included modules

### Existing workspace
- Dashboard and employee directory (create, view, edit and delete)
- Department overview and employee search
- User accounts and role management (Administrator, HR Manager, Read-only Viewer)
- Secure login, logout, change password, forgot-username and OTP password recovery
- Attendance tracking and leave requests with approval/rejection
- HR Operations: company assets, onboarding tasks, helpdesk tickets and document register
- Reports, CSV employee export and audit logs

### Enterprise HRMS workspace (`/enterprise`)
- **Payroll register:** monthly employee salary records, basic pay, allowances, deductions, calculated net salary and payment status
- **Performance management:** review period, reviewer, 1–5 rating, goals, feedback and acknowledgement status
- **Recruitment:** job openings, department, location, employment type, vacancies and opening status
- **Candidate applications:** candidate contact details and pipeline stages from Applied through Hired/Rejected
- **Shift scheduling:** employee/date/shift and start/end time
- **Training catalogue:** course, provider, category and duration
- **Training enrollments:** employee-course assignments and completion status
- **Expense claims:** employee expenses, amount, category and review/reimbursement status
- **Policy management:** policy versions, effective dates, content and active/archive status
- **Offboarding:** last working day, exit reason, owner and exit checklist tasks
- **Announcements:** audience, publish date, expiry and publication status
- **Company calendar:** events, holidays, meetings, training and review dates

Records are stored in SQLite. New tables are created automatically using additive migrations when the app starts. Existing employee and user records are not intentionally reset.

## Requirements
- Node.js 18 or newer (Node.js 20 LTS recommended)
- macOS, Windows or Linux

## Install or upgrade

1. Stop the currently running server with `Control + C` in its Terminal window.
2. Make a backup of the entire project folder and especially `employees.db`.
3. Extract this ZIP. Copy the files inside `Employee-Management-System` into your existing project folder and replace the application code files.
4. **Keep your existing `employees.db` file. Do not replace it with a blank database.** Also keep any existing `.env` file outside the ZIP if you use one.
5. Open Terminal in the project folder and run:

```bash
npm install
npm run check
```

6. Start the application. Set a strong session secret in the same Terminal session:

```bash
export SESSION_SECRET="$(openssl rand -hex 32)"
npm start
```

7. Open `http://localhost:3000` and sign in with your existing account. The Enterprise HRMS link is on the main dashboard.

The environment variable is per Terminal session. If you open a new Terminal window, set `SESSION_SECRET` again before starting the server. Keep Gmail credentials in environment variables only; never commit or share app passwords.

## Security and roles
- All write requests use the application's CSRF protection and authenticated session.
- New module writes are available to Administrator and HR Manager roles through the existing `operations:write` permission.
- Read-only Viewer accounts cannot create, edit or delete records. Payroll, expense and candidate application records are restricted from Viewer accounts.
- New create/update/delete actions are written to the audit log.
- Salary and expense values are stored as HR records only; the application does not connect to banks or execute payments.

## Important scope notes
- Payroll is a **payroll register**, not a statutory payroll engine. It does not calculate Indian income tax, PF, ESI, TDS, payslips, or bank transfers.
- The document register stores document metadata and secure storage references only. It does not upload or store document files.
- Recruitment tracks openings and applications; it does not publish jobs to external job boards or send candidate emails.
- Announcements and calendar events are stored in the system; automated email/push notifications are not configured.
- This is a local development HRMS. Before public/internet deployment, add HTTPS, production session settings, backups, operational monitoring, data retention rules, and a security review.

## Useful commands

```bash
npm install       # install dependencies
npm run check     # JavaScript syntax checks
npm start         # start EmployeeHub
```

## Backup

Stop the app before copying `employees.db`. Keep backups in a private location. The database can contain employee contact and HR information.


## EmployeeHub 4.0 UI refresh

This update refreshes the presentation layer while retaining the existing API routes,
database schema, authentication flow, and module scripts. The main dashboard, HR
workspace, HR Operations, and Enterprise HRMS now share a more consistent visual
system and cross-workspace navigation. Existing theme colours are retained.

### Safe replacement on an existing installation

1. Stop the currently running server with Control+C.
2. Make a backup copy of your existing `employees.db` before replacing files.
3. Extract this ZIP. Copy the updated source files into your existing
   `Employee-Management-System` folder and choose Replace when macOS asks.
4. Keep your existing `employees.db` if it contains newer records than the copy
   supplied in this ZIP. Do not replace it without checking.
5. In Terminal, open the project folder and run `npm install` if dependencies
   are not present, then start the app as described below.

### Start the server

In Terminal, from this project folder:

```bash
export SESSION_SECRET="$(openssl rand -hex 32)"
npm start
```

Then open http://localhost:3000. Keep the Terminal window open while using
the local application. A new Terminal session needs a newly generated secret.


## EmployeeHub Professional UI update

This update refreshes the visual presentation across the existing dashboard and HR modules while keeping the current Express routes, API calls, database schema, authentication, and feature JavaScript intact.

### Replace your local project safely (macOS)

1. Stop the currently running server with `Control + C`.
2. Make a backup copy of your existing `Employee-Management-System` folder.
3. Extract this ZIP. Keep your existing `employees.db` if it contains newer records than the database snapshot in this archive.
4. Open the extracted project folder in VS Code.
5. In Terminal, run `npm install` once if dependencies are not installed.
6. Start the app with `./Start EmployeeHub.command` or run `npm start` after setting `SESSION_SECRET`.

The launcher creates a fresh secure `SESSION_SECRET` automatically for each local run. If you use `npm start` manually, run:

```bash
export SESSION_SECRET="$(openssl rand -hex 32)"
npm start
```

Open `http://localhost:3000`.

**Important:** Do not share your `.env` file, Gmail App Password, session secrets, or employee database publicly. Keep a backup of `employees.db` before replacing project files.

## EmployeeHub People & AI Workspace update

The People & AI workspace adds the next layer of employee-facing workflows:

- **Employee Self-Service:** linked employees can view their own profile, goals, leave and expense history, announcements and notifications; submit leave and expense requests.
- **Account-to-employee linking:** administrators can connect a login account to the correct employee profile. This is required before personal self-service data is displayed.
- **Goals & Development:** HR managers and administrators can create measurable employee goals with a target date, category, success criteria, progress percentage and status. Linked employees can update progress on their own goals.
- **Workforce Analytics:** live summaries from the local database for headcount, departments, attendance, recruitment pipeline, leave, expenses and goal progress.
- **Workflow Automation setup:** HR/admin users can configure and enable/disable workflow rules. In this version, rules are saved as configuration; automatic background execution and scheduled triggers are not yet implemented.
- **HR Assistant:** built-in guided answers for common EmployeeHub questions, plus a live employee-count lookup. It is a rules/FAQ assistant, not an external generative-AI model and it does not make HR decisions.

### First-time setup for Employee Self-Service

1. Sign in with an administrator account and open **Enterprise HRMS → People & AI Workspace**.
2. Open **Account Linking** and connect each employee's login account to their matching employee profile.
3. Ask the employee to sign in with that linked account and open **People & AI Workspace**.
4. The employee can now view their own profile and submit leave and expense requests. Personal data is scoped to the linked employee record.

### Important limitations

- The existing recruitment, performance review, payroll register and expense claim modules remain available in Enterprise HRMS. The new Goals workspace adds trackable progress alongside existing performance reviews.
- Workforce Analytics reports descriptive totals from records already entered; it does not predict attrition, hiring success or future costs.
- Workflow rules are configurable but do not yet run automatically in the background.
- The HR Assistant is a local FAQ-style helper. Connect an approved AI provider and add privacy controls/security review before describing it as a generative AI assistant.
- Keep your own `employees.db` when upgrading if it contains newer records. The ZIP includes a database snapshot for a clean/test installation, not a replacement for a newer live database.


## People & AI Workspace — automation and assistant upgrade

The People & AI Workspace (`/people`) includes employee self-service, goals,
workforce analytics, workflow automation, HR Assistant and administrator account linking.

### Workflow Automation
- Enabled rules execute when a new employee is created, a leave request is submitted,
  or an expense claim is submitted.
- Supported actions: create an employee notification, create an HR task, or flag a
  record by creating a high-priority HR review task.
- Goal due-date rules are checked automatically every six hours and shortly after
  server startup. HR can also run a manual due-date check from the workspace.
- Execution history records succeeded/failed outcomes and avoids duplicate executions
  for the same rule and event.
- HR can update generated task status (Open, In Progress, Completed).

### AI HR Assistant
- The assistant uses role-filtered context: employees receive only their own linked
  profile, goals, leave requests and expense summaries; HR/admin receive workforce
  aggregates and workflow/recruitment counts. It does not expose payroll records.
- Without a Gemini key, a built-in data-aware assistant remains available.
- To enable Gemini, set these environment variables in the same Terminal session:

```bash
export GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
export GEMINI_MODEL="gemini-2.5-flash"
```

The key is read only by the server and must never be placed in frontend code or committed
into Git. When Gemini is enabled, role-filtered context and the user's question are sent
to Google's Gemini API to generate an answer. Do not enable this for sensitive production
records without reviewing your organization's AI/data-processing requirements. The AI
assistant provides guidance only; it cannot approve leave, payroll, expenses or other HR
transactions.

### New database tables
- `workflow_executions`: workflow event execution and result history.
- `hr_workflow_tasks`: generated HR follow-up and review tasks.

These tables are created with additive migrations. Existing employee, user, payroll,
attendance, leave and other business records are retained. Back up `employees.db`
before upgrading and keep your existing database when replacing application files.
