const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const path = require('path');
const sessionStore = require('./session-store');
const db = require('./database');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET;
const production = process.env.NODE_ENV === 'production';

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('SESSION_SECRET is missing or shorter than 32 characters. Set it before starting.');
  process.exit(1);
}

if (production) app.set('trust proxy', 1);

app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

app.use(session({
  name: 'employee.sid',
  secret: SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: production,
    maxAge: 30 * 60 * 1000
  }
}));

// Rate limiter
function makeRateLimiter(windowMs, limit, message) {
  const buckets = new Map();

  const timer = setInterval(() => {
    const now = Date.now();

    for (const [key, bucket] of buckets) {
      if (bucket.until <= now) buckets.delete(key);
    }
  }, windowMs);

  timer.unref();

  return (req, res, next) => {
    const key = String(req.ip || req.socket.remoteAddress || 'unknown');
    const now = Date.now();
    let bucket = buckets.get(key);

    if (!bucket || bucket.until <= now) {
      bucket = { count: 0, until: now + windowMs };
      buckets.set(key, bucket);
    }

    bucket.count += 1;

    res.setHeader('RateLimit-Limit', String(limit));
    res.setHeader(
      'RateLimit-Remaining',
      String(Math.max(0, limit - bucket.count))
    );

    if (bucket.count > limit) {
      res.setHeader(
        'Retry-After',
        String(Math.ceil((bucket.until - now) / 1000))
      );

      return res.status(429).json({
        error: message
      });
    }

    next();
  };
}

const loginLimiter = makeRateLimiter(
  15 * 60 * 1000,
  10,
  'Too many login attempts. Please wait 15 minutes and try again.'
);

const recoveryLimiter = makeRateLimiter(
  15 * 60 * 1000,
  5,
  'Too many recovery requests. Please wait and try again.'
);

const leaveLimiter = makeRateLimiter(
  60 * 1000,
  30,
  'Too many requests. Please wait a moment and try again.'
);

const roles = {
  admin: ['*'],
  hr: [
    'employees:read',
    'employees:write',
    'attendance:read',
    'attendance:write',
    'leave:read',
    'leave:write',
    'reports:read',
    'audit:read',
    'operations:read',
    'operations:write'
  ],
  viewer: [
    'employees:read',
    'attendance:read',
    'leave:read',
    'reports:read',
    'operations:read'
  ]
};

function audit(req, action, entityType, entityId = null, details = '') {
  try {
    db.prepare(`
      INSERT INTO audit_logs
      (user_id, username, action, entity_type, entity_id, details, ip_address)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.session?.userId || null,
      req.session?.username || 'system',
      action,
      entityType,
      entityId == null ? null : String(entityId),
      String(details).slice(0, 1000),
      String(req.ip || '').slice(0, 80)
    );
  } catch (err) {
    console.error('Audit log write failed:', err.message);
  }
}

function requireAuth(req, res, next) {
  if (!req.session?.userId) {
    return res.status(401).json({
      error: 'Please log in first.'
    });
  }

  const account = db.prepare(
    'SELECT id, username, role FROM users WHERE id = ?'
  ).get(req.session.userId);

  if (!account) {
    return req.session.destroy(() =>
      res.status(401).json({
        error: 'Account is no longer available. Please sign in again.'
      })
    );
  }

  req.session.username = account.username;
  req.session.role = account.role;

  next();
}

function requirePermission(permission) {
  return (req, res, next) => {
    const allowed = roles[req.session?.role] || [];

    if (!allowed.includes('*') && !allowed.includes(permission)) {
      return res.status(403).json({
        error: 'Your account does not have permission for this action.'
      });
    }

    next();
  };
}

function csrfProtection(req, res, next) {
  if (
    ['GET', 'HEAD', 'OPTIONS'].includes(req.method) ||
    req.path === '/api/auth/login'
  ) {
    return next();
  }

  const sent = req.get('x-csrf-token');

  if (
    !sent ||
    !req.session?.csrfToken ||
    sent.length !== req.session.csrfToken.length ||
    !crypto.timingSafeEqual(
      Buffer.from(sent),
      Buffer.from(req.session.csrfToken)
    )
  ) {
    return res.status(403).json({
      error: 'Security token missing or expired. Refresh the page and try again.'
    });
  }

  next();
}

function validDate(s) {
  return typeof s === 'string' &&
    /^\d{4}-\d{2}-\d{2}$/.test(s) &&
    !Number.isNaN(Date.parse(s));
}

function text(s, max = 200) {
  return typeof s === 'string' ? s.trim().slice(0, max) : '';
}

// Event-driven workflow engine. Every rule execution is idempotent per event/rule.
function executeWorkflowEvent(eventName, employeeId, eventKey, details = '') {
  const rules = db.prepare('SELECT * FROM workflow_rules WHERE enabled=1 AND trigger_event=?').all(eventName);
  for (const rule of rules) {
    try {
      const already = db.prepare('SELECT id FROM workflow_executions WHERE rule_id=? AND event_key=?').get(rule.id, eventKey);
      if (already) continue;
      const employee = employeeId ? db.prepare('SELECT id,name FROM employees WHERE id=?').get(employeeId) : null;
      if (!employee) throw new Error('Employee record for workflow event was not found.');
      let message = '';
      if (rule.action_type === 'Create notification') {
        db.prepare('INSERT INTO employee_notifications(employee_id,title,message,category) VALUES(?,?,?,?)')
          .run(employee.id, rule.name, `${rule.description || rule.name}${details ? ' — ' + details : ''}`, 'Workflow');
        message = 'Employee notification created.';
      } else if (rule.action_type === 'Create HR task') {
        db.prepare('INSERT INTO hr_workflow_tasks(employee_id,title,description,priority,source_rule_id) VALUES(?,?,?,?,?)')
          .run(employee.id, rule.name, rule.description || details || 'Created automatically by workflow.', 'Normal', rule.id);
        message = 'HR task created.';
      } else if (rule.action_type === 'Flag for review') {
        db.prepare('INSERT INTO hr_workflow_tasks(employee_id,title,description,priority,source_rule_id) VALUES(?,?,?,?,?)')
          .run(employee.id, `Review: ${rule.name}`, rule.description || details || 'This record requires HR review.', 'High', rule.id);
        message = 'High-priority HR review task created.';
      } else {
        throw new Error('Unsupported workflow action.');
      }
      db.prepare(`INSERT INTO workflow_executions(rule_id,event_name,event_key,employee_id,status,result_message) VALUES(?,?,?,?,?,?)`)
        .run(rule.id, eventName, eventKey, employee.id, 'Succeeded', message);
    } catch (error) {
      try {
        db.prepare(`INSERT OR IGNORE INTO workflow_executions(rule_id,event_name,event_key,employee_id,status,result_message) VALUES(?,?,?,?,?,?)`)
          .run(rule.id, eventName, eventKey, employeeId || null, 'Failed', text(error.message, 500));
      } catch (_) {}
      console.error(`Workflow ${rule.id} failed:`, error.message);
    }
  }
}

function runDueGoalWorkflows() {
  const due = db.prepare(`SELECT id,employee_id,title,target_date FROM employee_goals
    WHERE target_date<>'' AND target_date BETWEEN date('now') AND date('now','+3 day') AND status<>'Completed'`).all();
  for (const goal of due) {
    executeWorkflowEvent('Goal due date approaching', goal.employee_id, `goal-due:${goal.id}:${goal.target_date}`, `Goal “${goal.title}” is due on ${goal.target_date}.`);
  }
  return due.length;
}
// Page routes
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/', (req, res) => {
  if (req.session.userId) {
    return res.sendFile(path.join(__dirname, 'index.html'));
  }

  res.redirect('/login');
});

app.get('/hr', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'hr.html'));
});

app.get('/operations', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'operations.html'));
});

app.get('/enterprise', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'enterprise.html'));
});

// Authentication status
app.get('/api/auth/me', (req, res) => {
  if (req.session.userId) {
    return res.json({
      authenticated: true,
      username: req.session.username,
      role: req.session.role
    });
  }

  res.status(401).json({ authenticated: false });
});

// CSRF token
app.get('/api/auth/csrf', requireAuth, (req, res) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }

  res.json({ csrfToken: req.session.csrfToken });
});

// Login
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const username = text(req.body?.username, 80);
    const password = req.body?.password;

    if (!username || typeof password !== 'string' || password.length > 200) {
      return res.status(400).json({
        error: 'Enter a valid username and password.'
      });
    }

    const user = db.prepare(
      'SELECT id, username, password_hash, role FROM users WHERE username = ?'
    ).get(username);

    const valid = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (!valid) {
      audit(req, 'LOGIN_FAILED', 'user', username, 'Invalid login attempt');

      return res.status(401).json({
        error: 'Invalid username or password.'
      });
    }

    req.session.regenerate(err => {
      if (err) {
        return res.status(500).json({
          error: 'Could not start login session.'
        });
      }

      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');

      req.session.save(saveErr => {
        if (saveErr) {
          return res.status(500).json({
            error: 'Could not save login session.'
          });
        }

        audit(req, 'LOGIN_SUCCESS', 'user', user.id, 'Signed in');

        res.json({ success: true });
      });
    });
  } catch (err) {
    console.error('Login error:', err.message);

    res.status(500).json({
      error: 'Login failed. Please try again.'
    });
  }
});

// Account recovery email configuration
function recoveryMailer() {
  const { GMAIL_USER, GMAIL_APP_PASSWORD } = process.env;

  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) {
    throw new Error('Gmail recovery email is not configured.');
  }

  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: GMAIL_USER,
      pass: GMAIL_APP_PASSWORD
    }
  });
}

function validEmail(value) {
  return typeof value === 'string' &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

async function sendRecoveryMail(to, subject, textBody) {
  const mailer = recoveryMailer();

  await mailer.sendMail({
    from: `EmployeeHub <${process.env.GMAIL_USER}>`,
    to,
    subject,
    text: textBody
  });
}

// Forgot username
app.post('/api/auth/forgot-username', recoveryLimiter, async (req, res) => {
  const email = text(req.body?.email, 254).toLowerCase();

  if (!validEmail(email)) {
    return res.status(400).json({
      error: 'Enter a valid registered email address.'
    });
  }

  try {
    const account = db.prepare(
      'SELECT username FROM users WHERE lower(recovery_email) = ?'
    ).get(email);

    if (account) {
      await sendRecoveryMail(
        email,
        'Your EmployeeHub username',
        `Your EmployeeHub username is: ${account.username}

If you did not request this, you can ignore this email.`
      );
    }

    res.json({
      success: true,
      message: 'If an account is registered with that email, recovery instructions have been sent.'
    });
  } catch (err) {
    console.error('Username recovery email failed:', err.message);

    res.status(503).json({
      error: 'Email delivery is not configured or is temporarily unavailable.'
    });
  }
});

// Forgot password - send OTP
app.post('/api/auth/forgot-password', recoveryLimiter, async (req, res) => {
  const email = text(req.body?.email, 254).toLowerCase();

  if (!validEmail(email)) {
    return res.status(400).json({
      error: 'Enter a valid registered email address.'
    });
  }

  try {
    const account = db.prepare(
      'SELECT id FROM users WHERE lower(recovery_email) = ?'
    ).get(email);

    if (account) {
      const otp = String(
        crypto.randomInt(0, 1000000)
      ).padStart(6, '0');

      const otpHash = await bcrypt.hash(otp, 10);

      db.prepare(
        'DELETE FROM password_reset_codes WHERE user_id = ? OR expires_at < ?'
      ).run(account.id, Date.now());

      db.prepare(`
        INSERT INTO password_reset_codes
        (user_id, code_hash, expires_at)
        VALUES (?, ?, ?)
      `).run(
        account.id,
        otpHash,
        Date.now() + 10 * 60 * 1000
      );

      await sendRecoveryMail(
        email,
        'EmployeeHub password reset code',
        `Your EmployeeHub password reset code is ${otp}.

It expires in 10 minutes.

If you did not request this, ignore this email.`
      );
    }

    res.json({
      success: true,
      message: 'If an account is registered with that email, a reset code has been sent.'
    });
  } catch (err) {
    console.error('Password recovery email failed:', err.message);

    res.status(503).json({
      error: 'Email delivery is not configured or is temporarily unavailable.'
    });
  }
});

// Reset password using OTP
app.post('/api/auth/reset-password', recoveryLimiter, async (req, res) => {
  const email = text(req.body?.email, 254).toLowerCase();
  const otp = text(req.body?.otp, 6);
  const password = req.body?.newPassword;

  if (
    !validEmail(email) ||
    !/^\d{6}$/.test(otp) ||
    typeof password !== 'string' ||
    password.length < 12 ||
    password.length > 200
  ) {
    return res.status(400).json({
      error: 'Enter your email, 6-digit code, and a new password of at least 12 characters.'
    });
  }

  try {
    const account = db.prepare(
      'SELECT id FROM users WHERE lower(recovery_email) = ?'
    ).get(email);

    if (!account) {
      return res.status(400).json({
        error: 'Invalid or expired reset code.'
      });
    }

    const reset = db.prepare(`
      SELECT id, code_hash, expires_at
      FROM password_reset_codes
      WHERE user_id = ?
    `).get(account.id);

    if (
      !reset ||
      reset.expires_at < Date.now() ||
      !(await bcrypt.compare(otp, reset.code_hash))
    ) {
      return res.status(400).json({
        error: 'Invalid or expired reset code.'
      });
    }

    db.prepare(`
      UPDATE users
      SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(
      await bcrypt.hash(password, 12),
      account.id
    );

    db.prepare(
      'DELETE FROM password_reset_codes WHERE user_id = ?'
    ).run(account.id);

    // Sign out all existing sessions after password reset.
    db.prepare('DELETE FROM sessions').run();

    audit(
      req,
      'PASSWORD_RESET',
      'user',
      account.id,
      'Password reset using email verification'
    );

    res.json({
      success: true,
      message: 'Password reset successfully. You can now sign in.'
    });
  } catch (err) {
    console.error('Password reset error:', err.message);

    res.status(500).json({
      error: 'Could not reset password. Please try again.'
    });
  }
});
// Logout
app.post('/api/auth/logout', requireAuth, csrfProtection, (req, res) => {
  audit(req, 'LOGOUT', 'user', req.session.userId, 'Signed out');

  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: 'Could not log out.'
      });
    }

    res.clearCookie('employee.sid', {
      httpOnly: true,
      sameSite: 'lax',
      secure: production
    });

    res.json({ success: true });
  });
});

// Change password
app.post('/api/auth/change-password', requireAuth, csrfProtection, async (req, res) => {
  const current = req.body?.currentPassword;
  const next = req.body?.newPassword;

  if (
    typeof current !== 'string' ||
    typeof next !== 'string' ||
    next.length < 12 ||
    next.length > 200
  ) {
    return res.status(400).json({
      error: 'New password must be at least 12 characters.'
    });
  }

  const user = db.prepare(
    'SELECT password_hash FROM users WHERE id = ?'
  ).get(req.session.userId);

  if (!user || !(await bcrypt.compare(current, user.password_hash))) {
    return res.status(400).json({
      error: 'Current password is incorrect.'
    });
  }

  db.prepare(`
    UPDATE users
    SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(await bcrypt.hash(next, 12), req.session.userId);

  audit(req, 'PASSWORD_CHANGED', 'user', req.session.userId, 'Password changed');

  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({
        error: 'Password changed, but sign-out failed. Please sign in again.'
      });
    }

    res.json({
      success: true,
      message: 'Password changed. Please sign in again.'
    });
  });
});

// Apply CSRF and authentication to protected API routes.
app.use('/api', csrfProtection);
app.use('/api', requireAuth);

// Employee directory
app.get('/api/employees', requirePermission('employees:read'), (req, res) => {
  res.json(
    db.prepare('SELECT * FROM employees ORDER BY id DESC').all()
  );
});

app.post('/api/employees', requirePermission('employees:write'), (req, res) => {
  const name = text(req.body?.name, 120);
  const email = text(req.body?.email, 180);
  const department = text(req.body?.department, 100);

  if (
    !name ||
    !email ||
    !department ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return res.status(400).json({
      error: 'Enter a name, valid email, and department.'
    });
  }

  const result = db.prepare(`
    INSERT INTO employees
    (name, email, department, phone, job_title, joining_date, status)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    name,
    email,
    department,
    text(req.body?.phone, 40),
    text(req.body?.job_title, 100),
    validDate(req.body?.joining_date) ? req.body.joining_date : '',
    ['Active', 'Inactive'].includes(req.body?.status)
      ? req.body.status
      : 'Active'
  );

  audit(req, 'CREATE', 'employee', result.lastInsertRowid, `Created employee ${name}`);
  executeWorkflowEvent('New employee added', result.lastInsertRowid, `employee-created:${result.lastInsertRowid}`, `New employee ${name} joined ${department}.`);

  res.status(201).json(
    db.prepare('SELECT * FROM employees WHERE id = ?').get(result.lastInsertRowid)
  );
});

app.put('/api/employees/:id', requirePermission('employees:write'), (req, res) => {
  const id = Number(req.params.id);
  const old = db.prepare('SELECT * FROM employees WHERE id = ?').get(id);

  const name = text(req.body?.name, 120);
  const email = text(req.body?.email, 180);
  const department = text(req.body?.department, 100);

  if (!Number.isInteger(id) || !old) {
    return res.status(404).json({ error: 'Employee not found.' });
  }

  if (
    !name ||
    !department ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return res.status(400).json({
      error: 'Enter a name, valid email, and department.'
    });
  }

  const phone = req.body?.phone === undefined
    ? old.phone
    : text(req.body.phone, 40);

  const jobTitle = req.body?.job_title === undefined
    ? old.job_title
    : text(req.body.job_title, 100);

  const joiningDate = req.body?.joining_date === undefined
    ? old.joining_date
    : (validDate(req.body.joining_date) ? req.body.joining_date : '');

  const status = req.body?.status === undefined
    ? old.status
    : (['Active', 'Inactive'].includes(req.body.status)
        ? req.body.status
        : old.status);

  db.prepare(`
    UPDATE employees
    SET name = ?, email = ?, department = ?, phone = ?,
        job_title = ?, joining_date = ?, status = ?
    WHERE id = ?
  `).run(name, email, department, phone, jobTitle, joiningDate, status, id);

  audit(req, 'UPDATE', 'employee', id, `Updated employee ${name}`);

  res.json(
    db.prepare('SELECT * FROM employees WHERE id = ?').get(id)
  );
});

app.delete('/api/employees/:id', requirePermission('employees:write'), (req, res) => {
  if (req.session.role !== 'admin') {
    return res.status(403).json({
      error: 'Only an administrator can delete employee records.'
    });
  }

  const id = Number(req.params.id);
  const emp = db.prepare('SELECT name FROM employees WHERE id = ?').get(id);

  if (!emp) {
    return res.status(404).json({ error: 'Employee not found.' });
  }

  db.prepare('DELETE FROM employees WHERE id = ?').run(id);

  audit(req, 'DELETE', 'employee', id, `Deleted employee ${emp.name}`);

  res.json({ success: true });
});

// User administration
app.get('/api/users', requirePermission('users:manage'), (req, res) => {
  res.json(
    db.prepare('SELECT id, username, role, employee_id, created_at FROM users ORDER BY id').all()
  );
});

app.post('/api/users', requirePermission('users:manage'), async (req, res) => {
  const username = text(req.body?.username, 80);
  const password = req.body?.password;
  const role = req.body?.role;

  if (
    !/^[a-zA-Z0-9._-]{3,80}$/.test(username) ||
    typeof password !== 'string' ||
    password.length < 12 ||
    !['admin', 'hr', 'viewer'].includes(role)
  ) {
    return res.status(400).json({
      error: 'Use a 3+ character username, password of at least 12 characters, and valid role.'
    });
  }

  try {
    const result = db.prepare(`
      INSERT INTO users (username, password_hash, role)
      VALUES (?, ?, ?)
    `).run(username, await bcrypt.hash(password, 12), role);

    audit(req, 'CREATE', 'user', result.lastInsertRowid, `Created ${role} account ${username}`);

    res.status(201).json({
      id: result.lastInsertRowid,
      username,
      role
    });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({
        error: 'That username already exists.'
      });
    }

    throw err;
  }
});

app.put('/api/users/:id/role', requirePermission('users:manage'), (req, res) => {
  const id = Number(req.params.id);
  const role = req.body?.role;

  if (!['admin', 'hr', 'viewer'].includes(role)) {
    return res.status(400).json({
      error: 'Choose admin, hr, or viewer.'
    });
  }

  if (id === req.session.userId && role !== 'admin') {
    return res.status(400).json({
      error: 'You cannot remove your own administrator role.'
    });
  }

  const result = db.prepare(`
    UPDATE users
    SET role = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(role, id);

  if (!result.changes) {
    return res.status(404).json({ error: 'User not found.' });
  }

  audit(req, 'UPDATE', 'user', id, `Role changed to ${role}`);

  res.json({ success: true });
});

// Attendance
app.get('/api/attendance', requirePermission('attendance:read'), (req, res) => {
  const date = validDate(req.query.date) ? req.query.date : null;

  const rows = date
    ? db.prepare(`
        SELECT a.*, e.name AS employee_name, e.department
        FROM attendance a
        JOIN employees e ON e.id = a.employee_id
        WHERE attendance_date = ?
        ORDER BY e.name
      `).all(date)
    : db.prepare(`
        SELECT a.*, e.name AS employee_name, e.department
        FROM attendance a
        JOIN employees e ON e.id = a.employee_id
        ORDER BY attendance_date DESC, e.name
        LIMIT 500
      `).all();

  res.json(rows);
});

app.post('/api/attendance', requirePermission('attendance:write'), (req, res) => {
  const employeeId = Number(req.body?.employee_id);
  const date = req.body?.attendance_date;
  const status = req.body?.status;
  const notes = text(req.body?.notes, 500);

  if (
    !Number.isInteger(employeeId) ||
    !validDate(date) ||
    !['Present', 'Absent', 'Leave', 'Half Day', 'Work From Home'].includes(status)
  ) {
    return res.status(400).json({
      error: 'Select an employee, valid date, and attendance status.'
    });
  }

  if (!db.prepare('SELECT id FROM employees WHERE id = ?').get(employeeId)) {
    return res.status(404).json({ error: 'Employee not found.' });
  }

  db.prepare(`
    INSERT INTO attendance
    (employee_id, attendance_date, status, notes, created_by)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(employee_id, attendance_date)
    DO UPDATE SET
      status = excluded.status,
      notes = excluded.notes,
      created_by = excluded.created_by
  `).run(employeeId, date, status, notes, req.session.userId);

  const row = db.prepare(`
    SELECT * FROM attendance
    WHERE employee_id = ? AND attendance_date = ?
  `).get(employeeId, date);

  audit(req, 'UPSERT', 'attendance', row.id, `${status} for employee ${employeeId} on ${date}`);

  res.json(row);
});

// Leave requests and approvals
app.get('/api/leaves', requirePermission('leave:read'), (req, res) => {
  res.json(
    db.prepare(`
      SELECT l.*, e.name AS employee_name, e.department,
             u.username AS reviewer
      FROM leave_requests l
      JOIN employees e ON e.id = l.employee_id
      LEFT JOIN users u ON u.id = l.reviewed_by
      ORDER BY l.created_at DESC
      LIMIT 500
    `).all()
  );
});

app.post('/api/leaves', requirePermission('leave:write'), leaveLimiter, (req, res) => {
  const employeeId = Number(req.body?.employee_id);
  const type = text(req.body?.leave_type, 60);
  const start = req.body?.start_date;
  const end = req.body?.end_date;
  const reason = text(req.body?.reason, 1000);

  const daySpan = validDate(start) && validDate(end)
    ? (Date.parse(end + 'T00:00:00Z') - Date.parse(start + 'T00:00:00Z')) / 86400000
    : Infinity;

  if (
    !Number.isInteger(employeeId) ||
    !['Annual', 'Sick', 'Personal', 'Unpaid', 'Other'].includes(type) ||
    !validDate(start) ||
    !validDate(end) ||
    start > end ||
    daySpan > 90 ||
    !reason
  ) {
    return res.status(400).json({
      error: 'Complete all leave fields with valid dates.'
    });
  }

  if (!db.prepare('SELECT id FROM employees WHERE id = ?').get(employeeId)) {
    return res.status(404).json({ error: 'Employee not found.' });
  }

  const result = db.prepare(`
    INSERT INTO leave_requests
    (employee_id, leave_type, start_date, end_date, reason, requested_by)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(employeeId, type, start, end, reason, req.session.userId);

  audit(req, 'CREATE', 'leave', result.lastInsertRowid, `Leave requested for employee ${employeeId}`);
  executeWorkflowEvent('Leave request submitted', employeeId, `leave-submitted:${result.lastInsertRowid}`, `Leave request ${type}, ${start} to ${end}.`);

  res.status(201).json({
    id: result.lastInsertRowid,
    status: 'Pending'
  });
});

app.put('/api/leaves/:id/review', requirePermission('leave:write'), (req, res) => {
  const id = Number(req.params.id);
  const status = req.body?.status;

  if (!['Approved', 'Rejected'].includes(status)) {
    return res.status(400).json({
      error: 'Choose Approved or Rejected.'
    });
  }

  const old = db.prepare(
    'SELECT * FROM leave_requests WHERE id = ?'
  ).get(id);

  if (!old) {
    return res.status(404).json({
      error: 'Leave request not found.'
    });
  }

  if (old.status !== 'Pending') {
    return res.status(409).json({
      error: 'This request has already been reviewed.'
    });
  }

  db.prepare(`
    UPDATE leave_requests
    SET status = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(status, req.session.userId, id);

  if (status === 'Approved') {
    const startDate = new Date(old.start_date + 'T00:00:00Z');
    const endDate = new Date(old.end_date + 'T00:00:00Z');

    const insert = db.prepare(`
      INSERT INTO attendance
      (employee_id, attendance_date, status, notes, created_by)
      VALUES (?, ?, 'Leave', 'Approved leave', ?)
      ON CONFLICT(employee_id, attendance_date)
      DO UPDATE SET
        status = 'Leave',
        notes = 'Approved leave',
        created_by = excluded.created_by
    `);

    const transaction = db.transaction(() => {
      for (let date = new Date(startDate); date <= endDate; date.setUTCDate(date.getUTCDate() + 1)) {
        insert.run(
          old.employee_id,
          date.toISOString().slice(0, 10),
          req.session.userId
        );
      }
    });

    transaction();
  }

  audit(req, 'REVIEW', 'leave', id, `Leave ${status}`);

  res.json({ success: true, status });
});

// Additional HR operations: assets, onboarding tasks, helpdesk and document register.
app.get('/api/operations/assets', requirePermission('operations:read'), (req, res) => {
  res.json(db.prepare(`SELECT a.*, e.name AS employee_name FROM assets a LEFT JOIN employees e ON e.id=a.assigned_to ORDER BY a.id DESC`).all());
});
app.post('/api/operations/assets', requirePermission('operations:write'), (req, res) => {
  const name=text(req.body?.asset_name,120), tag=text(req.body?.asset_tag,80), category=text(req.body?.category,80);
  const status=['Available','Assigned','Repair','Retired'].includes(req.body?.status)?req.body.status:'Available';
  const assigned=req.body?.assigned_to ? Number(req.body.assigned_to) : null;
  if(!name||!tag||!category|| (assigned && !db.prepare('SELECT id FROM employees WHERE id=?').get(assigned))) return res.status(400).json({error:'Enter an asset name, unique asset tag and category; choose a valid employee.'});
  try {
    const r=db.prepare(`INSERT INTO assets(asset_name,asset_tag,category,serial_number,assigned_to,purchase_date,status,notes) VALUES(?,?,?,?,?,?,?,?)`).run(name,tag,category,text(req.body?.serial_number,100),assigned,validDate(req.body?.purchase_date)?req.body.purchase_date:'',status,text(req.body?.notes,500));
    audit(req,'CREATE','asset',r.lastInsertRowid,`Registered asset ${tag}`); res.status(201).json(db.prepare('SELECT * FROM assets WHERE id=?').get(r.lastInsertRowid));
  } catch(e){if(e.code==='SQLITE_CONSTRAINT_UNIQUE')return res.status(409).json({error:'That asset tag is already registered.'});throw e;}
});
app.put('/api/operations/assets/:id', requirePermission('operations:write'), (req,res)=>{
  const id=Number(req.params.id), old=db.prepare('SELECT * FROM assets WHERE id=?').get(id); if(!old)return res.status(404).json({error:'Asset not found.'});
  const name=text(req.body?.asset_name,120), tag=text(req.body?.asset_tag,80), category=text(req.body?.category,80), status=req.body?.status;
  const assigned=req.body?.assigned_to ? Number(req.body.assigned_to) : null;
  if(!name||!tag||!category||!['Available','Assigned','Repair','Retired'].includes(status)||(assigned&&!db.prepare('SELECT id FROM employees WHERE id=?').get(assigned)))return res.status(400).json({error:'Check the asset details and assignment.'});
  try{db.prepare(`UPDATE assets SET asset_name=?,asset_tag=?,category=?,serial_number=?,assigned_to=?,purchase_date=?,status=?,notes=? WHERE id=?`).run(name,tag,category,text(req.body?.serial_number,100),assigned,validDate(req.body?.purchase_date)?req.body.purchase_date:'',status,text(req.body?.notes,500),id);audit(req,'UPDATE','asset',id,`Updated asset ${tag}`);res.json(db.prepare('SELECT * FROM assets WHERE id=?').get(id));}catch(e){if(e.code==='SQLITE_CONSTRAINT_UNIQUE')return res.status(409).json({error:'That asset tag is already registered.'});throw e;}
});
app.delete('/api/operations/assets/:id', requirePermission('operations:write'), (req,res)=>{const id=Number(req.params.id);const r=db.prepare('DELETE FROM assets WHERE id=?').run(id);if(!r.changes)return res.status(404).json({error:'Asset not found.'});audit(req,'DELETE','asset',id,'Deleted asset');res.json({success:true});});

app.get('/api/operations/tasks', requirePermission('operations:read'), (req,res)=>res.json(db.prepare(`SELECT t.*,e.name AS employee_name FROM onboarding_tasks t JOIN employees e ON e.id=t.employee_id ORDER BY t.id DESC`).all()));
app.post('/api/operations/tasks', requirePermission('operations:write'), (req,res)=>{const employee=Number(req.body?.employee_id),title=text(req.body?.task_title,160);if(!Number.isInteger(employee)||!db.prepare('SELECT id FROM employees WHERE id=?').get(employee)||!title|| (req.body?.due_date&&!validDate(req.body.due_date)))return res.status(400).json({error:'Choose an employee, enter a task and a valid due date.'});const r=db.prepare(`INSERT INTO onboarding_tasks(employee_id,task_title,due_date,owner,notes) VALUES(?,?,?,?,?)`).run(employee,title,req.body.due_date||'',text(req.body?.owner,100),text(req.body?.notes,500));audit(req,'CREATE','onboarding_task',r.lastInsertRowid,title);res.status(201).json({id:r.lastInsertRowid});});
app.put('/api/operations/tasks/:id', requirePermission('operations:write'), (req,res)=>{const id=Number(req.params.id),status=req.body?.status;if(!['Pending','In Progress','Completed'].includes(status))return res.status(400).json({error:'Choose a valid task status.'});const r=db.prepare('UPDATE onboarding_tasks SET status=? WHERE id=?').run(status,id);if(!r.changes)return res.status(404).json({error:'Task not found.'});audit(req,'UPDATE','onboarding_task',id,`Task status ${status}`);res.json({success:true});});

app.get('/api/operations/tickets', requirePermission('operations:read'), (req,res)=>res.json(db.prepare(`SELECT t.*,e.name AS employee_name FROM helpdesk_tickets t LEFT JOIN employees e ON e.id=t.employee_id ORDER BY t.id DESC LIMIT 500`).all()));
app.post('/api/operations/tickets', requirePermission('operations:write'), (req,res)=>{const subject=text(req.body?.subject,160),category=text(req.body?.category,80),description=text(req.body?.description,2000),priority=['Low','Normal','High','Urgent'].includes(req.body?.priority)?req.body.priority:'Normal',employee=req.body?.employee_id?Number(req.body.employee_id):null;if(!subject||!category||!description||(employee&&!db.prepare('SELECT id FROM employees WHERE id=?').get(employee)))return res.status(400).json({error:'Enter a subject, category and description.'});const r=db.prepare(`INSERT INTO helpdesk_tickets(employee_id,subject,category,priority,description) VALUES(?,?,?,?,?)`).run(employee,subject,category,priority,description);audit(req,'CREATE','helpdesk_ticket',r.lastInsertRowid,subject);res.status(201).json({id:r.lastInsertRowid});});
app.put('/api/operations/tickets/:id', requirePermission('operations:write'), (req,res)=>{const id=Number(req.params.id),status=req.body?.status;if(!['Open','In Progress','Resolved','Closed'].includes(status))return res.status(400).json({error:'Choose a valid ticket status.'});const r=db.prepare(`UPDATE helpdesk_tickets SET status=?,assigned_to=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(status,text(req.body?.assigned_to,100),id);if(!r.changes)return res.status(404).json({error:'Ticket not found.'});audit(req,'UPDATE','helpdesk_ticket',id,`Ticket status ${status}`);res.json({success:true});});

app.get('/api/operations/documents', requirePermission('operations:read'), (req,res)=>res.json(db.prepare(`SELECT d.*,e.name AS employee_name FROM document_register d LEFT JOIN employees e ON e.id=d.employee_id ORDER BY d.id DESC`).all()));
app.post('/api/operations/documents', requirePermission('operations:write'), (req,res)=>{const name=text(req.body?.document_name,160),type=text(req.body?.document_type,80),employee=req.body?.employee_id?Number(req.body.employee_id):null,expiry=req.body?.expiry_date||'';if(!name||!type||(employee&&!db.prepare('SELECT id FROM employees WHERE id=?').get(employee))||(expiry&&!validDate(expiry)))return res.status(400).json({error:'Enter a document name and type, with valid employee and expiry details.'});const r=db.prepare(`INSERT INTO document_register(employee_id,document_name,document_type,reference_note,expiry_date) VALUES(?,?,?,?,?)`).run(employee,name,type,text(req.body?.reference_note,500),expiry);audit(req,'CREATE','document_register',r.lastInsertRowid,name);res.status(201).json({id:r.lastInsertRowid});});
app.delete('/api/operations/documents/:id', requirePermission('operations:write'), (req,res)=>{const id=Number(req.params.id),r=db.prepare('DELETE FROM document_register WHERE id=?').run(id);if(!r.changes)return res.status(404).json({error:'Document record not found.'});audit(req,'DELETE','document_register',id,'Deleted document register entry');res.json({success:true});});

// Reports
app.get('/api/reports/summary', requirePermission('reports:read'), (req, res) => {
  const employees = db.prepare(`
    SELECT COUNT(*) AS total,
           SUM(CASE WHEN status = 'Active' THEN 1 ELSE 0 END) AS active
    FROM employees
  `).get();

  const departments = db.prepare(`
    SELECT department, COUNT(*) AS count
    FROM employees
    GROUP BY department
    ORDER BY count DESC, department
  `).all();

  const attendance = db.prepare(`
    SELECT status, COUNT(*) AS count
    FROM attendance
    WHERE attendance_date = ?
    GROUP BY status
  `).all(
    validDate(req.query.date)
      ? req.query.date
      : new Date().toISOString().slice(0, 10)
  );

  const leaves = db.prepare(`
    SELECT status, COUNT(*) AS count
    FROM leave_requests
    GROUP BY status
  `).all();

  res.json({ employees, departments, attendance, leaves });
});

app.get('/api/reports/employees.csv', requirePermission('reports:read'), (req, res) => {
  const rows = db.prepare(`
    SELECT id, name, email, department, phone, job_title, joining_date, status
    FROM employees
    ORDER BY id
  `).all();

  const keys = [
    'id', 'name', 'email', 'department',
    'phone', 'job_title', 'joining_date', 'status'
  ];

  const cell = value => {
    let result = String(value ?? '');

    if (/^[=+@\-\t\r]/.test(result)) {
      result = "'" + result;
    }

    return '"' + result.replace(/"/g, '""') + '"';
  };

  const csv = [
    keys,
    ...rows.map(row => keys.map(key => row[key]))
  ].map(row => row.map(cell).join(',')).join('\r\n');

  audit(req, 'EXPORT', 'report', null, 'Employee CSV exported');

  res.type('text/csv')
    .attachment('employee-report.csv')
    .send('\uFEFF' + csv);
});

// Audit logs
app.get('/api/audit', requirePermission('audit:read'), (req, res) => {
  res.json(
    db.prepare(`
      SELECT id, username, action, entity_type, entity_id,
             details, ip_address, created_at
      FROM audit_logs
      ORDER BY id DESC
      LIMIT 300
    `).all()
  );
});


// Enterprise HRMS modules. All writes are permission-gated, validated and audited.
const enterpriseResources = {
  payroll: { table:'payroll_records', fields:['employee_id','pay_period','basic_salary','allowances','deductions','payment_status','payment_date','notes'], required:['employee_id','pay_period'], numbers:['employee_id','basic_salary','allowances','deductions'], dates:['payment_date'], enums:{payment_status:['Draft','Approved','Paid','On Hold']}, employee:true, order:'id DESC' },
  performance: { table:'performance_reviews', fields:['employee_id','reviewer','review_period','rating','goals','feedback','status'], required:['employee_id','review_period','rating'], numbers:['employee_id','rating'], enums:{status:['Draft','Shared','Acknowledged']}, employee:true, order:'id DESC' },
  openings: { table:'job_openings', fields:['title','department','location','employment_type','openings','status','description'], required:['title','department'], numbers:['openings'], enums:{status:['Draft','Open','On Hold','Closed']}, order:'id DESC' },
  applications: { table:'job_applications', fields:['opening_id','candidate_name','email','phone','stage','notes'], required:['candidate_name'], numbers:['opening_id'], enums:{stage:['Applied','Screening','Interview','Offer','Hired','Rejected']}, order:'id DESC' },
  shifts: { table:'shift_schedules', fields:['employee_id','shift_date','shift_name','start_time','end_time','notes'], required:['employee_id','shift_date','shift_name','start_time','end_time'], numbers:['employee_id'], dates:['shift_date'], employee:true, order:'shift_date DESC,id DESC' },
  courses: { table:'training_courses', fields:['title','provider','category','duration_hours','description'], required:['title'], numbers:['duration_hours'], order:'id DESC' },
  enrollments: { table:'training_enrollments', fields:['employee_id','course_id','status','completion_date','notes'], required:['employee_id','course_id'], numbers:['employee_id','course_id'], dates:['completion_date'], enums:{status:['Enrolled','In Progress','Completed','Withdrawn']}, employee:true, order:'id DESC' },
  expenses: { table:'expense_claims', fields:['employee_id','category','amount','expense_date','description','status','reviewer_notes'], required:['employee_id','category','amount','expense_date','description'], numbers:['employee_id','amount'], dates:['expense_date'], enums:{status:['Submitted','Under Review','Approved','Rejected','Reimbursed']}, employee:true, order:'id DESC' },
  policies: { table:'company_policies', fields:['title','category','version','effective_date','status','content'], required:['title','category'], dates:['effective_date'], enums:{status:['Draft','Active','Archived']}, order:'id DESC' },
  offboarding: { table:'offboarding_tasks', fields:['employee_id','last_working_day','reason','task_title','owner','status','notes'], required:['employee_id','last_working_day','task_title'], numbers:['employee_id'], dates:['last_working_day'], enums:{status:['Pending','In Progress','Completed']}, employee:true, order:'id DESC' },
  announcements: { table:'announcements', fields:['title','message','audience','publish_date','expires_on','status'], required:['title','message','publish_date'], dates:['publish_date','expires_on'], enums:{status:['Draft','Published','Archived']}, order:'id DESC' },
  events: { table:'calendar_events', fields:['title','event_date','start_time','end_time','category','description'], required:['title','event_date'], dates:['event_date'], order:'event_date DESC,id DESC' }
};
function enterpriseValue(field, value, config) {
  if (config.numbers?.includes(field)) {
    if (value === '' || value === null || value === undefined) return ['opening_id','employee_id','course_id'].includes(field) ? null : Number(value || 0);
    const n = Number(value);
    return Number.isFinite(n) ? n : NaN;
  }
  if (config.dates?.includes(field)) return value ? (validDate(String(value)) ? String(value) : null) : '';
  if (config.enums?.[field]) { if (value === undefined || value === '') return config.enums[field][0]; return config.enums[field].includes(value) ? value : null; }
  return text(value, field === 'content' || field === 'description' || field === 'message' || field === 'feedback' || field === 'goals' ? 4000 : 500);
}
function enterpriseList(resource, config) {
  let sql = `SELECT t.*`;
  if (config.employee) sql += `, e.name AS employee_name`;
  if (resource === 'applications') sql += `, j.title AS opening_title`;
  if (resource === 'enrollments') sql += `, c.title AS course_title, e.name AS employee_name`;
  sql += ` FROM ${config.table} t`;
  if (config.employee) sql += ` LEFT JOIN employees e ON e.id=t.employee_id`;
  if (resource === 'applications') sql += ` LEFT JOIN job_openings j ON j.id=t.opening_id`;
  if (resource === 'enrollments') sql += ` LEFT JOIN training_courses c ON c.id=t.course_id`;
  sql += ` ORDER BY ${config.order} LIMIT 1000`;
  return db.prepare(sql).all();
}
app.get('/api/enterprise/:resource', requirePermission('operations:read'), (req,res)=>{
  const resource=req.params.resource, config=enterpriseResources[resource];
  if(!config) return res.status(404).json({error:'Unknown HRMS module.'});
  if(['payroll','expenses','applications'].includes(resource) && req.session.role==='viewer') return res.status(403).json({error:'This module contains restricted business or personal information.'});
  res.json(enterpriseList(resource,config));
});
app.post('/api/enterprise/:resource', requirePermission('operations:write'), (req,res)=>{
  const resource=req.params.resource, config=enterpriseResources[resource];
  if(!config) return res.status(404).json({error:'Unknown HRMS module.'});
  const values={};
  for(const field of config.fields) values[field]=enterpriseValue(field,req.body?.[field],config);
  for(const field of config.required){if(values[field]===null||values[field]===undefined||values[field]===''||(typeof values[field]==='number'&&!Number.isFinite(values[field])))return res.status(400).json({error:`Please provide a valid ${field.replaceAll('_',' ')}.`});}
  for(const field of config.fields){if(values[field]===null && req.body?.[field]!=='' && req.body?.[field]!==undefined)return res.status(400).json({error:`Invalid ${field.replaceAll('_',' ')}.`});if(typeof values[field]==='number'&&!Number.isFinite(values[field]))return res.status(400).json({error:`Invalid ${field.replaceAll('_',' ')}.`});}
  if(config.employee && !db.prepare('SELECT id FROM employees WHERE id=?').get(values.employee_id))return res.status(400).json({error:'Choose a valid employee.'});
  if(resource==='applications'&&values.opening_id&&!db.prepare('SELECT id FROM job_openings WHERE id=?').get(values.opening_id))return res.status(400).json({error:'Choose a valid job opening.'});
  if(resource==='enrollments'&&!db.prepare('SELECT id FROM training_courses WHERE id=?').get(values.course_id))return res.status(400).json({error:'Choose a valid training course.'});
  if(resource==='performance' && (!Number.isInteger(values.rating)||values.rating<1||values.rating>5))return res.status(400).json({error:'Performance rating must be from 1 to 5.'});
  if(resource==='openings' && values.openings<1)return res.status(400).json({error:'At least one opening is required.'});
  if(resource==='payroll'){
    for(const f of ['basic_salary','allowances','deductions']) if(values[f]<0)return res.status(400).json({error:'Salary amounts cannot be negative.'});
    values.net_salary=Math.max(0,values.basic_salary+values.allowances-values.deductions);
  }
  try{
    const fields=Object.keys(values), placeholders=fields.map(()=>'?').join(',');
    const result=db.prepare(`INSERT INTO ${config.table} (${fields.join(',')}) VALUES (${placeholders})`).run(...fields.map(f=>values[f]));
    audit(req,'CREATE',resource,result.lastInsertRowid,`Created ${resource} record`);
    if(resource==='expenses')executeWorkflowEvent('Expense claim submitted',values.employee_id,`expense-submitted:${result.lastInsertRowid}`,`Expense claim ₹${values.amount} for ${values.category}.`);
    res.status(201).json({id:result.lastInsertRowid,success:true});
  }catch(err){if(err.code==='SQLITE_CONSTRAINT_UNIQUE')return res.status(409).json({error:'A matching record already exists.'});throw err;}
});
app.put('/api/enterprise/:resource/:id', requirePermission('operations:write'), (req,res)=>{
  const resource=req.params.resource, config=enterpriseResources[resource], id=Number(req.params.id);
  if(!config) return res.status(404).json({error:'Unknown HRMS module.'});
  if(!Number.isInteger(id)||id<1)return res.status(400).json({error:'Invalid record ID.'});
  const current=db.prepare(`SELECT * FROM ${config.table} WHERE id=?`).get(id);
  if(!current)return res.status(404).json({error:'Record not found.'});
  const values={};
  for(const field of config.fields) values[field]=enterpriseValue(field,req.body?.[field] ?? current[field],config);
  for(const field of config.required){if(values[field]===null||values[field]===undefined||values[field]==='')return res.status(400).json({error:`Please provide a valid ${field.replaceAll('_',' ')}.`});}
  for(const field of config.fields){if(values[field]===null)return res.status(400).json({error:`Invalid ${field.replaceAll('_',' ')}.`});if(typeof values[field]==='number'&&!Number.isFinite(values[field]))return res.status(400).json({error:`Invalid ${field.replaceAll('_',' ')}.`});}
  if(config.employee&&!db.prepare('SELECT id FROM employees WHERE id=?').get(values.employee_id))return res.status(400).json({error:'Choose a valid employee.'});
  if(resource==='applications'&&values.opening_id&&!db.prepare('SELECT id FROM job_openings WHERE id=?').get(values.opening_id))return res.status(400).json({error:'Choose a valid job opening.'});
  if(resource==='enrollments'&&!db.prepare('SELECT id FROM training_courses WHERE id=?').get(values.course_id))return res.status(400).json({error:'Choose a valid training course.'});
  if(resource==='performance' && (!Number.isInteger(values.rating)||values.rating<1||values.rating>5))return res.status(400).json({error:'Performance rating must be from 1 to 5.'});
  if(resource==='openings' && values.openings<1)return res.status(400).json({error:'At least one opening is required.'});
  if(resource==='expenses' && values.amount<0)return res.status(400).json({error:'Expense amount cannot be negative.'});
  if(resource==='payroll'){for(const f of ['basic_salary','allowances','deductions'])if(values[f]<0)return res.status(400).json({error:'Salary amounts cannot be negative.'});values.net_salary=Math.max(0,values.basic_salary+values.allowances-values.deductions);}
  const fields=Object.keys(values);db.prepare(`UPDATE ${config.table} SET ${fields.map(f=>`${f}=?`).join(',')} WHERE id=?`).run(...fields.map(f=>values[f]),id);
  audit(req,'UPDATE',resource,id,`Updated ${resource} record`);res.json({success:true});
});
app.delete('/api/enterprise/:resource/:id', requirePermission('operations:write'), (req,res)=>{
  const config=enterpriseResources[req.params.resource], id=Number(req.params.id);
  if(!config)return res.status(404).json({error:'Unknown HRMS module.'});
  const result=db.prepare(`DELETE FROM ${config.table} WHERE id=?`).run(id);
  if(!result.changes)return res.status(404).json({error:'Record not found.'});
  audit(req,'DELETE',req.params.resource,id,`Deleted ${req.params.resource} record`);res.json({success:true});
});

// Employee Self-Service, measurable goals, analytics, workflows and HR assistant.
function peopleManager(req) { return ['admin','hr'].includes(req.session.role); }
function linkedEmployee(req) { return db.prepare('SELECT e.* FROM users u JOIN employees e ON e.id=u.employee_id WHERE u.id=?').get(req.session.userId); }
app.get('/people', requireAuth, (req,res)=>res.sendFile(path.join(__dirname,'people.html')));
app.get('/api/people/employees', requireAuth, requirePermission('employees:read'), (req,res)=>res.json(db.prepare('SELECT id,name,email,department FROM employees ORDER BY name').all()));
app.get('/api/people/link-options', requireAuth, requirePermission('users:manage'), (req,res)=>{
  res.json({users:db.prepare('SELECT id,username,role,employee_id FROM users ORDER BY username').all(),employees:db.prepare('SELECT id,name,email,department FROM employees ORDER BY name').all()});
});
app.put('/api/people/link/:userId', requireAuth, requirePermission('users:manage'), (req,res)=>{
  const uid=Number(req.params.userId), eid=req.body?.employee_id===null?null:Number(req.body?.employee_id);
  if(!db.prepare('SELECT id FROM users WHERE id=?').get(uid))return res.status(404).json({error:'User account not found.'});
  if(eid!==null && (!Number.isInteger(eid)||!db.prepare('SELECT id FROM employees WHERE id=?').get(eid)))return res.status(400).json({error:'Choose a valid employee.'});
  db.prepare('UPDATE users SET employee_id=? WHERE id=?').run(eid,uid);audit(req,'UPDATE','user_employee_link',uid,`Linked employee ${eid||'none'}`);res.json({success:true});
});
app.get('/api/people/me', requireAuth, (req,res)=>{
  const employee=linkedEmployee(req); if(!employee)return res.json({linked:false,username:req.session.username,role:req.session.role});
  const goals=db.prepare('SELECT * FROM employee_goals WHERE employee_id=? ORDER BY target_date,id DESC').all(employee.id);
  const leaves=db.prepare('SELECT * FROM leave_requests WHERE employee_id=? ORDER BY id DESC LIMIT 30').all(employee.id);
  const expenses=db.prepare('SELECT id,category,amount,expense_date,description,status,reviewer_notes FROM expense_claims WHERE employee_id=? ORDER BY id DESC LIMIT 30').all(employee.id);
  const notifications=db.prepare('SELECT * FROM employee_notifications WHERE employee_id=? ORDER BY id DESC LIMIT 30').all(employee.id);
  const announcements=db.prepare("SELECT * FROM announcements WHERE status='Published' AND (expires_on='' OR expires_on>=date('now')) ORDER BY publish_date DESC LIMIT 20").all();
  res.json({linked:true,employee,goals,leaves,expenses,notifications,announcements});
});
app.post('/api/people/leave', requireAuth, (req,res)=>{
  const e=linkedEmployee(req);if(!e)return res.status(403).json({error:'Ask HR to link your login to your employee profile first.'});
  const {leave_type,start_date,end_date,reason}=req.body||{};
  if(!text(leave_type,60)||!validDate(start_date)||!validDate(end_date)||end_date<start_date||!text(reason,1000))return res.status(400).json({error:'Enter a valid leave type, date range and reason.'});
  const r=db.prepare('INSERT INTO leave_requests(employee_id,leave_type,start_date,end_date,reason,requested_by) VALUES(?,?,?,?,?,?)').run(e.id,text(leave_type,60),start_date,end_date,text(reason,1000),req.session.userId);audit(req,'CREATE','leave_request',r.lastInsertRowid,'Employee self-service leave request');executeWorkflowEvent('Leave request submitted',e.id,`leave-submitted:${r.lastInsertRowid}`,`Leave request ${leave_type}, ${start_date} to ${end_date}.`);res.status(201).json({id:r.lastInsertRowid});
});
app.post('/api/people/expenses', requireAuth, (req,res)=>{
  const e=linkedEmployee(req);if(!e)return res.status(403).json({error:'Ask HR to link your login to your employee profile first.'});
  const b=req.body||{},amount=Number(b.amount);if(!text(b.category,60)||!Number.isFinite(amount)||amount<=0||!validDate(b.expense_date)||!text(b.description,1000))return res.status(400).json({error:'Enter a valid expense category, positive amount, date and description.'});
  const r=db.prepare("INSERT INTO expense_claims(employee_id,category,amount,expense_date,description,status) VALUES(?,?,?,?,?,'Submitted')").run(e.id,text(b.category,60),amount,b.expense_date,text(b.description,1000));audit(req,'CREATE','expense_claim',r.lastInsertRowid,'Employee self-service expense claim');executeWorkflowEvent('Expense claim submitted',e.id,`expense-submitted:${r.lastInsertRowid}`,`Expense claim ₹${amount} for ${b.category}.`);res.status(201).json({id:r.lastInsertRowid});
});
app.post('/api/people/notifications/:id/read', requireAuth, (req,res)=>{const e=linkedEmployee(req);if(!e)return res.status(403).json({error:'Employee profile is not linked.'});const r=db.prepare('UPDATE employee_notifications SET is_read=1 WHERE id=? AND employee_id=?').run(Number(req.params.id),e.id);if(!r.changes)return res.status(404).json({error:'Notification not found.'});res.json({success:true});});
app.get('/api/people/goals', requireAuth, (req,res)=>{const e=linkedEmployee(req);if(!peopleManager(req)&&!e)return res.status(403).json({error:'Employee profile is not linked.'});const sql=peopleManager(req)?'SELECT g.*,e.name AS employee_name FROM employee_goals g JOIN employees e ON e.id=g.employee_id ORDER BY g.id DESC':'SELECT g.*,e.name AS employee_name FROM employee_goals g JOIN employees e ON e.id=g.employee_id WHERE g.employee_id=? ORDER BY g.id DESC';res.json(peopleManager(req)?db.prepare(sql).all():db.prepare(sql).all(e.id));});
app.post('/api/people/goals', requireAuth, requirePermission('operations:write'), (req,res)=>{const b=req.body||{},eid=Number(b.employee_id),progress=Number(b.progress||0);if(!db.prepare('SELECT id FROM employees WHERE id=?').get(eid)||!text(b.title,180)||!Number.isInteger(progress)||progress<0||progress>100||(b.target_date&&!validDate(b.target_date)))return res.status(400).json({error:'Enter a valid employee, goal title, progress and target date.'});const status=['Not Started','In Progress','Completed','At Risk'].includes(b.status)?b.status:(progress===100?'Completed':progress?'In Progress':'Not Started');const r=db.prepare('INSERT INTO employee_goals(employee_id,title,description,category,target_date,progress,status,created_by) VALUES(?,?,?,?,?,?,?,?)').run(eid,text(b.title,180),text(b.description,2000),text(b.category,60)||'Performance',b.target_date||'',progress,status,req.session.userId);audit(req,'CREATE','employee_goal',r.lastInsertRowid,b.title);res.status(201).json({id:r.lastInsertRowid});});
app.put('/api/people/goals/:id', requireAuth, (req,res)=>{const e=linkedEmployee(req),id=Number(req.params.id),goal=db.prepare('SELECT * FROM employee_goals WHERE id=?').get(id);if(!goal)return res.status(404).json({error:'Goal not found.'});if(!peopleManager(req)&&(!e||e.id!==goal.employee_id))return res.status(403).json({error:'You can only update your own goals.'});const progress=Number(req.body?.progress);if(!Number.isInteger(progress)||progress<0||progress>100)return res.status(400).json({error:'Progress must be between 0 and 100.'});const status=['Not Started','In Progress','Completed','At Risk'].includes(req.body?.status)?req.body.status:(progress===100?'Completed':progress?'In Progress':'Not Started');db.prepare('UPDATE employee_goals SET progress=?,status=? WHERE id=?').run(progress,status,id);audit(req,'UPDATE','employee_goal',id,`Progress ${progress}%`);res.json({success:true});});
app.get('/api/people/analytics', requireAuth, requirePermission('reports:read'), (req,res)=>{
 const employees=db.prepare("SELECT COUNT(*) total,SUM(CASE WHEN status='Active' THEN 1 ELSE 0 END) active FROM employees").get();
 const departments=db.prepare('SELECT department,COUNT(*) count FROM employees GROUP BY department ORDER BY count DESC').all();
 const hiring=db.prepare('SELECT stage,COUNT(*) count FROM job_applications GROUP BY stage').all();
 const leave=db.prepare('SELECT status,COUNT(*) count FROM leave_requests GROUP BY status').all();
 const expenses=db.prepare('SELECT status,COUNT(*) count,COALESCE(SUM(amount),0) amount FROM expense_claims GROUP BY status').all();
 const goals=db.prepare('SELECT status,COUNT(*) count,ROUND(AVG(progress),1) average_progress FROM employee_goals GROUP BY status').all();
 const attendance=db.prepare("SELECT status,COUNT(*) count FROM attendance WHERE attendance_date=date('now') GROUP BY status").all();
 res.json({employees,departments,hiring,leave,expenses,goals,attendance});
});
app.get('/api/people/workflows', requireAuth, requirePermission('operations:read'), (req,res)=>{
 const rules=db.prepare('SELECT * FROM workflow_rules ORDER BY id DESC').all();
 const executions=db.prepare(`SELECT x.*,w.name AS rule_name,e.name AS employee_name FROM workflow_executions x LEFT JOIN workflow_rules w ON w.id=x.rule_id LEFT JOIN employees e ON e.id=x.employee_id ORDER BY x.id DESC LIMIT 100`).all();
 const tasks=db.prepare(`SELECT t.*,e.name AS employee_name FROM hr_workflow_tasks t LEFT JOIN employees e ON e.id=t.employee_id ORDER BY t.id DESC LIMIT 100`).all();
 res.json({rules,executions,tasks});
});
app.post('/api/people/workflows', requireAuth, requirePermission('operations:write'), (req,res)=>{
 const b=req.body||{};
 const triggers=['New employee added','Leave request submitted','Expense claim submitted','Goal due date approaching'];
 const actions=['Create notification','Create HR task','Flag for review'];
 if(!text(b.name,120)||!triggers.includes(b.trigger_event)||!actions.includes(b.action_type))return res.status(400).json({error:'Choose a workflow name, supported trigger and action.'});
 const r=db.prepare('INSERT INTO workflow_rules(name,trigger_event,action_type,description,created_by) VALUES(?,?,?,?,?)').run(text(b.name,120),b.trigger_event,b.action_type,text(b.description,500),req.session.userId);
 audit(req,'CREATE','workflow_rule',r.lastInsertRowid,b.name);res.status(201).json({id:r.lastInsertRowid});
});
app.put('/api/people/workflows/:id', requireAuth, requirePermission('operations:write'), (req,res)=>{const enabled=req.body?.enabled?1:0;const r=db.prepare('UPDATE workflow_rules SET enabled=? WHERE id=?').run(enabled,Number(req.params.id));if(!r.changes)return res.status(404).json({error:'Workflow not found.'});audit(req,'UPDATE','workflow_rule',req.params.id,`Workflow enabled=${enabled}`);res.json({success:true});});
app.post('/api/people/workflows/run-due-check', requireAuth, requirePermission('operations:write'), (req,res)=>{const checked=runDueGoalWorkflows();audit(req,'RUN','workflow_scheduler',null,`Checked due goal workflows; ${checked} goal(s) matched.`);res.json({success:true,goalsChecked:checked});});
app.put('/api/people/workflow-tasks/:id', requireAuth, requirePermission('operations:write'), (req,res)=>{const status=req.body?.status;if(!['Open','In Progress','Completed'].includes(status))return res.status(400).json({error:'Choose a valid task status.'});const r=db.prepare('UPDATE hr_workflow_tasks SET status=? WHERE id=?').run(status,Number(req.params.id));if(!r.changes)return res.status(404).json({error:'Workflow task not found.'});audit(req,'UPDATE','workflow_task',req.params.id,`Task status ${status}`);res.json({success:true});});

// The assistant uses a small, role-filtered context. Gemini is optional; without an API key,
// a deterministic database-aware assistant remains available locally.
app.post('/api/people/assistant', requireAuth, async (req,res)=>{
 const question=text(req.body?.question,700);if(!question)return res.status(400).json({error:'Enter a question.'});
 const employee=linkedEmployee(req);const manager=peopleManager(req);
 const context={role:req.session.role,availableTopics:['leave requests','expense claims','goals','recruitment pipeline','attendance','company policies','workforce summary']};
 if(manager){
   context.workforce={employees:db.prepare("SELECT COUNT(*) total,SUM(CASE WHEN status='Active' THEN 1 ELSE 0 END) active FROM employees").get(),departments:db.prepare('SELECT department,COUNT(*) employees FROM employees GROUP BY department ORDER BY employees DESC').all(),pendingLeave:db.prepare("SELECT COUNT(*) count FROM leave_requests WHERE status='Pending'").get().count,pendingExpenses:db.prepare("SELECT COUNT(*) count,COALESCE(SUM(amount),0) amount FROM expense_claims WHERE status IN ('Submitted','Under Review')").get(),recruitment:db.prepare('SELECT stage,COUNT(*) count FROM job_applications GROUP BY stage').all(),openWorkflowTasks:db.prepare("SELECT COUNT(*) count FROM hr_workflow_tasks WHERE status<>'Completed'").get().count};
 } else if(employee){
   context.employee={name:employee.name,department:employee.department,jobTitle:employee.job_title,goals:db.prepare('SELECT title,progress,status,target_date FROM employee_goals WHERE employee_id=? ORDER BY id DESC LIMIT 10').all(employee.id),leaveRequests:db.prepare('SELECT leave_type,start_date,end_date,status FROM leave_requests WHERE employee_id=? ORDER BY id DESC LIMIT 10').all(employee.id),expenseClaims:db.prepare('SELECT category,amount,expense_date,status FROM expense_claims WHERE employee_id=? ORDER BY id DESC LIMIT 10').all(employee.id),unreadNotifications:db.prepare('SELECT COUNT(*) count FROM employee_notifications WHERE employee_id=? AND is_read=0').get(employee.id).count};
 }
 let answer='';let mode='built-in';
 if(process.env.GEMINI_API_KEY){
   try{
     const model=text(process.env.GEMINI_MODEL,80)||'gemini-2.5-flash';
     const response=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(process.env.GEMINI_API_KEY)}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({systemInstruction:{parts:[{text:'You are EmployeeHub HR Assistant. Answer using only the supplied role-filtered EmployeeHub context and general navigation guidance. Never invent HR policy, salary, leave balance, or records. If context is insufficient, say so and direct the user to HR. Do not approve requests or claim to perform actions. Keep answers clear and concise.'}]},contents:[{role:'user',parts:[{text:`Question: ${question}

Authorized context: ${JSON.stringify(context)}`}]}],generationConfig:{temperature:0.2,maxOutputTokens:500}})});
     const payload=await response.json();if(!response.ok)throw new Error(payload?.error?.message||'Gemini request failed');
     answer=payload?.candidates?.[0]?.content?.parts?.map(p=>p.text||'').join('').trim()||'';if(!answer)throw new Error('Gemini returned an empty answer');mode='Gemini AI';
   }catch(error){console.error('Gemini assistant fallback:',error.message);}
 }
 if(!answer){
   const q=question.toLowerCase();
   if(/headcount|how many employees|employee count|staff/.test(q)&&manager){const w=context.workforce;answer=`EmployeeHub has ${w.employees.total||0} employee profile(s), of which ${w.employees.active||0} are active. There are ${w.departments.length} department(s).`;}
   else if(/pending leave|leave approval/.test(q)&&manager)answer=`There are ${context.workforce.pendingLeave} leave request(s) awaiting review. Open HR Workspace → Leave Management to review them.`;
   else if(/expense|reimburse/.test(q)&&manager)answer=`There are ${context.workforce.pendingExpenses.count} expense claim(s) awaiting review, totalling ₹${Number(context.workforce.pendingExpenses.amount||0).toFixed(2)}. Open Enterprise HRMS → Expenses to review them.`;
   else if(/goal|performance/.test(q)&&employee)answer=`You have ${context.employee.goals.length} goal record(s). ${context.employee.goals.filter(g=>g.status==='Completed').length} are marked completed. Open People & AI Workspace → Goals & Development to review progress.`;
   else if(/leave|vacation/.test(q)&&employee)answer=`You have ${context.employee.leaveRequests.length} recent leave request(s). Open Employee Self-Service to submit a new request and check its status. Your current records do not include a calculated leave balance.`;
   else if(/expense|reimburse/.test(q)&&employee)answer=`You have ${context.employee.expenseClaims.length} recent expense claim(s). Submit a claim in Employee Self-Service and follow its status there.`;
   else if(/workflow|automation/.test(q)&&manager)answer=`There are ${context.workforce.openWorkflowTasks} open workflow task(s). Open People & AI Workspace → Workflow Automation to review rules, executions and tasks.`;
   else if(/recruit|candidate|applicant|hiring/.test(q)&&manager)answer=`Current recruitment pipeline: ${context.workforce.recruitment.map(x=>`${x.stage}: ${x.count}`).join(', ')||'No candidate applications recorded'}. Open Enterprise HRMS → Recruitment for details.`;
   else if(/attendance/.test(q))answer='Attendance records are maintained in HR Workspace. If a record needs correction, contact an HR Manager.';
   else if(/policy|handbook/.test(q))answer='Open Enterprise HRMS → Policies to review published company policies. If the policy you need is not available, contact HR.';
   else answer='I can help with EmployeeHub leave, expenses, goals, recruitment, attendance, policies and workflow navigation. Ask a specific question about one of these areas.';
 }
 res.json({answer,mode,disclaimer:mode==='Gemini AI'?'AI-generated guidance uses only data your account is authorized to access. Verify important HR decisions with HR; this assistant cannot approve requests.':'Built-in assistant using your role-authorized EmployeeHub records. Add GEMINI_API_KEY to enable Gemini AI responses.'});
});

// Scheduled goal-due workflow scan: run on startup and every six hours.
setTimeout(()=>{try{runDueGoalWorkflows();}catch(e){console.error('Scheduled workflow scan failed:',e.message);}},15000).unref();
setInterval(()=>{try{runDueGoalWorkflows();}catch(e){console.error('Scheduled workflow scan failed:',e.message);}},6*60*60*1000).unref();


// Error handling
app.use((err, req, res, next) => {
  console.error('Request error:', err.message);

  res.status(500).json({
    error: 'An unexpected server error occurred.'
  });
});

// Unknown routes
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found.'
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`EmployeeHub is running on port ${PORT}`);
});
