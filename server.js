const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
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
  name: 'employee.sid', secret: SESSION_SECRET, store: sessionStore,
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: production, maxAge: 30 * 60 * 1000 }
}));

// Small per-process rate limiter keeps repeated login attempts in check for this local app.
// For a multi-instance public deployment, use a shared Redis/database-backed limiter.
function makeRateLimiter(windowMs, limit, message) {
  const buckets = new Map();
  const timer = setInterval(() => { const now = Date.now(); for (const [key, bucket] of buckets) if (bucket.until <= now) buckets.delete(key); }, windowMs);
  timer.unref();
  return (req, res, next) => {
    const key = String(req.ip || req.socket.remoteAddress || 'unknown');
    const now = Date.now(); let bucket = buckets.get(key);
    if (!bucket || bucket.until <= now) { bucket = { count: 0, until: now + windowMs }; buckets.set(key, bucket); }
    bucket.count += 1;
    res.setHeader('RateLimit-Limit', String(limit));
    res.setHeader('RateLimit-Remaining', String(Math.max(0, limit - bucket.count)));
    if (bucket.count > limit) { res.setHeader('Retry-After', String(Math.ceil((bucket.until - now) / 1000))); return res.status(429).json({ error: message }); }
    next();
  };
}
const loginLimiter = makeRateLimiter(15 * 60 * 1000, 10, 'Too many login attempts. Please wait 15 minutes and try again.');
const leaveLimiter = makeRateLimiter(60 * 1000, 30, 'Too many requests. Please wait a moment and try again.');
const roles = { admin: ['*'], hr: ['employees:read','employees:write','attendance:read','attendance:write','leave:read','leave:write','reports:read','audit:read'], viewer: ['employees:read','attendance:read','leave:read','reports:read'] };

function audit(req, action, entityType, entityId = null, details = '') {
  try {
    db.prepare(`INSERT INTO audit_logs (user_id,username,action,entity_type,entity_id,details,ip_address)
      VALUES (?,?,?,?,?,?,?)`).run(req.session?.userId || null, req.session?.username || 'system', action, entityType, entityId == null ? null : String(entityId), String(details).slice(0,1000), String(req.ip || '').slice(0,80));
  } catch (err) { console.error('Audit log write failed:', err.message); }
}
function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Please log in first.' });
  const account = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(req.session.userId);
  if (!account) { return req.session.destroy(() => res.status(401).json({ error: 'Account is no longer available. Please sign in again.' })); }
  // Refresh role on every protected request so permission changes take effect immediately.
  req.session.username = account.username;
  req.session.role = account.role;
  next();
}
function requirePermission(permission) {
  return (req, res, next) => {
    const allowed = roles[req.session?.role] || [];
    if (!allowed.includes('*') && !allowed.includes(permission)) return res.status(403).json({ error: 'Your account does not have permission for this action.' });
    next();
  };
}
function csrfProtection(req, res, next) {
  if (['GET','HEAD','OPTIONS'].includes(req.method) || req.path === '/api/auth/login') return next();
  const sent = req.get('x-csrf-token');
  if (!sent || !req.session?.csrfToken || sent.length !== req.session.csrfToken.length || !crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(req.session.csrfToken))) {
    return res.status(403).json({ error: 'Security token missing or expired. Refresh the page and try again.' });
  }
  next();
}
function validDate(s) { return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s)); }
function text(s, max = 200) { return typeof s === 'string' ? s.trim().slice(0,max) : ''; }

app.get('/login', (req,res) => res.sendFile(path.join(__dirname,'login.html')));
app.get('/', (req,res) => req.session.userId ? res.sendFile(path.join(__dirname,'index.html')) : res.redirect('/login'));
app.get('/hr', requireAuth, (req,res) => res.sendFile(path.join(__dirname,'hr.html')));
app.get('/api/auth/me', (req,res) => req.session.userId ? res.json({authenticated:true,username:req.session.username,role:req.session.role}) : res.status(401).json({authenticated:false}));
app.get('/api/auth/csrf', requireAuth, (req,res) => { if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex'); res.json({ csrfToken: req.session.csrfToken }); });
app.post('/api/auth/login', loginLimiter, async (req,res) => {
  try {
    const username = text(req.body?.username,80); const password = req.body?.password;
    if (!username || typeof password !== 'string' || password.length > 200) return res.status(400).json({error:'Enter a valid username and password.'});
    const user = db.prepare('SELECT id,username,password_hash,role FROM users WHERE username=?').get(username);
    const valid = user ? await bcrypt.compare(password,user.password_hash) : false;
    if (!valid) { audit(req,'LOGIN_FAILED','user',username,'Invalid login attempt'); return res.status(401).json({error:'Invalid username or password.'}); }
    req.session.regenerate(err => {
      if (err) return res.status(500).json({error:'Could not start login session.'});
      req.session.userId=user.id; req.session.username=user.username; req.session.role=user.role; req.session.csrfToken=crypto.randomBytes(32).toString('hex');
      req.session.save(saveErr => {
        if (saveErr) return res.status(500).json({error:'Could not save login session.'});
        audit(req,'LOGIN_SUCCESS','user',user.id,'Signed in'); res.json({success:true});
      });
    });
  } catch(e) { console.error('Login error:',e.message); res.status(500).json({error:'Login failed. Please try again.'}); }
});
app.post('/api/auth/logout', requireAuth, csrfProtection, (req,res) => {
  audit(req,'LOGOUT','user',req.session.userId,'Signed out');
  req.session.destroy(err => { if(err) return res.status(500).json({error:'Could not log out.'}); res.clearCookie('employee.sid',{httpOnly:true,sameSite:'lax',secure:production}); res.json({success:true}); });
});
app.post('/api/auth/change-password', requireAuth, csrfProtection, async (req,res) => {
  const current = req.body?.currentPassword; const next = req.body?.newPassword;
  if(typeof current!=='string'||typeof next!=='string'||next.length<12||next.length>200) return res.status(400).json({error:'New password must be at least 12 characters.'});
  const user=db.prepare('SELECT password_hash FROM users WHERE id=?').get(req.session.userId);
  if(!user || !(await bcrypt.compare(current,user.password_hash))) return res.status(400).json({error:'Current password is incorrect.'});
  db.prepare('UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(await bcrypt.hash(next,12),req.session.userId);
  audit(req,'PASSWORD_CHANGED','user',req.session.userId,'Password changed');
  req.session.destroy(err=>err?res.status(500).json({error:'Password changed, but sign-out failed. Please sign in again.'}):res.json({success:true, message:'Password changed. Please sign in again.'}));
});
app.use('/api', csrfProtection);
app.use('/api', requireAuth);

// Employee directory
app.get('/api/employees', requirePermission('employees:read'), (req,res) => res.json(db.prepare('SELECT * FROM employees ORDER BY id DESC').all()));
app.post('/api/employees', requirePermission('employees:write'), (req,res) => {
  const name=text(req.body?.name,120), email=text(req.body?.email,180), department=text(req.body?.department,100);
  if(!name||!email||!department||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'Enter a name, valid email, and department.'});
  const result=db.prepare(`INSERT INTO employees(name,email,department,phone,job_title,joining_date,status) VALUES(?,?,?,?,?,?,?)`).run(name,email,department,text(req.body?.phone,40),text(req.body?.job_title,100),validDate(req.body?.joining_date)?req.body.joining_date:'', ['Active','Inactive'].includes(req.body?.status)?req.body.status:'Active');
  audit(req,'CREATE','employee',result.lastInsertRowid,`Created employee ${name}`); res.status(201).json(db.prepare('SELECT * FROM employees WHERE id=?').get(result.lastInsertRowid));
});
app.put('/api/employees/:id', requirePermission('employees:write'), (req,res) => {
  const id=Number(req.params.id), old=db.prepare('SELECT * FROM employees WHERE id=?').get(id);
  const name=text(req.body?.name,120), email=text(req.body?.email,180), department=text(req.body?.department,100);
  if(!Number.isInteger(id)||!old) return res.status(404).json({error:'Employee not found.'});
  if(!name||!department||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'Enter a name, valid email, and department.'});
  // Keep profile fields intact when the older dashboard sends only name/email/department.
  const phone = req.body?.phone === undefined ? old.phone : text(req.body.phone,40);
  const jobTitle = req.body?.job_title === undefined ? old.job_title : text(req.body.job_title,100);
  const joiningDate = req.body?.joining_date === undefined ? old.joining_date : (validDate(req.body.joining_date) ? req.body.joining_date : '');
  const status = req.body?.status === undefined ? old.status : (['Active','Inactive'].includes(req.body.status) ? req.body.status : old.status);
  db.prepare(`UPDATE employees SET name=?,email=?,department=?,phone=?,job_title=?,joining_date=?,status=? WHERE id=?`).run(name,email,department,phone,jobTitle,joiningDate,status,id);
  audit(req,'UPDATE','employee',id,`Updated employee ${name}`); res.json(db.prepare('SELECT * FROM employees WHERE id=?').get(id));
});
app.delete('/api/employees/:id', requirePermission('employees:write'), (req,res) => {
  if(req.session.role!=='admin') return res.status(403).json({error:'Only an administrator can delete employee records.'});
  const id=Number(req.params.id), emp=db.prepare('SELECT name FROM employees WHERE id=?').get(id); if(!emp) return res.status(404).json({error:'Employee not found.'});
  db.prepare('DELETE FROM employees WHERE id=?').run(id); audit(req,'DELETE','employee',id,`Deleted employee ${emp.name}`); res.json({success:true});
});

// User administration: only admins can create, assign, or disable accounts.
app.get('/api/users', requirePermission('users:manage'), (req,res)=>res.json(db.prepare('SELECT id,username,role,created_at FROM users ORDER BY id').all()));
app.post('/api/users', requirePermission('users:manage'), async (req,res)=>{
  const username=text(req.body?.username,80), password=req.body?.password, role=req.body?.role;
  if(!/^[a-zA-Z0-9._-]{3,80}$/.test(username)||typeof password!=='string'||password.length<12||!['admin','hr','viewer'].includes(role)) return res.status(400).json({error:'Use a 3+ character username, password of at least 12 characters, and valid role.'});
  try { const r=db.prepare('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)').run(username,await bcrypt.hash(password,12),role); audit(req,'CREATE','user',r.lastInsertRowid,`Created ${role} account ${username}`); res.status(201).json({id:r.lastInsertRowid,username,role}); } catch(e){ if(e.code==='SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({error:'That username already exists.'}); throw e; }
});
app.put('/api/users/:id/role', requirePermission('users:manage'), (req,res)=>{
  const id=Number(req.params.id), role=req.body?.role; if(!['admin','hr','viewer'].includes(role)) return res.status(400).json({error:'Choose admin, hr, or viewer.'});
  if(id===req.session.userId && role!=='admin') return res.status(400).json({error:'You cannot remove your own administrator role.'});
  const result=db.prepare('UPDATE users SET role=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(role,id); if(!result.changes) return res.status(404).json({error:'User not found.'}); audit(req,'UPDATE','user',id,`Role changed to ${role}`); res.json({success:true});
});

// Attendance
app.get('/api/attendance', requirePermission('attendance:read'), (req,res)=>{
  const date=validDate(req.query.date)?req.query.date:null;
  const rows=date?db.prepare(`SELECT a.*,e.name AS employee_name,e.department FROM attendance a JOIN employees e ON e.id=a.employee_id WHERE attendance_date=? ORDER BY e.name`).all(date):db.prepare(`SELECT a.*,e.name AS employee_name,e.department FROM attendance a JOIN employees e ON e.id=a.employee_id ORDER BY attendance_date DESC,e.name LIMIT 500`).all(); res.json(rows);
});
app.post('/api/attendance', requirePermission('attendance:write'), (req,res)=>{
  const employeeId=Number(req.body?.employee_id), date=req.body?.attendance_date, status=req.body?.status, notes=text(req.body?.notes,500);
  if(!Number.isInteger(employeeId)||!validDate(date)||!['Present','Absent','Leave','Half Day','Work From Home'].includes(status)) return res.status(400).json({error:'Select an employee, valid date, and attendance status.'});
  if(!db.prepare('SELECT id FROM employees WHERE id=?').get(employeeId)) return res.status(404).json({error:'Employee not found.'});
  db.prepare(`INSERT INTO attendance(employee_id,attendance_date,status,notes,created_by) VALUES(?,?,?,?,?) ON CONFLICT(employee_id,attendance_date) DO UPDATE SET status=excluded.status,notes=excluded.notes,created_by=excluded.created_by`).run(employeeId,date,status,notes,req.session.userId);
  const row=db.prepare('SELECT * FROM attendance WHERE employee_id=? AND attendance_date=?').get(employeeId,date); audit(req,'UPSERT','attendance',row.id,`${status} for employee ${employeeId} on ${date}`); res.json(row);
});

// Leave requests and approvals
app.get('/api/leaves', requirePermission('leave:read'), (req,res)=>res.json(db.prepare(`SELECT l.*,e.name AS employee_name,e.department,u.username AS reviewer FROM leave_requests l JOIN employees e ON e.id=l.employee_id LEFT JOIN users u ON u.id=l.reviewed_by ORDER BY l.created_at DESC LIMIT 500`).all()));
app.post('/api/leaves', requirePermission('leave:write'), leaveLimiter, (req,res)=>{
  const employeeId=Number(req.body?.employee_id), type=text(req.body?.leave_type,60), start=req.body?.start_date, end=req.body?.end_date, reason=text(req.body?.reason,1000);
  const daySpan = validDate(start) && validDate(end) ? (Date.parse(end+'T00:00:00Z')-Date.parse(start+'T00:00:00Z'))/86400000 : Infinity;
  if(!Number.isInteger(employeeId)||!['Annual','Sick','Personal','Unpaid','Other'].includes(type)||!validDate(start)||!validDate(end)||start>end||daySpan>90||!reason) return res.status(400).json({error:'Complete all leave fields with valid dates.'});
  if(!db.prepare('SELECT id FROM employees WHERE id=?').get(employeeId)) return res.status(404).json({error:'Employee not found.'});
  const r=db.prepare(`INSERT INTO leave_requests(employee_id,leave_type,start_date,end_date,reason,requested_by) VALUES(?,?,?,?,?,?)`).run(employeeId,type,start,end,reason,req.session.userId); audit(req,'CREATE','leave',r.lastInsertRowid,`Leave requested for employee ${employeeId}`); res.status(201).json({id:r.lastInsertRowid,status:'Pending'});
});
app.put('/api/leaves/:id/review', requirePermission('leave:write'), (req,res)=>{
  const id=Number(req.params.id), status=req.body?.status; if(!['Approved','Rejected'].includes(status)) return res.status(400).json({error:'Choose Approved or Rejected.'});
  const old=db.prepare('SELECT * FROM leave_requests WHERE id=?').get(id); if(!old) return res.status(404).json({error:'Leave request not found.'}); if(old.status!=='Pending') return res.status(409).json({error:'This request has already been reviewed.'});
  db.prepare('UPDATE leave_requests SET status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?').run(status,req.session.userId,id);
  if(status==='Approved') { const d0=new Date(old.start_date+'T00:00:00Z'), d1=new Date(old.end_date+'T00:00:00Z'); const ins=db.prepare(`INSERT INTO attendance(employee_id,attendance_date,status,notes,created_by) VALUES(?,?,'Leave','Approved leave',?) ON CONFLICT(employee_id,attendance_date) DO UPDATE SET status='Leave',notes='Approved leave',created_by=excluded.created_by`); const tx=db.transaction(()=>{for(let d=new Date(d0);d<=d1;d.setUTCDate(d.getUTCDate()+1)) ins.run(old.employee_id,d.toISOString().slice(0,10),req.session.userId);}); tx(); }
  audit(req,'REVIEW','leave',id,`Leave ${status}`); res.json({success:true,status});
});

// Reports
app.get('/api/reports/summary', requirePermission('reports:read'), (req,res)=>{
  const employees=db.prepare(`SELECT COUNT(*) AS total, SUM(CASE WHEN status='Active' THEN 1 ELSE 0 END) AS active FROM employees`).get();
  const departments=db.prepare(`SELECT department,COUNT(*) AS count FROM employees GROUP BY department ORDER BY count DESC,department`).all();
  const attendance=db.prepare(`SELECT status,COUNT(*) AS count FROM attendance WHERE attendance_date=? GROUP BY status`).all(validDate(req.query.date)?req.query.date:new Date().toISOString().slice(0,10));
  const leaves=db.prepare(`SELECT status,COUNT(*) AS count FROM leave_requests GROUP BY status`).all(); res.json({employees,departments,attendance,leaves});
});
app.get('/api/reports/employees.csv', requirePermission('reports:read'), (req,res)=>{
  const rows=db.prepare('SELECT id,name,email,department,phone,job_title,joining_date,status FROM employees ORDER BY id').all(); const keys=['id','name','email','department','phone','job_title','joining_date','status'];
  const cell=v=>{ let value=String(v??''); if(/^[=+@\-\t\r]/.test(value)) value="'"+value; return '"'+value.replace(/"/g,'""')+'"'; }; const csv=[keys,...rows.map(r=>keys.map(k=>r[k]))].map(r=>r.map(cell).join(',')).join('\r\n'); audit(req,'EXPORT','report',null,'Employee CSV exported'); res.type('text/csv').attachment('employee-report.csv').send('\uFEFF'+csv);
});
app.get('/api/audit', requirePermission('audit:read'), (req,res)=>res.json(db.prepare('SELECT id,username,action,entity_type,entity_id,details,ip_address,created_at FROM audit_logs ORDER BY id DESC LIMIT 300').all()));

app.use((err,req,res,next)=>{ console.error('Request error:',err.message); res.status(500).json({error:'An unexpected server error occurred.'}); });
app.use((req,res)=>res.status(404).json({error:'Endpoint not found.'}));
app.listen(PORT,'127.0.0.1',()=>console.log(`Employee Management System running at http://localhost:${PORT}`));
