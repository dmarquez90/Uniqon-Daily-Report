const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const { query, one } = require('./db');
const { buildReportsPdf } = require('./pdf');
const drive = require('./drive');
const mail = require('./mail');

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production' || !!process.env.VERCEL;
// A random fallback would sign everyone out on each cold start (and differ between serverless instances)
if (IS_PROD && (process.env.JWT_SECRET || '').length < 32) throw new Error('JWT_SECRET must be set (32+ characters) in production');
if (IS_PROD && !process.env.APP_URL) throw new Error('APP_URL must be set in production (used in password reset links)');
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
// Each new account gets its own random temporary password; the app forces a change on first sign-in
const tempPassword = () => crypto.randomBytes(9).toString('base64').replace(/[+/]/g, 'x');
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 10); // equalizes login timing for unknown users

// Master user (created once, from env vars)
let seeded;
function seedAdmin() {
  seeded ||= (async () => {
    const email = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
    const pass = process.env.ADMIN_PASSWORD || '';
    if (!email || !pass) return;
    if (await one('SELECT id FROM employees WHERE email = $1', [email])) return;
    await query(`INSERT INTO employees (emp_number, name, email, password_hash, role, must_change)
                 VALUES ($1,$2,$3,$4,'admin',TRUE) ON CONFLICT DO NOTHING`,
      ['1000', process.env.ADMIN_NAME || 'Administrator', email, bcrypt.hashSync(pass, 10)]);
    console.log('Master user created:', email, '(ID 1000)');
  })().catch(e => { seeded = null; throw e; });
  return seeded;
}

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});
// CSRF defense in depth (on top of SameSite=Lax): state-changing API calls must come from this site
app.use('/api', (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  const origin = req.get('origin');
  let host = null;
  try { host = origin && new URL(origin).host; } catch {}
  if (origin && host !== req.get('host')) return res.status(403).json({ error: 'Forbidden' });
  next();
});
app.use(express.json({ limit: '200kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', (req, res, next) => seedAdmin().then(() => next(), next));
const h = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------- Utilities ----------
const failures = new Map(); // login attempt limit (per instance)
const throttleKey = (req, id) => req.ip + '|' + id;
function isBlocked(key) {
  const f = failures.get(key);
  if (!f) return false;
  if (Date.now() - f.first > 15 * 60 * 1000) { failures.delete(key); return false; }
  return f.count >= 5;
}
function addFailure(key) {
  if (failures.size > 10000) for (const [k, v] of failures) if (Date.now() - v.first > 15 * 60 * 1000) failures.delete(k);
  const f = failures.get(key);
  if (!f || Date.now() - f.first > 15 * 60 * 1000) failures.set(key, { count: 1, first: Date.now() });
  else f.count++;
}
function clearFailures(emp) {
  for (const k of failures.keys()) {
    const id = k.slice(k.lastIndexOf('|') + 1);
    if (id === emp.emp_number || id === emp.email.toLowerCase()) failures.delete(k);
  }
}

const appUrl = req => (process.env.APP_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
// pv ties the session to the current password: changing or resetting it signs out every other session
const pwVersion = emp => sha(emp.password_hash).slice(0, 16);
const signSession = emp => jwt.sign({ id: emp.id, pv: pwVersion(emp) }, JWT_SECRET, { expiresIn: '12h', algorithm: 'HS256' });
const cookieOpts = req => ({ httpOnly: true, sameSite: 'lax', secure: req.secure });
const setCookie = (req, res, token) => res.cookie('session', token, { ...cookieOpts(req), maxAge: 12 * 3600 * 1000 });
const publicEmp = e => ({ id: e.id, emp_number: e.emp_number, name: e.name, email: e.email, title: e.title || '', role: e.role, must_change: !!e.must_change, active: !!e.active });

const auth = h(async (req, res, next) => {
  let data;
  try { data = jwt.verify(req.cookies.session, JWT_SECRET, { algorithms: ['HS256'] }); } catch { return res.status(401).json({ error: 'Invalid session' }); }
  const emp = await one('SELECT * FROM employees WHERE id = $1', [data.id]);
  if (!emp || !emp.active || emp.deleted_at || data.pv !== pwVersion(emp)) return res.status(401).json({ error: 'Invalid session' });
  req.emp = emp;
  next();
});
function notForced(req, res, next) {
  if (req.emp.must_change) return res.status(403).json({ error: 'You must change your password first' });
  next();
}
function adminOnly(req, res, next) {
  if (req.emp.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}
async function nextEmpNumber() {
  const row = await one("SELECT MAX(CAST(emp_number AS INTEGER)) AS m FROM employees");
  return String(Math.max(1000, Number(row.m) || 1000) + 1);
}

// ---------- Authentication ----------
app.post('/api/login', h(async (req, res) => {
  const identifier = String(req.body.identifier || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!identifier || !password) return res.status(400).json({ error: 'Enter your ID or email and password' });
  const key = throttleKey(req, identifier);
  if (isBlocked(key)) return res.status(429).json({ error: 'Too many attempts. Wait 15 minutes.' });
  const emp = await one('SELECT * FROM employees WHERE lower(email) = $1 OR emp_number = $1', [identifier]);
  const ok = bcrypt.compareSync(password, emp ? emp.password_hash : DUMMY_HASH);
  if (!emp || !emp.active || !ok) {
    addFailure(key);
    return res.status(401).json({ error: 'Incorrect ID, email or password' });
  }
  failures.delete(key);
  setCookie(req, res, signSession(emp));
  res.json(publicEmp(emp));
}));

app.post('/api/logout', (req, res) => { res.clearCookie('session', cookieOpts(req)); res.json({ ok: true }); });

app.get('/api/me', auth, (req, res) => res.json(publicEmp(req.emp)));

app.post('/api/change-password', auth, h(async (req, res) => {
  const current = String(req.body.current || '');
  const next = String(req.body.next || '');
  const key = throttleKey(req, 'change:' + req.emp.id);
  if (isBlocked(key)) return res.status(429).json({ error: 'Too many attempts. Wait 15 minutes.' });
  if (!bcrypt.compareSync(current, req.emp.password_hash)) { addFailure(key); return res.status(400).json({ error: 'Current password is incorrect' }); }
  if (next.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  if (next.length > 72) return res.status(400).json({ error: 'Password is too long' }); // bcrypt ignores bytes past 72
  if (next === current) return res.status(400).json({ error: 'New password must be different from the current one' });
  const emp = await one('UPDATE employees SET password_hash = $1, must_change = FALSE WHERE id = $2 RETURNING *', [bcrypt.hashSync(next, 10), req.emp.id]);
  setCookie(req, res, signSession(emp)); // keep this session; all others are signed out
  res.json({ ok: true });
}));

// Forgot password: emails a one-time link (valid 1 hour). Same answer whether or not the email exists.
async function sendResetEmail(req, emp) {
  const token = crypto.randomBytes(32).toString('hex');
  await query('INSERT INTO password_resets (token_hash, employee_id, expires_at) VALUES ($1,$2, now() + interval \'1 hour\')', [sha(token), emp.id]);
  const base = appUrl(req);
  await mail.sendReset({ to: emp.email, name: emp.name, link: `${base}/#reset=${token}`, appUrl: base });
}

app.post('/api/forgot', h(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const key = throttleKey(req, 'forgot:' + email);
  if (isBlocked(key)) return res.status(429).json({ error: 'Too many attempts. Wait 15 minutes.' });
  addFailure(key);
  const emp = email && await one('SELECT * FROM employees WHERE lower(email) = $1 AND active', [email]);
  if (emp) {
    try { await sendResetEmail(req, emp); } catch (e) { console.error('Reset email failed:', e.message); }
  }
  res.json({ ok: true });
}));

app.post('/api/reset', h(async (req, res) => {
  const token = String(req.body.token || '');
  const next = String(req.body.password || '');
  if (next.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  if (next.length > 72) return res.status(400).json({ error: 'Password is too long' });
  // Atomic claim, so the same link cannot be used twice by concurrent requests
  const row = await one('UPDATE password_resets SET used = TRUE WHERE token_hash = $1 AND NOT used AND expires_at > now() RETURNING employee_id', [sha(token)]);
  if (!row) return res.status(400).json({ error: 'This reset link is invalid or has expired' });
  await query('UPDATE password_resets SET used = TRUE WHERE employee_id = $1', [row.employee_id]);
  const emp = await one('UPDATE employees SET password_hash = $1, must_change = FALSE WHERE id = $2 RETURNING *', [bcrypt.hashSync(next, 10), row.employee_id]);
  clearFailures(emp);
  res.json({ ok: true });
}));

// ---------- Daily report ----------
const REPORT_NUM = ['walk_ins', 'calls', 'quotations', 'orders', 'total_sales', 'payments_received', 'daily_expenses'];
const REPORT_TEXT = ['opening', 'closing', 'payment_methods', 'completed_work', 'pending_followups', 'issues', 'prepared_by', 'signature'];
const isDate = d => /^\d{4}-\d{2}-\d{2}$/.test(d);

function cleanReport(body) {
  const out = {};
  for (const k of REPORT_NUM) {
    const v = body[k];
    out[k] = v === '' || v == null ? null : Number(v);
    if (out[k] != null && (!Number.isFinite(out[k]) || out[k] < 0)) throw new Error('Invalid number in ' + k.replace(/_/g, ' '));
  }
  for (const k of REPORT_TEXT) out[k] = String(body[k] ?? '').slice(0, 5000);
  return out;
}

// Locations: each employee keeps their own saved list; the admin can also pick any location already created
const LOC_TYPES = ['Show Run', 'Project', 'Office', 'Other'];
const myLocations = empId => query(`
  SELECT l.id, l.name, l.type, l.city, l.address FROM locations l
  JOIN employee_locations el ON el.location_id = l.id
  WHERE el.employee_id = $1 ORDER BY l.name`, [empId]);
// Locations in someone else's list (or nobody's) that are not in this person's list, with who created them
const otherLocations = empId => query(`
  SELECT l.id, l.name, l.type, l.city, l.address, coalesce(e.name, '') AS created_by_name FROM locations l
  LEFT JOIN employees e ON e.id = l.created_by
  WHERE NOT EXISTS (SELECT 1 FROM employee_locations el WHERE el.location_id = l.id AND el.employee_id = $1)
  ORDER BY l.name`, [empId]);
const locLabel = l => [l.name, l.address, l.city].filter(Boolean).join(' — ');
const normName = s => s.toLowerCase().replace(/\s+/g, ' ').trim();

app.get('/api/my/locations', auth, notForced, h(async (req, res) => res.json(await myLocations(req.emp.id))));

app.get('/api/admin/locations', auth, notForced, adminOnly, h(async (req, res) => res.json(await otherLocations(req.emp.id))));

app.post('/api/my/locations', auth, notForced, h(async (req, res) => {
  const name = String(req.body.name || '').trim().replace(/\s+/g, ' ').slice(0, 200);
  const type = LOC_TYPES.includes(req.body.type) ? req.body.type : 'Other';
  const city = String(req.body.city || '').trim().slice(0, 200);
  const address = String(req.body.address || '').trim().slice(0, 300);
  if (!name) return res.status(400).json({ error: 'Enter the location name' });
  // One place, one record: a name that already exists (ignoring case and spaces) reuses that location
  const existing = await one(`SELECT id, name, type, city, address FROM locations
    WHERE lower(regexp_replace(trim(name), '\\s+', ' ', 'g')) = $1 ORDER BY id LIMIT 1`, [normName(name)]);
  const loc = existing || await one('INSERT INTO locations (name, type, city, address, created_by) VALUES ($1,$2,$3,$4,$5) RETURNING id, name, type, city, address',
    [name, type, city, address, req.emp.id]);
  await query('INSERT INTO employee_locations (employee_id, location_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.emp.id, loc.id]);
  res.json({ ...loc, existing: !!existing });
}));

app.post('/api/my/locations/:id/remove', auth, notForced, h(async (req, res) => {
  await query('DELETE FROM employee_locations WHERE employee_id = $1 AND location_id = $2', [req.emp.id, Number(req.params.id) || 0]);
  res.json({ ok: true });
}));

const reportRow = r => ({ id: r.id, date: r.report_date, updated_at: r.updated_at, emp_number: r.emp_number, name: r.name, title: r.title, drive_file_id: r.drive_file_id, ...r.data, photo_ids: r.photo_ids || [] });

// ---------- Report photos (compressed to JPEG in the browser, stored in Postgres) ----------
const MAX_PHOTOS = 10;
const photoIdsSql = `(SELECT coalesce(array_agg(p.id ORDER BY p.id), '{}') FROM report_photos p WHERE p.report_id = r.id) AS photo_ids`;

app.post('/api/my/photos', auth, notForced, express.raw({ type: ['image/jpeg', 'image/png'], limit: '3mb' }), h(async (req, res) => {
  if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'Invalid image' });
  // Trust the file bytes, not the Content-Type header
  const b = req.body;
  const mime = b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF ? 'image/jpeg'
    : b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])) ? 'image/png' : null;
  if (!mime) return res.status(400).json({ error: 'Invalid image' });
  // Clean up photos that were uploaded but never attached to a report
  await query("DELETE FROM report_photos WHERE employee_id = $1 AND report_id IS NULL AND created_at < now() - interval '2 days'", [req.emp.id]);
  const pending = await one('SELECT count(*)::int AS n FROM report_photos WHERE employee_id = $1 AND report_id IS NULL', [req.emp.id]);
  if (pending.n >= MAX_PHOTOS * 3) return res.status(429).json({ error: 'Too many photos waiting to be attached. Submit the report first.' });
  const { id } = await one('INSERT INTO report_photos (employee_id, mime, data) VALUES ($1,$2,$3) RETURNING id', [req.emp.id, mime, req.body]);
  res.json({ id });
}));

app.get('/api/photos/:id', auth, notForced, h(async (req, res) => {
  const p = await one('SELECT employee_id, mime, data FROM report_photos WHERE id = $1', [Number(req.params.id) || 0]);
  if (!p || (p.employee_id !== req.emp.id && req.emp.role !== 'admin')) return res.status(404).json({ error: 'Not found' });
  res.setHeader('Content-Type', p.mime);
  res.setHeader('Cache-Control', 'private, max-age=86400');
  res.send(Buffer.from(p.data));
}));

// Loads image bytes for the PDF
async function withPhotos(reports) {
  const ids = reports.flatMap(r => r.photo_ids || []);
  if (!ids.length) return reports;
  const rows = await query('SELECT id, data FROM report_photos WHERE id = ANY($1::int[])', [ids]);
  const map = new Map(rows.map(p => [p.id, Buffer.from(p.data)]));
  return reports.map(r => ({ ...r, photos: (r.photo_ids || []).map(id => map.get(id)).filter(Boolean) }));
}

app.get('/api/my/report', auth, notForced, h(async (req, res) => {
  const date = String(req.query.date || '');
  if (!isDate(date)) return res.status(400).json({ error: 'Invalid date' });
  const row = await one(`SELECT r.*, ${photoIdsSql} FROM daily_reports r WHERE r.employee_id = $1 AND r.report_date = $2`, [req.emp.id, date]);
  res.json(row ? { date, updated_at: row.updated_at, ...row.data, photo_ids: row.photo_ids } : null);
}));

app.post('/api/my/report', auth, notForced, h(async (req, res) => {
  const date = String(req.body.date || '');
  if (!isDate(date)) return res.status(400).json({ error: 'Invalid date' });
  let data;
  try { data = cleanReport(req.body); } catch (e) { return res.status(400).json({ error: e.message }); }
  // Location snapshot, so old reports keep the place even if it is later removed from the list
  const locId = Number(req.body.location_id);
  let loc = (await myLocations(req.emp.id)).find(l => l.id === locId);
  if (!loc && req.emp.role === 'admin') {
    // Admin visiting a place another employee created: use it and keep it in the admin's list
    loc = await one('SELECT id, name, type, city, address FROM locations WHERE id = $1', [locId || 0]);
    if (loc) await query('INSERT INTO employee_locations (employee_id, location_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.emp.id, loc.id]);
  }
  if (!loc) return res.status(400).json({ error: 'Select the location where you are working' });
  if (loc.type === 'Project') { REPORT_NUM.forEach(k => data[k] = null); data.payment_methods = ''; } // parts 1 and 2 do not apply
  Object.assign(data, { location_id: loc.id, location_name: loc.name, location_type: loc.type, location: locLabel(loc), title: req.emp.title || '' });
  const photoIds = [...new Set((Array.isArray(req.body.photo_ids) ? req.body.photo_ids : []).map(Number).filter(Number.isInteger))].slice(0, MAX_PHOTOS);
  const row = await one(`INSERT INTO daily_reports (employee_id, report_date, data) VALUES ($1,$2,$3)
      ON CONFLICT (employee_id, report_date) DO UPDATE SET data = excluded.data, updated_at = now()
      RETURNING *`, [req.emp.id, date, data]);
  // Attach the selected photos (only the employee's own) and drop the ones that were removed
  await query('UPDATE report_photos SET report_id = $1 WHERE employee_id = $2 AND id = ANY($3::int[]) AND (report_id IS NULL OR report_id = $1)', [row.id, req.emp.id, photoIds]);
  await query('DELETE FROM report_photos WHERE report_id = $1 AND NOT (id = ANY($2::int[]))', [row.id, photoIds]);
  row.photo_ids = (await query('SELECT id FROM report_photos WHERE report_id = $1 ORDER BY id', [row.id])).map(p => p.id);

  // Save the PDF to Google Drive: MBG-Daily Report/<Location name>/
  let driveStatus = 'off';
  if (drive.enabled()) {
    try {
      const report = reportRow({ ...row, emp_number: req.emp.emp_number, name: req.emp.name, title: req.emp.title });
      const pdf = await buildReportsPdf(await withPhotos([report]));
      const fileName = `${date} - ${req.emp.name}.pdf`.replace(/[\\/]/g, '-');
      const id = await drive.savePdf(pdf, fileName, loc.name, row.drive_file_id);
      if (id !== row.drive_file_id) {
        // Only one request may attach its file; if another one (e.g. a double click) won, remove our duplicate
        const won = await query('UPDATE daily_reports SET drive_file_id = $1 WHERE id = $2 AND drive_file_id IS NOT DISTINCT FROM $3 RETURNING id',
          [id, row.id, row.drive_file_id]);
        if (!won.length) {
          const cur = await one('SELECT drive_file_id FROM daily_reports WHERE id = $1', [row.id]);
          await drive.deleteFile(id).catch(() => {});
          if (cur?.drive_file_id) await drive.savePdf(pdf, fileName, loc.name, cur.drive_file_id); // keep the latest content
        }
      }
      driveStatus = 'saved';
    } catch (e) {
      console.error('Drive upload failed:', e.message);
      driveStatus = 'failed';
    }
  }
  res.json({ ok: true, updated_at: row.updated_at, drive: driveStatus });
}));

async function reportsBetween(fromQ, toQ) {
  const from = isDate(fromQ) ? fromQ : '0000-01-01';
  const to = isDate(toQ) ? toQ : '9999-12-31';
  const rows = await query(`
    SELECT r.id, r.report_date, r.data, r.updated_at, r.drive_file_id, e.emp_number, e.name, e.title, ${photoIdsSql}
    FROM daily_reports r JOIN employees e ON e.id = r.employee_id
    WHERE r.report_date >= $1 AND r.report_date <= $2
    ORDER BY r.report_date DESC, e.name`, [from, to]);
  return rows.map(reportRow);
}

app.get('/api/admin/reports', auth, notForced, adminOnly, h(async (req, res) => res.json(await reportsBetween(req.query.from, req.query.to))));

function sendPdf(res, buf, name) {
  res.setHeader('Content-Type', 'application/pdf');
  res.attachment(name); // RFC 5987 encoding: non-ASCII employee names no longer crash the download
  res.send(buf);
}

app.get('/api/admin/reports/:id.pdf', auth, notForced, adminOnly, h(async (req, res) => {
  const r = (await query(`SELECT r.id, r.report_date, r.data, r.updated_at, r.drive_file_id, e.emp_number, e.name, e.title, ${photoIdsSql}
    FROM daily_reports r JOIN employees e ON e.id = r.employee_id WHERE r.id = $1`, [Number(req.params.id) || 0])).map(reportRow)[0];
  if (!r) return res.status(404).json({ error: 'Not found' });
  sendPdf(res, await buildReportsPdf(await withPhotos([r])), `${r.date} - ${r.name}.pdf`.replace(/["\\/]/g, '-'));
}));

// ---------- Administration ----------
app.get('/api/admin/employees', auth, notForced, adminOnly, h(async (req, res) => {
  const rows = await query('SELECT * FROM employees WHERE deleted_at IS NULL ORDER BY CAST(emp_number AS INTEGER)');
  res.json(rows.map(publicEmp));
}));

app.post('/api/admin/employees', auth, notForced, adminOnly, h(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 120);
  const email = String(req.body.email || '').trim().toLowerCase().slice(0, 254);
  const title = String(req.body.title || '').trim().slice(0, 100);
  if (!name) return res.status(400).json({ error: 'Enter the name' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email address' });
  if (await one('SELECT id FROM employees WHERE lower(email) = $1', [email])) return res.status(400).json({ error: 'That email is already registered' });
  const temp = tempPassword();
  let num;
  for (let tries = 0; ; tries++) { // two admins creating at the same time can race for the same number
    num = await nextEmpNumber();
    try {
      await query(`INSERT INTO employees (emp_number, name, email, title, password_hash, role, must_change) VALUES ($1,$2,$3,$4,$5,'employee',TRUE)`,
        [num, name, email, title, bcrypt.hashSync(temp, 10)]);
      break;
    } catch (e) {
      if (e.code !== '23505' || tries >= 3) throw e;
      if (await one('SELECT id FROM employees WHERE lower(email) = $1', [email])) return res.status(400).json({ error: 'That email is already registered' });
    }
  }
  let emailed = false;
  try { await mail.sendWelcome({ to: email, name, empNumber: num, tempPassword: temp, appUrl: appUrl(req) }); emailed = true; }
  catch (e) { console.error('Welcome email failed:', e.message); }
  res.json({ emp_number: num, name, email, temp_password: temp, emailed });
}));

app.post('/api/admin/employees/:id/reset', auth, notForced, adminOnly, h(async (req, res) => {
  const emp = await one('SELECT * FROM employees WHERE id = $1 AND deleted_at IS NULL', [Number(req.params.id) || 0]);
  if (!emp) return res.status(404).json({ error: 'Not found' });
  try { await sendResetEmail(req, emp); }
  catch (e) { console.error('Reset email failed:', e.message); return res.status(500).json({ error: 'Could not send the email' }); }
  res.json({ ok: true, email: emp.email, name: emp.name });
}));

app.post('/api/admin/employees/:id/name', auth, notForced, adminOnly, h(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 120);
  if (!name) return res.status(400).json({ error: 'Enter the name' });
  const r = await query('UPDATE employees SET name = $1 WHERE id = $2 AND deleted_at IS NULL RETURNING id', [name, Number(req.params.id) || 0]);
  if (!r.length) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

app.post('/api/admin/employees/:id/title', auth, notForced, adminOnly, h(async (req, res) => {
  const r = await query('UPDATE employees SET title = $1 WHERE id = $2 AND deleted_at IS NULL RETURNING id', [String(req.body.title || '').trim().slice(0, 100), Number(req.params.id) || 0]);
  if (!r.length) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

// Delete: the person disappears from the list, cannot sign in and the email can be reused.
// Past reports (and their PDFs in Drive) are kept with the employee's name.
app.post('/api/admin/employees/:id/delete', auth, notForced, adminOnly, h(async (req, res) => {
  const id = Number(req.params.id) || 0;
  if (id === req.emp.id) return res.status(400).json({ error: 'You cannot delete your own account' });
  const r = await query(`UPDATE employees SET deleted_at = now(), active = FALSE, email = email || '#deleted-' || id,
      password_hash = 'deleted' WHERE id = $1 AND deleted_at IS NULL RETURNING id`, [id]);
  if (!r.length) return res.status(404).json({ error: 'Not found' });
  await query('DELETE FROM password_resets WHERE employee_id = $1', [id]);
  await query('DELETE FROM employee_locations WHERE employee_id = $1', [id]);
  await query('DELETE FROM report_photos WHERE employee_id = $1 AND report_id IS NULL', [id]);
  res.json({ ok: true });
}));

app.post('/api/admin/employees/:id/active', auth, notForced, adminOnly, h(async (req, res) => {
  const id = Number(req.params.id) || 0;
  if (id === req.emp.id) return res.status(400).json({ error: 'You cannot deactivate your own account' });
  const r = await query('UPDATE employees SET active = $1 WHERE id = $2 AND deleted_at IS NULL RETURNING id', [!!req.body.active, id]);
  if (!r.length) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'File or request is too large' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid request' });
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

if (require.main === module) app.listen(PORT, () => console.log('Uniqon Daily Reports listening on port ' + PORT));
module.exports = app;
