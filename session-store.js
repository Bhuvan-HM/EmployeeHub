const session = require('express-session');
const db = require('./database');
const Store = session.Store;

class SQLiteSessionStore extends Store {
  constructor() {
    super();
    this.getStmt = db.prepare('SELECT sess, expired FROM sessions WHERE sid = ?');
    this.setStmt = db.prepare('INSERT INTO sessions(sid,sess,expired) VALUES(?,?,?) ON CONFLICT(sid) DO UPDATE SET sess=excluded.sess, expired=excluded.expired');
    this.destroyStmt = db.prepare('DELETE FROM sessions WHERE sid = ?');
    this.touchStmt = db.prepare('UPDATE sessions SET expired=? WHERE sid=?');
    this.cleanupStmt = db.prepare('DELETE FROM sessions WHERE expired <= ?');
    this.cleanupTimer = setInterval(() => { try { this.cleanupStmt.run(Date.now()); } catch {} }, 15 * 60 * 1000);
    this.cleanupTimer.unref();
  }
  get(sid, cb) {
    try { const row = this.getStmt.get(sid); if (!row) return cb(null, null); if (row.expired <= Date.now()) { this.destroyStmt.run(sid); return cb(null, null); } cb(null, JSON.parse(row.sess)); }
    catch (e) { cb(e); }
  }
  set(sid, sess, cb = () => {}) {
    try { const expires = sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 30 * 60 * 1000; this.setStmt.run(sid, JSON.stringify(sess), expires); cb(null); }
    catch (e) { cb(e); }
  }
  destroy(sid, cb = () => {}) { try { this.destroyStmt.run(sid); cb(null); } catch (e) { cb(e); } }
  touch(sid, sess, cb = () => {}) { try { const expires = sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 30 * 60 * 1000; this.touchStmt.run(expires, sid); cb(null); } catch (e) { cb(e); } }
}
module.exports = new SQLiteSessionStore();
