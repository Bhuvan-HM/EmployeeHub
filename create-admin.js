const bcrypt = require('bcrypt');
const db = require('./database');
const readline = require('readline');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
function ask(question) { return new Promise(resolve => rl.question(question, resolve)); }
function askHidden(question) {
  return new Promise((resolve, reject) => {
    const input = process.stdin;
    if (!input.isTTY || typeof input.setRawMode !== 'function') {
      const fallback = readline.createInterface({ input: process.stdin, output: process.stdout });
      return fallback.question(question + ' (input may be visible): ', value => { fallback.close(); resolve(value); });
    }
    process.stdout.write(question);
    let value = '';
    input.setRawMode(true);
    input.resume();
    const onData = chunk => {
      const char = chunk.toString('utf8');
      if (char === '\u0003') { cleanup(); reject(new Error('Cancelled.')); return; }
      if (char === '\r' || char === '\n') { cleanup(); process.stdout.write('\n'); resolve(value); return; }
      if (char === '\u007f' || char === '\b') { value = value.slice(0, -1); process.stdout.write('\b \b'); return; }
      if (char >= ' ') { value += char; process.stdout.write('*'); }
    };
    function cleanup() { input.removeListener('data', onData); input.setRawMode(false); input.pause(); }
    input.on('data', onData);
  });
}

async function main() {
  try {
    const username = (await ask('Admin username (3+ characters): ')).trim();
    rl.close();
    const password = await askHidden('Admin password (minimum 12 characters): ');
    if (!/^[a-zA-Z0-9._-]{3,80}$/.test(username)) throw new Error('Username must be 3–80 characters using letters, numbers, dot, underscore or hyphen.');
    if (password.length < 12 || password.length > 200) throw new Error('Password must be between 12 and 200 characters.');
    const hash = await bcrypt.hash(password, 12);
    db.prepare(`INSERT INTO users (username,password_hash,role) VALUES (?,?, 'admin')`).run(username, hash);
    console.log('Administrator account created successfully.');
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') console.error('That username already exists. Choose another username.');
    else console.error(error.message || 'Could not create administrator account.');
    process.exitCode = 1;
  } finally {
    rl.close();
    db.close();
  }
}
main();
