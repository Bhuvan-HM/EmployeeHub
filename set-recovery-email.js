
const readline = require('readline');
const db = require('./database');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question('EmployeeHub username: ', username => {
  rl.question('Recovery email address: ', email => {
    try {
      const cleanUsername = username.trim();
      const cleanEmail = email.trim().toLowerCase();

      // Validate email address
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
        console.error('Please enter a valid email address.');
        rl.close();
        db.close();
        return;
      }

      // Find username without case sensitivity or extra spaces
      const result = db.prepare(`
        UPDATE users
        SET recovery_email = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE lower(trim(username)) = lower(trim(?))
      `).run(cleanEmail, cleanUsername);

      if (result.changes === 0) {
        console.error('Username not found. No changes made.');
      } else {
        console.log('Recovery email saved successfully!');
        console.log('You can now use Forgot Username and Forgot Password.');
      }

    } catch (error) {
      console.error('Error:', error.message);
    } finally {
      rl.close();
      db.close();
    }
  });
});