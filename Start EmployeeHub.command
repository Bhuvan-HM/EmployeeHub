
#!/bin/bash
cd "$HOME/Downloads/Employee-Management-System" || exit 1

export SESSION_SECRET="$(node -e "console.log(require('crypto').randomBytes(48).toString('hex'))")"

echo "Starting EmployeeHub..."
npm start
