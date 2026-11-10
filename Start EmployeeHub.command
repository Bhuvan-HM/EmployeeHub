#!/bin/bash
# EmployeeHub local launcher
cd "$(dirname "$0")" || exit 1

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed. Install Node.js, then try again."
  read -r -p "Press Enter to close..."
  exit 1
fi

if [ ! -d "node_modules" ]; then
  echo "Installing EmployeeHub dependencies..."
  npm install
fi

export SESSION_SECRET="$(node -e "console.log(require('crypto').randomBytes(48).toString('hex'))")"
echo "Starting EmployeeHub at http://localhost:3000"
npm start
