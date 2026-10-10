#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
node -e 'process.exit(Number(process.versions.node.split(".")[0]) === 24 ? 0 : 1)' || {
  echo 'Install Node.js 24 LTS from https://nodejs.org/ first.' >&2
  exit 1
}
unset DEBUG PWDEBUG
if [ ! -d node_modules/playwright ]; then
  npm ci --ignore-scripts --no-audit --no-fund
fi
npm run install:browser
exec node src/cli.mjs "$@"
