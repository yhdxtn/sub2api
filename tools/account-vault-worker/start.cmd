@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Please install Node.js 24 LTS from https://nodejs.org/ first.
  pause
  exit /b 1
)
node -e "process.exit(Number(process.versions.node.split('.')[0]) === 24 ? 0 : 1)"
if errorlevel 1 (
  echo This helper requires Node.js 24 LTS.
  pause
  exit /b 1
)
set DEBUG=
set PWDEBUG=
if not exist node_modules\playwright\package.json (
  call npm ci --ignore-scripts --no-audit --no-fund
  if errorlevel 1 goto failed
)
call npm run install:browser
if errorlevel 1 goto failed
node src\cli.mjs %*
if errorlevel 1 goto failed
exit /b 0
:failed
echo Setup or worker stopped. See README.md. No credential is written by this helper.
pause
exit /b 1
