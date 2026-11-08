$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$frontendDir = Join-Path $repoRoot "frontend"
$python = Join-Path $repoRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
  throw "Missing Python environment. Create .venv and install backend/requirements.txt first."
}
if (-not (Test-Path (Join-Path $frontendDir "node_modules"))) {
  throw "Missing frontend dependencies. Run npm install in frontend/ first."
}
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
  throw "npm was not found. Install Node.js, then run npm install in frontend/."
}

Push-Location $frontendDir
try {
  & npm.cmd run build
  if ($LASTEXITCODE -ne 0) {
    throw "Frontend build failed with exit code $LASTEXITCODE."
  }
} finally {
  Pop-Location
}

Write-Host "Starting SPIDERS.Mk1 at http://127.0.0.1:8600/"
Push-Location (Join-Path $repoRoot "backend")
try {
  & $python "run.py"
} finally {
  Pop-Location
}
