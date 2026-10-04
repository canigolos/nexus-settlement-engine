# PowerShell script to set up local Stellar environment

# Exit on any error
$ErrorActionPreference = "Stop"

Write-Host "=== Starting local Stellar environment setup ===" -ForegroundColor Cyan

# 1. Verify required tools
$required = @("node", "npm", "cargo", "docker", "docker-compose", "stellar-cli", "soroban-cli")
foreach ($tool in $required) {
  if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
    Write-Error "Required tool '$tool' is not installed or not in PATH. Install it and retry."
  }
}

# 2. Install npm dependencies
npm ci

# 3. Build Soroban contracts (assumes contracts in contracts/soroban)
pushd contracts/soroban
cargo build --target wasm32-unknown-unknown --release
popd

# 4. Start Docker Compose services
docker compose -f infra/docker-compose.yml up -d

# 5. Wait for Horizon to be healthy (simple retry loop)
Write-Host "Waiting for Horizon service..." -ForegroundColor Yellow
for ($i = 0; $i -lt 30; $i++) {
  try {
    $resp = Invoke-RestMethod http://localhost:8000
    if ($resp) { break }
  } catch {}
  Start-Sleep -Seconds 5
}

# 6. Run initialization script to fund accounts, deploy contracts, generate config
node scripts/setup-local-env/init.js

# 7. Success banner
Write-Host "====================================================" -ForegroundColor Green
Write-Host "Local Stellar environment is ready!" -ForegroundColor Green
Write-Host "Config file generated at client-config.json" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
