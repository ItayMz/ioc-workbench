$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$backendPath = Join-Path $root 'backend'
$frontendPath = Join-Path $root 'frontend'

Start-Process powershell -ArgumentList @('-NoExit', '-Command', "Set-Location '$backendPath'; uvicorn app.main:app --reload")
Start-Process powershell -ArgumentList @('-NoExit', '-Command', "Set-Location '$frontendPath'; npm run dev")

Write-Host 'Started backend and frontend in separate PowerShell windows.'
Write-Host 'Backend:  http://localhost:8000'
Write-Host 'Frontend: http://localhost:5173'
