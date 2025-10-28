# Uninstall.ps1
# Uninstallation script for RDP QR Credential Provider
# Must be run as Administrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Uninstalling RDP QR Credential Provider" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check for Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

$dllPath = "$env:SystemRoot\System32\RDPQRProvider.dll"

if (-not (Test-Path $dllPath)) {
    Write-Host "Credential provider not found. May already be uninstalled." -ForegroundColor Yellow
    exit 0
}

Write-Host "Unregistering credential provider..." -ForegroundColor Yellow

try {
    $regsvr32 = "$env:SystemRoot\System32\regsvr32.exe"
    & $regsvr32 /u /s $dllPath
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Credential provider unregistered" -ForegroundColor Green
    }
} catch {
    Write-Host "Warning: Failed to unregister: $_" -ForegroundColor Yellow
}

Write-Host "Removing DLL..." -ForegroundColor Yellow

try {
    Remove-Item -Path $dllPath -Force
    Write-Host "✓ DLL removed" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to remove DLL: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Uninstallation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "A restart is recommended." -ForegroundColor Yellow
Write-Host ""
