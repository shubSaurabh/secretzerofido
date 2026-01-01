# Uninstall RDP QR Credential Provider
# Must run as Administrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RDP QR Credential Provider - UNINSTALL" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check for admin rights
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click and select 'Run with PowerShell as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

# Unregister DLL
Write-Host "[1/4] Unregistering DLL..." -ForegroundColor Yellow
try {
    $result = Start-Process "regsvr32.exe" -ArgumentList "/u", "/s", "C:\Windows\System32\RDPQRProvider.dll" -Wait -PassThru
    if ($result.ExitCode -eq 0) {
        Write-Host "  SUCCESS: DLL unregistered" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: DLL unregistration failed (might not be registered)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  WARNING: Could not unregister DLL" -ForegroundColor Yellow
}

# Delete registry entries
Write-Host ""
Write-Host "[2/4] Deleting registry entries..." -ForegroundColor Yellow

$providerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}"
if (Test-Path $providerKey) {
    Remove-Item -Path $providerKey -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  SUCCESS: Provider registry entry deleted" -ForegroundColor Green
} else {
    Write-Host "  INFO: Provider registry entry not found" -ForegroundColor Gray
}

$clsidKey = "HKLM:\SOFTWARE\Classes\CLSID\{8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}"
if (Test-Path $clsidKey) {
    Remove-Item -Path $clsidKey -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  SUCCESS: CLSID registry entry deleted" -ForegroundColor Green
} else {
    Write-Host "  INFO: CLSID registry entry not found" -ForegroundColor Gray
}

# Delete DLL file
Write-Host ""
Write-Host "[3/4] Deleting DLL file..." -ForegroundColor Yellow
$dllPath = "C:\Windows\System32\RDPQRProvider.dll"
if (Test-Path $dllPath) {
    try {
        Remove-Item -Path $dllPath -Force -ErrorAction Stop
        Write-Host "  SUCCESS: DLL file deleted" -ForegroundColor Green
    } catch {
        Write-Host "  WARNING: Could not delete DLL (might be in use)" -ForegroundColor Yellow
        Write-Host "  You may need to delete it manually after reboot: $dllPath" -ForegroundColor Yellow
    }
} else {
    Write-Host "  INFO: DLL file not found" -ForegroundColor Gray
}

# Delete log file
Write-Host ""
Write-Host "[4/4] Cleaning up log file..." -ForegroundColor Yellow
$logPath = "C:\ProgramData\RDPQRProvider.log"
if (Test-Path $logPath) {
    Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
    Write-Host "  SUCCESS: Log file deleted" -ForegroundColor Green
} else {
    Write-Host "  INFO: Log file not found (already clean)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "UNINSTALL COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: You must RESTART your computer for changes to take effect!" -ForegroundColor Yellow
Write-Host ""
pause