# Install.ps1
# Installation script for RDP QR Credential Provider
# Must be run as Administrator

param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Installing RDP QR Credential Provider" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check for Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check if running from build directory or copied location
$dllPath = ""
if (Test-Path "$scriptDir\..\x64\$Configuration\RDPQRProvider.dll") {
    # Running from Scripts folder in build directory
    $dllPath = "$scriptDir\..\x64\$Configuration\RDPQRProvider.dll"
} elseif (Test-Path "$scriptDir\x64\$Configuration\RDPQRProvider.dll") {
    # x64 folder copied next to script
    $dllPath = "$scriptDir\x64\$Configuration\RDPQRProvider.dll"
} elseif (Test-Path "$scriptDir\RDPQRProvider.dll") {
    # DLL copied directly next to script
    $dllPath = "$scriptDir\RDPQRProvider.dll"
} else {
    Write-Host "ERROR: RDPQRProvider.dll not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Searched locations:" -ForegroundColor Yellow
    Write-Host "  1. $scriptDir\..\x64\$Configuration\RDPQRProvider.dll" -ForegroundColor Gray
    Write-Host "  2. $scriptDir\x64\$Configuration\RDPQRProvider.dll" -ForegroundColor Gray
    Write-Host "  3. $scriptDir\RDPQRProvider.dll" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Please copy the DLL to one of these locations." -ForegroundColor Yellow
    exit 1
}

Write-Host "Found DLL: $dllPath" -ForegroundColor Green
Write-Host ""

# Copy DLL to System32
$destPath = "$env:SystemRoot\System32\RDPQRProvider.dll"
Write-Host "Copying DLL to: $destPath" -ForegroundColor Yellow

try {
    Copy-Item -Path $dllPath -Destination $destPath -Force
    Write-Host "✓ DLL copied successfully" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to copy DLL: $_" -ForegroundColor Red
    exit 1
}

# Register the DLL
Write-Host ""
Write-Host "Registering credential provider..." -ForegroundColor Yellow

try {
    $regsvr32 = "$env:SystemRoot\System32\regsvr32.exe"
    $process = Start-Process -FilePath $regsvr32 -ArgumentList "/s `"$destPath`"" -Wait -PassThru
    
    if ($process.ExitCode -eq 0) {
        Write-Host "✓ Credential provider registered successfully" -ForegroundColor Green
    } else {
        Write-Host "ERROR: Registration failed with exit code $($process.ExitCode)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Common causes:" -ForegroundColor Yellow
        Write-Host "  - Missing dependencies (vcredist)" -ForegroundColor Gray
        Write-Host "  - DLL is blocked by antivirus" -ForegroundColor Gray
        Write-Host "  - Incorrect architecture (use x64 DLL on x64 Windows)" -ForegroundColor Gray
        exit 1
    }
} catch {
    Write-Host "ERROR: Failed to register DLL: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "⚠️  IMPORTANT: You must restart your computer for changes to take effect!" -ForegroundColor Yellow
Write-Host ""
Write-Host "After restart:" -ForegroundColor Cyan
Write-Host "1. The QR code will appear on the login screen" -ForegroundColor White
Write-Host "2. Scan it with your QR Scanner application" -ForegroundColor White
Write-Host "3. You'll be automatically logged in" -ForegroundColor White
Write-Host ""
Write-Host "To verify installation:" -ForegroundColor Cyan
Write-Host '  Check registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}' -ForegroundColor Gray
Write-Host ""
Write-Host "Troubleshooting:" -ForegroundColor Cyan
Write-Host "  - Check logs: C:\Windows\Temp\RDPQRProvider.log" -ForegroundColor Gray
Write-Host "  - Verify DLL: C:\Windows\System32\RDPQRProvider.dll" -ForegroundColor Gray
Write-Host "  - Run Test.ps1 to verify installation" -ForegroundColor Gray
Write-Host ""

$restart = Read-Host "Do you want to restart now? (Y/N)"
if ($restart -eq 'Y' -or $restart -eq 'y') {
    Write-Host "Restarting computer in 10 seconds..." -ForegroundColor Yellow
    Write-Host "Press Ctrl+C to cancel" -ForegroundColor Gray
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}