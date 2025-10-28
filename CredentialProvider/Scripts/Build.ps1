# Build.ps1
# Automated build script for RDP QR Provider

param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Building RDP QR Credential Provider" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check for Visual Studio
$vsPath = & "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath
if (-not $vsPath) {
    Write-Host "ERROR: Visual Studio 2022 not found!" -ForegroundColor Red
    Write-Host "Please install Visual Studio 2022 with C++ Desktop Development workload" -ForegroundColor Yellow
    exit 1
}

Write-Host "Found Visual Studio at: $vsPath" -ForegroundColor Green

# Import Visual Studio environment
$vsVarsPath = "$vsPath\Common7\Tools\VsDevCmd.bat"
if (-not (Test-Path $vsVarsPath)) {
    Write-Host "ERROR: VsDevCmd.bat not found!" -ForegroundColor Red
    exit 1
}

Write-Host "Loading Visual Studio environment..." -ForegroundColor Yellow
cmd /c "`"$vsVarsPath`" && set" | ForEach-Object {
    if ($_ -match "^(.+?)=(.*)$") {
        [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2])
    }
}

# Navigate to solution directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$solutionDir = Split-Path -Parent $scriptDir
Push-Location $solutionDir

Write-Host ""
Write-Host "Building solution..." -ForegroundColor Yellow
Write-Host "Configuration: $Configuration" -ForegroundColor Cyan
Write-Host "Platform: $Platform" -ForegroundColor Cyan
Write-Host ""

# Build the solution
msbuild RDPQRProvider.sln /p:Configuration=$Configuration /p:Platform=$Platform /m /v:minimal

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Build Successful!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output: $Platform\$Configuration\RDPQRProvider.dll" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Update common.h line 54 with your auth server IP" -ForegroundColor White
    Write-Host "2. Run Scripts\Install.ps1 as Administrator" -ForegroundColor White
    Write-Host "3. Restart your computer" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "Build Failed!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please check the build output above for errors." -ForegroundColor Yellow
    Write-Host ""
}

Pop-Location
exit $LASTEXITCODE
