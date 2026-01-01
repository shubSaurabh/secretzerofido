# Test.ps1
# Test script to verify RDP QR Credential Provider installation

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Testing RDP QR Credential Provider" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$allGood = $true

# Test 1: Check if DLL exists
Write-Host "[1/4] Checking DLL..." -ForegroundColor Yellow
$dllPath = "$env:SystemRoot\System32\RDPQRProvider.dll"

if (Test-Path $dllPath) {
    Write-Host "    ✓ DLL found: $dllPath" -ForegroundColor Green
    
    # Get file version
    try {
        $version = (Get-Item $dllPath).VersionInfo
        Write-Host "      Product: $($version.ProductName)" -ForegroundColor Gray
        Write-Host "      Version: $($version.FileVersion)" -ForegroundColor Gray
        
        # Check file size
        $size = (Get-Item $dllPath).Length
        $sizeKB = [math]::Round($size / 1KB, 2)
        Write-Host "      Size: $sizeKB KB" -ForegroundColor Gray
        
        # Check if file is blocked
        $zone = Get-Item $dllPath -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($zone) {
            Write-Host "      ⚠ File is blocked by Windows!" -ForegroundColor Yellow
            Write-Host "      Run: Unblock-File '$dllPath'" -ForegroundColor Gray
        }
    } catch {
        Write-Host "      Warning: Could not read file info" -ForegroundColor Yellow
    }
} else {
    Write-Host "    ✗ DLL not found!" -ForegroundColor Red
    Write-Host "      Please run Install.ps1 as Administrator" -ForegroundColor Yellow
    $allGood = $false
}

Write-Host ""

# Test 2: Check registry - Credential Provider
Write-Host "[2/4] Checking Credential Provider registration..." -ForegroundColor Yellow
$cpRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}"

if (Test-Path $cpRegPath) {
    Write-Host "    ✓ Credential Provider registry key found" -ForegroundColor Green
    
    try {
        $regValue = Get-ItemProperty -Path $cpRegPath -Name "(Default)" -ErrorAction SilentlyContinue
        if ($regValue) {
            Write-Host "      Name: $($regValue.'(Default)')" -ForegroundColor Gray
        }
    } catch {
        # Default value might not exist, that's okay
    }
} else {
    Write-Host "    ✗ Registry key not found!" -ForegroundColor Red
    Write-Host "      The credential provider may not be registered" -ForegroundColor Yellow
    Write-Host "      Run: regsvr32 /s $dllPath" -ForegroundColor Gray
    $allGood = $false
}

Write-Host ""

# Test 3: Check CLSID registration
Write-Host "[3/4] Checking COM registration..." -ForegroundColor Yellow
$clsidPath = "HKLM:\SOFTWARE\Classes\CLSID\{8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}"

if (Test-Path $clsidPath) {
    Write-Host "    ✓ CLSID registered" -ForegroundColor Green
    
    # Check InprocServer32
    $inprocPath = "$clsidPath\InprocServer32"
    if (Test-Path $inprocPath) {
        $dllReg = Get-ItemProperty -Path $inprocPath -Name "(Default)" -ErrorAction SilentlyContinue
        if ($dllReg) {
            Write-Host "      DLL Path: $($dllReg.'(Default)')" -ForegroundColor Gray
            
            # Verify it points to the right location
            if ($dllReg.'(Default)' -ne $dllPath) {
                Write-Host "      ⚠ Warning: Registry points to different location!" -ForegroundColor Yellow
            }
        }
        
        $threading = Get-ItemProperty -Path $inprocPath -Name "ThreadingModel" -ErrorAction SilentlyContinue
        if ($threading) {
            Write-Host "      Threading Model: $($threading.ThreadingModel)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "    ✗ CLSID not registered!" -ForegroundColor Red
    Write-Host "      The COM object may not be registered" -ForegroundColor Yellow
    $allGood = $false
}

Write-Host ""

# Test 4: Check if credential provider is enabled
Write-Host "[4/4] Checking if provider is enabled..." -ForegroundColor Yellow

# Check if it's in the disabled list
$disabledPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters"
if (Test-Path $disabledPath) {
    $disabled = Get-ItemProperty -Path $disabledPath -Name "{8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}" -ErrorAction SilentlyContinue
    if ($disabled) {
        Write-Host "    ⚠ Provider is in the disabled list!" -ForegroundColor Yellow
        $allGood = $false
    } else {
        Write-Host "    ✓ Provider is not disabled" -ForegroundColor Green
    }
} else {
    Write-Host "    ✓ No disabled provider filters found" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($allGood) {
    Write-Host "✓ All tests passed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Installation appears correct!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Restart your computer" -ForegroundColor White
    Write-Host "  2. The QR code should appear on login screen" -ForegroundColor White
    Write-Host "  3. Scan with your QR Scanner app" -ForegroundColor White
    Write-Host ""
    Write-Host "To test without restarting:" -ForegroundColor Cyan
    Write-Host "  1. Lock screen (Win + L)" -ForegroundColor White
    Write-Host "  2. Check if QR code appears" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "✗ Some tests failed!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting steps:" -ForegroundColor Yellow
    Write-Host "  1. Run Install.ps1 as Administrator" -ForegroundColor White
    Write-Host "  2. Check if DLL is blocked: Unblock-File '$dllPath'" -ForegroundColor White
    Write-Host "  3. Manually register: regsvr32 /s '$dllPath'" -ForegroundColor White
    Write-Host "  4. Check Event Viewer for errors" -ForegroundColor White
    Write-Host "  5. Verify you're using x64 DLL on x64 Windows" -ForegroundColor White
    Write-Host ""
}

# Additional diagnostics
Write-Host "Additional Information:" -ForegroundColor Cyan
Write-Host "  OS: $([System.Environment]::OSVersion.VersionString)" -ForegroundColor Gray
Write-Host "  Architecture: $($env:PROCESSOR_ARCHITECTURE)" -ForegroundColor Gray
Write-Host "  PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
Write-Host ""

# Check for log file
$logPath = "C:\Windows\Temp\RDPQRProvider.log"
if (Test-Path $logPath) {
    Write-Host "Debug log found at: $logPath" -ForegroundColor Cyan
    $logSize = (Get-Item $logPath).Length
    if ($logSize -gt 0) {
        Write-Host "Log size: $([math]::Round($logSize / 1KB, 2)) KB" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Last 10 log entries:" -ForegroundColor Cyan
        Get-Content $logPath -Tail 10 | ForEach-Object {
            Write-Host "  $_" -ForegroundColor Gray
        }
    } else {
        Write-Host "Log file is empty (provider may not have run yet)" -ForegroundColor Gray
    }
    Write-Host ""
}

Write-Host "Test complete!" -ForegroundColor Cyan
Write-Host ""