# Quick Test Script - Run this to validate basic functionality
# This tests core components without making system changes

Write-Host "=== SecOps TOOL QUICK TEST ===" -ForegroundColor Cyan
Write-Host "Testing basic functionality without system modifications`n" -ForegroundColor White

$testResults = @{
    Passed = 0
    Failed = 0
    Tests = @()
}

# Test 1: PowerShell Version
Write-Host "Test 1: PowerShell Version Check..." -ForegroundColor Yellow
try {
    $psVersion = $PSVersionTable.PSVersion.Major
    if ($psVersion -ge 5) {
        Write-Host "PASS - PowerShell $psVersion detected" -ForegroundColor Green
        $testResults.Passed++
        $testResults.Tests += "PowerShell Version: PASS"
    } else {
        Write-Host "FAIL - PowerShell $psVersion too old (need 5+)" -ForegroundColor Red
        $testResults.Failed++
        $testResults.Tests += "PowerShell Version: FAIL"
    }
} catch {
    Write-Host "ERROR - Could not check PowerShell version" -ForegroundColor Red
    $testResults.Failed++
    $testResults.Tests += "PowerShell Version: ERROR"
}

# Test 2: Admin Privileges Check
Write-Host "Test 2: Administrator Privileges..." -ForegroundColor Yellow
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($isAdmin) {
        Write-Host "PASS - Running as Administrator" -ForegroundColor Green
        $testResults.Passed++
        $testResults.Tests += "Admin Privileges: PASS"
    } else {
        Write-Host "FAIL - Not running as Administrator" -ForegroundColor Red
        $testResults.Failed++
        $testResults.Tests += "Admin Privileges: FAIL"
    }
} catch {
    Write-Host "ERROR - Could not check admin privileges" -ForegroundColor Red
    $testResults.Failed++
    $testResults.Tests += "Admin Privileges: ERROR"
}

# Test 3: Module Files Present
Write-Host "Test 3: Required Module Files..." -ForegroundColor Yellow
try {
    $requiredFiles = @(
        "Main-Tool.ps1",
        "Modules\Phase0-SystemIdentification.ps1",
        "Modules\Phase1-Hardening.ps1",
        "Modules\Phase3-Detection.ps1"
    )
    
    $missingFiles = @()
    foreach ($file in $requiredFiles) {
        if (!(Test-Path $file)) {
            $missingFiles += $file
        }
    }
    
    if ($missingFiles.Count -eq 0) {
        Write-Host "PASS - All required files present" -ForegroundColor Green
        $testResults.Passed++
        $testResults.Tests += "Module Files: PASS"
    } else {
        Write-Host "FAIL - Missing files: $($missingFiles -join ', ')" -ForegroundColor Red
        $testResults.Failed++
        $testResults.Tests += "Module Files: FAIL"
    }
} catch {
    Write-Host "ERROR - Could not check module files" -ForegroundColor Red
    $testResults.Failed++
    $testResults.Tests += "Module Files: ERROR"
}

# Test 4: System Information Gathering
Write-Host "Test 4: System Information Gathering..." -ForegroundColor Yellow
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $computerName = $env:COMPUTERNAME
    
    if ($osInfo -and $computerName) {
        Write-Host "PASS - System info: $($osInfo.Caption) on $computerName" -ForegroundColor Green
        $testResults.Passed++
        $testResults.Tests += "System Info: PASS"
    } else {
        Write-Host "FAIL - Could not gather system information" -ForegroundColor Red
        $testResults.Failed++
        $testResults.Tests += "System Info: FAIL"
    }
} catch {
    Write-Host "ERROR - System information gathering failed" -ForegroundColor Red
    $testResults.Failed++
    $testResults.Tests += "System Info: ERROR"
}

# Test 5: Network Connectivity Test
Write-Host "Test 5: Network Connectivity..." -ForegroundColor Yellow
try {
    $networkTest = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($networkTest) {
        Write-Host "PASS - Network connectivity confirmed" -ForegroundColor Green
        $testResults.Passed++
        $testResults.Tests += "Network: PASS"
    } else {
        Write-Host "FAIL - No network connectivity" -ForegroundColor Red
        $testResults.Failed++
        $testResults.Tests += "Network: FAIL"
    }
} catch {
    Write-Host "ERROR - Network test failed" -ForegroundColor Red
    $testResults.Failed++
    $testResults.Tests += "Network: ERROR"
}

# Test 6: Windows Defender Status
Write-Host "Test 6: Windows Defender Status..." -ForegroundColor Yellow
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus) {
        $rtpEnabled = $defenderStatus.RealTimeProtectionEnabled
        if ($rtpEnabled) {
            Write-Host "PASS - Windows Defender operational" -ForegroundColor Green
            $testResults.Passed++
            $testResults.Tests += "Defender: PASS"
        } else {
            Write-Host "WARN - Windows Defender real-time protection disabled" -ForegroundColor Yellow
            $testResults.Passed++
            $testResults.Tests += "Defender: WARN"
        }
    } else {
        Write-Host "FAIL - Could not check Windows Defender status" -ForegroundColor Red
        $testResults.Failed++
        $testResults.Tests += "Defender: FAIL"
    }
} catch {
    Write-Host "ERROR - Defender status check failed" -ForegroundColor Red
    $testResults.Failed++
    $testResults.Tests += "Defender: ERROR"
}

# Test 7: Windows Firewall Status
Write-Host "Test 7: Windows Firewall Status..." -ForegroundColor Yellow
try {
    $firewallProfiles = Get-NetFirewallProfile
    $enabledProfiles = ($firewallProfiles | Where-Object { $_.Enabled -eq $true }).Count
    
    if ($enabledProfiles -gt 0) {
        Write-Host "PASS - Windows Firewall enabled ($enabledProfiles profiles)" -ForegroundColor Green
        $testResults.Passed++
        $testResults.Tests += "Firewall: PASS"
    } else {
        Write-Host "FAIL - Windows Firewall disabled" -ForegroundColor Red
        $testResults.Failed++
        $testResults.Tests += "Firewall: FAIL"
    }
} catch {
    Write-Host "ERROR - Firewall status check failed" -ForegroundColor Red
    $testResults.Failed++
    $testResults.Tests += "Firewall: ERROR"
}

# Test 8: Process Monitoring Test
Write-Host "Test 8: Process Monitoring Capability..." -ForegroundColor Yellow
try {
    $processes = Get-Process | Select-Object -First 5
    if ($processes.Count -ge 5) {
        Write-Host "PASS - Process monitoring functional" -ForegroundColor Green
        $testResults.Passed++
        $testResults.Tests += "Process Monitor: PASS"
    } else {
        Write-Host "FAIL - Process monitoring limited" -ForegroundColor Red
        $testResults.Failed++
        $testResults.Tests += "Process Monitor: FAIL"
    }
} catch {
    Write-Host "ERROR - Process monitoring test failed" -ForegroundColor Red
    $testResults.Failed++
    $testResults.Tests += "Process Monitor: ERROR"
}

# Calculate Results
$totalTests = $testResults.Passed + $testResults.Failed
$successRate = if ($totalTests -gt 0) { [Math]::Round(($testResults.Passed / $totalTests) * 100, 1) } else { 0 }

# Display Results
Write-Host "`n=== TEST RESULTS ===" -ForegroundColor Cyan
Write-Host "Total Tests: $totalTests" -ForegroundColor White
Write-Host "Passed: $($testResults.Passed)" -ForegroundColor Green
Write-Host "Failed: $($testResults.Failed)" -ForegroundColor Red
Write-Host "Success Rate: $successRate%" -ForegroundColor $(if($successRate -ge 80){"Green"}elseif($successRate -ge 60){"Yellow"}else{"Red"})

Write-Host "`n=== DETAILED RESULTS ===" -ForegroundColor Cyan
foreach ($test in $testResults.Tests) {
    Write-Host "  $test" -ForegroundColor White
}

# Recommendations
Write-Host "`n=== RECOMMENDATIONS ===" -ForegroundColor Cyan
if ($testResults.Failed -gt 0) {
    Write-Host "Issues detected. Address failed tests before deployment." -ForegroundColor Yellow
    
    if ($testResults.Tests -contains "Admin Privileges: FAIL") {
        Write-Host "  -> Run PowerShell as Administrator" -ForegroundColor Yellow
    }
    if ($testResults.Tests -contains "Module Files: FAIL") {
        Write-Host "  -> Ensure all module files are present" -ForegroundColor Yellow
    }
    if ($testResults.Tests -contains "Network: FAIL") {
        Write-Host "  -> Check network connectivity" -ForegroundColor Yellow
    }
} else {
    Write-Host "All tests passed! System ready for SecOps tool deployment." -ForegroundColor Green
}

Write-Host "`nTest completed at $(Get-Date)" -ForegroundColor Gray