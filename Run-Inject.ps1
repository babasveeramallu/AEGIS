#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Quick Inject Response Tool - Rapid execution of inject tasks
    
.DESCRIPTION
    Handles common SecOps injects with one command
    Based on 2026 performance analysis - fixes 0-score injects
    
.PARAMETER InjectType
    Type of inject to execute
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet(
        "FileSystemIntegrity",
        "DetectBeaconing",
        "MitigationPlan",
        "StartupFiles",
        "PrecisionTime",
        "FirewallExport",
        "NetworkConnectivity"
    )]
    [string]$InjectType
)

# Import modules
$ModulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ModulePath\Config\Configuration.ps1"
Get-ChildItem "$ModulePath\Modules\*.ps1" | ForEach-Object { . $_.FullName }

# Initialize globals
$Global:LogPath = "C:\Security-Logs"
if (!(Test-Path $Global:LogPath)) {
    New-Item -Path $Global:LogPath -ItemType Directory -Force | Out-Null
}

if (!(Test-Path "$Global:LogPath\Reports")) {
    New-Item -Path "$Global:LogPath\Reports" -ItemType Directory -Force | Out-Null
}

Write-Host "`n[INJECT RESPONSE: $InjectType]" -ForegroundColor Cyan
Write-Host "Executing at $(Get-Date -Format 'HH:mm:ss')`n" -ForegroundColor Gray

switch ($InjectType) {
    "FileSystemIntegrity" {
        Write-Host "Running file system integrity check..." -ForegroundColor Yellow
        # Existing capability - already scores 100
        if (Get-Command Invoke-FileSystemIntegrityCheck -ErrorAction SilentlyContinue) {
            Invoke-FileSystemIntegrityCheck
        } else {
            Write-Host "Creating baseline file integrity check..." -ForegroundColor Yellow
            $paths = @("C:\Windows\System32", "C:\Program Files", "C:\inetpub")
            foreach ($path in $paths) {
                if (Test-Path $path) {
                    Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue | 
                        Select-Object FullName, Length, LastWriteTime, @{N='Hash';E={(Get-FileHash $_.FullName).Hash}} |
                        Export-Csv "$Global:LogPath\Reports\FileIntegrity_$(Split-Path $path -Leaf).csv" -NoTypeInformation
                }
            }
            Write-Host "File integrity baseline created in $Global:LogPath\Reports\" -ForegroundColor Green
        }
    }
    
    "DetectBeaconing" {
        Write-Host "Detecting beaconing software..." -ForegroundColor Yellow
        # Existing capability - already scores 100
        if (Get-Command Invoke-BeaconDetection -ErrorAction SilentlyContinue) {
            Invoke-BeaconDetection
        } else {
            Write-Host "Analyzing network connections for beaconing..." -ForegroundColor Yellow
            $connections = Get-NetTCPConnection | Where-Object State -eq "Established" |
                Group-Object RemoteAddress | Where-Object Count -gt 5
            $connections | Export-Csv "$Global:LogPath\Reports\Beaconing_Analysis.csv" -NoTypeInformation
            Write-Host "Beaconing analysis complete: $Global:LogPath\Reports\Beaconing_Analysis.csv" -ForegroundColor Green
        }
    }
    
    "MitigationPlan" {
        Write-Host "Generating mitigation plan..." -ForegroundColor Yellow
        # Existing capability - already scores 100
        if (Get-Command Generate-MitigationPlan -ErrorAction SilentlyContinue) {
            Generate-MitigationPlan
        } else {
            $plan = @"
Incident Mitigation Plan
Generated: $(Get-Date)

1. IMMEDIATE ACTIONS
   - Isolate affected systems
   - Preserve evidence
   - Document timeline

2. CONTAINMENT
   - Block malicious IPs
   - Disable compromised accounts
   - Patch vulnerabilities

3. ERADICATION
   - Remove malware
   - Reset credentials
   - Verify system integrity

4. RECOVERY
   - Restore from backups
   - Verify services operational
   - Monitor for reinfection

5. LESSONS LEARNED
   - Document incident
   - Update procedures
   - Train team
"@
            $plan | Out-File "$Global:LogPath\Reports\Mitigation_Plan.txt"
            Write-Host "Mitigation plan: $Global:LogPath\Reports\Mitigation_Plan.txt" -ForegroundColor Green
        }
    }
    
    "StartupFiles" {
        Write-Host "Auditing startup files..." -ForegroundColor Yellow
        Invoke-StartupFileSecurity
        Write-Host "Startup files audit complete" -ForegroundColor Green
    }
    
    "PrecisionTime" {
        Write-Host "Configuring precision time synchronization..." -ForegroundColor Yellow
        Enable-PrecisionTimeLogging
        Write-Host "Precision time logging enabled" -ForegroundColor Green
    }
    
    "FirewallExport" {
        Write-Host "Exporting firewall security policy..." -ForegroundColor Yellow
        Export-FirewallSecurityPolicy
        Write-Host "Firewall policy exported" -ForegroundColor Green
    }
    
    "NetworkConnectivity" {
        Write-Host "Testing network connectivity..." -ForegroundColor Yellow
        $result = Test-NetworkConnectivity
        Export-NetworkConnectivityReport
        if ($result) {
            Write-Host "Network connectivity verified" -ForegroundColor Green
        } else {
            Write-Host "Network connectivity issues detected - check report" -ForegroundColor Red
        }
    }
}

Write-Host "`n[INJECT COMPLETE]" -ForegroundColor Green
Write-Host "Check $Global:LogPath\Reports\ for output files`n" -ForegroundColor Cyan
