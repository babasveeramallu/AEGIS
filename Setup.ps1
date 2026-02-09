#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SecOps 2026 - Quick Deployment Script
    
.DESCRIPTION
    Rapid deployment script for competition day.
    Performs pre-flight checks and launches the main tool.
    
.PARAMETER QuickStart
    Skip confirmations and start immediately
    
.PARAMETER CheckOnly
    Only perform pre-flight checks, don't start tool
#>

param(
    [switch]$QuickStart,
    [switch]$CheckOnly
)

function Write-DeployLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    switch ($Level) {
        "INFO"    { Write-Host "[$timestamp] [INFO] $Message" -ForegroundColor White }
        "WARN"    { Write-Host "[$timestamp] [WARN] $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host "[$timestamp] [ERROR] $Message" -ForegroundColor Red }
        "SUCCESS" { Write-Host "[$timestamp] [SUCCESS] $Message" -ForegroundColor Green }
    }
}

function Test-Prerequisites {
    Write-DeployLog "Performing pre-flight checks..." "INFO"
    $issues = @()
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $issues += "PowerShell version $($PSVersionTable.PSVersion) is too old. Requires 5.1+"
    } else {
        Write-DeployLog "PowerShell version: $($PSVersionTable.PSVersion)" "SUCCESS"
    }
    
    # Check admin privileges
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        $issues += "Not running as Administrator"
    } else {
        Write-DeployLog "Administrator privileges confirmed" "SUCCESS"
    }
    
    # Check execution policy
    $execPolicy = Get-ExecutionPolicy
    if ($execPolicy -eq "Restricted") {
        $issues += "PowerShell execution policy is Restricted"
        Write-DeployLog "Attempting to set execution policy..." "WARN"
        try {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
            Write-DeployLog "Execution policy updated" "SUCCESS"
        } catch {
            $issues += "Failed to update execution policy: $($_.Exception.Message)"
        }
    } else {
        Write-DeployLog "Execution policy: $execPolicy" "SUCCESS"
    }
    
    if ((Get-ChildItem ".\Modules\*.ps1" -ErrorAction SilentlyContinue).Count -gt 0) {
        Write-DeployLog "Modules found" "SUCCESS"
    } else {
        $issues += "No modules found in .\Modules\"
    }
    
    # Check main tool exists
    if (-not (Test-Path ".\SystemManager.ps1")) {
        $issues += "SystemManager.ps1 not found"
    } else {
        Write-DeployLog "Main tool script found" "SUCCESS"
    }
    
    # Check disk space (need at least 1GB for logs/backups)
    $drive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }
    $freeSpaceGB = [Math]::Round($drive.FreeSpace / 1GB, 2)
    if ($freeSpaceGB -lt 1) {
        $issues += "Low disk space: $freeSpaceGB GB free (need at least 1GB)"
    } else {
        Write-DeployLog "Disk space: $freeSpaceGB GB free" "SUCCESS"
    }
    
    # Check Windows version
    $osInfo = Get-CimInstance Win32_OperatingSystem
    Write-DeployLog "OS: $($osInfo.Caption) (Build $($osInfo.BuildNumber))" "INFO"
    
    # Check network connectivity
    try {
        $ping = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet
        if ($ping) {
            Write-DeployLog "Network connectivity confirmed" "SUCCESS"
        } else {
            Write-DeployLog "Network connectivity issues detected" "WARN"
        }
    } catch {
        Write-DeployLog "Could not test network connectivity" "WARN"
    }
    
    return $issues
}

function Show-SystemInfo {
    Write-Host "`n=== SYSTEM INFORMATION ===" -ForegroundColor Cyan
    
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $compInfo = Get-CimInstance Win32_ComputerSystem
    
    Write-Host "Computer Name: $($compInfo.Name)" -ForegroundColor White
    Write-Host "OS: $($osInfo.Caption)" -ForegroundColor White
    Write-Host "Build: $($osInfo.BuildNumber)" -ForegroundColor White
    Write-Host "Domain: $($compInfo.Domain)" -ForegroundColor White
    Write-Host "Total RAM: $([Math]::Round($compInfo.TotalPhysicalMemory / 1GB, 2)) GB" -ForegroundColor White
    
    # Check for server roles
    try {
        $features = Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed" } | Select-Object -First 5
        if ($features) {
            Write-Host "Installed Features: $($features.Name -join ', ')..." -ForegroundColor White
        }
    } catch {
        Write-Host "Could not query Windows Features (likely workstation)" -ForegroundColor White
    }
    
    # Check listening ports
    $ports = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique | Select-Object -First 10
    Write-Host "Listening Ports: $($ports -join ', ')..." -ForegroundColor White
}

function Start-DeploymentWizard {
    Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                    AEGIS - Enterprise Security Platform                     ║
║                              Deployment Wizard                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

    # Pre-flight checks
    $issues = Test-Prerequisites
    
    if ($issues.Count -gt 0) {
        Write-Host "`n❌ PRE-FLIGHT CHECK FAILED" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-DeployLog $issue "ERROR"
        }
        Write-Host "`nPlease resolve these issues before proceeding." -ForegroundColor Red
        return $false
    } else {
        Write-Host "`n✅ PRE-FLIGHT CHECK PASSED" -ForegroundColor Green
    }
    
    if ($CheckOnly) {
        Write-Host "`nCheck-only mode complete. System is ready for deployment." -ForegroundColor Green
        return $true
    }
    
    # Show system information
    Show-SystemInfo
    
    # Deployment confirmation
    if (-not $QuickStart) {
        Write-Host "`n=== DEPLOYMENT CONFIRMATION ===" -ForegroundColor Yellow
        Write-Host "This will:" -ForegroundColor White
        Write-Host "  • Identify this system's role and services" -ForegroundColor White
        Write-Host "  • Create comprehensive backups" -ForegroundColor White
        Write-Host "  • Apply appropriate hardening measures" -ForegroundColor White
        Write-Host "  • Start continuous monitoring and detection" -ForegroundColor White
        Write-Host "  • Begin scoring service validation" -ForegroundColor White
        
        $confirm = Read-Host "`nProceed with deployment? (y/N)"
        if ($confirm -ne 'y' -and $confirm -ne 'Y') {
            Write-Host "Deployment cancelled." -ForegroundColor Yellow
            return $false
        }
    }
    
    return $true
}

# Main execution
try {
    if (Start-DeploymentWizard) {
        if (-not $CheckOnly) {
            Write-Host "`n🚀 STARTING SecOps ADAPTIVE TOOL..." -ForegroundColor Green
            Write-Host "Monitor progress in the main tool output below." -ForegroundColor White
            Write-Host "Press Ctrl+C to stop the tool when competition ends.`n" -ForegroundColor White
            
            & ".\SystemManager.ps1"
        }
    }
} catch {
    Write-DeployLog "Deployment failed: $($_.Exception.Message)" "ERROR"
    Write-Host "`nDeployment failed. Check the error above and try again." -ForegroundColor Red
    exit 1
}

Write-Host "`nDeployment script completed." -ForegroundColor Green