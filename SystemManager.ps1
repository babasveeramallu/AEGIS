#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AEGIS - Adaptive Enterprise Guardian & Intrusion Shield

.DESCRIPTION
    Enterprise security automation platform

.AUTHOR
    Baba

.VERSION
    2.0
#>

param(
    [switch]$SkipBackup,
    [switch]$ForceRollback,
    [string]$ConfigPath = ".\Config\",
    [switch]$TestMode
)

$Global:ToolVersion = "2.0"
$Global:SystemProfile = $null
$Global:BackupPath = "C:\SystemBackups"
$Global:LogPath = "C:\SystemLogs"
$Global:DetectionActive = $false

$ModulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
. "$ModulePath\Config\Configuration.ps1"
Get-ChildItem "$ModulePath\Modules\*.ps1" | ForEach-Object { . $_.FullName }

function Write-SecLog {
    param([string]$Message, [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        "INFO"    { Write-Host $logEntry -ForegroundColor White }
        "WARN"    { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
    }
    if (!(Test-Path $Global:LogPath)) { New-Item -Path $Global:LogPath -ItemType Directory -Force | Out-Null }
    Add-Content -Path "$Global:LogPath\system.log" -Value $logEntry
}

function Initialize-Tool {
    Write-SecLog "AEGIS v$Global:ToolVersion" "SUCCESS"
    @($Global:BackupPath, $Global:LogPath, "$ModulePath\Config", "$ModulePath\Reports") | ForEach-Object {
        if (!(Test-Path $_)) { New-Item -Path $_ -ItemType Directory -Force | Out-Null }
    }
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-SecLog "Administrator privileges required" "ERROR"
        exit 1
    }
}

function Start-AdaptiveTool {
    try {
        Initialize-Tool
        $Global:SystemProfile = Invoke-SystemIdentification
        $Global:AdvancedProfile = Invoke-AdvancedSystemAnalysis -SystemProfile $Global:SystemProfile
        
        if ($ForceRollback) {
            Invoke-SystemRollback
            return
        }
        
        if (-not $SkipBackup) {
            $backupResult = Invoke-SystemBackup -SystemProfile $Global:SystemProfile
            if (-not $backupResult) { return }
            $Global:SystemProfile.BackupCompleted = $true
        }
        
        Invoke-SystemHardening -SystemProfile $Global:SystemProfile
        Invoke-AdvancedHardening -SystemProfile $Global:SystemProfile
        
        $vulnerabilities = Invoke-SecurityVulnerabilityAssessment -DeepScan
        if ($vulnerabilities.Malware.Count -gt 0) {
            Invoke-ThreatMitigation -Vulnerabilities $vulnerabilities
        }
        
        Start-MonitoringModule -SystemProfile $Global:SystemProfile
        Start-DetectionModule -SystemProfile $Global:SystemProfile
        $Global:DetectionActive = $true
        Deploy-AdvancedHoneypots -SystemProfile $Global:SystemProfile
        Start-IncidentResponseModule -SystemProfile $Global:SystemProfile
        Start-ScoringValidation -SystemProfile $Global:SystemProfile
        
        Write-SecLog "All systems operational" "SUCCESS"
        
        if (-not $TestMode) {
            while ($true) { Start-Sleep -Seconds 30 }
        }
    } catch {
        Write-SecLog "ERROR: $($_.Exception.Message)" "ERROR"
        if ($Global:DetectionActive) { Stop-DetectionModule }
    }
}

$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    if ($Global:DetectionActive) { Stop-DetectionModule }
}

Start-AdaptiveTool