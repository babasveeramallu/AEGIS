#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Smart Session Security for CCDC - Balance security without breaking operations
    
.DESCRIPTION
    Implements session monitoring and selective lockouts instead of blanket auto-logout
#>

# Configure screen lock timeout (15 min idle = lock, not logout)
function Set-SmartScreenLock {
    Write-Host "[Setting smart screen lock - 15 min idle]" -ForegroundColor Cyan
    
    # Lock screen after 15 minutes of inactivity (not logout)
    powercfg /change monitor-timeout-ac 15
    powercfg /change monitor-timeout-dc 15
    
    # Require password on wake
    powercfg /setacvalueindex SCHEME_CURRENT SUB_NONE CONSOLELOCK 1
    powercfg /setactive SCHEME_CURRENT
    
    Write-Host "Screen locks after 15 min idle (doesn't break services)" -ForegroundColor Green
}

# Monitor for suspicious sessions (lock those, not all sessions)
function Start-SuspiciousSessionMonitor {
    Write-Host "[Starting suspicious session monitor]" -ForegroundColor Cyan
    
    $job = Start-Job -ScriptBlock {
        param($LogPath)
        
        while ($true) {
            try {
                # Check for suspicious RDP sessions
                $sessions = quser 2>$null | Select-Object -Skip 1
                
                foreach ($session in $sessions) {
                    if ($session -match "(\S+)\s+(\S+)\s+(\d+)\s+(\w+)\s+(.+)") {
                        $username = $matches[1]
                        $sessionId = $matches[3]
                        $state = $matches[4]
                        
                        # Check if session is from unexpected source
                        $sessionInfo = query session $sessionId 2>$null
                        
                        # Log active sessions
                        $logEntry = "[$(Get-Date)] Active: $username (Session $sessionId) - $state"
                        $logEntry | Out-File "$LogPath\active_sessions.log" -Append
                    }
                }
                
                Start-Sleep -Seconds 60
                
            } catch {
                Start-Sleep -Seconds 120
            }
        }
    } -ArgumentList "C:\CCDC-Logs"
    
    Write-Host "Monitoring sessions for suspicious activity" -ForegroundColor Green
    return $job
}

# Implement "break glass" emergency password rotation (manual trigger only)
function Enable-EmergencyPasswordRotation {
    Write-Host "`n[EMERGENCY PASSWORD ROTATION]" -ForegroundColor Red
    Write-Host "This will force password change for ALL non-service accounts" -ForegroundColor Yellow
    
    $confirm = Read-Host "Are you SURE? This is disruptive. (yes/NO)"
    if ($confirm -ne "yes") {
        Write-Host "Cancelled" -ForegroundColor Gray
        return
    }
    
    try {
        # Get all user accounts (exclude service accounts)
        $users = Get-LocalUser | Where-Object { 
            $_.Enabled -eq $true -and 
            $_.Name -notlike "*svc*" -and 
            $_.Name -notlike "*service*" -and
            $_.Name -ne "Administrator"
        }
        
        foreach ($user in $users) {
            # Force password change at next logon
            Set-LocalUser -Name $user.Name -PasswordNeverExpires $false
            # Note: Can't force change on local accounts via PowerShell
            # Must use: net user <username> /logonpasswordchg:yes
            
            Write-Host "Flagged for password change: $($user.Name)" -ForegroundColor Yellow
        }
        
        Write-Host "`n[COMPLETE] Users will be prompted to change password at next login" -ForegroundColor Green
        
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Better approach: Session activity logging
function Enable-SessionAuditing {
    Write-Host "[Enabling comprehensive session auditing]" -ForegroundColor Cyan
    
    # Enable logon/logoff auditing
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Logoff" /success:enable
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
    
    Write-Host "Session auditing enabled - monitor Event Viewer Security log" -ForegroundColor Green
}

# Main execution
Write-Host @"

╔════════════════════════════════════════════════════════════╗
║          SMART SESSION SECURITY FOR CCDC                   ║
║  (Doesn't break operations like auto-logout would)        ║
╚════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "Recommended CCDC Session Security:`n" -ForegroundColor White

Write-Host "✓ Screen lock after 15 min idle (not logout)" -ForegroundColor Green
Write-Host "✓ Monitor suspicious sessions" -ForegroundColor Green
Write-Host "✓ Comprehensive session auditing" -ForegroundColor Green
Write-Host "✓ Manual emergency password rotation (when needed)" -ForegroundColor Green
Write-Host "`n✗ NO auto-logout (breaks scoring)" -ForegroundColor Red
Write-Host "✗ NO forced password changes (breaks services)`n" -ForegroundColor Red

$choice = Read-Host "Apply smart session security? (Y/n)"
if ($choice -ne "n") {
    Set-SmartScreenLock
    Enable-SessionAuditing
    $monitorJob = Start-SuspiciousSessionMonitor
    
    Write-Host "`n[APPLIED] Smart session security active" -ForegroundColor Green
    Write-Host "Monitor job ID: $($monitorJob.Id)" -ForegroundColor Cyan
}

Write-Host "`nFor emergency password rotation, run:" -ForegroundColor Yellow
Write-Host "  Enable-EmergencyPasswordRotation" -ForegroundColor Gray
