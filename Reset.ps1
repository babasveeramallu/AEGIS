#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Emergency Network Killswitch - Isolate compromised system
    
.DESCRIPTION
    Immediately isolates system from network to prevent lateral movement
    Blocks all inbound/outbound traffic except localhost
    
.PARAMETER Restore
    Restore network connectivity from killswitch state
#>

param(
    [switch]$Restore
)

$killswitchMarker = "C:\CCDC-Logs\KILLSWITCH_ACTIVE.flag"

function Invoke-EmergencyKillswitch {
    Write-Host "`n[EMERGENCY KILLSWITCH ACTIVATED]" -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "Isolating system from network..." -ForegroundColor Red
    
    try {
        # Block ALL traffic - nuclear option
        Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
        
        # Remove all existing allow rules
        Get-NetFirewallRule | Where-Object { $_.Action -eq "Allow" } | Disable-NetFirewallRule
        
        # Only allow loopback
        New-NetFirewallRule -DisplayName "KILLSWITCH-Loopback-In" -Direction Inbound -InterfaceType Loopback -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "KILLSWITCH-Loopback-Out" -Direction Outbound -InterfaceType Loopback -Action Allow -ErrorAction SilentlyContinue
        
        # Disable network adapters (optional - uncomment if needed)
        # Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Disable-NetAdapter -Confirm:$false
        
        # Mark killswitch as active
        "ACTIVATED: $(Get-Date)" | Out-File $killswitchMarker
        
        Write-Host "`n[SYSTEM ISOLATED]" -ForegroundColor Green
        Write-Host "All network traffic blocked except localhost" -ForegroundColor Yellow
        Write-Host "To restore: .\Emergency-Killswitch.ps1 -Restore" -ForegroundColor Cyan
        
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

function Restore-NetworkAccess {
    Write-Host "`n[RESTORING NETWORK ACCESS]" -ForegroundColor Yellow
    
    if (-not (Test-Path $killswitchMarker)) {
        Write-Host "Killswitch was not active" -ForegroundColor Gray
        return
    }
    
    try {
        # Re-enable all firewall rules
        Get-NetFirewallRule | Where-Object { $_.DisplayName -notlike "KILLSWITCH-*" } | Enable-NetFirewallRule
        
        # Remove killswitch rules
        Remove-NetFirewallRule -DisplayName "KILLSWITCH-*" -ErrorAction SilentlyContinue
        
        # Restore default firewall to secure but functional state
        Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow
        
        # Re-enable network adapters if disabled
        # Get-NetAdapter | Where-Object { $_.Status -eq "Disabled" } | Enable-NetAdapter -Confirm:$false
        
        # Remove marker
        Remove-Item $killswitchMarker -Force
        
        Write-Host "`n[NETWORK RESTORED]" -ForegroundColor Green
        Write-Host "Firewall returned to secure defaults" -ForegroundColor Cyan
        
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Execute
if ($Restore) {
    Restore-NetworkAccess
} else {
    $confirm = Read-Host "`nACTIVATE EMERGENCY KILLSWITCH? This will BLOCK ALL NETWORK TRAFFIC. (yes/NO)"
    if ($confirm -eq "yes") {
        Invoke-EmergencyKillswitch
    } else {
        Write-Host "Cancelled" -ForegroundColor Gray
    }
}
