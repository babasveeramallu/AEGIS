@echo off
REM Emergency Killswitch - Quick Activation
echo.
echo ========================================
echo   EMERGENCY NETWORK KILLSWITCH
echo ========================================
echo.
echo This will IMMEDIATELY isolate this system
echo from ALL network traffic.
echo.
pause

powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block; Get-NetFirewallRule | Where-Object { $_.Action -eq 'Allow' } | Disable-NetFirewallRule; New-NetFirewallRule -DisplayName 'KILLSWITCH-Loopback' -Direction Inbound -InterfaceType Loopback -Action Allow -ErrorAction SilentlyContinue; Write-Host '[KILLSWITCH ACTIVATED - SYSTEM ISOLATED]' -ForegroundColor Red"

echo.
echo System is now isolated from network.
echo To restore: Run Emergency-Killswitch.ps1 -Restore
echo.
pause
