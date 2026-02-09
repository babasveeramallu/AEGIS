#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Safe Testing Script - Read-Only Operations Only
    
.DESCRIPTION
    Tests SecOps scripts without making system changes
    Safe to run on your personal machine
#>

Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║          SecOps SCRIPTS - SAFE TESTING MODE                    ║
║          Read-Only Operations - No System Changes            ║
╚══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "This script will ONLY perform read-only tests." -ForegroundColor Green
Write-Host "No system changes will be made.`n" -ForegroundColor Green

$confirm = Read-Host "Continue with safe testing? (Y/n)"
if ($confirm -eq 'n') { exit }

# Import modules
$ModulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
Get-ChildItem "$ModulePath\Modules\*.ps1" -ErrorAction SilentlyContinue | ForEach-Object { . $_.FullName }

$Global:LogPath = "C:\Security-Logs"
if (!(Test-Path $Global:LogPath)) {
    New-Item -Path $Global:LogPath -ItemType Directory -Force | Out-Null
}

Write-Host "`n[TEST 1: System Information]" -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "  OS: $($os.Caption)" -ForegroundColor White
Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  Admin: $(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))" -ForegroundColor White

Write-Host "`n[TEST 2: Network Connectivity]" -ForegroundColor Yellow
if (Get-Command Test-NetworkConnectivity -ErrorAction SilentlyContinue) {
    Test-NetworkConnectivity
} else {
    Write-Host "  Testing basic connectivity..." -ForegroundColor White
    $ping = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet
    Write-Host "  Internet: $ping" -ForegroundColor $(if($ping){"Green"}else{"Red"})
}

Write-Host "`n[TEST 3: Running Services]" -ForegroundColor Yellow
$services = Get-Service | Where-Object Status -eq "Running"
Write-Host "  Running services: $($services.Count)" -ForegroundColor White
Write-Host "  Critical services:" -ForegroundColor White
@("Winmgmt", "Dhcp", "Dnscache", "EventLog") | ForEach-Object {
    $svc = Get-Service -Name $_ -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "    $_ : $($svc.Status)" -ForegroundColor $(if($svc.Status -eq "Running"){"Green"}else{"Red"})
    }
}

Write-Host "`n[TEST 4: Open Ports]" -ForegroundColor Yellow
$ports = Get-NetTCPConnection | Where-Object State -eq "Listen" | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object
Write-Host "  Listening ports: $($ports -join ', ')" -ForegroundColor White

Write-Host "`n[TEST 5: Firewall Status]" -ForegroundColor Yellow
$fw = Get-NetFirewallProfile
foreach ($profile in $fw) {
    Write-Host "  $($profile.Name): Enabled=$($profile.Enabled), Inbound=$($profile.DefaultInboundAction)" -ForegroundColor White
}

Write-Host "`n[TEST 6: Windows Defender]" -ForegroundColor Yellow
try {
    $defender = Get-MpComputerStatus
    Write-Host "  Real-time Protection: $($defender.RealTimeProtectionEnabled)" -ForegroundColor $(if($defender.RealTimeProtectionEnabled){"Green"}else{"Red"})
    Write-Host "  Antivirus Enabled: $($defender.AntivirusEnabled)" -ForegroundColor $(if($defender.AntivirusEnabled){"Green"}else{"Red"})
} catch {
    Write-Host "  Could not check Defender status" -ForegroundColor Yellow
}

Write-Host "`n[TEST 7: Disk Space]" -ForegroundColor Yellow
$drive = Get-WmiObject -Class Win32_LogicalDisk | Where-Object DeviceID -eq "C:"
$freeGB = [Math]::Round($drive.FreeSpace / 1GB, 2)
Write-Host "  C: drive free space: $freeGB GB" -ForegroundColor $(if($freeGB -gt 10){"Green"}else{"Red"})

Write-Host "`n[TEST 8: PowerShell Version]" -ForegroundColor Yellow
Write-Host "  Version: $($PSVersionTable.PSVersion)" -ForegroundColor White
Write-Host "  Execution Policy: $(Get-ExecutionPolicy)" -ForegroundColor White

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║          SAFE TESTING COMPLETE - NO CHANGES MADE             ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`nTo test with system changes, use a VM or Windows Sandbox." -ForegroundColor Yellow
Write-Host "Never run full deployment on your personal machine!`n" -ForegroundColor Red
