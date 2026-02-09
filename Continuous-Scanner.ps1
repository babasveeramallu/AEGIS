#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Network-Wide Port Monitor with Live Color-Coded Dashboard
    
.DESCRIPTION
    - Scans all machines every 10 minutes
    - Logs system changes every 3 minutes
    - Runs vulnerability checks every 10 minutes
    - Displays live color-coded port table
    
.PARAMETER Targets
    Array of IP addresses to scan (comma-separated)
    Example: .\Continuous-Scanner.ps1 -Targets "192.168.1.10","192.168.1.20"
#>

param(
    [string[]]$Targets = @()
)

$Global:ContinuousScanJobs = @()
$Global:PortData = @{}

function Get-SubnetHosts {
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch "^127\." }).IPAddress | Select-Object -First 1
    if (-not $localIP -or $localIP -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
        Write-Host "Invalid local IP detected" -ForegroundColor Red
        return @()
    }
    $subnet = $localIP -replace "\d+$", ""
    Write-Host "Quick scanning subnet: $subnet*" -ForegroundColor Cyan
    $activeHosts = @()
    1..254 | ForEach-Object {
        $ip = "$subnet$_"
        if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1) {
            $activeHosts += $ip
            Write-Host "  Found: $ip" -ForegroundColor Green
        }
    }
    return $activeHosts
}

function Show-PortDashboard {
    Clear-Host
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              AEGIS NETWORK PORT MONITOR - LIVE DASHBOARD                      ║" -ForegroundColor Cyan
    Write-Host "║                         $timestamp                                ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Table header
    $header = "{0,-18} {1,-40} {2,-15} {3,-10}" -f "IP ADDRESS", "OPEN TCP PORTS", "OPEN UDP PORTS", "STATUS"
    Write-Host $header -ForegroundColor White -BackgroundColor DarkGray
    Write-Host ("-" * 85) -ForegroundColor Gray
    
    # Sort by IP
    $sortedIPs = $Global:PortData.Keys | Sort-Object { [System.Version]($_ -replace '[^\d.]', '') }
    
    foreach ($ip in $sortedIPs) {
        $data = $Global:PortData[$ip]
        
        # Format ports
        $tcpPorts = if ($data.TCP.Count -gt 0) { $data.TCP -join ", " } else { "None" }
        $udpPorts = if ($data.UDP.Count -gt 0) { $data.UDP -join ", " } else { "None" }
        
        # Truncate if too long
        if ($tcpPorts.Length -gt 38) { $tcpPorts = $tcpPorts.Substring(0, 35) + "..." }
        if ($udpPorts.Length -gt 13) { $udpPorts = $udpPorts.Substring(0, 10) + "..." }
        
        # Determine status and color
        $status = "NORMAL"
        $color = "Green"
        
        # Check for suspicious ports
        $suspiciousPorts = @(4444, 4445, 5555, 6666, 7777, 8888, 9999, 31337)
        $hasSuspicious = $data.TCP | Where-Object { $_ -in $suspiciousPorts }
        
        if ($hasSuspicious) {
            $status = "SUSPICIOUS"
            $color = "Red"
        } elseif ($data.TCP.Count -gt 15) {
            $status = "MANY PORTS"
            $color = "Yellow"
        } elseif ($data.TCP.Count -eq 0) {
            $status = "FILTERED"
            $color = "Gray"
        }
        
        $line = "{0,-18} {1,-40} {2,-15} {3,-10}" -f $ip, $tcpPorts, $udpPorts, $status
        Write-Host $line -ForegroundColor $color
    }
    
    Write-Host ""
    Write-Host "Legend: " -ForegroundColor White -NoNewline
    Write-Host "GREEN=Normal " -ForegroundColor Green -NoNewline
    Write-Host "YELLOW=Many Ports " -ForegroundColor Yellow -NoNewline
    Write-Host "RED=Suspicious " -ForegroundColor Red -NoNewline
    Write-Host "GRAY=Filtered" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Refreshes every 30 seconds | Full scan every 10 minutes | Press Ctrl+C to stop" -ForegroundColor Cyan
}

function Start-ContinuousSecurityScanning {
    # Auto-detect targets if not provided
    if ($Targets.Count -eq 0) {
        Write-Host "[AUTO-DETECTING NETWORK HOSTS]" -ForegroundColor Yellow
        $Targets = Get-SubnetHosts
        Write-Host "Found $($Targets.Count) active hosts" -ForegroundColor Green
        Start-Sleep -Seconds 2
    }
    
    # Initialize port data
    foreach ($target in $Targets) {
        $Global:PortData[$target] = @{
            TCP = @()
            UDP = @()
            LastScan = $null
        }
    }
    
    Write-Host "[STARTING CONTINUOUS SECURITY SCANNING]" -ForegroundColor Cyan
    
    # Job 1: Network-Wide Port Scanner (every 10 minutes)
    $portScanJob = Start-Job -ScriptBlock {
        param($Targets, $LogPath)
        
        while ($true) {
            try {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $scanResults = @{}
                
                foreach ($target in $Targets) {
                    $tcpPorts = @()
                    $udpPorts = @()
                    
                    # Common TCP ports to scan
                    $commonTCP = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080, 8443, 3306, 5432, 1433, 27017, 4444, 5555, 6666, 7777, 8888, 9999)
                    
                    foreach ($port in $commonTCP) {
                        $result = Test-NetConnection -ComputerName $target -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                        if ($result) {
                            $tcpPorts += $port
                        }
                    }
                    
                    $scanResults[$target] = @{
                        TCP = $tcpPorts
                        UDP = $udpPorts
                        LastScan = $timestamp
                    }
                }
                
                # Export results for main thread
                $scanResults | Export-Clixml "$LogPath\port_scan_results.xml" -Force
                
                # Log to file
                "[$timestamp] Scanned $($Targets.Count) hosts" | Out-File "$LogPath\port_scans.log" -Append
                
                Start-Sleep -Seconds 600  # 10 minutes
                
            } catch {
                "Port scan error: $($_.Exception.Message)" | Out-File "$LogPath\scan_errors.log" -Append
                Start-Sleep -Seconds 600
            }
        }
    } -ArgumentList $Targets, "C:\Security-Logs"
    
    # Job 2: System Change Logger (every 3 minutes)
    $changeJob = Start-Job -ScriptBlock {
        param($LogPath)
        
        # Baseline
        $baseline = @{
            Services = (Get-Service | Select-Object Name, Status, StartType | ConvertTo-Json -Compress)
            ScheduledTasks = (Get-ScheduledTask | Select-Object TaskName, State | ConvertTo-Json -Compress)
            FirewallRules = (Get-NetFirewallRule | Select-Object DisplayName, Enabled | ConvertTo-Json -Compress)
            Users = (Get-LocalUser | Select-Object Name, Enabled | ConvertTo-Json -Compress)
        }
        
        while ($true) {
            try {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $changes = @()
                
                # Check services
                $currentServices = Get-Service | Select-Object Name, Status, StartType | ConvertTo-Json -Compress
                if ($currentServices -ne $baseline.Services) {
                    $changes += "Services changed"
                    $baseline.Services = $currentServices
                }
                
                # Check scheduled tasks
                $currentTasks = Get-ScheduledTask | Select-Object TaskName, State | ConvertTo-Json -Compress
                if ($currentTasks -ne $baseline.ScheduledTasks) {
                    $changes += "Scheduled tasks changed"
                    $baseline.ScheduledTasks = $currentTasks
                }
                
                # Check firewall rules
                $currentFW = Get-NetFirewallRule | Select-Object DisplayName, Enabled | ConvertTo-Json -Compress
                if ($currentFW -ne $baseline.FirewallRules) {
                    $changes += "Firewall rules changed"
                    $baseline.FirewallRules = $currentFW
                }
                
                # Check users
                $currentUsers = Get-LocalUser | Select-Object Name, Enabled | ConvertTo-Json -Compress
                if ($currentUsers -ne $baseline.Users) {
                    $changes += "User accounts changed"
                    $baseline.Users = $currentUsers
                }
                
                # Log changes
                if ($changes.Count -gt 0) {
                    $logEntry = "[$timestamp] CHANGES DETECTED: $($changes -join ', ')"
                    $logEntry | Out-File "$LogPath\system_changes.log" -Append
                }
                
                Start-Sleep -Seconds 180  # 3 minutes
                
            } catch {
                "Change detection error: $($_.Exception.Message)" | Out-File "$LogPath\scan_errors.log" -Append
                Start-Sleep -Seconds 180
            }
        }
    } -ArgumentList "C:\Security-Logs"
    
    # Job 3: Vulnerability Scanner (every 10 minutes)
    $vulnJob = Start-Job -ScriptBlock {
        param($LogPath)
        
        while ($true) {
            try {
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                
                $vulns = @{
                    UnpatchedServices = @()
                    WeakConfigs = @()
                }
                
                # Check for dangerous services
                $services = Get-Service | Where-Object { $_.Status -eq "Running" }
                foreach ($svc in $services) {
                    if ($svc.Name -in @("RemoteRegistry", "Spooler", "SNMP", "Telnet")) {
                        $vulns.UnpatchedServices += "$($svc.Name) - Should be disabled"
                    }
                }
                
                # Check firewall
                $allowRules = Get-NetFirewallRule | Where-Object { 
                    $_.Enabled -eq $true -and $_.Action -eq "Allow" -and $_.Direction -eq "Inbound"
                }
                if ($allowRules.Count -gt 50) {
                    $vulns.WeakConfigs += "Too many inbound allow rules: $($allowRules.Count)"
                }
                
                $result = [PSCustomObject]@{
                    Timestamp = $timestamp
                    VulnerabilitiesFound = ($vulns.UnpatchedServices.Count + $vulns.WeakConfigs.Count)
                    Details = $vulns
                }
                
                $result | ConvertTo-Json -Compress | Out-File "$LogPath\vuln_scans.log" -Append
                
                Start-Sleep -Seconds 600  # 10 minutes
                
            } catch {
                "Vuln scan error: $($_.Exception.Message)" | Out-File "$LogPath\scan_errors.log" -Append
                Start-Sleep -Seconds 600
            }
        }
    } -ArgumentList "C:\Security-Logs"
    
    $Global:ContinuousScanJobs = @($portScanJob, $changeJob, $vulnJob)
    
    Write-Host "[CONTINUOUS SCANNING ACTIVE]" -ForegroundColor Green
    Write-Host "  Network port scans: Every 10 minutes" -ForegroundColor Cyan
    Write-Host "  System change logging: Every 3 minutes" -ForegroundColor Cyan
    Write-Host "  Vulnerability scans: Every 10 minutes" -ForegroundColor Cyan
    Write-Host "  Monitoring $($Targets.Count) hosts" -ForegroundColor Cyan
    Write-Host "`nLogs: C:\Security-Logs\" -ForegroundColor Yellow
    
    # Initial scan
    Write-Host "`nPerforming initial scan..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    
    # Live dashboard loop
    while ($true) {
        # Load latest scan results
        $resultsFile = "C:\Security-Logs\port_scan_results.xml"
        if (Test-Path $resultsFile) {
            try {
                $scanData = Import-Clixml $resultsFile
                foreach ($ip in $scanData.Keys) {
                    $Global:PortData[$ip] = $scanData[$ip]
                }
            } catch {
                # Ignore read errors
            }
        }
        
        # Display dashboard
        Show-PortDashboard
        
        # Refresh every 30 seconds
        Start-Sleep -Seconds 30
    }
}

function Stop-ContinuousSecurityScanning {
    Write-Host "[STOPPING CONTINUOUS SCANNING]" -ForegroundColor Yellow
    
    foreach ($job in $Global:ContinuousScanJobs) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -ErrorAction SilentlyContinue
    }
    
    $Global:ContinuousScanJobs = @()
    Write-Host "All scan jobs stopped" -ForegroundColor Green
}

# Auto-start if run directly
if ($MyInvocation.InvocationName -ne '.') {
    # Create log directory
    if (!(Test-Path "C:\Security-Logs")) {
        New-Item -Path "C:\Security-Logs" -ItemType Directory -Force | Out-Null
    }
    
    try {
        Start-ContinuousSecurityScanning
    } finally {
        Stop-ContinuousSecurityScanning
    }
}
