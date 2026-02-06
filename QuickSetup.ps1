#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Rapid System Hardening Tool - Competition Deployment
    
.DESCRIPTION
    Fast deployment with network isolation and comprehensive security scanning
    
.PARAMETER IsolateNetwork
    Immediately isolate system from network during hardening
    
.PARAMETER SkipMalwareScan
    Skip comprehensive malware scan (not recommended)
#>

param(
    [switch]$IsolateNetwork = $true,
    [switch]$SkipMalwareScan = $false,
    [switch]$EmergencyMode = $false
)

# Import configuration with security functions
. ".\Config\Configuration.ps1"

$script:SecureLogPath = "C:\CCDC-Logs\RapidDeploy"
$Global:NetworkIsolated = $false
$Global:OriginalFirewallState = $null
$Global:MalwareDetected = $false

function Write-SecureLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss.fff"
    $entry = "[$timestamp][$Level] $Message"
    Add-Content -Path "$script:SecureLogPath\deploy.log" -Value $entry -Force
    if ($Level -eq "ERROR") { Write-Host $entry -ForegroundColor Red }
    elseif ($Level -eq "WARN") { Write-Host $entry -ForegroundColor Yellow }
    else { Write-Host $entry -ForegroundColor Green }
}

function Initialize-SecureEnvironment {
    try {
        # Create secure log directory
        New-Item -Path $script:SecureLogPath -ItemType Directory -Force | Out-Null
        
        # Verify admin privileges
        if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "Administrator privileges required"
        }
        
        # Secure execution policy with proper restoration
        $originalPolicy = Get-ExecutionPolicy -Scope Process
        try {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
            Write-SecureLog "Execution policy temporarily changed to RemoteSigned"
        } catch {
            Write-SecureLog "Failed to change execution policy: $($_.Exception.Message)" "ERROR"
            return $false
        } finally {
            # Always restore original policy
            try {
                Set-ExecutionPolicy -ExecutionPolicy $originalPolicy -Scope Process -Force
                Write-SecureLog "Execution policy restored to $originalPolicy"
            } catch {
                Write-SecureLog "Failed to restore execution policy" "WARN"
            }
        }
        
        Write-SecureLog "Secure environment initialized"
        return $true
    } catch {
        Write-SecureLog "Failed to initialize: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Invoke-NetworkIsolation {
    if (-not $IsolateNetwork) { return }
    
    Write-SecureLog "Isolating system from network..."
    
    try {
        # Backup current firewall state
        $Global:OriginalFirewallState = @{
            DomainProfile = (Get-NetFirewallProfile -Profile Domain).Enabled
            PrivateProfile = (Get-NetFirewallProfile -Profile Private).Enabled
            PublicProfile = (Get-NetFirewallProfile -Profile Public).Enabled
        }
        
        # Use whitelist approach for better security
        Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
        
        # Explicitly allow only required services
        $allowedServices = @(
            @{Port=53; Protocol="UDP"; Name="DNS"},
            @{Port=53; Protocol="TCP"; Name="DNS-TCP"},
            @{Port=80; Protocol="TCP"; Name="HTTP"},
            @{Port=443; Protocol="TCP"; Name="HTTPS"},
            @{Port=88; Protocol="TCP"; Name="Kerberos"},
            @{Port=389; Protocol="TCP"; Name="LDAP"},
            @{Port=636; Protocol="TCP"; Name="LDAPS"},
            @{Port=445; Protocol="TCP"; Name="SMB"},
            @{Port=135; Protocol="TCP"; Name="RPC"},
            @{Port=3268; Protocol="TCP"; Name="GC"},
            @{Port=3269; Protocol="TCP"; Name="GC-SSL"},
            @{Port=123; Protocol="UDP"; Name="NTP"},
            @{Port=8530; Protocol="TCP"; Name="WSUS"}
        )
        
        foreach ($service in $allowedServices) {
            New-NetFirewallRule -DisplayName "CCDC-Allow-$($service.Name)" -Direction Outbound -Protocol $service.Protocol -RemotePort $service.Port -Action Allow -ErrorAction SilentlyContinue
        }
        
        # Allow only essential local traffic
        New-NetFirewallRule -DisplayName "TEMP-Allow-Loopback" -Direction Inbound -InterfaceType Loopback -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "TEMP-Allow-Loopback-Out" -Direction Outbound -InterfaceType Loopback -Action Allow -ErrorAction SilentlyContinue
        
        $Global:NetworkIsolated = $true
        Write-SecureLog "Network isolation active" "WARN"
        
    } catch {
        Write-SecureLog "Network isolation failed: $($_.Exception.Message)" "ERROR"
    }
}

function Invoke-ComprehensiveMalwareScan {
    if ($SkipMalwareScan) { return $true }
    
    Write-SecureLog "Starting comprehensive malware scan..."
    
    try {
        # Quick Defender scan first
        Write-SecureLog "Running Windows Defender quick scan..."
        Start-MpScan -ScanType QuickScan
        
        # Check for suspicious processes
        $suspiciousProcesses = @(
            "mimikatz", "cobalt", "beacon", "meterpreter", "empire", "covenant",
            "bloodhound", "sharphound", "rubeus", "kerberoast", "asrep",
            "psexec", "paexec", "remcom", "winexesvc", "procdump", "dumpert"
        )
        
        $runningProcesses = Get-Process | Select-Object Name, Id, Path, CommandLine
        $detectedThreats = @()
        
        foreach ($process in $runningProcesses) {
            $safeName = Get-SafeString -Input $process.Name
            $safePath = if ($process.Path) { Get-SafeString -Input $process.Path } else { "" }
            
            foreach ($suspicious in $suspiciousProcesses) {
                if ($safeName -like "*$suspicious*" -or $safePath -like "*$suspicious*") {
                    $detectedThreats += $process
                    Write-SecureLog "THREAT: $safeName (PID: $($process.Id))" "ERROR"
                }
            }
        }
        
        # Scan for suspicious files
        $suspiciousLocations = @(
            "$env:TEMP", "$env:APPDATA", "C:\Windows\Temp", "C:\PerfLogs",
            "C:\Users\Public", "$env:USERPROFILE\Downloads"
        )
        
        foreach ($location in $suspiciousLocations) {
            if (Test-Path $location) {
                $recentFiles = Get-ChildItem $location -Recurse -File -ErrorAction SilentlyContinue | 
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) -and $_.Length -gt 1MB }
                
                foreach ($file in $recentFiles) {
                    if ($file.Name -match "(mimikatz|cobalt|beacon|empire|bloodhound|psexec)") {
                        Write-SecureLog "SUSPICIOUS FILE: $($file.FullName)" "ERROR"
                        $Global:MalwareDetected = $true
                    }
                }
            }
        }
        
        # Check for suspicious network connections
        $suspiciousConnections = Get-NetTCPConnection | Where-Object { 
            $_.State -eq "Established" -and 
            $_.RemoteAddress -notmatch "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)" -and
            $_.RemoteAddress -ne "0.0.0.0"
        }
        
        if ($suspiciousConnections) {
            Write-SecureLog "SUSPICIOUS CONNECTIONS DETECTED: $($suspiciousConnections.Count)" "WARN"
            foreach ($conn in $suspiciousConnections) {
                Write-SecureLog "Connection: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)" "WARN"
            }
        }
        
        if ($detectedThreats.Count -gt 0) {
            Write-SecureLog "Terminating $($detectedThreats.Count) suspicious processes..."
            foreach ($threat in $detectedThreats) {
                if (Stop-ProcessSafe -Id $threat.Id -Name $threat.Name) {
                    Write-SecureLog "Terminated: $($threat.Name)"
                }
            }
            $Global:MalwareDetected = $true
        }
        
        if ($Global:MalwareDetected) {
            Write-SecureLog "MALWARE DETECTED - System may be compromised" "ERROR"
            if (-not $EmergencyMode) {
                $continue = Read-Host "Continue deployment despite threats? (y/N)"
                if ($continue -ne 'y') { return $false }
            }
        }
        
        Write-SecureLog "Malware scan completed"
        return $true
        
    } catch {
        Write-SecureLog "Malware scan failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Invoke-RapidHardening {
    Write-SecureLog "Starting rapid hardening sequence..."
    
    try {
        # Critical security controls only (for speed)
        
        # 1. Disable SMBv1 immediately
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
        
        # 2. Enable LSASS protection
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
        
        # 3. Disable NTLMv1
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord
        
        # 4. Enable PowerShell logging
        $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (!(Test-Path $psPath)) { New-Item -Path $psPath -Force | Out-Null }
        Set-ItemProperty -Path $psPath -Name "EnableScriptBlockLogging" -Value 1
        
        # 5. Disable dangerous services
        $dangerousServices = @("RemoteRegistry", "Spooler")
        foreach ($service in $dangerousServices) {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            }
        }
        
        # 6. Enable Windows Defender
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        
        Write-SecureLog "Rapid hardening completed"
        return $true
        
    } catch {
        Write-SecureLog "Rapid hardening failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Restore-NetworkAccess {
    if (-not $Global:NetworkIsolated) { return }
    
    Write-SecureLog "Restoring network access..."
    
    try {
        # Remove temporary rules
        Remove-NetFirewallRule -DisplayName "TEMP-Allow-Loopback*" -ErrorAction SilentlyContinue
        
        # Restore original firewall state
        if ($Global:OriginalFirewallState) {
            Set-NetFirewallProfile -Profile Domain -Enabled $Global:OriginalFirewallState.DomainProfile
            Set-NetFirewallProfile -Profile Private -Enabled $Global:OriginalFirewallState.PrivateProfile
            Set-NetFirewallProfile -Profile Public -Enabled $Global:OriginalFirewallState.PublicProfile
        }
        
        # Set secure defaults
        Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow
        
        # Allow ICMP (required for scoring)
        New-NetFirewallRule -DisplayName "Allow-ICMP-In" -Direction Inbound -Protocol ICMPv4 -Action Allow -ErrorAction SilentlyContinue
        
        $Global:NetworkIsolated = $false
        Write-SecureLog "Network access restored with secure defaults"
        
    } catch {
        Write-SecureLog "Failed to restore network: $($_.Exception.Message)" "ERROR"
    }
}

function Start-RapidDeployment {
    $startTime = Get-Date
    
    Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                         AEGIS RAPID DEPLOYMENT                              ║
║                            Emergency Mode                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Red
    
    try {
        # Phase 1: Initialize secure environment
        if (-not (Initialize-SecureEnvironment)) {
            throw "Environment initialization failed"
        }
        
        # Phase 2: Network isolation
        if ($IsolateNetwork) {
            Invoke-NetworkIsolation
        }
        
        # Phase 3: Malware scan
        if (-not (Invoke-ComprehensiveMalwareScan)) {
            throw "Malware scan failed or threats detected"
        }
        
        # Phase 4: Rapid hardening
        if (-not (Invoke-RapidHardening)) {
            throw "Rapid hardening failed"
        }
        
        # Phase 5: Restore network (if isolated)
        if ($Global:NetworkIsolated) {
            Restore-NetworkAccess
        }
        
        $duration = (Get-Date) - $startTime
        Write-SecureLog "Rapid deployment completed in $($duration.TotalSeconds) seconds" "SUCCESS"
        
        if (Test-Path ".\SystemManager.ps1") {
            Write-SecureLog "Launching main security tool..."
            & ".\SystemManager.ps1" -TestMode
        }
        
    } catch {
        Write-SecureLog "DEPLOYMENT FAILED: $($_.Exception.Message)" "ERROR"
        
        # Emergency cleanup
        if ($Global:NetworkIsolated) {
            Restore-NetworkAccess
        }
        
        exit 1
    }
}

# Execute rapid deployment
Start-RapidDeployment