# Phase 1 - Hardening Module
# Each sub-section is a playbook. The tool only runs the playbooks that match the system profile from Phase 0.
# Universal hardening runs on every machine regardless.

function Invoke-SystemHardening {
    param([PSCustomObject]$SystemProfile)
    
    Write-SecLog "Starting system hardening based on detected role: $($SystemProfile.DetectedRole)" "INFO"
    
    # CRITICAL: Get baseline BEFORE any hardening
    $baseline = Test-ScoringServicesBaseline
    
    try {
        # Always run Universal Hardening first
        Invoke-UniversalHardening
        
        # IMMEDIATE validation after universal hardening
        if (-not (Test-ScoringServicesHealth -Baseline $baseline)) {
            Write-SecLog "Universal hardening broke scoring services - initiating rollback" "ERROR"
            Invoke-SystemRollback
            return $false
        }
        
        # Run role-specific hardening with validation after each
        switch ($SystemProfile.DetectedRole) {
            "ActiveDirectory_DNS" {
                if ($SystemProfile.Confidence -gt 0.90) {
                    Invoke-ADDNSHardening -SystemProfile $SystemProfile
                    if (-not (Test-ScoringServicesHealth -Baseline $baseline)) {
                        Write-SecLog "AD/DNS hardening broke services - initiating rollback" "ERROR"
                        Invoke-SystemRollback
                        return $false
                    }
                } else {
                    Write-SecLog "Confidence too low for AD/DNS hardening. Running universal only." "WARN"
                }
            }
            "WebServer" {
                if ($SystemProfile.Confidence -gt 0.85) {
                    Invoke-WebServerHardening -SystemProfile $SystemProfile
                    if (-not (Test-ScoringServicesHealth -Baseline $baseline)) {
                        Write-SecLog "Web Server hardening broke services - initiating rollback" "ERROR"
                        Invoke-SystemRollback
                        return $false
                    }
                } else {
                    Write-SecLog "Confidence too low for Web Server hardening. Running universal only." "WARN"
                }
            }
            "FTPServer" {
                if ($SystemProfile.Confidence -gt 0.85) {
                    Invoke-FTPServerHardening -SystemProfile $SystemProfile
                    if (-not (Test-ScoringServicesHealth -Baseline $baseline)) {
                        Write-SecLog "FTP Server hardening broke services - initiating rollback" "ERROR"
                        Invoke-SystemRollback
                        return $false
                    }
                } else {
                    Write-SecLog "Confidence too low for FTP Server hardening. Running universal only." "WARN"
                }
            }
            "Workstation" {
                if ($SystemProfile.Confidence -gt 0.80) {
                    Invoke-WorkstationHardening -SystemProfile $SystemProfile
                    if (-not (Test-ScoringServicesHealth -Baseline $baseline)) {
                        Write-SecLog "Workstation hardening broke services - initiating rollback" "ERROR"
                        Invoke-SystemRollback
                        return $false
                    }
                } else {
                    Write-SecLog "Confidence too low for Workstation hardening. Running universal only." "WARN"
                }
            }
            "UNKNOWN" {
                Write-SecLog "Unknown system type. Universal hardening only." "WARN"
            }
        }
        
        Write-SecLog "System hardening completed successfully - all scoring services operational" "SUCCESS"
        return $true
        
    } catch {
        Write-SecLog "Error during system hardening: $($_.Exception.Message)" "ERROR"
        Write-SecLog "Initiating emergency rollback" "WARN"
        Invoke-SystemRollback
        return $false
    }
}

function Invoke-UniversalHardening {
    Write-SecLog "=== UNIVERSAL HARDENING (ALL SYSTEMS) ===" "INFO"
    
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-SecLog "SMBv1 disabled" "SUCCESS"
    } catch { Write-SecLog "SMBv1 disable failed: $($_.Exception.Message)" "ERROR" }
    
    try {
        $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
        if (!(Test-Path $psPath)) { New-Item -Path $psPath -Force | Out-Null }
        
        $scriptBlockPath = "$psPath\ScriptBlockLogging"
        if (!(Test-Path $scriptBlockPath)) { New-Item -Path $scriptBlockPath -Force | Out-Null }
        Set-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -Value 1
        
        $transcriptionPath = "$psPath\Transcription"
        if (!(Test-Path $transcriptionPath)) { New-Item -Path $transcriptionPath -Force | Out-Null }
        Set-ItemProperty -Path $transcriptionPath -Name "EnableTranscripting" -Value 1
        Set-ItemProperty -Path $transcriptionPath -Name "OutputDirectory" -Value "C:\Security-Logs\PowerShell"
        
        Write-SecLog "PowerShell logging enabled" "SUCCESS"
    } catch { Write-SecLog "PowerShell logging failed: $($_.Exception.Message)" "ERROR" }
    
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Engine" -NoRestart
        Write-SecLog "PowerShell v2 disabled" "SUCCESS"
    } catch { Write-SecLog "PowerShell v2 disable failed" "WARN" }
    
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" -Name "DisableRpcOverTcp" -Value 1
        Write-SecLog "Remote scheduled tasks disabled" "SUCCESS"
    } catch { Write-SecLog "Remote task disable failed" "WARN" }
    
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block
        
        Remove-NetFirewallRule -DisplayName "*ICMP*" -ErrorAction SilentlyContinue
        
        New-NetFirewallRule -DisplayName "Allow-ICMPv4-In" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "Allow-ICMPv4-Out" -Direction Outbound -Protocol ICMPv4 -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "Allow-ICMPv6-In" -Direction Inbound -Protocol ICMPv6 -IcmpType 128 -Action Allow -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "Allow-ICMPv6-Out" -Direction Outbound -Protocol ICMPv6 -Action Allow -ErrorAction SilentlyContinue
        
        Write-SecLog "Firewall configured with ICMP" "SUCCESS"
        
        if (-not (Test-NetworkConnectivity)) {
            Write-SecLog "WARNING: Network connectivity broken" "ERROR"
        }
    } catch { Write-SecLog "Firewall config failed: $($_.Exception.Message)" "ERROR" }
}

function Invoke-ADDNSHardening {
    param([PSCustomObject]$SystemProfile)
    
    Write-SecLog "=== AD/DNS HARDENING ===" "INFO"
    
    try {
        $adminAccount = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith("-500") }
        if ($adminAccount) {
            $newName = "SecAdmin_$(Get-Random -Minimum 1000 -Maximum 9999)"
            Rename-LocalUser -Name $adminAccount.Name -NewName $newName
            Disable-LocalUser -Name $newName
            Write-SecLog "Admin renamed to $newName and disabled" "SUCCESS"
        }
    } catch { Write-SecLog "Admin secure failed: $($_.Exception.Message)" "ERROR" }
    
    try {
        net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
        Write-SecLog "Password policy enforced" "SUCCESS"
    } catch { Write-SecLog "Password policy failed: $($_.Exception.Message)" "ERROR" }
    
    try {
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (!(Test-Path $llmnrPath)) { New-Item -Path $llmnrPath -Force | Out-Null }
        Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0
        
        $nbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
        Get-ChildItem $nbtPath | ForEach-Object {
            Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -ErrorAction SilentlyContinue
        }
        
        Write-SecLog "LLMNR/NBT-NS disabled" "SUCCESS"
    } catch { Write-SecLog "LLMNR/NBT-NS disable failed: $($_.Exception.Message)" "ERROR" }
    
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LdapClientIntegrityLevel" -Value 2
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LdapServerIntegrityLevel" -Value 2
        Write-SecLog "LDAP signing enforced" "SUCCESS"
    } catch { Write-SecLog "LDAP signing failed: $($_.Exception.Message)" "ERROR" }
    
    try {
        auditpol /set /category:"Account Logon" /success:enable /failure:enable
        auditpol /set /category:"Account Management" /success:enable /failure:enable
        auditpol /set /category:"Directory Service Access" /success:enable /failure:enable
        Write-SecLog "AD audit logging enabled" "SUCCESS"
    } catch { Write-SecLog "AD audit failed: $($_.Exception.Message)" "ERROR" }
}

function Invoke-WebServerHardening {
    param([PSCustomObject]$SystemProfile)
    
    Write-SecLog "=== WEB SERVER HARDENING ===" "INFO"
    
    try {
        Import-Module WebAdministration -ErrorAction Stop
        
        @("iisstart.htm", "welcome.png") | ForEach-Object {
            $filePath = "C:\inetpub\wwwroot\$_"
            if (Test-Path $filePath) { Remove-Item $filePath -Force }
        }
        
        Set-WebConfigurationProperty -Filter "system.webServer/directoryBrowse" -Name enabled -Value $false
        Remove-WebConfigurationProperty -Filter "system.webServer/modules" -Name "." -AtElement @{name="WebDAVModule"} -ErrorAction SilentlyContinue
        Set-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/requestLimits" -Name maxAllowedContentLength -Value 30000000
        Set-WebConfigurationProperty -Filter "system.web/httpRuntime" -Name maxRequestLength -Value 30000
        
        $webrootPath = "C:\inetpub\wwwroot"
        if (Test-Path $webrootPath) {
            $baseline = Get-ChildItem $webrootPath -Recurse -File | ForEach-Object {
                [PSCustomObject]@{
                    Path = $_.FullName
                    Hash = (Get-FileHash $_.FullName).Hash
                    LastModified = $_.LastWriteTime
                }
            }
            $baseline | Export-Csv "$Global:BackupPath\webroot_baseline.csv" -NoTypeInformation
            Write-SecLog "Webroot baseline: $($baseline.Count) files" "SUCCESS"
        }
        
        Write-SecLog "Web server hardening complete" "SUCCESS"
    } catch {
        Write-SecLog "Web server hardening failed: $($_.Exception.Message)" "ERROR"
    }
}

function Invoke-FTPServerHardening {
    param([PSCustomObject]$SystemProfile)
    
    Write-SecLog "=== FTP SERVER HARDENING ===" "INFO"
    
    try {
        Set-WebConfigurationProperty -Filter "system.ftpServer/log" -Name enabled -Value $true -PSPath "IIS:\" -ErrorAction SilentlyContinue
        Write-SecLog "FTP logging enabled" "SUCCESS"
    } catch {
        Write-SecLog "FTP hardening failed: $($_.Exception.Message)" "ERROR"
    }
}

function Invoke-WorkstationHardening {
    param([PSCustomObject]$SystemProfile)
    
    Write-SecLog "=== WORKSTATION HARDENING ===" "INFO"
    
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableBlockAtFirstSeen $false -MAPSReporting Advanced
        Write-SecLog "Windows Defender configured" "SUCCESS"
    } catch { Write-SecLog "Defender config failed: $($_.Exception.Message)" "ERROR" }
    
    try {
        Disable-PSRemoting -Force
        Write-SecLog "PowerShell remoting disabled" "SUCCESS"
    } catch { Write-SecLog "PS remoting disable failed" "WARN" }
    
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
        Write-SecLog "RDP NLA enabled" "SUCCESS"
    } catch { Write-SecLog "RDP config failed" "WARN" }
    
    try {
        wevtutil sl Security /ms:1073741824
        wevtutil sl System /ms:1073741824
        wevtutil sl Application /ms:1073741824
        Write-SecLog "Event log sizes increased" "SUCCESS"
    } catch { Write-SecLog "Event log config failed" "WARN" }
}