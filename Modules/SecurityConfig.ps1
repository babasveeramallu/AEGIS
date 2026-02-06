# Phase 1 - Hardening Module
# Each sub-section is a playbook. The tool only runs the playbooks that match the system profile from Phase 0.
# Universal hardening runs on every machine regardless.

function Invoke-SystemHardening {
    param([PSCustomObject]$SystemProfile)
    
    Write-CCDCLog "Starting system hardening based on detected role: $($SystemProfile.DetectedRole)" "INFO"
    
    try {
        # Always run Universal Hardening first
        Invoke-UniversalHardening
        
        # Run role-specific hardening
        switch ($SystemProfile.DetectedRole) {
            "ActiveDirectory_DNS" {
                if ($SystemProfile.Confidence -gt 0.90) {
                    Invoke-ADDNSHardening -SystemProfile $SystemProfile
                } else {
                    Write-CCDCLog "Confidence too low for AD/DNS hardening. Running universal only." "WARN"
                }
            }
            "WebServer" {
                if ($SystemProfile.Confidence -gt 0.85) {
                    Invoke-WebServerHardening -SystemProfile $SystemProfile
                } else {
                    Write-CCDCLog "Confidence too low for Web Server hardening. Running universal only." "WARN"
                }
            }
            "FTPServer" {
                if ($SystemProfile.Confidence -gt 0.85) {
                    Invoke-FTPServerHardening -SystemProfile $SystemProfile
                } else {
                    Write-CCDCLog "Confidence too low for FTP Server hardening. Running universal only." "WARN"
                }
            }
            "Workstation" {
                if ($SystemProfile.Confidence -gt 0.80) {
                    Invoke-WorkstationHardening -SystemProfile $SystemProfile
                } else {
                    Write-CCDCLog "Confidence too low for Workstation hardening. Running universal only." "WARN"
                }
            }
            "UNKNOWN" {
                Write-CCDCLog "Unknown system type. Universal hardening only." "WARN"
            }
        }
        
        Write-CCDCLog "System hardening completed" "SUCCESS"
        
    } catch {
        Write-CCDCLog "Error during system hardening: $($_.Exception.Message)" "ERROR"
    }
}

function Invoke-UniversalHardening {
    Write-CCDCLog "=== UNIVERSAL HARDENING (ALL SYSTEMS) ===" "INFO"
    
    # 1. Disable SMBv1 everywhere
    Write-CCDCLog "Disabling SMBv1..." "INFO"
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-CCDCLog "SMBv1 disabled successfully" "SUCCESS"
    } catch {
        Write-CCDCLog "Failed to disable SMBv1: $($_.Exception.Message)" "ERROR"
    }
    
    # 2. Enable PowerShell Script Block Logging and Transcription
    Write-CCDCLog "Enabling PowerShell logging..." "INFO"
    try {
        $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
        if (!(Test-Path $psPath)) { New-Item -Path $psPath -Force | Out-Null }
        
        # Script Block Logging
        $scriptBlockPath = "$psPath\ScriptBlockLogging"
        if (!(Test-Path $scriptBlockPath)) { New-Item -Path $scriptBlockPath -Force | Out-Null }
        Set-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -Value 1
        
        # Transcription Logging
        $transcriptionPath = "$psPath\Transcription"
        if (!(Test-Path $transcriptionPath)) { New-Item -Path $transcriptionPath -Force | Out-Null }
        Set-ItemProperty -Path $transcriptionPath -Name "EnableTranscripting" -Value 1
        Set-ItemProperty -Path $transcriptionPath -Name "OutputDirectory" -Value "C:\CCDC-Logs\PowerShell"
        
        Write-CCDCLog "PowerShell logging enabled" "SUCCESS"
    } catch {
        Write-CCDCLog "Failed to enable PowerShell logging: $($_.Exception.Message)" "ERROR"
    }
    
    # 3. Disable PowerShell v2 engine (downgrade attack prevention)
    Write-CCDCLog "Disabling PowerShell v2 engine..." "INFO"
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Engine" -NoRestart
        Write-CCDCLog "PowerShell v2 engine disabled" "SUCCESS"
    } catch {
        Write-CCDCLog "Failed to disable PowerShell v2: $($_.Exception.Message)" "WARN"
    }
    
    # 4. Disable WMI remoting where not required
    Write-CCDCLog "Securing WMI..." "INFO"
    try {
        # Disable WMI service if not critical
        $wmiService = Get-Service -Name "Winmgmt" -ErrorAction SilentlyContinue
        if ($wmiService -and $wmiService.StartType -ne "Disabled") {
            # Don't disable WMI completely as it may break things, just secure it
            Write-CCDCLog "WMI service found - securing instead of disabling" "INFO"
        }
    } catch {
        Write-CCDCLog "WMI security configuration failed: $($_.Exception.Message)" "WARN"
    }
    
    # 5. Disable Remote Scheduled Tasks
    Write-CCDCLog "Disabling remote scheduled tasks..." "INFO"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" -Name "DisableRpcOverTcp" -Value 1
        Write-CCDCLog "Remote scheduled tasks disabled" "SUCCESS"
    } catch {
        Write-CCDCLog "Failed to disable remote scheduled tasks: $($_.Exception.Message)" "WARN"
    }
    
    # 6. Configure Windows Firewall
    Write-CCDCLog "Configuring Windows Firewall..." "INFO"
    try {
        # Enable firewall for all profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        
        # Set default inbound to block
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
        
        # Ensure ICMP is allowed (required for scoring)
        New-NetFirewallRule -DisplayName "Allow ICMP" -Direction Inbound -Protocol ICMPv4 -Action Allow -ErrorAction SilentlyContinue
        
        Write-CCDCLog "Windows Firewall configured" "SUCCESS"
    } catch {
        Write-CCDCLog "Firewall configuration failed: $($_.Exception.Message)" "ERROR"
    }
    
    # 7. Disable WinRM if not used
    Write-CCDCLog "Checking WinRM status..." "INFO"
    try {
        $winrmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
        if ($winrmService -and $winrmService.Status -eq "Running") {
            # Don't auto-disable as it might be needed for management
            Write-CCDCLog "WinRM is running - consider disabling if not needed for management" "WARN"
        }
    } catch {
        Write-CCDCLog "WinRM check failed: $($_.Exception.Message)" "WARN"
    }
}

function Invoke-ADDNSHardening {
    param([PSCustomObject]$SystemProfile)
    
    Write-CCDCLog "=== ACTIVE DIRECTORY & DNS HARDENING ===" "INFO"
    
    # 1. Rename and disable built-in Administrator
    Write-CCDCLog "Securing built-in Administrator account..." "INFO"
    try {
        $adminAccount = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith("-500") }
        if ($adminAccount) {
            $newName = "CCDCAdmin_$(Get-Random -Minimum 1000 -Maximum 9999)"
            Rename-LocalUser -Name $adminAccount.Name -NewName $newName
            Disable-LocalUser -Name $newName
            Write-CCDCLog "Built-in Administrator renamed to $newName and disabled" "SUCCESS"
        }
    } catch {
        Write-CCDCLog "Failed to secure Administrator account: $($_.Exception.Message)" "ERROR"
    }
    
    # 2. Enforce password policy
    Write-CCDCLog "Enforcing password policy..." "INFO"
    try {
        net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
        Write-CCDCLog "Password policy enforced" "SUCCESS"
    } catch {
        Write-CCDCLog "Password policy configuration failed: $($_.Exception.Message)" "ERROR"
    }
    
    # 3. Disable LLMNR and NBT-NS
    Write-CCDCLog "Disabling LLMNR and NBT-NS..." "INFO"
    try {
        # Disable LLMNR
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (!(Test-Path $llmnrPath)) { New-Item -Path $llmnrPath -Force | Out-Null }
        Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0
        
        # Disable NBT-NS via registry
        $nbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
        Get-ChildItem $nbtPath | ForEach-Object {
            Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -ErrorAction SilentlyContinue
        }
        
        Write-CCDCLog "LLMNR and NBT-NS disabled" "SUCCESS"
    } catch {
        Write-CCDCLog "Failed to disable LLMNR/NBT-NS: $($_.Exception.Message)" "ERROR"
    }
    
    # 4. Enforce LDAP signing and channel binding
    Write-CCDCLog "Enforcing LDAP signing..." "INFO"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LdapClientIntegrityLevel" -Value 2
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LdapServerIntegrityLevel" -Value 2
        Write-CCDCLog "LDAP signing enforced" "SUCCESS"
    } catch {
        Write-CCDCLog "LDAP signing configuration failed: $($_.Exception.Message)" "ERROR"
    }
    
    # 5. Enable PowerShell Constrained Language Mode
    Write-CCDCLog "Enabling PowerShell Constrained Language Mode..." "INFO"
    try {
        $clmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        Set-ItemProperty -Path $clmPath -Name "__PSLockdownPolicy" -Value 4
        Write-CCDCLog "PowerShell Constrained Language Mode enabled" "SUCCESS"
    } catch {
        Write-CCDCLog "CLM configuration failed: $($_.Exception.Message)" "WARN"
    }
    
    # 6. Harden DNS
    Write-CCDCLog "Hardening DNS configuration..." "INFO"
    try {
        # Enable DNS query logging
        Add-DnsServerQueryResolutionPolicy -Name "LogAllQueries" -Action ALLOW -PassThru -ZoneName "." -QType "Equal,A" -ErrorAction SilentlyContinue
        
        # Disable zone transfers to unauthorized hosts
        $zones = Get-DnsServerZone
        foreach ($zone in $zones) {
            if ($zone.ZoneType -eq "Primary") {
                Set-DnsServerZoneTransfer -Name $zone.ZoneName -SecondaryServers @() -ErrorAction SilentlyContinue
            }
        }
        
        Write-CCDCLog "DNS hardening completed" "SUCCESS"
    } catch {
        Write-CCDCLog "DNS hardening failed: $($_.Exception.Message)" "WARN"
    }
    
    # 7. Disable unnecessary services
    Write-CCDCLog "Disabling unnecessary services..." "INFO"
    $servicesToDisable = @("Spooler", "Fax")
    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                # Check if it's a scoring service first
                if ($SystemProfile.ScoringServices -notcontains "$service") {
                    Stop-Service -Name $service -Force
                    Set-Service -Name $service -StartupType Disabled
                    Write-CCDCLog "Disabled service: $service" "SUCCESS"
                } else {
                    Write-CCDCLog "Skipping $service - appears to be scoring-related" "WARN"
                }
            }
        } catch {
            Write-CCDCLog "Could not disable service $service : $($_.Exception.Message)" "WARN"
        }
    }
    
    # 8. Enable comprehensive AD auditing
    Write-CCDCLog "Enabling AD audit logging..." "INFO"
    try {
        auditpol /set /category:"Account Logon" /success:enable /failure:enable
        auditpol /set /category:"Account Management" /success:enable /failure:enable
        auditpol /set /category:"Directory Service Access" /success:enable /failure:enable
        auditpol /set /category:"Object Access" /success:enable /failure:enable
        Write-CCDCLog "AD audit logging enabled" "SUCCESS"
    } catch {
        Write-CCDCLog "AD audit configuration failed: $($_.Exception.Message)" "ERROR"
    }
}

function Invoke-WebServerHardening {
    param([PSCustomObject]$SystemProfile)
    
    Write-CCDCLog "=== WEB SERVER (IIS) HARDENING ===" "INFO"
    
    try {
        Import-Module WebAdministration -ErrorAction Stop
        
        # 1. Remove default IIS pages
        Write-CCDCLog "Securing default web content..." "INFO"
        $defaultFiles = @("iisstart.htm", "welcome.png")
        foreach ($file in $defaultFiles) {
            $filePath = "C:\inetpub\wwwroot\$file"
            if (Test-Path $filePath) {
                Remove-Item $filePath -Force
                Write-CCDCLog "Removed default file: $file" "SUCCESS"
            }
        }
        
        # 2. Disable directory browsing
        Write-CCDCLog "Disabling directory browsing..." "INFO"
        Set-WebConfigurationProperty -Filter "system.webServer/directoryBrowse" -Name enabled -Value $false
        Write-CCDCLog "Directory browsing disabled" "SUCCESS"
        
        # 3. Remove WebDAV module
        Write-CCDCLog "Removing WebDAV module..." "INFO"
        try {
            Remove-WebConfigurationProperty -Filter "system.webServer/modules" -Name "." -AtElement @{name="WebDAVModule"}
            Write-CCDCLog "WebDAV module removed" "SUCCESS"
        } catch {
            Write-CCDCLog "WebDAV module not found or already removed" "INFO"
        }
        
        # 4. Force HTTPS redirect
        Write-CCDCLog "Configuring HTTPS redirect..." "INFO"
        try {
            # Only if HTTPS is available
            if ($SystemProfile.ListenPorts -contains 443) {
                # This would require URL Rewrite module - skip if not available
                Write-CCDCLog "HTTPS available - manual HTTPS redirect configuration recommended" "INFO"
            }
        } catch {
            Write-CCDCLog "HTTPS redirect configuration failed: $($_.Exception.Message)" "WARN"
        }
        
        # 5. Set request limits
        Write-CCDCLog "Setting request limits..." "INFO"
        Set-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/requestLimits" -Name maxAllowedContentLength -Value 30000000
        Set-WebConfigurationProperty -Filter "system.web/httpRuntime" -Name maxRequestLength -Value 30000
        Write-CCDCLog "Request limits configured" "SUCCESS"
        
        # 6. Hash baseline webroot
        Write-CCDCLog "Creating webroot baseline..." "INFO"
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
            Write-CCDCLog "Webroot baseline created with $($baseline.Count) files" "SUCCESS"
        }
        
    } catch {
        Write-CCDCLog "Web server hardening failed: $($_.Exception.Message)" "ERROR"
    }
}

function Invoke-FTPServerHardening {
    param([PSCustomObject]$SystemProfile)
    
    Write-CCDCLog "=== FTP SERVER HARDENING ===" "INFO"
    
    try {
        # 1. Check anonymous FTP (but don't disable without confirmation)
        Write-CCDCLog "Checking FTP anonymous access..." "INFO"
        $ftpSites = & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list site | Where-Object { $_ -match "ftp" }
        if ($ftpSites) {
            Write-CCDCLog "FTP sites detected - manual review of anonymous access recommended" "WARN"
        }
        
        # 2. Enable FTP logging
        Write-CCDCLog "Enabling FTP logging..." "INFO"
        try {
            # Enable IIS FTP logging
            Set-WebConfigurationProperty -Filter "system.ftpServer/log" -Name enabled -Value $true -PSPath "IIS:\"
            Write-CCDCLog "FTP logging enabled" "SUCCESS"
        } catch {
            Write-CCDCLog "FTP logging configuration failed: $($_.Exception.Message)" "WARN"
        }
        
        # 3. Restrict FTP users
        Write-CCDCLog "FTP user restrictions should be manually configured based on scoring requirements" "INFO"
        
    } catch {
        Write-CCDCLog "FTP server hardening failed: $($_.Exception.Message)" "ERROR"
    }
}

function Invoke-WorkstationHardening {
    param([PSCustomObject]$SystemProfile)
    
    Write-CCDCLog "=== WORKSTATION HARDENING ===" "INFO"
    
    # 1. Enable Windows Defender
    Write-CCDCLog "Configuring Windows Defender..." "INFO"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableBlockAtFirstSeen $false
        Set-MpPreference -MAPSReporting Advanced
        Write-CCDCLog "Windows Defender configured" "SUCCESS"
    } catch {
        Write-CCDCLog "Windows Defender configuration failed: $($_.Exception.Message)" "ERROR"
    }
    
    # 2. Disable PowerShell remoting
    Write-CCDCLog "Disabling PowerShell remoting..." "INFO"
    try {
        Disable-PSRemoting -Force
        Write-CCDCLog "PowerShell remoting disabled" "SUCCESS"
    } catch {
        Write-CCDCLog "PowerShell remoting disable failed: $($_.Exception.Message)" "WARN"
    }
    
    # 3. Configure RDP restrictions
    Write-CCDCLog "Configuring RDP restrictions..." "INFO"
    try {
        # Enable NLA
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
        Write-CCDCLog "RDP Network Level Authentication enabled" "SUCCESS"
    } catch {
        Write-CCDCLog "RDP configuration failed: $($_.Exception.Message)" "WARN"
    }
    
    # 4. Enable maximum event logging
    Write-CCDCLog "Enabling comprehensive event logging..." "INFO"
    try {
        # Increase log sizes
        wevtutil sl Security /ms:1073741824
        wevtutil sl System /ms:1073741824
        wevtutil sl Application /ms:1073741824
        Write-CCDCLog "Event log sizes increased" "SUCCESS"
    } catch {
        Write-CCDCLog "Event log configuration failed: $($_.Exception.Message)" "WARN"
    }
}