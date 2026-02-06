# Enhanced Honeypot & Deception Module
# Based on CCDC expert insights and honeypot best practices
# References: https://pswalia2u.medium.com/creating-and-configuring-a-honeypot-account-in-active-directory-94153385275d

function Deploy-AdvancedHoneypots {
    param([PSCustomObject]$SystemProfile)
    
    Write-CCDCLog "Deploying advanced honeypot and deception layer..." "INFO"
    
    try {
        # 1. AD Honeypot Accounts (multiple types)
        if ($SystemProfile.DetectedRole -eq "ActiveDirectory_DNS") {
            Deploy-ADHoneypotAccounts
        }
        
        # 2. File System Honeypots
        Deploy-FileSystemHoneypots
        
        # 3. Network Share Honeypots
        Deploy-NetworkShareHoneypots
        
        # 4. Registry Honeypots
        Deploy-RegistryHoneypots
        
        # 5. Service Honeypots
        Deploy-ServiceHoneypots
        
        # 6. Credential Honeypots (fake credentials in files)
        Deploy-CredentialHoneypots
        
        # 7. SSH Honeypot (if applicable)
        Deploy-SSHHoneypot
        
        Write-CCDCLog "Advanced honeypot deployment completed" "SUCCESS"
        
    } catch {
        Write-CCDCLog "Honeypot deployment failed: $($_.Exception.Message)" "ERROR"
    }
}

function Deploy-ADHoneypotAccounts {
    Write-CCDCLog "Creating AD honeypot accounts..." "INFO"
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        
        $honeypotAccounts = @(
            @{
                Name = "svc_backup_$(Get-SecureRandom)"
                Description = "Backup Service Account"
                Password = Get-HoneypotPassword -AccountName "svc_backup"
                Groups = @()
                Attributes = @{ "Department" = "IT"; "Title" = "Service Account" }
            },
            @{
                Name = "admin_temp_$(Get-SecureRandom)"
                Description = "Temporary Administrator Account"
                Password = Get-HoneypotPassword -AccountName "admin_temp"
                Groups = @("Domain Admins")
                Attributes = @{ "Department" = "IT"; "Title" = "System Administrator" }
            },
            @{
                Name = "sql_service_$(Get-SecureRandom)"
                Description = "SQL Server Service Account"
                Password = Get-HoneypotPassword -AccountName "sql_service"
                Groups = @()
                Attributes = @{ "Department" = "Database"; "Title" = "SQL Service" }
            },
            @{
                Name = "monitoring_$(Get-SecureRandom)"
                Description = "System Monitoring Account"
                Password = Get-HoneypotPassword -AccountName "monitoring"
                Groups = @()
                Attributes = @{ "Department" = "Operations"; "Title" = "Monitoring Service" }
            }
        )
        
        $Global:DeployedHoneypots = @()
        
        foreach ($account in $honeypotAccounts) {
            try {
                $securePassword = ConvertTo-SecureString $account.Password -AsPlainText -Force
                
                # Create the user
                $newUser = New-ADUser -Name $account.Name -SamAccountName $account.Name -Enabled $true -AccountPassword $securePassword -Description $account.Description -PassThru
                
                # Set additional attributes
                foreach ($attr in $account.Attributes.Keys) {
                    Set-ADUser -Identity $newUser -Replace @{$attr = $account.Attributes[$attr]}
                }
                
                # Add to groups (especially dangerous for Domain Admin honeypot)
                foreach ($group in $account.Groups) {
                    try {
                        Add-ADGroupMember -Identity $group -Members $newUser -ErrorAction SilentlyContinue
                        Write-CCDCLog "Added honeypot $($account.Name) to $group - HIGH RISK HONEYPOT" "WARN"
                    } catch {
                        Write-CCDCLog "Could not add $($account.Name) to $group" "WARN"
                    }
                }
                
                # Set account to never expire (realistic for service accounts)
                Set-ADUser -Identity $newUser -PasswordNeverExpires $true
                
                $Global:DeployedHoneypots += [PSCustomObject]@{
                    Type = "ADUser"
                    Name = $account.Name
                    RiskLevel = if ($account.Groups -contains "Domain Admins") { "CRITICAL" } else { "HIGH" }
                    Created = Get-Date
                }
                
                Write-CCDCLog "Created AD honeypot: $($account.Name)" "SUCCESS"
                
            } catch {
                Write-CCDCLog "Failed to create honeypot $($account.Name): $($_.Exception.Message)" "ERROR"
            }
        }
        
        # Create honeypot monitoring job
        Start-HoneypotMonitoring
        
        Write-CCDCLog "Created $($Global:DeployedHoneypots.Count) AD honeypot accounts" "SUCCESS"
        
    } catch {
        Write-CCDCLog "AD honeypot deployment failed: $($_.Exception.Message)" "ERROR"
    }
}

function Deploy-FileSystemHoneypots {
    Write-CCDCLog "Deploying file system honeypots..." "INFO"
    
    try {
        $honeypotFiles = @(
            @{
                Path = "C:\Backup\Database_Passwords.txt"
                Content = @"
# Database Connection Strings - CONFIDENTIAL

SQL_PROD_SERVER = server01.domain.local
SQL_PROD_USER = sa
SQL_PROD_PASS = $(Get-HoneypotPassword -AccountName "SQL_PROD")

SQL_DEV_SERVER = devdb.domain.local  
SQL_DEV_USER = dev_admin
SQL_DEV_PASS = $(Get-HoneypotPassword -AccountName "SQL_DEV")

BACKUP_USER = backup_admin
BACKUP_PASS = $(Get-HoneypotPassword -AccountName "BACKUP")

EMERGENCY_USER = emergency_admin
EMERGENCY_PASS = $(Get-HoneypotPassword -AccountName "EMERGENCY")
"@
                AuditLevel = "FullControl"
            },
            @{
                Path = "C:\Scripts\Admin\credentials.xml"
                Content = @"
<Credentials>
    <Account name="domain_admin" password="DomainAdmin2024!" />
    <Account name="service_account" password="ServiceAcc123#" />
    <Account name="backup_service" password="BackupSvc2024$" />
</Credentials>
"@
                AuditLevel = "FullControl"
            },
            @{
                Path = "C:\Users\Public\Documents\SSH_Keys\private_key.pem"
                Content = @"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2K8H9F7J2L5M3N8P9Q1R2S3T4U5V6W7X8Y9Z0A1B2C3D4E5F
[FAKE SSH PRIVATE KEY - HONEYPOT]
6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6A7B8C9D0E1F2G3H4I5J6K7L
-----END RSA PRIVATE KEY-----
"@
                AuditLevel = "FullControl"
            },
            @{
                Path = "C:\inetpub\logs\access_tokens.log"
                Content = @"
[2024-01-15 10:30:15] API_TOKEN: sk-1234567890abcdef1234567890abcdef
[2024-01-15 10:31:22] ADMIN_TOKEN: admin_token_xyz789abc123def456
[2024-01-15 10:32:45] SERVICE_KEY: service_key_abc123def456ghi789
"@
                AuditLevel = "FullControl"
            }
        )
        
        foreach ($file in $honeypotFiles) {
            try {
                # Create directory if it doesn't exist
                $directory = Split-Path $file.Path -Parent
                if (!(Test-Path $directory)) {
                    New-Item -Path $directory -ItemType Directory -Force | Out-Null
                }
                
                # Create the honeypot file
                $file.Content | Out-File -FilePath $file.Path -Encoding UTF8
                
                # Set up auditing
                $acl = Get-Acl $file.Path
                $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                    "Everyone", 
                    $file.AuditLevel, 
                    "Success,Failure"
                )
                $acl.SetAuditRule($auditRule)
                Set-Acl $file.Path $acl
                
                # Hide the file (make it less obvious but still discoverable)
                $fileItem = Get-Item $file.Path
                $fileItem.Attributes = $fileItem.Attributes -bor [System.IO.FileAttributes]::Hidden
                
                $Global:DeployedHoneypots += [PSCustomObject]@{
                    Type = "File"
                    Name = $file.Path
                    RiskLevel = "HIGH"
                    Created = Get-Date
                }
                
                Write-CCDCLog "Created file honeypot: $($file.Path)" "SUCCESS"
                
            } catch {
                Write-CCDCLog "Failed to create file honeypot $($file.Path): $($_.Exception.Message)" "ERROR"
            }
        }
        
    } catch {
        Write-CCDCLog "File system honeypot deployment failed: $($_.Exception.Message)" "ERROR"
    }
}

function Deploy-NetworkShareHoneypots {
    Write-CCDCLog "Deploying network share honeypots..." "INFO"
    
    try {
        $honeypotShares = @(
            @{
                Name = "Backup$"
                Path = "C:\HoneypotShares\Backup"
                Description = "Backup Files - Restricted Access"
                Access = "Everyone,Read"
            },
            @{
                Name = "Scripts$"
                Path = "C:\HoneypotShares\Scripts"
                Description = "Administrative Scripts"
                Access = "Everyone,Read"
            },
            @{
                Name = "Logs$"
                Path = "C:\HoneypotShares\Logs"
                Description = "System Logs"
                Access = "Everyone,Read"
            }
        )
        
        foreach ($share in $honeypotShares) {
            try {
                # Create the directory
                if (!(Test-Path $share.Path)) {
                    New-Item -Path $share.Path -ItemType Directory -Force | Out-Null
                }
                
                # Create some realistic files in the share
                "Backup completed: $(Get-Date)" | Out-File "$($share.Path)\backup_log.txt"
                "Administrative notes - DO NOT SHARE" | Out-File "$($share.Path)\admin_notes.txt"
                
                # Create the share
                New-SmbShare -Name $share.Name -Path $share.Path -Description $share.Description -ReadAccess "Everyone" -ErrorAction SilentlyContinue
                
                # Set up auditing on the share
                $acl = Get-Acl $share.Path
                $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                    "Everyone", 
                    "FullControl", 
                    "ContainerInherit,ObjectInherit",
                    "None",
                    "Success,Failure"
                )
                $acl.SetAuditRule($auditRule)
                Set-Acl $share.Path $acl
                
                $Global:DeployedHoneypots += [PSCustomObject]@{
                    Type = "NetworkShare"
                    Name = $share.Name
                    Path = $share.Path
                    RiskLevel = "MEDIUM"
                    Created = Get-Date
                }
                
                Write-CCDCLog "Created network share honeypot: $($share.Name)" "SUCCESS"
                
            } catch {
                Write-CCDCLog "Failed to create share honeypot $($share.Name): $($_.Exception.Message)" "ERROR"
            }
        }
        
    } catch {
        Write-CCDCLog "Network share honeypot deployment failed: $($_.Exception.Message)" "ERROR"
    }
}

function Deploy-RegistryHoneypots {
    Write-CCDCLog "Deploying registry honeypots..." "INFO"
    
    try {
        $registryTraps = @(
            @{
                Path = "HKLM:\SOFTWARE\Company\DatabaseConfig"
                Values = @{
                    "ConnectionString" = "Server=db01;Database=prod;User=sa;Password=DbProd2024!"
                    "BackupPath" = "\\backup01\sql_backups"
                    "AdminUser" = "db_admin"
                    "AdminPass" = "DbAdmin123#"
                }
            },
            @{
                Path = "HKLM:\SOFTWARE\Company\ServiceAccounts"
                Values = @{
                    "BackupService" = "backup_svc:BackupSvc2024!"
                    "MonitoringService" = "monitor_svc:MonitorSvc123#"
                    "WebService" = "web_svc:WebSvc2024$"
                }
            }
        )
        
        foreach ($trap in $registryTraps) {
            try {
                # Create the registry key
                if (!(Test-Path $trap.Path)) {
                    New-Item -Path $trap.Path -Force | Out-Null
                }
                
                # Set the values
                foreach ($valueName in $trap.Values.Keys) {
                    Set-ItemProperty -Path $trap.Path -Name $valueName -Value $trap.Values[$valueName]
                }
                
                # Set up auditing (requires additional permissions)
                try {
                    $acl = Get-Acl $trap.Path
                    $auditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
                        "Everyone",
                        "FullControl",
                        "ContainerInherit,ObjectInherit",
                        "None",
                        "Success,Failure"
                    )
                    $acl.SetAuditRule($auditRule)
                    Set-Acl $trap.Path $acl
                } catch {
                    Write-CCDCLog "Could not set registry auditing for $($trap.Path)" "WARN"
                }
                
                $Global:DeployedHoneypots += [PSCustomObject]@{
                    Type = "Registry"
                    Name = $trap.Path
                    RiskLevel = "MEDIUM"
                    Created = Get-Date
                }
                
                Write-CCDCLog "Created registry honeypot: $($trap.Path)" "SUCCESS"
                
            } catch {
                Write-CCDCLog "Failed to create registry honeypot $($trap.Path): $($_.Exception.Message)" "ERROR"
            }
        }
        
    } catch {
        Write-CCDCLog "Registry honeypot deployment failed: $($_.Exception.Message)" "ERROR"
    }
}

function Deploy-ServiceHoneypots {
    Write-CCDCLog "Deploying service honeypots..." "INFO"
    
    try {
        # Create fake service that looks valuable but does nothing
        $serviceName = "BackupMonitorService"
        $serviceDisplayName = "Backup Monitoring Service"
        $serviceDescription = "Monitors backup operations and maintains backup logs"
        
        # Create a simple PowerShell script that does nothing but logs access
        $serviceScript = @"
# Backup Monitoring Service - Honeypot
while (`$true) {
    Start-Sleep -Seconds 60
    "Service heartbeat: `$(Get-Date)" | Out-File "C:\Windows\Temp\backup_monitor.log" -Append
}
"@
        
        $scriptPath = "C:\Windows\System32\backup_monitor.ps1"
        $serviceScript | Out-File $scriptPath
        
        # Create the service (but don't start it - makes it look disabled/vulnerable)
        try {
            New-Service -Name $serviceName -DisplayName $serviceDisplayName -Description $serviceDescription -BinaryPathName "powershell.exe -ExecutionPolicy Bypass -File $scriptPath" -StartupType Manual
            
            $Global:DeployedHoneypots += [PSCustomObject]@{
                Type = "Service"
                Name = $serviceName
                Path = $scriptPath
                RiskLevel = "LOW"
                Created = Get-Date
            }
            
            Write-CCDCLog "Created service honeypot: $serviceName" "SUCCESS"
            
        } catch {
            Write-CCDCLog "Failed to create service honeypot: $($_.Exception.Message)" "ERROR"
        }
        
    } catch {
        Write-CCDCLog "Service honeypot deployment failed: $($_.Exception.Message)" "ERROR"
    }
}

function Deploy-CredentialHoneypots {
    Write-CCDCLog "Deploying credential honeypots in common locations..." "INFO"
    
    try {
        # Common locations where admins might store credentials
        $credentialLocations = @(
            @{
                Path = "C:\Users\Administrator\Desktop\passwords.txt"
                Content = @"
Server Passwords - Keep Secure!

Web Server: webadmin / $(Get-HoneypotPassword -AccountName "WEB_ADMIN")
Database: dbadmin / $(Get-HoneypotPassword -AccountName "DB_ADMIN")
Backup: backup_admin / $(Get-HoneypotPassword -AccountName "BACKUP_ADMIN")
Emergency: emergency / $(Get-HoneypotPassword -AccountName "EMERGENCY_ADMIN")
"@
            },
            @{
                Path = "C:\Windows\System32\config\credentials.ini"
                Content = @"
[Database]
server=db01.domain.local
username=sa
password=SqlProd2024!

[Backup]
server=backup01.domain.local
username=backup_admin
password=BackupSvc2024#

[Monitoring]
server=monitor01.domain.local
username=monitor_svc
password=MonitorSvc123$
"@
            }
        )
        
        foreach ($location in $credentialLocations) {
            try {
                $directory = Split-Path $location.Path -Parent
                if (!(Test-Path $directory)) {
                    New-Item -Path $directory -ItemType Directory -Force | Out-Null
                }
                
                $location.Content | Out-File $location.Path -Encoding UTF8
                
                # Set up auditing
                $acl = Get-Acl $location.Path
                $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                    "Everyone", 
                    "FullControl", 
                    "Success,Failure"
                )
                $acl.SetAuditRule($auditRule)
                Set-Acl $location.Path $acl
                
                $Global:DeployedHoneypots += [PSCustomObject]@{
                    Type = "CredentialFile"
                    Name = $location.Path
                    RiskLevel = "CRITICAL"
                    Created = Get-Date
                }
                
                Write-CCDCLog "Created credential honeypot: $($location.Path)" "SUCCESS"
                
            } catch {
                Write-CCDCLog "Failed to create credential honeypot $($location.Path): $($_.Exception.Message)" "ERROR"
            }
        }
        
    } catch {
        Write-CCDCLog "Credential honeypot deployment failed: $($_.Exception.Message)" "ERROR"
    }
}

function Deploy-SSHHoneypot {
    Write-CCDCLog "Checking for SSH honeypot opportunities..." "INFO"
    
    try {
        # Check if OpenSSH is installed (common in newer Windows)
        $sshService = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
        
        if ($sshService) {
            Write-CCDCLog "OpenSSH detected - consider deploying SSH honeypot similar to tunnelbees" "INFO"
            Write-CCDCLog "Reference: https://github.com/JakeGinesin/tunnelbees" "INFO"
            
            # Create fake SSH keys as honeypot
            $sshKeyPath = "C:\Users\Administrator\.ssh\id_rsa"
            $sshKeyDir = Split-Path $sshKeyPath -Parent
            
            if (!(Test-Path $sshKeyDir)) {
                New-Item -Path $sshKeyDir -ItemType Directory -Force | Out-Null
            }
            
            $fakePrivateKey = @"
-----BEGIN OPENSSH PRIVATE KEY-----
$(Get-HoneypotPassword -AccountName "SSH_KEY_1")
$(Get-HoneypotPassword -AccountName "SSH_KEY_2")
[FAKE SSH PRIVATE KEY - HONEYPOT TRAP]
-----END OPENSSH PRIVATE KEY-----
"@
            
            $fakePrivateKey | Out-File $sshKeyPath -Encoding UTF8
            
            # Set up auditing
            $acl = Get-Acl $sshKeyPath
            $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                "Everyone", 
                "FullControl", 
                "Success,Failure"
            )
            $acl.SetAuditRule($auditRule)
            Set-Acl $sshKeyPath $acl
            
            $Global:DeployedHoneypots += [PSCustomObject]@{
                Type = "SSHKey"
                Name = $sshKeyPath
                RiskLevel = "HIGH"
                Created = Get-Date
            }
            
            Write-CCDCLog "Created SSH key honeypot: $sshKeyPath" "SUCCESS"
        }
        
    } catch {
        Write-CCDCLog "SSH honeypot deployment failed: $($_.Exception.Message)" "ERROR"
    }
}

function Start-HoneypotMonitoring {
    Write-CCDCLog "Starting enhanced honeypot monitoring..." "INFO"
    
    $honeypotMonitorJob = Start-Job -ScriptBlock {
        param($LogPath, $DeployedHoneypots)
        
        while ($true) {
            try {
                # Monitor for honeypot access via event logs
                $honeypotEvents = Get-WinEvent -FilterHashTable @{
                    LogName = "Security"
                    ID = @(4624, 4625, 4648, 4672, 4768, 4769, 4776, 4663)  # Expanded monitoring
                    StartTime = (Get-Date).AddMinutes(-2)
                } -ErrorAction SilentlyContinue
                
                foreach ($event in $honeypotEvents) {
                    $eventXml = [xml]$event.ToXml()
                    $eventData = @{}
                    
                    foreach ($data in $eventXml.Event.EventData.Data) {
                        $eventData[$data.Name] = $data.'#text'
                    }
                    
                    # Check if event involves any honeypot accounts
                    $targetUser = $eventData['TargetUserName']
                    $objectName = $eventData['ObjectName']
                    
                    foreach ($honeypot in $DeployedHoneypots) {
                        $triggered = $false
                        $alertType = ""
                        
                        if ($honeypot.Type -eq "ADUser" -and $targetUser -eq $honeypot.Name) {
                            $triggered = $true
                            $alertType = "HONEYPOT_ACCOUNT_ACCESS"
                        } elseif (($honeypot.Type -in @("File", "CredentialFile", "SSHKey")) -and $objectName -eq $honeypot.Name) {
                            $triggered = $true
                            $alertType = "HONEYPOT_FILE_ACCESS"
                        }
                        
                        if ($triggered) {
                            $alert = [PSCustomObject]@{
                                Timestamp = Get-Date
                                AlertType = $alertType
                                Severity = "CRITICAL"
                                Message = "HONEYPOT TRIGGERED: $($honeypot.Type) - $($honeypot.Name)"
                                HoneypotType = $honeypot.Type
                                HoneypotName = $honeypot.Name
                                RiskLevel = $honeypot.RiskLevel
                                EventId = $event.Id
                                SourceIP = $eventData['IpAddress']
                                TargetUser = $targetUser
                                ObjectName = $objectName
                                ProcessName = $eventData['ProcessName']
                            }
                            
                            $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                            
                            # Also create immediate incident report
                            $incidentReport = [PSCustomObject]@{
                                ReportId = "HONEYPOT-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
                                Timestamp = Get-Date
                                AlertType = $alertType
                                Severity = "CRITICAL"
                                Summary = "HONEYPOT COMPROMISE DETECTED"
                                HoneypotDetails = $honeypot
                                EventDetails = $eventData
                                ImmediateActions = @(
                                    "1. ISOLATE SOURCE SYSTEM IMMEDIATELY",
                                    "2. IDENTIFY ALL SYSTEMS ACCESSED BY THIS ATTACKER",
                                    "3. CHECK FOR LATERAL MOVEMENT",
                                    "4. REVIEW ALL RECENT LOGON ACTIVITY",
                                    "5. CONSIDER NETWORK SEGMENTATION"
                                )
                            }
                            
                            $incidentReport | ConvertTo-Json -Depth 10 | Out-File "$LogPath\Reports\HONEYPOT_INCIDENT_$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
                        }
                    }
                }
                
                Start-Sleep -Seconds 15  # Check every 15 seconds for honeypot access
                
            } catch {
                "Honeypot monitoring error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                Start-Sleep -Seconds 60
            }
        }
    } -ArgumentList $Global:LogPath, $Global:DeployedHoneypots
    
    $Global:DetectionJobs += $honeypotMonitorJob
    Write-CCDCLog "Enhanced honeypot monitoring started (Job ID: $($honeypotMonitorJob.Id))" "SUCCESS"
}

function Get-HoneypotStatus {
    if ($Global:DeployedHoneypots) {
        return [PSCustomObject]@{
            TotalHoneypots = $Global:DeployedHoneypots.Count
            ByType = $Global:DeployedHoneypots | Group-Object Type | ForEach-Object { @{ $_.Name = $_.Count } }
            ByRiskLevel = $Global:DeployedHoneypots | Group-Object RiskLevel | ForEach-Object { @{ $_.Name = $_.Count } }
            DeploymentTime = ($Global:DeployedHoneypots | Measure-Object Created -Minimum).Minimum
        }
    } else {
        return @{ TotalHoneypots = 0; Message = "No honeypots deployed" }
    }
}