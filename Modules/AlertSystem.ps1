# Phase 3 - Detection & Alert Module
# Advanced threat detection based on system profile and behavioral analysis

$Global:DetectionJobs = @()
$Global:HoneypotCreated = $false

function Start-DetectionModule {
    param([PSCustomObject]$SystemProfile)
    
    Write-CCDCLog "Starting detection and alert systems..." "INFO"
    
    try {
        # 1. Identity & Credential Abuse Detection
        Start-CredentialAbuseDetection
        
        # 2. Lateral Movement Detection
        Start-LateralMovementDetection
        
        # 3. Persistence Detection
        Start-PersistenceDetection
        
        # 4. Living-Off-The-Land (LOLBin) Detection
        Start-LOLBinDetection
        
        # 5. Firewall & Logging Tampering Detection
        Start-TamperingDetection
        
        # 6. AD-Specific Threat Detection
        if ($SystemProfile.DetectedRole -eq "ActiveDirectory_DNS") {
            Start-ADThreatDetection
        }
        
        # 7. Honeypot & Deception Layer
        Start-HoneypotDeception -SystemProfile $SystemProfile
        
        Write-CCDCLog "Detection module started successfully" "SUCCESS"
        
    } catch {
        Write-CCDCLog "Error starting detection module: $($_.Exception.Message)" "ERROR"
    }
}

function Start-CredentialAbuseDetection {
    Write-CCDCLog "Starting credential abuse detection..." "INFO"
    
    $credDetectionJob = Start-Job -ScriptBlock {
        param($LogPath)
        
        # Track logon patterns
        $logonHistory = @{}
        $suspiciousAccounts = @{}
        
        while ($true) {
            try {
                # Monitor for suspicious logon events
                $recentLogons = Get-WinEvent -FilterHashTable @{
                    LogName = "Security"
                    ID = @(4624, 4648, 4625)
                    StartTime = (Get-Date).AddMinutes(-5)
                } -ErrorAction SilentlyContinue
                
                foreach ($event in $recentLogons) {
                    $eventXml = [xml]$event.ToXml()
                    $eventData = @{}
                    
                    foreach ($data in $eventXml.Event.EventData.Data) {
                        $eventData[$data.Name] = $data.'#text'
                    }
                    
                    $account = $eventData['TargetUserName']
                    $sourceIP = $eventData['IpAddress']
                    $logonType = $eventData['LogonType']
                    
                    if ($account -and $account -ne '-' -and $account -ne 'ANONYMOUS LOGON') {
                        # Track logon patterns
                        $key = "$account-$sourceIP"
                        
                        if (-not $logonHistory.ContainsKey($key)) {
                            $logonHistory[$key] = @{
                                Account = $account
                                SourceIP = $sourceIP
                                FirstSeen = $event.TimeCreated
                                Count = 0
                                LogonTypes = @()
                            }
                        }
                        
                        $logonHistory[$key].Count++
                        $logonHistory[$key].LogonTypes += $logonType
                        $logonHistory[$key].LastSeen = $event.TimeCreated
                        
                        # Detect Pass-the-Hash (Network logon type 3 with NTLM)
                        if ($logonType -eq '3' -and $eventData['AuthenticationPackageName'] -eq 'NTLM') {
                            # Check if this account typically does network logons
                            $networkLogons = $logonHistory[$key].LogonTypes | Where-Object { $_ -eq '3' }
                            $interactiveLogons = $logonHistory[$key].LogonTypes | Where-Object { $_ -eq '2' }
                            
                            if ($networkLogons.Count -gt 0 -and $interactiveLogons.Count -eq 0) {
                                $alert = [PSCustomObject]@{
                                    Timestamp = Get-Date
                                    AlertType = "PASS_THE_HASH"
                                    Severity = "HIGH"
                                    Message = "Potential Pass-the-Hash detected for account: $account from $sourceIP"
                                    Account = $account
                                    SourceIP = $sourceIP
                                    LogonType = $logonType
                                    EventId = $event.Id
                                }
                                
                                $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                            }
                        }
                        
                        # Detect multiple failed logons (brute force)
                        if ($event.Id -eq 4625) {
                            if (-not $suspiciousAccounts.ContainsKey($account)) {
                                $suspiciousAccounts[$account] = @{
                                    FailedAttempts = 0
                                    FirstFailure = $event.TimeCreated
                                }
                            }
                            
                            $suspiciousAccounts[$account].FailedAttempts++
                            
                            if ($suspiciousAccounts[$account].FailedAttempts -ge 5) {
                                $alert = [PSCustomObject]@{
                                    Timestamp = Get-Date
                                    AlertType = "BRUTE_FORCE"
                                    Severity = "HIGH"
                                    Message = "Brute force attack detected against account: $account"
                                    Account = $account
                                    FailedAttempts = $suspiciousAccounts[$account].FailedAttempts
                                    SourceIP = $sourceIP
                                }
                                
                                $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                            }
                        }
                        
                        # Detect logons from unexpected IPs
                        $knownGoodIPs = @('127.0.0.1', '::1', '-')  # Add known good IPs
                        if ($sourceIP -and $sourceIP -notin $knownGoodIPs -and $sourceIP -notmatch '^192\.168\.' -and $sourceIP -notmatch '^10\.' -and $sourceIP -notmatch '^172\.(1[6-9]|2[0-9]|3[01])\.') {
                            $alert = [PSCustomObject]@{
                                Timestamp = Get-Date
                                AlertType = "SUSPICIOUS_LOGON_SOURCE"
                                Severity = "MEDIUM"
                                Message = "Logon from unexpected IP: $account from $sourceIP"
                                Account = $account
                                SourceIP = $sourceIP
                                LogonType = $logonType
                            }
                            
                            $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                        }
                    }
                }
                
                Start-Sleep -Seconds 30
                
            } catch {
                "Credential abuse detection error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                Start-Sleep -Seconds 60
            }
        }
    } -ArgumentList $Global:LogPath
    
    $Global:DetectionJobs += $credDetectionJob
    Write-CCDCLog "Credential abuse detection started (Job ID: $($credDetectionJob.Id))" "SUCCESS"
}

function Start-LateralMovementDetection {
    Write-CCDCLog "Starting lateral movement detection..." "INFO"
    
    $lateralMoveJob = Start-Job -ScriptBlock {
        param($LogPath)
        
        $accountActivity = @{}
        
        while ($true) {
            try {
                # Monitor for cross-machine activity
                $recentLogons = Get-WinEvent -FilterHashTable @{
                    LogName = "Security"
                    ID = 4624
                    StartTime = (Get-Date).AddMinutes(-5)
                } -ErrorAction SilentlyContinue
                
                foreach ($event in $recentLogons) {
                    $eventXml = [xml]$event.ToXml()
                    $eventData = @{}
                    
                    foreach ($data in $eventXml.Event.EventData.Data) {
                        $eventData[$data.Name] = $data.'#text'
                    }
                    
                    $account = $eventData['TargetUserName']
                    $sourceIP = $eventData['IpAddress']
                    $workstation = $eventData['WorkstationName']
                    
                    if ($account -and $account -ne '-') {
                        if (-not $accountActivity.ContainsKey($account)) {
                            $accountActivity[$account] = @{
                                Machines = @()
                                Timeline = @()
                            }
                        }
                        
                        $machineInfo = [PSCustomObject]@{
                            Machine = $env:COMPUTERNAME
                            SourceIP = $sourceIP
                            Workstation = $workstation
                            Timestamp = $event.TimeCreated
                        }
                        
                        $accountActivity[$account].Timeline += $machineInfo
                        
                        # Keep only last 10 minutes of activity
                        $accountActivity[$account].Timeline = $accountActivity[$account].Timeline | Where-Object { 
                            $_.Timestamp -gt (Get-Date).AddMinutes(-10) 
                        }
                        
                        # Check for rapid cross-machine access
                        $uniqueMachines = $accountActivity[$account].Timeline | Select-Object -ExpandProperty Machine -Unique
                        if ($uniqueMachines.Count -ge 3) {
                            $timeSpan = ($accountActivity[$account].Timeline | Measure-Object -Property Timestamp -Maximum -Minimum)
                            $duration = ($timeSpan.Maximum - $timeSpan.Minimum).TotalMinutes
                            
                            if ($duration -le 5) {
                                $alert = [PSCustomObject]@{
                                    Timestamp = Get-Date
                                    AlertType = "LATERAL_MOVEMENT"
                                    Severity = "HIGH"
                                    Message = "Account $account accessed $($uniqueMachines.Count) machines in $([math]::Round($duration, 2)) minutes"
                                    Account = $account
                                    MachineCount = $uniqueMachines.Count
                                    Duration = $duration
                                    Machines = $uniqueMachines
                                }
                                
                                $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                            }
                        }
                    }
                }
                
                # Monitor for PsExec-style remote execution
                $serviceEvents = Get-WinEvent -FilterHashTable @{
                    LogName = "System"
                    ID = 7045
                    StartTime = (Get-Date).AddMinutes(-2)
                } -ErrorAction SilentlyContinue
                
                foreach ($event in $serviceEvents) {
                    if ($event.Message -match "PSEXESVC|PAExec|RemCom") {
                        $alert = [PSCustomObject]@{
                            Timestamp = Get-Date
                            AlertType = "REMOTE_EXECUTION"
                            Severity = "HIGH"
                            Message = "Remote execution tool detected: $($event.Message)"
                            ServiceName = $event.Message
                            EventId = $event.Id
                        }
                        
                        $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                    }
                }
                
                Start-Sleep -Seconds 30
                
            } catch {
                "Lateral movement detection error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                Start-Sleep -Seconds 60
            }
        }
    } -ArgumentList $Global:LogPath
    
    $Global:DetectionJobs += $lateralMoveJob
    Write-CCDCLog "Lateral movement detection started (Job ID: $($lateralMoveJob.Id))" "SUCCESS"
}

function Start-PersistenceDetection {
    Write-CCDCLog "Starting persistence detection..." "INFO"
    
    # Create baseline of current state
    $baseline = @{
        ScheduledTasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State
        Services = Get-Service | Select-Object Name, Status, StartType
        RunKeys = @()
        StartupItems = @()
    }
    
    # Get registry run keys
    $runKeyPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($path in $runKeyPaths) {
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($items) {
                $baseline.RunKeys += [PSCustomObject]@{
                    Path = $path
                    Items = $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | Select-Object Name, Value
                }
            }
        } catch {
            # Registry key doesn't exist or can't be read
        }
    }
    
    # Get startup folder items
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $baseline.StartupItems += Get-ChildItem $path | Select-Object Name, FullName, LastWriteTime
        }
    }
    
    # Export baseline
    $baseline | Export-Clixml "$Global:LogPath\persistence_baseline.xml"
    
    $persistenceJob = Start-Job -ScriptBlock {
        param($LogPath, $BaselineFile)
        
        $baseline = Import-Clixml $BaselineFile
        
        while ($true) {
            try {
                # Check for new scheduled tasks
                $currentTasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State
                $newTasks = Compare-Object $baseline.ScheduledTasks $currentTasks -Property TaskName, TaskPath | Where-Object { $_.SideIndicator -eq '=>' }
                
                foreach ($task in $newTasks) {
                    $alert = [PSCustomObject]@{
                        Timestamp = Get-Date
                        AlertType = "NEW_SCHEDULED_TASK"
                        Severity = "MEDIUM"
                        Message = "New scheduled task detected: $($task.TaskName)"
                        TaskName = $task.TaskName
                        TaskPath = $task.TaskPath
                    }
                    
                    $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                }
                
                # Check for new services
                $currentServices = Get-Service | Select-Object Name, Status, StartType
                $newServices = Compare-Object $baseline.Services $currentServices -Property Name | Where-Object { $_.SideIndicator -eq '=>' }
                
                foreach ($service in $newServices) {
                    $alert = [PSCustomObject]@{
                        Timestamp = Get-Date
                        AlertType = "NEW_SERVICE"
                        Severity = "HIGH"
                        Message = "New service detected: $($service.Name)"
                        ServiceName = $service.Name
                    }
                    
                    $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                }
                
                # Monitor for shadow copy deletion
                $vssEvents = Get-WinEvent -FilterHashTable @{
                    LogName = "System"
                    ID = 8194
                    StartTime = (Get-Date).AddMinutes(-5)
                } -ErrorAction SilentlyContinue
                
                if ($vssEvents) {
                    $alert = [PSCustomObject]@{
                        Timestamp = Get-Date
                        AlertType = "SHADOW_COPY_DELETION"
                        Severity = "HIGH"
                        Message = "Shadow copy deletion detected - possible ransomware activity"
                        EventCount = $vssEvents.Count
                    }
                    
                    $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                }
                
                Start-Sleep -Seconds 120  # Check every 2 minutes
                
            } catch {
                "Persistence detection error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                Start-Sleep -Seconds 300
            }
        }
    } -ArgumentList $Global:LogPath, "$Global:LogPath\persistence_baseline.xml"
    
    $Global:DetectionJobs += $persistenceJob
    Write-CCDCLog "Persistence detection started (Job ID: $($persistenceJob.Id))" "SUCCESS"
}

function Start-LOLBinDetection {
    Write-CCDCLog "Starting Living-Off-The-Land binary detection..." "INFO"
    
    $lolbinJob = Start-Job -ScriptBlock {
        param($LogPath)
        
        # Suspicious LOLBins and their indicators
        $suspiciousProcesses = @{
            "certutil.exe" = @("urlcache", "decode", "decodehex", "-f")
            "bitsadmin.exe" = @("transfer", "addfile", "/download")
            "mshta.exe" = @("http", "javascript", "vbscript")
            "rundll32.exe" = @("javascript", "shell32.dll", "url.dll")
            "wscript.exe" = @(".js", ".vbs", ".wsf")
            "cscript.exe" = @(".js", ".vbs", ".wsf")
            "powershell.exe" = @("-enc", "-e", "downloadstring", "iex", "invoke-expression")
            "cmd.exe" = @("powershell", "/c echo", "certutil")
        }
        
        while ($true) {
            try {
                # Monitor Sysmon process creation events if available
                $processEvents = Get-WinEvent -FilterHashTable @{
                    LogName = "Microsoft-Windows-Sysmon/Operational"
                    ID = 1
                    StartTime = (Get-Date).AddMinutes(-2)
                } -ErrorAction SilentlyContinue
                
                foreach ($event in $processEvents) {
                    $eventXml = [xml]$event.ToXml()
                    $eventData = @{}
                    
                    foreach ($data in $eventXml.Event.EventData.Data) {
                        $eventData[$data.Name] = $data.'#text'
                    }
                    
                    $processName = Split-Path $eventData['Image'] -Leaf
                    $commandLine = $eventData['CommandLine']
                    $parentProcess = Split-Path $eventData['ParentImage'] -Leaf
                    
                    if ($suspiciousProcesses.ContainsKey($processName.ToLower())) {
                        $indicators = $suspiciousProcesses[$processName.ToLower()]
                        $matchedIndicators = $indicators | Where-Object { $commandLine -match [regex]::Escape($_) }
                        
                        if ($matchedIndicators) {
                            $alert = [PSCustomObject]@{
                                Timestamp = Get-Date
                                AlertType = "LOLBIN_ABUSE"
                                Severity = "HIGH"
                                Message = "Suspicious LOLBin usage: $processName with indicators: $($matchedIndicators -join ', ')"
                                ProcessName = $processName
                                CommandLine = $commandLine
                                ParentProcess = $parentProcess
                                Indicators = $matchedIndicators
                            }
                            
                            $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                        }
                    }
                }
                
                Start-Sleep -Seconds 30
                
            } catch {
                "LOLBin detection error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                Start-Sleep -Seconds 60
            }
        }
    } -ArgumentList $Global:LogPath
    
    $Global:DetectionJobs += $lolbinJob
    Write-CCDCLog "LOLBin detection started (Job ID: $($lolbinJob.Id))" "SUCCESS"
}

function Start-TamperingDetection {
    Write-CCDCLog "Starting firewall and logging tampering detection..." "INFO"
    
    $tamperingJob = Start-Job -ScriptBlock {
        param($LogPath)
        
        while ($true) {
            try {
                # Monitor for event log clearing
                $logClearEvents = Get-WinEvent -FilterHashTable @{
                    LogName = "Security"
                    ID = 1102
                    StartTime = (Get-Date).AddMinutes(-5)
                } -ErrorAction SilentlyContinue
                
                foreach ($event in $logClearEvents) {
                    $alert = [PSCustomObject]@{
                        Timestamp = Get-Date
                        AlertType = "LOG_CLEARING"
                        Severity = "CRITICAL"
                        Message = "Event log cleared - possible evidence destruction"
                        LogName = $event.LogName
                        ClearedBy = $event.UserId
                    }
                    
                    $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                }
                
                # Monitor for firewall rule changes
                $firewallEvents = Get-WinEvent -FilterHashTable @{
                    LogName = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
                    StartTime = (Get-Date).AddMinutes(-5)
                } -ErrorAction SilentlyContinue
                
                foreach ($event in $firewallEvents) {
                    if ($event.Id -eq 2004 -or $event.Id -eq 2005) {  # Rule added or changed
                        $alert = [PSCustomObject]@{
                            Timestamp = Get-Date
                            AlertType = "FIREWALL_RULE_CHANGE"
                            Severity = "MEDIUM"
                            Message = "Firewall rule modified: $($event.Message)"
                            EventId = $event.Id
                        }
                        
                        $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                    }
                }
                
                Start-Sleep -Seconds 60
                
            } catch {
                "Tampering detection error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                Start-Sleep -Seconds 120
            }
        }
    } -ArgumentList $Global:LogPath
    
    $Global:DetectionJobs += $tamperingJob
    Write-CCDCLog "Tampering detection started (Job ID: $($tamperingJob.Id))" "SUCCESS"
}

function Start-ADThreatDetection {
    Write-CCDCLog "Starting AD-specific threat detection..." "INFO"
    
    $adThreatJob = Start-Job -ScriptBlock {
        param($LogPath)
        
        while ($true) {
            try {
                # Monitor for DCSync attempts (Event 4662)
                $dcsyncEvents = Get-WinEvent -FilterHashTable @{
                    LogName = "Security"
                    ID = 4662
                    StartTime = (Get-Date).AddMinutes(-5)
                } -ErrorAction SilentlyContinue
                
                foreach ($event in $dcsyncEvents) {
                    if ($event.Message -match "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") {
                        $alert = [PSCustomObject]@{
                            Timestamp = Get-Date
                            AlertType = "DCSYNC_ATTEMPT"
                            Severity = "CRITICAL"
                            Message = "DCSync attempt detected - possible credential dumping"
                            EventMessage = $event.Message
                            UserId = $event.UserId
                        }
                        
                        $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                    }
                }
                
                # Monitor AdminSDHolder modifications
                $adminSDEvents = Get-WinEvent -FilterHashTable @{
                    LogName = "Security"
                    ID = 5136
                    StartTime = (Get-Date).AddMinutes(-5)
                } -ErrorAction SilentlyContinue
                
                foreach ($event in $adminSDEvents) {
                    if ($event.Message -match "AdminSDHolder") {
                        $alert = [PSCustomObject]@{
                            Timestamp = Get-Date
                            AlertType = "ADMINSDHOLDER_MODIFICATION"
                            Severity = "HIGH"
                            Message = "AdminSDHolder object modified - possible privilege escalation"
                            EventMessage = $event.Message
                            UserId = $event.UserId
                        }
                        
                        $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                    }
                }
                
                Start-Sleep -Seconds 60
                
            } catch {
                "AD threat detection error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                Start-Sleep -Seconds 120
            }
        }
    } -ArgumentList $Global:LogPath
    
    $Global:DetectionJobs += $adThreatJob
    Write-CCDCLog "AD threat detection started (Job ID: $($adThreatJob.Id))" "SUCCESS"
}

function Start-HoneypotDeception {
    param([PSCustomObject]$SystemProfile)
    
    Write-CCDCLog "Setting up honeypot and deception layer..." "INFO"
    
    try {
        # Create honeypot user account
        if ($SystemProfile.DetectedRole -eq "ActiveDirectory_DNS") {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                
                $honeypotName = "SVC_Backup_$(Get-SecureRandom)"
                $honeypotPassword = ConvertTo-SecureString (Get-HoneypotPassword -AccountName $honeypotName) -AsPlainText -Force
                
                New-ADUser -Name $honeypotName -SamAccountName $honeypotName -Enabled $true -AccountPassword $honeypotPassword -Description "Service Account - Do Not Use"
                
                Write-CCDCLog "Honeypot AD account created: $honeypotName" "SUCCESS"
                $Global:HoneypotCreated = $true
                
                # Monitor honeypot account usage
                $honeypotJob = Start-Job -ScriptBlock {
                    param($LogPath, $HoneypotName)
                    
                    while ($true) {
                        try {
                            $honeypotEvents = Get-WinEvent -FilterHashTable @{
                                LogName = "Security"
                                ID = @(4624, 4625, 4648)
                                StartTime = (Get-Date).AddMinutes(-2)
                            } -ErrorAction SilentlyContinue
                            
                            foreach ($event in $honeypotEvents) {
                                if ($event.Message -match $HoneypotName) {
                                    $alert = [PSCustomObject]@{
                                        Timestamp = Get-Date
                                        AlertType = "HONEYPOT_TRIGGERED"
                                        Severity = "CRITICAL"
                                        Message = "HONEYPOT ACCOUNT ACCESSED: $HoneypotName - IMMEDIATE INVESTIGATION REQUIRED"
                                        Account = $HoneypotName
                                        EventId = $event.Id
                                        EventMessage = $event.Message
                                    }
                                    
                                    $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                                }
                            }
                            
                            Start-Sleep -Seconds 30
                            
                        } catch {
                            "Honeypot monitoring error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                            Start-Sleep -Seconds 60
                        }
                    }
                } -ArgumentList $Global:LogPath, $honeypotName
                
                $Global:DetectionJobs += $honeypotJob
                
            } catch {
                Write-CCDCLog "Failed to create AD honeypot: $($_.Exception.Message)" "WARN"
            }
        }
        
        # Create canary file
        $canaryPath = "C:\Shares\Important"
        if (!(Test-Path $canaryPath)) {
            New-Item -Path $canaryPath -ItemType Directory -Force | Out-Null
        }
        
        $canaryFile = "$canaryPath\Confidential_Passwords.txt"
        "DO NOT ACCESS - MONITORING ENABLED" | Out-File $canaryFile
        
        # Enable auditing on canary file
        $acl = Get-Acl $canaryFile
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "Read,Write", "Success,Failure")
        $acl.SetAuditRule($auditRule)
        Set-Acl $canaryFile $acl
        
        Write-CCDCLog "Canary file created: $canaryFile" "SUCCESS"
        
    } catch {
        Write-CCDCLog "Honeypot setup failed: $($_.Exception.Message)" "ERROR"
    }
}

function Stop-DetectionModule {
    Write-CCDCLog "Stopping detection jobs..." "INFO"
    
    foreach ($job in $Global:DetectionJobs) {
        try {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -ErrorAction SilentlyContinue
            Write-CCDCLog "Stopped detection job: $($job.Id)" "INFO"
        } catch {
            Write-CCDCLog "Error stopping detection job $($job.Id): $($_.Exception.Message)" "WARN"
        }
    }
    
    $Global:DetectionJobs = @()
    Write-CCDCLog "Detection module stopped" "SUCCESS"
}