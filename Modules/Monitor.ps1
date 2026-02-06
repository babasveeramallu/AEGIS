# Phase 2 - Monitoring & Logging Module
# Detection without data is blind guessing. This module captures everything that matters before the Red Team moves.

$Global:MonitoringJobs = @()

function Start-MonitoringModule {
    param([PSCustomObject]$SystemProfile)
    
    Write-CCDCLog "Starting monitoring and logging systems..." "INFO"
    
    try {
        # 1. Event Log Collection
        Start-EventLogCollection -SystemProfile $SystemProfile
        
        # 2. Sysmon Integration
        Start-SysmonIntegration
        
        # 3. Network Trace
        Start-NetworkTrace
        
        # 4. Time Drift Monitoring
        Start-TimeDriftMonitoring
        
        # 5. Certificate Monitoring
        Start-CertificateMonitoring
        
        # 6. Defender Tampering Detection
        Start-DefenderTamperingDetection
        
        # 7. Splunk Forwarding Check
        Test-SplunkForwarding
        
        Write-CCDCLog "Monitoring module started successfully" "SUCCESS"
        
    } catch {
        Write-CCDCLog "Error starting monitoring module: $($_.Exception.Message)" "ERROR"
    }
}

function Start-EventLogCollection {
    param([PSCustomObject]$SystemProfile)
    
    Write-CCDCLog "Starting event log collection..." "INFO"
    
    $eventLogJob = Start-Job -ScriptBlock {
        param($LogPath, $ComputerName)
        
        # Key Event IDs to monitor
        $criticalEvents = @{
            "Security" = @(4624, 4625, 4634, 4648, 4662, 4672, 4697, 4698, 4702, 4720, 4732, 1102, 1149)
            "System" = @(7045)
            "Microsoft-Windows-PowerShell/Operational" = @(4103, 4104)
            "Microsoft-Windows-Sysmon/Operational" = @(1, 3, 10, 11, 13)
        }
        
        $lastCheck = Get-Date
        
        while ($true) {
            try {
                foreach ($logName in $criticalEvents.Keys) {
                    $eventIds = $criticalEvents[$logName]
                    
                    $events = Get-WinEvent -FilterHashTable @{
                        LogName = $logName
                        ID = $eventIds
                        StartTime = $lastCheck
                    } -ErrorAction SilentlyContinue
                    
                    if ($events) {
                        foreach ($event in $events) {
                            $eventData = [PSCustomObject]@{
                                TimeCreated = $event.TimeCreated
                                Id = $event.Id
                                LogName = $event.LogName
                                LevelDisplayName = $event.LevelDisplayName
                                Message = $event.Message
                                ComputerName = $ComputerName
                            }
                            
                            # Export to JSON for easy parsing
                            $eventData | ConvertTo-Json -Compress | Out-File "$LogPath\events.json" -Append
                        }
                    }
                }
                
                $lastCheck = Get-Date
                Start-Sleep -Seconds 10
                
            } catch {
                "Event collection error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                Start-Sleep -Seconds 30
            }
        }
    } -ArgumentList $Global:LogPath, $SystemProfile.ComputerName
    
    $Global:MonitoringJobs += $eventLogJob
    Write-CCDCLog "Event log collection job started (Job ID: $($eventLogJob.Id))" "SUCCESS"
}

function Start-SysmonIntegration {
    Write-CCDCLog "Checking Sysmon integration..." "INFO"
    
    try {
        # Check if Sysmon is installed
        $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
        
        if ($sysmonService) {
            Write-CCDCLog "Sysmon detected: $($sysmonService.Name)" "SUCCESS"
            
            # Verify Sysmon is running
            if ($sysmonService.Status -ne "Running") {
                Start-Service -Name $sysmonService.Name
                Write-CCDCLog "Started Sysmon service" "SUCCESS"
            }
            
            # Check Sysmon configuration
            $sysmonConfig = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($sysmonConfig) {
                Write-CCDCLog "Sysmon logging confirmed" "SUCCESS"
            }
            
        } else {
            Write-CCDCLog "Sysmon not installed - consider installing for enhanced monitoring" "WARN"
            
            # Offer to download and install Sysmon
            $sysmonPath = "$env:TEMP\Sysmon.exe"
            if (!(Test-Path $sysmonPath)) {
                Write-CCDCLog "Sysmon installation would require manual download from Microsoft Sysinternals" "INFO"
            }
        }
        
    } catch {
        Write-CCDCLog "Sysmon integration check failed: $($_.Exception.Message)" "WARN"
    }
}

function Start-NetworkTrace {
    Write-CCDCLog "Starting network trace..." "INFO"
    
    try {
        # Start netsh trace for lateral movement detection
        $traceFile = "$Global:LogPath\network_trace.etl"
        
        $traceJob = Start-Job -ScriptBlock {
            param($TraceFile, $LogPath)
            
            try {
                # Start network trace
                netsh trace start capture=yes filemode=circular overwrite=yes maxfilesize=500 tracefile=$TraceFile
                
                # Monitor for 10 minutes, then rotate
                Start-Sleep -Seconds 600
                
                # Stop and restart trace
                netsh trace stop
                
                # Archive the trace file
                $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                $archiveFile = "$LogPath\network_trace_$timestamp.etl"
                Move-Item $TraceFile $archiveFile -ErrorAction SilentlyContinue
                
                # Restart trace
                netsh trace start capture=yes filemode=circular overwrite=yes maxfilesize=500 tracefile=$TraceFile
                
            } catch {
                "Network trace error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
            }
        } -ArgumentList $traceFile, $Global:LogPath
        
        $Global:MonitoringJobs += $traceJob
        Write-CCDCLog "Network trace started (Job ID: $($traceJob.Id))" "SUCCESS"
        
    } catch {
        Write-CCDCLog "Network trace startup failed: $($_.Exception.Message)" "ERROR"
    }
}

function Start-TimeDriftMonitoring {
    Write-CCDCLog "Starting time drift monitoring..." "INFO"
    
    $timeDriftJob = Start-Job -ScriptBlock {
        param($LogPath)
        
        while ($true) {
            try {
                # Check time synchronization status
                $timeStatus = w32tm /query /status 2>$null
                
                if ($timeStatus) {
                    # Parse the output for offset
                    $offsetLine = $timeStatus | Select-String "Last Successful Sync Time"
                    $sourceLine = $timeStatus | Select-String "Source:"
                    
                    # Check for time drift (simplified check)
                    $ntpQuery = w32tm /stripchart /computer:time.windows.com /samples:1 /dataonly 2>$null
                    
                    if ($ntpQuery) {
                        $offsetMatch = $ntpQuery | Select-String "([+-]\d+\.\d+)s"
                        if ($offsetMatch) {
                            $offset = [double]$offsetMatch.Matches[0].Groups[1].Value
                            
                            if ([Math]::Abs($offset) -gt 5) {
                                $alert = [PSCustomObject]@{
                                    Timestamp = Get-Date
                                    AlertType = "TIME_DRIFT"
                                    Severity = "HIGH"
                                    Message = "Time drift detected: $offset seconds"
                                    Offset = $offset
                                }
                                
                                $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                            }
                        }
                    }
                }
                
                Start-Sleep -Seconds 300  # Check every 5 minutes
                
            } catch {
                "Time drift monitoring error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                Start-Sleep -Seconds 600
            }
        }
    } -ArgumentList $Global:LogPath
    
    $Global:MonitoringJobs += $timeDriftJob
    Write-CCDCLog "Time drift monitoring started (Job ID: $($timeDriftJob.Id))" "SUCCESS"
}

function Start-CertificateMonitoring {
    Write-CCDCLog "Starting certificate monitoring..." "INFO"
    
    $certMonitorJob = Start-Job -ScriptBlock {
        param($LogPath)
        
        while ($true) {
            try {
                # Check certificates expiring within 7 days
                $expiringCerts = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
                    $_.NotAfter -lt (Get-Date).AddDays(7) -and $_.NotAfter -gt (Get-Date)
                }
                
                foreach ($cert in $expiringCerts) {
                    $alert = [PSCustomObject]@{
                        Timestamp = Get-Date
                        AlertType = "CERTIFICATE_EXPIRING"
                        Severity = "MEDIUM"
                        Message = "Certificate expiring soon: $($cert.Subject)"
                        Subject = $cert.Subject
                        Expiry = $cert.NotAfter
                        Thumbprint = $cert.Thumbprint
                    }
                    
                    $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                }
                
                # Check for expired certificates
                $expiredCerts = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
                    $_.NotAfter -lt (Get-Date)
                }
                
                foreach ($cert in $expiredCerts) {
                    $alert = [PSCustomObject]@{
                        Timestamp = Get-Date
                        AlertType = "CERTIFICATE_EXPIRED"
                        Severity = "HIGH"
                        Message = "Certificate expired: $($cert.Subject)"
                        Subject = $cert.Subject
                        Expiry = $cert.NotAfter
                        Thumbprint = $cert.Thumbprint
                    }
                    
                    $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                }
                
                Start-Sleep -Seconds 3600  # Check every hour
                
            } catch {
                "Certificate monitoring error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                Start-Sleep -Seconds 3600
            }
        }
    } -ArgumentList $Global:LogPath
    
    $Global:MonitoringJobs += $certMonitorJob
    Write-CCDCLog "Certificate monitoring started (Job ID: $($certMonitorJob.Id))" "SUCCESS"
}

function Start-DefenderTamperingDetection {
    Write-CCDCLog "Starting Defender tampering detection..." "INFO"
    
    try {
        # Get baseline Defender configuration
        $defenderBaseline = Get-MpPreference | Select-Object DisableRealtimeMonitoring, ExclusionPath, ExclusionProcess
        $defenderBaseline | Export-Clixml "$Global:LogPath\defender_baseline.xml"
        
        $defenderMonitorJob = Start-Job -ScriptBlock {
            param($LogPath, $BaselineFile)
            
            # Load baseline
            $baseline = Import-Clixml $BaselineFile
            
            while ($true) {
                try {
                    $current = Get-MpPreference | Select-Object DisableRealtimeMonitoring, ExclusionPath, ExclusionProcess
                    
                    # Check for changes
                    $changes = @()
                    
                    if ($current.DisableRealtimeMonitoring -ne $baseline.DisableRealtimeMonitoring) {
                        $changes += "Real-time monitoring changed"
                    }
                    
                    if (Compare-Object $current.ExclusionPath $baseline.ExclusionPath) {
                        $changes += "Exclusion paths modified"
                    }
                    
                    if (Compare-Object $current.ExclusionProcess $baseline.ExclusionProcess) {
                        $changes += "Exclusion processes modified"
                    }
                    
                    if ($changes.Count -gt 0) {
                        $alert = [PSCustomObject]@{
                            Timestamp = Get-Date
                            AlertType = "DEFENDER_TAMPERING"
                            Severity = "HIGH"
                            Message = "Windows Defender configuration changed: $($changes -join ', ')"
                            Changes = $changes
                        }
                        
                        $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                        
                        # Update baseline
                        $current | Export-Clixml $BaselineFile
                    }
                    
                    Start-Sleep -Seconds 60  # Check every minute
                    
                } catch {
                    "Defender monitoring error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                    Start-Sleep -Seconds 300
                }
            }
        } -ArgumentList $Global:LogPath, "$Global:LogPath\defender_baseline.xml"
        
        $Global:MonitoringJobs += $defenderMonitorJob
        Write-CCDCLog "Defender tampering detection started (Job ID: $($defenderMonitorJob.Id))" "SUCCESS"
        
    } catch {
        Write-CCDCLog "Defender tampering detection failed to start: $($_.Exception.Message)" "ERROR"
    }
}

function Test-SplunkForwarding {
    Write-CCDCLog "Checking Splunk Universal Forwarder..." "INFO"
    
    try {
        # Check for Splunk Universal Forwarder
        $splunkService = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
        
        if ($splunkService) {
            if ($splunkService.Status -eq "Running") {
                Write-CCDCLog "Splunk Universal Forwarder is running" "SUCCESS"
            } else {
                Write-CCDCLog "Splunk Universal Forwarder found but not running" "WARN"
                try {
                    Start-Service -Name "SplunkForwarder"
                    Write-CCDCLog "Started Splunk Universal Forwarder" "SUCCESS"
                } catch {
                    Write-CCDCLog "Failed to start Splunk Universal Forwarder: $($_.Exception.Message)" "ERROR"
                }
            }
        } else {
            Write-CCDCLog "Splunk Universal Forwarder not found" "INFO"
        }
        
    } catch {
        Write-CCDCLog "Splunk forwarder check failed: $($_.Exception.Message)" "WARN"
    }
}

function Stop-MonitoringModule {
    Write-CCDCLog "Stopping monitoring jobs..." "INFO"
    
    foreach ($job in $Global:MonitoringJobs) {
        try {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -ErrorAction SilentlyContinue
            Write-CCDCLog "Stopped monitoring job: $($job.Id)" "INFO"
        } catch {
            Write-CCDCLog "Error stopping job $($job.Id): $($_.Exception.Message)" "WARN"
        }
    }
    
    # Stop network trace
    try {
        netsh trace stop 2>$null
        Write-CCDCLog "Network trace stopped" "INFO"
    } catch {
        Write-CCDCLog "Error stopping network trace: $($_.Exception.Message)" "WARN"
    }
    
    $Global:MonitoringJobs = @()
    Write-CCDCLog "Monitoring module stopped" "SUCCESS"
}