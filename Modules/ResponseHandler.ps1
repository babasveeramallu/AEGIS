# Phase 4 - Incident Response Module
# When a detection fires, the tool does not just alert — it acts.
# Split responses into AUTO and OPERATOR tiers for safety.

$Global:IncidentQueue = @()
$Global:AutoResponseEnabled = $true

function Start-IncidentResponseModule {
    param([PSCustomObject]$SystemProfile)
    
    Write-SecLog "Starting incident response module..." "INFO"
    
    try {
        # Start alert processing job
        $irJob = Start-Job -ScriptBlock {
            param($LogPath, $BackupPath)
            
            $processedAlerts = @()
            
            while ($true) {
                try {
                    # Check for new alerts
                    $alertFile = "$LogPath\alerts.json"
                    if (Test-Path $alertFile) {
                        $allAlerts = Get-Content $alertFile | ForEach-Object { $_ | ConvertFrom-Json }
                        $newAlerts = $allAlerts | Where-Object { $_.Timestamp -notin $processedAlerts }
                        
                        foreach ($alert in $newAlerts) {
                            # Process alert based on type and severity
                            $response = Get-ResponseAction -Alert $alert
                            
                            if ($response.Tier -eq "AUTO") {
                                # Execute automatic response
                                $result = Invoke-AutoResponse -Alert $alert -Action $response.Action
                                
                                # Log the response
                                $responseLog = [PSCustomObject]@{
                                    Timestamp = Get-Date
                                    AlertType = $alert.AlertType
                                    ResponseAction = $response.Action
                                    Result = $result
                                    AutoExecuted = $true
                                }
                                
                                $responseLog | ConvertTo-Json -Compress | Out-File "$LogPath\responses.json" -Append
                                
                            } elseif ($response.Tier -eq "OPERATOR") {
                                # Queue for operator approval
                                $operatorAlert = [PSCustomObject]@{
                                    Timestamp = Get-Date
                                    Alert = $alert
                                    RecommendedAction = $response.Action
                                    Reason = $response.Reason
                                    RequiresApproval = $true
                                }
                                
                                $operatorAlert | ConvertTo-Json -Compress | Out-File "$LogPath\operator_queue.json" -Append
                            }
                            
                            $processedAlerts += $alert.Timestamp
                        }
                    }
                    
                    Start-Sleep -Seconds 10
                    
                } catch {
                    "Incident response error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                    Start-Sleep -Seconds 30
                }
            }
        } -ArgumentList $Global:LogPath, $Global:BackupPath
        
        $Global:MonitoringJobs += $irJob
        Write-SecLog "Incident response processing started (Job ID: $($irJob.Id))" "SUCCESS"
        
    } catch {
        Write-SecLog "Failed to start incident response module: $($_.Exception.Message)" "ERROR"
    }
}

function Get-ResponseAction {
    param([PSCustomObject]$Alert)
    
    # Response tier mapping based on alert type and severity
    $responseMap = @{
        "PASS_THE_HASH" = @{
            Tier = "OPERATOR"
            Action = "DISABLE_ACCOUNT"
            Reason = "Could break scoring if account is service-linked"
        }
        "BRUTE_FORCE" = @{
            Tier = "AUTO"
            Action = "BLOCK_SOURCE_IP"
            Reason = "Safe - inbound block only, reversible via rollback"
        }
        "LATERAL_MOVEMENT" = @{
            Tier = "OPERATOR"
            Action = "ISOLATE_MACHINE"
            Reason = "Breaks all services on that machine"
        }
        "LOLBIN_ABUSE" = @{
            Tier = "AUTO"
            Action = "KILL_PROCESS"
            Reason = "Safe - process is logged and dead, nothing else changes"
        }
        "LOG_CLEARING" = @{
            Tier = "AUTO"
            Action = "ALERT_AND_LOG"
            Reason = "Always safe"
        }
        "HONEYPOT_TRIGGERED" = @{
            Tier = "AUTO"
            Action = "ALERT_AND_LOG"
            Reason = "Critical alert - immediate investigation required"
        }
        "DCSYNC_ATTEMPT" = @{
            Tier = "OPERATOR"
            Action = "DISABLE_ACCOUNT"
            Reason = "High-impact - needs human judgment"
        }
        "NEW_SCHEDULED_TASK" = @{
            Tier = "AUTO"
            Action = "DELETE_TASK"
            Reason = "Safe if task was not in Phase 0 baseline"
        }
        "DEFENDER_TAMPERING" = @{
            Tier = "AUTO"
            Action = "RESTORE_DEFENDER"
            Reason = "Safe - restores security configuration"
        }
    }
    
    $alertType = $Alert.AlertType
    
    if ($responseMap.ContainsKey($alertType)) {
        return $responseMap[$alertType]
    } else {
        # Default response for unknown alert types
        return @{
            Tier = "OPERATOR"
            Action = "MANUAL_REVIEW"
            Reason = "Unknown alert type requires human analysis"
        }
    }
}

function Invoke-AutoResponse {
    param(
        [PSCustomObject]$Alert,
        [string]$Action
    )
    
    Write-SecLog "Executing auto-response: $Action for alert: $($Alert.AlertType)" "INFO"
    
    try {
        switch ($Action) {
            "BLOCK_SOURCE_IP" {
                $safeIP = Get-SafeString -Input $Alert.SourceIP
                if ($safeIP -and $safeIP -ne '-' -and $safeIP -ne '127.0.0.1' -and $safeIP -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
                    $ruleName = "BLOCK_$($safeIP.Replace('.', '_'))"
                    netsh advfirewall firewall add rule name=$ruleName dir=in action=block remoteip=$safeIP
                    Write-SecLog "Blocked source IP: $safeIP" "SUCCESS"
                    return "SUCCESS: Blocked IP $safeIP"
                } else {
                    return "SKIPPED: Invalid or local IP address"
                }
            }
            
            "KILL_PROCESS" {
                if ($Alert.ProcessId) {
                    if (Stop-ProcessSafe -Id $Alert.ProcessId -Name ($Alert.ProcessName -replace '[^\w\-\.]', '')) {
                        Write-SecLog "Killed suspicious process: $($Alert.ProcessId)" "SUCCESS"
                        return "SUCCESS: Process $($Alert.ProcessId) terminated"
                    } else {
                        return "FAILED: Could not terminate process $($Alert.ProcessId)"
                    }
                } else {
                    return "SKIPPED: No process ID available"
                }
            }
            
            "DELETE_TASK" {
                if ($Alert.TaskName) {
                    try {
                        Unregister-ScheduledTask -TaskName $Alert.TaskName -Confirm:$false
                        Write-SecLog "Deleted suspicious scheduled task: $($Alert.TaskName)" "SUCCESS"
                        return "SUCCESS: Task $($Alert.TaskName) deleted"
                    } catch {
                        return "FAILED: Could not delete task $($Alert.TaskName)"
                    }
                } else {
                    return "SKIPPED: No task name available"
                }
            }
            
            "RESTORE_DEFENDER" {
                try {
                    # Restore Defender to secure configuration
                    Set-MpPreference -DisableRealtimeMonitoring $false
                    Set-MpPreference -DisableBehaviorMonitoring $false
                    Set-MpPreference -DisableBlockAtFirstSeen $false
                    Write-SecLog "Restored Windows Defender configuration" "SUCCESS"
                    return "SUCCESS: Defender configuration restored"
                } catch {
                    return "FAILED: Could not restore Defender configuration"
                }
            }
            
            "ALERT_AND_LOG" {
                # Generate incident report
                $incident = Generate-IncidentReport -Alert $Alert
                Write-SecLog "Generated incident report for: $($Alert.AlertType)" "SUCCESS"
                return "SUCCESS: Incident report generated"
            }
            
            default {
                Write-SecLog "Unknown auto-response action: $Action" "WARN"
                return "UNKNOWN: Action not implemented"
            }
        }
        
    } catch {
        Write-SecLog "Auto-response failed: $($_.Exception.Message)" "ERROR"
        return "ERROR: $($_.Exception.Message)"
    }
}

function Generate-IncidentReport {
    param([PSCustomObject]$Alert)
    
    $reportId = "IR-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$((Get-Random).ToString().Substring(0,4))"
    
    $report = [PSCustomObject]@{
        ReportId = $reportId
        Timestamp = Get-Date
        AlertType = $Alert.AlertType
        Severity = $Alert.Severity
        
        # What Happened
        Summary = $Alert.Message
        TechnicalDetails = $Alert
        
        # Source & Destination
        SourceIP = if ($Alert.SourceIP) { $Alert.SourceIP } else { "N/A" }
        DestinationIP = $env:COMPUTERNAME
        AffectedAccount = if ($Alert.Account) { $Alert.Account } else { "N/A" }
        
        # Timeline
        FirstDetected = $Alert.Timestamp
        LastActivity = $Alert.Timestamp
        
        # What Was Affected
        AffectedSystems = @($env:COMPUTERNAME)
        AffectedServices = @()
        AffectedFiles = @()
        
        # Actions Taken
        AutoResponseTaken = $true
        ManualActionRequired = $false
        
        # Remediation
        RecommendedActions = Get-RemediationSteps -AlertType $Alert.AlertType
        
        # Classification
        ThreatCategory = Get-ThreatCategory -AlertType $Alert.AlertType
        AttackPhase = Get-AttackPhase -AlertType $Alert.AlertType
    }
    
    # Add specific details based on alert type
    switch ($Alert.AlertType) {
        "PASS_THE_HASH" {
            $report.AffectedAccount = $Alert.Account
            $report.SourceIP = $Alert.SourceIP
            $report.ThreatCategory = "Credential Theft"
            $report.AttackPhase = "Lateral Movement"
        }
        "BRUTE_FORCE" {
            $report.AffectedAccount = $Alert.Account
            $report.SourceIP = $Alert.SourceIP
            $report.ThreatCategory = "Credential Attack"
            $report.AttackPhase = "Initial Access"
        }
        "LOLBIN_ABUSE" {
            $report.AffectedFiles = @($Alert.ProcessName)
            $report.TechnicalDetails = "Command Line: $($Alert.CommandLine)"
            $report.ThreatCategory = "Defense Evasion"
            $report.AttackPhase = "Execution"
        }
        "HONEYPOT_TRIGGERED" {
            $report.Severity = "CRITICAL"
            $report.ManualActionRequired = $true
            $report.ThreatCategory = "Reconnaissance"
            $report.AttackPhase = "Discovery"
        }
    }
    
    # Export report
    $reportPath = "$Global:LogPath\Reports\$reportId.json"
    if (!(Test-Path "$Global:LogPath\Reports")) {
        New-Item -Path "$Global:LogPath\Reports" -ItemType Directory -Force | Out-Null
    }
    
    $report | ConvertTo-Json -Depth 10 | Out-File $reportPath
    
    # Generate PDF-ready summary
    $pdfSummary = @"
INCIDENT REPORT - $reportId
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

EXECUTIVE SUMMARY
Alert Type: $($report.AlertType)
Severity: $($report.Severity)
Summary: $($report.Summary)

TECHNICAL DETAILS
Source IP: $($report.SourceIP)
Affected Account: $($report.AffectedAccount)
Affected Systems: $($report.AffectedSystems -join ', ')

TIMELINE
First Detected: $($report.FirstDetected)
Last Activity: $($report.LastActivity)

THREAT CLASSIFICATION
Category: $($report.ThreatCategory)
Attack Phase: $($report.AttackPhase)

ACTIONS TAKEN
Auto-Response: $($report.AutoResponseTaken)
Manual Action Required: $($report.ManualActionRequired)

RECOMMENDED REMEDIATION
$($report.RecommendedActions -join "`n")

END OF REPORT
"@
    
    $pdfSummary | Out-File "$Global:LogPath\Reports\$reportId.txt"
    
    Write-SecLog "Incident report generated: $reportId" "SUCCESS"
    return $report
}

function Get-RemediationSteps {
    param([string]$AlertType)
    
    $remediationMap = @{
        "PASS_THE_HASH" = @(
            "1. Immediately reset password for affected account",
            "2. Check for additional compromised accounts",
            "3. Review recent logon activity for the account",
            "4. Consider disabling account if not critical for scoring"
        )
        "BRUTE_FORCE" = @(
            "1. Source IP has been automatically blocked",
            "2. Monitor for additional attack sources",
            "3. Consider implementing account lockout policies",
            "4. Review password strength for targeted account"
        )
        "LOLBIN_ABUSE" = @(
            "1. Suspicious process has been terminated",
            "2. Scan system for additional malware",
            "3. Review process execution logs",
            "4. Consider application whitelisting"
        )
        "HONEYPOT_TRIGGERED" = @(
            "1. IMMEDIATE INVESTIGATION REQUIRED",
            "2. Identify source of honeypot access",
            "3. Check for lateral movement from source",
            "4. Review all recent account activity",
            "5. Consider isolating affected systems"
        )
        "LOG_CLEARING" = @(
            "1. Identify who cleared the logs",
            "2. Check for backup log sources",
            "3. Implement log forwarding to prevent future clearing",
            "4. Review system for signs of compromise"
        )
    }
    
    if ($remediationMap.ContainsKey($AlertType)) {
        return $remediationMap[$AlertType]
    } else {
        return @("1. Manual investigation required", "2. Review alert details", "3. Implement appropriate countermeasures")
    }
}

function Get-ThreatCategory {
    param([string]$AlertType)
    
    $categoryMap = @{
        "PASS_THE_HASH" = "Credential Theft"
        "BRUTE_FORCE" = "Credential Attack"
        "LATERAL_MOVEMENT" = "Lateral Movement"
        "LOLBIN_ABUSE" = "Defense Evasion"
        "LOG_CLEARING" = "Defense Evasion"
        "HONEYPOT_TRIGGERED" = "Reconnaissance"
        "DCSYNC_ATTEMPT" = "Credential Dumping"
        "NEW_SCHEDULED_TASK" = "Persistence"
        "DEFENDER_TAMPERING" = "Defense Evasion"
    }
    
    return if ($categoryMap.ContainsKey($AlertType)) { $categoryMap[$AlertType] } else { "Unknown" }
}

function Get-AttackPhase {
    param([string]$AlertType)
    
    $phaseMap = @{
        "PASS_THE_HASH" = "Lateral Movement"
        "BRUTE_FORCE" = "Initial Access"
        "LATERAL_MOVEMENT" = "Lateral Movement"
        "LOLBIN_ABUSE" = "Execution"
        "LOG_CLEARING" = "Defense Evasion"
        "HONEYPOT_TRIGGERED" = "Discovery"
        "DCSYNC_ATTEMPT" = "Credential Access"
        "NEW_SCHEDULED_TASK" = "Persistence"
        "DEFENDER_TAMPERING" = "Defense Evasion"
    }
    
    return if ($phaseMap.ContainsKey($AlertType)) { $phaseMap[$AlertType] } else { "Unknown" }
}

function Get-OperatorQueue {
    $queueFile = "$Global:LogPath\operator_queue.json"
    if (Test-Path $queueFile) {
        return Get-Content $queueFile | ForEach-Object { $_ | ConvertFrom-Json }
    } else {
        return @()
    }
}

function Approve-OperatorAction {
    param(
        [string]$AlertId,
        [bool]$Approved,
        [string]$Reason
    )
    
    Write-SecLog "Operator decision for alert $AlertId : Approved=$Approved, Reason=$Reason" "INFO"
    
    if ($Approved) {
        # Execute the recommended action
        # This would need to be implemented based on the specific action
        Write-SecLog "Executing operator-approved action for alert $AlertId" "INFO"
    } else {
        Write-SecLog "Operator rejected action for alert $AlertId : $Reason" "INFO"
    }
    
    # Log the decision
    $decision = [PSCustomObject]@{
        Timestamp = Get-Date
        AlertId = $AlertId
        Approved = $Approved
        Reason = $Reason
        Operator = $env:USERNAME
    }
    
    $decision | ConvertTo-Json -Compress | Out-File "$Global:LogPath\operator_decisions.json" -Append
}