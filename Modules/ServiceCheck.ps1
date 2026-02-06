# Phase 5 - Scoring Validation Loop
# If you break scoring, you lose. This phase runs continuously during the competition
# and tests every scoring-critical service locally before the external scoring engine does.

$Global:ScoringJobs = @()
$Global:ServiceBaselines = @{}

function Start-ScoringValidation {
    param([PSCustomObject]$SystemProfile)
    
    Write-CCDCLog "Starting scoring validation loop..." "INFO"
    
    try {
        # Create service baselines
        Initialize-ServiceBaselines -SystemProfile $SystemProfile
        
        # Start continuous validation
        $scoringJob = Start-Job -ScriptBlock {
            param($LogPath, $SystemProfile, $ServiceBaselines)
            
            while ($true) {
                try {
                    $validationResults = @()
                    
                    # Test each scoring service
                    foreach ($service in $SystemProfile.ScoringServices) {
                        $serviceParts = $service.Split(':')
                        $serviceName = $serviceParts[0]
                        $port = $serviceParts[1]
                        
                        $result = Test-ScoringService -ServiceName $serviceName -Port $port -SystemProfile $SystemProfile
                        $validationResults += $result
                        
                        # Check for service failures
                        if (-not $result.Success) {
                            # Check if a recent hardening action might have caused this
                            $correlation = Check-HardeningCorrelation -ServiceName $serviceName -FailureTime $result.Timestamp
                            
                            $alert = [PSCustomObject]@{
                                Timestamp = Get-Date
                                AlertType = "SCORING_SERVICE_FAILURE"
                                Severity = "CRITICAL"
                                Message = "Scoring service failure detected: $serviceName on port $port"
                                ServiceName = $serviceName
                                Port = $port
                                Error = $result.Error
                                PossibleCause = $correlation.PossibleCause
                                RecommendedAction = $correlation.RecommendedAction
                            }
                            
                            $alert | ConvertTo-Json -Compress | Out-File "$LogPath\alerts.json" -Append
                        }
                    }
                    
                    # Log validation results
                    $summary = [PSCustomObject]@{
                        Timestamp = Get-Date
                        TotalServices = $validationResults.Count
                        SuccessfulServices = ($validationResults | Where-Object { $_.Success }).Count
                        FailedServices = ($validationResults | Where-Object { -not $_.Success }).Count
                        Results = $validationResults
                    }
                    
                    $summary | ConvertTo-Json -Compress | Out-File "$LogPath\scoring_validation.json" -Append
                    
                    Start-Sleep -Seconds 30  # Test every 30 seconds
                    
                } catch {
                    "Scoring validation error: $($_.Exception.Message)" | Out-File "$LogPath\monitoring_errors.log" -Append
                    Start-Sleep -Seconds 60
                }
            }
        } -ArgumentList $Global:LogPath, $SystemProfile, $Global:ServiceBaselines
        
        $Global:ScoringJobs += $scoringJob
        Write-CCDCLog "Scoring validation started (Job ID: $($scoringJob.Id))" "SUCCESS"
        
    } catch {
        Write-CCDCLog "Failed to start scoring validation: $($_.Exception.Message)" "ERROR"
    }
}

function Initialize-ServiceBaselines {
    param([PSCustomObject]$SystemProfile)
    
    Write-CCDCLog "Creating service baselines..." "INFO"
    
    foreach ($service in $SystemProfile.ScoringServices) {
        $serviceParts = $service.Split(':')
        $serviceName = $serviceParts[0]
        $port = $serviceParts[1]
        
        try {
            $baseline = Create-ServiceBaseline -ServiceName $serviceName -Port $port -SystemProfile $SystemProfile
            $Global:ServiceBaselines[$service] = $baseline
            Write-CCDCLog "Baseline created for $serviceName on port $port" "SUCCESS"
        } catch {
            Write-CCDCLog "Failed to create baseline for $serviceName : $($_.Exception.Message)" "WARN"
        }
    }
}

function Create-ServiceBaseline {
    param(
        [string]$ServiceName,
        [string]$Port,
        [PSCustomObject]$SystemProfile
    )
    
    $baseline = [PSCustomObject]@{
        ServiceName = $ServiceName
        Port = $Port
        ExpectedResponse = $null
        ExpectedContent = $null
        ExpectedCertificate = $null
        ResponseTime = $null
        CreatedAt = Get-Date
    }
    
    switch ($ServiceName.ToUpper()) {
        "HTTP" {
            try {
                $response = Invoke-WebRequest -Uri "http://localhost:$Port" -TimeoutSec 10 -UseBasicParsing
                $baseline.ExpectedResponse = $response.StatusCode
                $baseline.ExpectedContent = $response.Content.Substring(0, [Math]::Min(500, $response.Content.Length))
                $baseline.ResponseTime = $response.Headers.'X-Response-Time'
            } catch {
                $baseline.ExpectedResponse = "ERROR"
                $baseline.ExpectedContent = $_.Exception.Message
            }
        }
        
        "HTTPS" {
            try {
                # Ignore certificate errors for baseline creation
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                $response = Invoke-WebRequest -Uri "https://localhost:$Port" -TimeoutSec 10 -UseBasicParsing
                $baseline.ExpectedResponse = $response.StatusCode
                $baseline.ExpectedContent = $response.Content.Substring(0, [Math]::Min(500, $response.Content.Length))
                
                # Get certificate info
                $cert = Get-WebCertificate -Uri "https://localhost:$Port"
                if ($cert) {
                    $baseline.ExpectedCertificate = @{
                        Subject = $cert.Subject
                        Thumbprint = $cert.Thumbprint
                        NotAfter = $cert.NotAfter
                    }
                }
            } catch {
                $baseline.ExpectedResponse = "ERROR"
                $baseline.ExpectedContent = $_.Exception.Message
            } finally {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
            }
        }
        
        "DNS" {
            try {
                $dnsTest = Resolve-DnsName -Name "localhost" -Server "127.0.0.1" -Type A -ErrorAction Stop
                $baseline.ExpectedResponse = "SUCCESS"
                $baseline.ExpectedContent = $dnsTest.IPAddress -join ','
            } catch {
                $baseline.ExpectedResponse = "ERROR"
                $baseline.ExpectedContent = $_.Exception.Message
            }
        }
        
        "SMTP" {
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect("localhost", $Port)
                $stream = $tcpClient.GetStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $banner = $reader.ReadLine()
                $baseline.ExpectedResponse = "220"
                $baseline.ExpectedContent = $banner
                $tcpClient.Close()
            } catch {
                $baseline.ExpectedResponse = "ERROR"
                $baseline.ExpectedContent = $_.Exception.Message
            }
        }
        
        "POP3" {
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect("localhost", $Port)
                $stream = $tcpClient.GetStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $banner = $reader.ReadLine()
                $baseline.ExpectedResponse = "+OK"
                $baseline.ExpectedContent = $banner
                $tcpClient.Close()
            } catch {
                $baseline.ExpectedResponse = "ERROR"
                $baseline.ExpectedContent = $_.Exception.Message
            }
        }
        
        "FTP" {
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect("localhost", $Port)
                $stream = $tcpClient.GetStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $banner = $reader.ReadLine()
                $baseline.ExpectedResponse = "220"
                $baseline.ExpectedContent = $banner
                $tcpClient.Close()
            } catch {
                $baseline.ExpectedResponse = "ERROR"
                $baseline.ExpectedContent = $_.Exception.Message
            }
        }
        
        default {
            # Generic port test
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect("localhost", $Port)
                $baseline.ExpectedResponse = "CONNECTED"
                $tcpClient.Close()
            } catch {
                $baseline.ExpectedResponse = "ERROR"
                $baseline.ExpectedContent = $_.Exception.Message
            }
        }
    }
    
    return $baseline
}

function Test-ScoringService {
    param(
        [string]$ServiceName,
        [string]$Port,
        [PSCustomObject]$SystemProfile
    )
    
    $result = [PSCustomObject]@{
        ServiceName = $ServiceName
        Port = $Port
        Timestamp = Get-Date
        Success = $false
        ResponseTime = $null
        Error = $null
        Details = $null
    }
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        switch ($ServiceName.ToUpper()) {
            "HTTP" {
                $response = Invoke-WebRequest -Uri "http://localhost:$Port" -TimeoutSec 10 -UseBasicParsing
                $result.Success = ($response.StatusCode -eq 200)
                $result.Details = "Status: $($response.StatusCode)"
                
                # Compare with baseline if available
                $baseline = $Global:ServiceBaselines["HTTP:$Port"]
                if ($baseline -and $baseline.ExpectedResponse -ne "ERROR") {
                    if ($response.StatusCode -ne $baseline.ExpectedResponse) {
                        $result.Error = "Response code changed from $($baseline.ExpectedResponse) to $($response.StatusCode)"
                        $result.Success = $false
                    }
                }
            }
            
            "HTTPS" {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                $response = Invoke-WebRequest -Uri "https://localhost:$Port" -TimeoutSec 10 -UseBasicParsing
                $result.Success = ($response.StatusCode -eq 200)
                $result.Details = "Status: $($response.StatusCode)"
                
                # Check certificate validity
                $cert = Get-WebCertificate -Uri "https://localhost:$Port"
                if ($cert -and $cert.NotAfter -lt (Get-Date)) {
                    $result.Error = "SSL Certificate expired: $($cert.NotAfter)"
                    $result.Success = $false
                }
                
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
            }
            
            "DNS" {
                # Test multiple DNS queries
                $testQueries = @("localhost", "google.com", $env:COMPUTERNAME)
                $successCount = 0
                
                foreach ($query in $testQueries) {
                    try {
                        $dnsResult = Resolve-DnsName -Name $query -Server "127.0.0.1" -Type A -ErrorAction Stop
                        if ($dnsResult) { $successCount++ }
                    } catch {
                        # Query failed
                    }
                }
                
                $result.Success = ($successCount -gt 0)
                $result.Details = "Successful queries: $successCount/$($testQueries.Count)"
                
                if ($successCount -eq 0) {
                    $result.Error = "All DNS queries failed"
                }
            }
            
            "SMTP" {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect("localhost", $Port)
                $stream = $tcpClient.GetStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $writer = New-Object System.IO.StreamWriter($stream)
                
                $banner = $reader.ReadLine()
                $result.Success = ($banner -match "^220")
                $result.Details = "Banner: $banner"
                
                # Test EHLO and AUTH commands
                $writer.WriteLine("EHLO test.domain.local")
                $writer.Flush()
                $ehloResponse = $reader.ReadLine()
                
                if ($ehloResponse -match "^250") {
                    # Test AUTH LOGIN capability
                    $writer.WriteLine("AUTH LOGIN")
                    $writer.Flush()
                    $authResponse = $reader.ReadLine()
                    
                    if (-not ($authResponse -match "^334")) {
                        $result.Error = "SMTP AUTH not supported: $authResponse"
                        $result.Success = $false
                    }
                } else {
                    $result.Error = "EHLO command failed: $ehloResponse"
                    $result.Success = $false
                }
                
                $writer.WriteLine("QUIT")
                $writer.Flush()
                $tcpClient.Close()
            }
            
            "POP3" {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect("localhost", $Port)
                $stream = $tcpClient.GetStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $writer = New-Object System.IO.StreamWriter($stream)
                
                $banner = $reader.ReadLine()
                $result.Success = ($banner -match "^\+OK")
                $result.Details = "Banner: $banner"
                
                # Test USER command with test credentials
                $writer.WriteLine("USER testuser")
                $writer.Flush()
                $userResponse = $reader.ReadLine()
                
                if (-not ($userResponse -match "^\+OK")) {
                    $result.Error = "POP3 USER command failed: $userResponse"
                    $result.Success = $false
                }
                
                $writer.WriteLine("QUIT")
                $writer.Flush()
                $tcpClient.Close()
            }
            
            "FTP" {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect("localhost", $Port)
                $stream = $tcpClient.GetStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $writer = New-Object System.IO.StreamWriter($stream)
                
                $banner = $reader.ReadLine()
                $result.Success = ($banner -match "^220")
                $result.Details = "Banner: $banner"
                
                # Test USER command for anonymous access
                $writer.WriteLine("USER anonymous")
                $writer.Flush()
                $userResponse = $reader.ReadLine()
                
                if (-not ($userResponse -match "^(331|230)")) {
                    $result.Error = "FTP USER command failed: $userResponse"
                    $result.Success = $false
                }
                
                $writer.WriteLine("QUIT")
                $writer.Flush()
                $tcpClient.Close()
            }
            
            "RDP" {
                # Simple port connectivity test for RDP
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect("localhost", $Port)
                $result.Success = $tcpClient.Connected
                $result.Details = "Port connectivity: $($tcpClient.Connected)"
                $tcpClient.Close()
            }
            
            default {
                # Generic port test
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect("localhost", $Port)
                $result.Success = $tcpClient.Connected
                $result.Details = "Port connectivity: $($tcpClient.Connected)"
                $tcpClient.Close()
            }
        }
        
    } catch {
        $result.Success = $false
        $result.Error = $_.Exception.Message
    } finally {
        $stopwatch.Stop()
        $result.ResponseTime = $stopwatch.ElapsedMilliseconds
    }
    
    return $result
}

function Check-HardeningCorrelation {
    param(
        [string]$ServiceName,
        [datetime]$FailureTime
    )
    
    $correlation = [PSCustomObject]@{
        PossibleCause = "Unknown"
        RecommendedAction = "Manual investigation required"
        Confidence = 0.0
    }
    
    # Check if any hardening actions occurred within 5 minutes of the failure
    $recentActions = Get-RecentHardeningActions -Minutes 5 -BeforeTime $FailureTime
    
    if ($recentActions.Count -gt 0) {
        # Analyze potential correlations
        foreach ($action in $recentActions) {
            switch ($action.ActionType) {
                "FIREWALL_RULE_CHANGE" {
                    $correlation.PossibleCause = "Firewall rule modification may have blocked service"
                    $correlation.RecommendedAction = "Review firewall rules and consider rollback"
                    $correlation.Confidence = 0.8
                }
                "SERVICE_DISABLE" {
                    if ($action.ServiceName -eq $ServiceName) {
                        $correlation.PossibleCause = "Service was disabled during hardening"
                        $correlation.RecommendedAction = "Re-enable service and update hardening playbook"
                        $correlation.Confidence = 0.95
                    }
                }
                "REGISTRY_CHANGE" {
                    $correlation.PossibleCause = "Registry modification may have affected service configuration"
                    $correlation.RecommendedAction = "Review registry changes and consider rollback"
                    $correlation.Confidence = 0.6
                }
                "IIS_CONFIG_CHANGE" {
                    if ($ServiceName -in @("HTTP", "HTTPS")) {
                        $correlation.PossibleCause = "IIS configuration change affected web service"
                        $correlation.RecommendedAction = "Review IIS configuration and consider rollback"
                        $correlation.Confidence = 0.9
                    }
                }
            }
        }
    }
    
    return $correlation
}

function Get-RecentHardeningActions {
    param(
        [int]$Minutes = 5,
        [datetime]$BeforeTime = (Get-Date)
    )
    
    # This would read from a hardening actions log
    # For now, return empty array as placeholder
    return @()
}

function Get-WebCertificate {
    param([string]$Uri)
    
    try {
        $request = [System.Net.WebRequest]::Create($Uri)
        $request.Timeout = 10000
        $response = $request.GetResponse()
        $cert = $request.ServicePoint.Certificate
        $response.Close()
        
        if ($cert) {
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
        }
    } catch {
        return $null
    }
    
    return $null
}

function Get-ScoringStatus {
    $statusFile = "$Global:LogPath\scoring_validation.json"
    if (Test-Path $statusFile) {
        $recentStatus = Get-Content $statusFile | ForEach-Object { $_ | ConvertFrom-Json } | Sort-Object Timestamp -Descending | Select-Object -First 1
        return $recentStatus
    } else {
        return $null
    }
}

function Stop-ScoringValidation {
    Write-CCDCLog "Stopping scoring validation..." "INFO"
    
    foreach ($job in $Global:ScoringJobs) {
        try {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -ErrorAction SilentlyContinue
            Write-CCDCLog "Stopped scoring job: $($job.Id)" "INFO"
        } catch {
            Write-CCDCLog "Error stopping scoring job $($job.Id): $($_.Exception.Message)" "WARN"
        }
    }
    
    $Global:ScoringJobs = @()
    Write-CCDCLog "Scoring validation stopped" "SUCCESS"
}