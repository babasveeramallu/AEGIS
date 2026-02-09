# Scoring Service Validation Module
# PRIORITY 1: Prevent service breakage during hardening

function Test-ScoringServicesBaseline {
    Write-SecLog "Creating scoring services baseline..." "INFO"
    
    $baseline = @{
        HTTP = Test-NetConnection -ComputerName localhost -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue
        HTTPS = Test-NetConnection -ComputerName localhost -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        DNS = (Resolve-DnsName localhost -ErrorAction SilentlyContinue) -ne $null
        SMTP = Test-NetConnection -ComputerName localhost -Port 25 -InformationLevel Quiet -WarningAction SilentlyContinue
        FTP = Test-NetConnection -ComputerName localhost -Port 21 -InformationLevel Quiet -WarningAction SilentlyContinue
        POP3 = Test-NetConnection -ComputerName localhost -Port 110 -InformationLevel Quiet -WarningAction SilentlyContinue
        RDP = Test-NetConnection -ComputerName localhost -Port 3389 -InformationLevel Quiet -WarningAction SilentlyContinue
        LDAP = Test-NetConnection -ComputerName localhost -Port 389 -InformationLevel Quiet -WarningAction SilentlyContinue
        LDAPS = Test-NetConnection -ComputerName localhost -Port 636 -InformationLevel Quiet -WarningAction SilentlyContinue
    }
    
    $baseline | Export-Clixml "$Global:BackupPath\scoring_baseline.xml"
    
    $activeServices = ($baseline.GetEnumerator() | Where-Object { $_.Value -eq $true }).Count
    Write-SecLog "Baseline: $activeServices active scoring services detected" "SUCCESS"
    
    return $baseline
}

function Test-ScoringServicesHealth {
    param([hashtable]$Baseline)
    
    $broken = @()
    
    foreach ($service in $Baseline.Keys) {
        if (-not $Baseline[$service]) { continue }
        
        $port = switch ($service) {
            "HTTP" { 80 }
            "HTTPS" { 443 }
            "DNS" { 53 }
            "SMTP" { 25 }
            "FTP" { 21 }
            "POP3" { 110 }
            "RDP" { 3389 }
            "LDAP" { 389 }
            "LDAPS" { 636 }
        }
        
        $current = Test-NetConnection -ComputerName localhost -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
        
        if (-not $current) {
            $broken += "$service (port $port)"
            Write-SecLog "SCORING FAILURE: $service on port $port is now broken!" "ERROR"
        }
    }
    
    if ($broken.Count -gt 0) {
        Write-SecLog "AUTO-ROLLBACK TRIGGERED: $($broken.Count) services broken - $($broken -join ', ')" "ERROR"
        return $false
    }
    
    Write-SecLog "Service health check passed - all scoring services operational" "SUCCESS"
    return $true
}

function Test-NetworkConnectivity {
    Write-SecLog "Verifying network connectivity for scoring..." "INFO"
    
    $tests = @{
        "Localhost Loopback" = Test-Connection -ComputerName 127.0.0.1 -Count 1 -Quiet
        "DNS Resolution" = (Resolve-DnsName google.com -ErrorAction SilentlyContinue) -ne $null
    }
    
    # Get gateway
    try {
        $gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue).NextHop | Select-Object -First 1
        if ($gateway) {
            $tests["Gateway Reachable"] = Test-Connection -ComputerName $gateway -Count 1 -Quiet -ErrorAction SilentlyContinue
        }
    } catch {
        $tests["Gateway Reachable"] = $false
    }
    
    $tests["Internet Connectivity"] = Test-NetConnection -ComputerName 8.8.8.8 -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue
    
    $failed = @()
    foreach ($test in $tests.Keys) {
        if (-not $tests[$test]) {
            $failed += $test
            Write-SecLog "NETWORK FAILURE: $test" "ERROR"
        } else {
            Write-SecLog "Network test passed: $test" "SUCCESS"
        }
    }
    
    if ($failed.Count -eq 0) {
        Write-SecLog "All network connectivity tests passed" "SUCCESS"
        return $true
    } else {
        Write-SecLog "Network connectivity issues: $($failed -join ', ')" "ERROR"
        return $false
    }
}

function Export-NetworkConnectivityReport {
    $reportPath = "$Global:LogPath\Reports\Network_Connectivity_$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    $report = @"
Network Connectivity Report
Generated: $(Get-Date)
Computer: $env:COMPUTERNAME

=== NETWORK INTERFACES ===
$(Get-NetAdapter | Where-Object Status -eq "Up" | Format-Table Name, InterfaceDescription, MacAddress, LinkSpeed | Out-String)

=== IP CONFIGURATION ===
$(Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, IPAddress, PrefixLength | Out-String)

=== DEFAULT GATEWAY ===
$(Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Format-Table DestinationPrefix, NextHop, InterfaceAlias | Out-String)

=== DNS SERVERS ===
$(Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, ServerAddresses | Out-String)

=== CONNECTIVITY TESTS ===
Localhost: $(Test-Connection -ComputerName 127.0.0.1 -Count 1 -Quiet)
DNS Resolution: $((Resolve-DnsName google.com -ErrorAction SilentlyContinue) -ne $null)
Internet: $(Test-NetConnection -ComputerName 8.8.8.8 -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue)

=== FIREWALL STATUS ===
$(Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Out-String)
"@
    
    $report | Out-File $reportPath
    Write-SecLog "Network connectivity report: $reportPath" "SUCCESS"
}
