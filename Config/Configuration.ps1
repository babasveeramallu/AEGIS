# CCDC 2026 Adaptive Hardening & Detection Tool
# Configuration and Reference Data

# Competition-Day Checklist (Enhanced with Professor Recommendations)
$Global:CompetitionChecklist = @(
    @{ ID = 1; Task = "Phase 0 ran — system profile generated for all 4 Windows machines"; Status = $false },
    @{ ID = 2; Task = "Phase 0.5 ran — backups completed for all systems before any changes"; Status = $false },
    @{ ID = 3; Task = "SMBv1 disabled on AD/DNS, Web, FTP, and Workstation"; Status = $false },
    @{ ID = 4; Task = "LLMNR and NBT-NS disabled on all machines"; Status = $false },
    @{ ID = 5; Task = "LDAP signing and channel binding enforced on AD"; Status = $false },
    @{ ID = 6; Task = "PowerShell Script Block + Transcription Logging enabled everywhere"; Status = $false },
    @{ ID = 7; Task = "PowerShell v2 engine disabled"; Status = $false },
    @{ ID = 8; Task = "Sysmon running on all Windows machines"; Status = $false },
    @{ ID = 9; Task = "IIS hardened: no dir listing, WebDAV off, HTTPS on, webroot hashed"; Status = $false },
    @{ ID = 10; Task = "FTP hardened: anonymous off, FTPS on, users chrooted, logging on"; Status = $false },
    @{ ID = 11; Task = "AD hardened: password policy, admin renamed, audit on, KRBTGT rotation noted"; Status = $false },
    @{ ID = 12; Task = "Windows Defender active and exclusion list verified on workstation"; Status = $false },
    @{ ID = 13; Task = "Honeypot account created — monitoring for any logon"; Status = $false },
    @{ ID = 14; Task = "Canary file planted — audit enabled"; Status = $false },
    @{ ID = 15; Task = "Detection running: cred abuse, lateral move, persist, LOLBin, firewall tamper watches on"; Status = $false },
    @{ ID = 16; Task = "Time drift monitoring active on all machines"; Status = $false },
    @{ ID = 17; Task = "Certificate expiry monitoring active"; Status = $false },
    @{ ID = 18; Task = "Splunk forwarder confirmed active (if reachable)"; Status = $false },
    @{ ID = 19; Task = "Phase 5 scoring loop running — HTTP, HTTPS, DNS, SMTP, POP3, FTP all green"; Status = $false },
    @{ ID = 20; Task = "IR report template loaded — can export PDF in under 2 minutes"; Status = $false },
    @{ ID = 21; Task = "ICMP is open on all machines"; Status = $false },
    @{ ID = 22; Task = "Cross-platform monitoring active — watching for lateral move to Linux / appliances"; Status = $false },
    
    # ENHANCED SECURITY CONTROLS (Professor Recommendations)
    @{ ID = 23; Task = "LSASS protected process enabled (RunAsPPL)"; Status = $false },
    @{ ID = 24; Task = "NTLMv1 disabled entirely, NTLM restricted to v2 only"; Status = $false },
    @{ ID = 25; Task = "Attack Surface Reduction (ASR) rules enabled"; Status = $false },
    @{ ID = 26; Task = "Anonymous SID enumeration disabled"; Status = $false },
    @{ ID = 27; Task = "Remote Registry service disabled"; Status = $false },
    @{ ID = 28; Task = "Legacy cipher suites and weak protocols disabled"; Status = $false },
    @{ ID = 29; Task = "Local administrator groups analyzed for unexpected users"; Status = $false },
    @{ ID = 30; Task = "Advanced audit policy baseline verified"; Status = $false },
    @{ ID = 31; Task = "VBS/Credential Guard state verified"; Status = $false },
    @{ ID = 32; Task = "High-risk kernel drivers scanned and flagged"; Status = $false },
    @{ ID = 33; Task = "Advanced honeypots deployed (AD accounts, files, shares, registry)"; Status = $false },
    @{ ID = 34; Task = "Security posture score calculated and monitored"; Status = $false }
)

# Key Event IDs for Detection
$Global:CriticalEventIDs = @{
    # Security Log Events
    4624 = @{ Log = "Security"; Description = "Successful Logon"; Relevance = "Track who logs in where and when" }
    4625 = @{ Log = "Security"; Description = "Failed Logon"; Relevance = "Brute force attempts" }
    4634 = @{ Log = "Security"; Description = "Logoff"; Relevance = "Session tracking and gaps" }
    4648 = @{ Log = "Security"; Description = "Explicit Credential Logon"; Relevance = "Pass-the-Hash / Pass-the-Ticket" }
    4662 = @{ Log = "Security"; Description = "Object Access on AD Object"; Relevance = "DCSync detection" }
    4672 = @{ Log = "Security"; Description = "Special Privileges Assigned"; Relevance = "Admin access — should be rare" }
    4697 = @{ Log = "Security"; Description = "Service Installed"; Relevance = "Backdoor service persistence" }
    4698 = @{ Log = "Security"; Description = "Scheduled Task Created"; Relevance = "Task-based persistence" }
    4702 = @{ Log = "Security"; Description = "Scheduled Task Modified"; Relevance = "Tampered existing task" }
    4720 = @{ Log = "Security"; Description = "User Account Created"; Relevance = "Attacker-created account" }
    4732 = @{ Log = "Security"; Description = "Account Added to Security Group"; Relevance = "Privilege escalation" }
    1102 = @{ Log = "Security"; Description = "Audit Log Cleared"; Relevance = "Attacker covering tracks" }
    1149 = @{ Log = "Security"; Description = "RDP Session Logon"; Relevance = "Remote access from unknown source" }
    
    # System Log Events
    7045 = @{ Log = "System"; Description = "New Service Installed"; Relevance = "Service-based persistence" }
    
    # Sysmon Events
    1 = @{ Log = "Sysmon"; Description = "Process Creation"; Relevance = "LOLBin execution tracking" }
    3 = @{ Log = "Sysmon"; Description = "Network Connection"; Relevance = "C2 and lateral move detection" }
    10 = @{ Log = "Sysmon"; Description = "Process Access"; Relevance = "LSASS access attempts" }
    11 = @{ Log = "Sysmon"; Description = "File Creation"; Relevance = "Payload / webshell drops" }
    13 = @{ Log = "Sysmon"; Description = "Registry Modification"; Relevance = "Persistence via registry" }
}

# Playbook Routing Table
$Global:PlaybookRouting = @{
    "ActiveDirectory_DNS" = @{
        MinConfidence = 0.90
        HardeningPlaybook = "AD_DNS_Hardening"
        DetectionModules = @("Kerberoast", "DCSync", "CredDump", "GPO", "AdminSDHolder")
    }
    "WebServer" = @{
        MinConfidence = 0.85
        HardeningPlaybook = "IIS_Hardening"
        DetectionModules = @("HTTPAnomaly", "WebShell", "SMTP_POP3")
    }
    "FTPServer" = @{
        MinConfidence = 0.85
        HardeningPlaybook = "FTP_Hardening"
        DetectionModules = @("AnonLogin", "PathTraversal", "CleartextCred")
    }
    "Workstation" = @{
        MinConfidence = 0.80
        HardeningPlaybook = "Endpoint_Hardening"
        DetectionModules = @("DefenderIntegrity", "LateralMoveSensor")
    }
    "UNKNOWN" = @{
        MinConfidence = 0.0
        HardeningPlaybook = "Universal_Only"
        DetectionModules = @("FullSpectrumLogging")
    }
}

# Response Tier Mapping
$Global:ResponseTiers = @{
    # AUTO Tier - Safe and reversible actions
    "KILL_PROCESS" = @{ Tier = "AUTO"; Reason = "Safe — process is logged and dead, nothing else changes" }
    "BLOCK_SOURCE_IP" = @{ Tier = "AUTO"; Reason = "Safe — inbound block only, reversible via rollback" }
    "ALERT_AND_LOG" = @{ Tier = "AUTO"; Reason = "Always safe" }
    "DELETE_ROGUE_TASK" = @{ Tier = "AUTO"; Reason = "Safe if task was not in Phase 0 baseline" }
    
    # OPERATOR Tier - High-impact actions requiring human judgment
    "DISABLE_ACCOUNT" = @{ Tier = "OPERATOR"; Reason = "Could break scoring if account is service-linked" }
    "ROTATE_CREDENTIALS" = @{ Tier = "OPERATOR"; Reason = "High-impact — needs human judgment" }
    "ISOLATE_MACHINE" = @{ Tier = "OPERATOR"; Reason = "Breaks all services on that machine" }
    "DISABLE_DOMAIN_ADMIN" = @{ Tier = "OPERATOR"; Reason = "Could lock out the entire team" }
}

# LOLBin Detection Signatures
$Global:LOLBinSignatures = @{
    "certutil.exe" = @("urlcache", "decode", "decodehex", "-f", "http", "https")
    "bitsadmin.exe" = @("transfer", "addfile", "/download", "/upload")
    "mshta.exe" = @("http", "https", "javascript", "vbscript", ".hta")
    "rundll32.exe" = @("javascript", "shell32.dll", "url.dll", "advpack.dll")
    "wscript.exe" = @(".js", ".vbs", ".wsf", "http", "https")
    "cscript.exe" = @(".js", ".vbs", ".wsf", "http", "https")
    "powershell.exe" = @("-enc", "-e", "downloadstring", "iex", "invoke-expression", "bypass")
    "cmd.exe" = @("powershell", "/c echo", "certutil", "bitsadmin")
    "regsvr32.exe" = @("scrobj.dll", "http", "https", "/s", "/u")
    "msiexec.exe" = @("/quiet", "/q", "http", "https", "/i")
}

# Threat Intelligence - Known Bad Indicators
$Global:ThreatIntelligence = @{
    SuspiciousProcessNames = @(
        "psexec.exe", "paexec.exe", "remcom.exe", "winexesvc.exe",
        "mimikatz.exe", "procdump.exe", "dumpert.exe",
        "cobalt.exe", "beacon.exe", "artifact.exe"
    )
    
    SuspiciousFileExtensions = @(
        ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".js", ".jar"
    )
    
    SuspiciousRegistryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SYSTEM\CurrentControlSet\Services"
    )
    
    KnownC2Domains = @(
        # Add known C2 domains here during competition
    )
}

# Scoring Service Templates
$Global:ScoringServiceTemplates = @{
    "HTTP" = @{
        Port = 80
        TestMethod = "WebRequest"
        ExpectedResponse = 200
        TestURL = "/"
        Timeout = 10
    }
    
    "HTTPS" = @{
        Port = 443
        TestMethod = "WebRequest"
        ExpectedResponse = 200
        TestURL = "/"
        Timeout = 10
        CheckCertificate = $true
    }
    
    "DNS" = @{
        Port = 53
        TestMethod = "DNSQuery"
        TestQueries = @("localhost", "google.com")
        Timeout = 5
    }
    
    "SMTP" = @{
        Port = 25
        TestMethod = "TCPConnect"
        ExpectedBanner = "220"
        Commands = @("EHLO test", "QUIT")
        Timeout = 10
    }
    
    "POP3" = @{
        Port = 110
        TestMethod = "TCPConnect"
        ExpectedBanner = "+OK"
        Commands = @("QUIT")
        Timeout = 10
    }
    
    "FTP" = @{
        Port = 21
        TestMethod = "TCPConnect"
        ExpectedBanner = "220"
        Commands = @("QUIT")
        Timeout = 10
    }
    
    "RDP" = @{
        Port = 3389
        TestMethod = "TCPConnect"
        Timeout = 5
    }
}

function Update-ChecklistItem {
    param(
        [int]$ItemID,
        [bool]$Status
    )
    
    $item = $Global:CompetitionChecklist | Where-Object { $_.ID -eq $ItemID }
    if ($item) {
        $item.Status = $Status
        Write-CCDCLog "Checklist item $ItemID updated: $($item.Task) = $Status" "INFO"
    }
}

function Get-ChecklistStatus {
    $completed = ($Global:CompetitionChecklist | Where-Object { $_.Status -eq $true }).Count
    $total = $Global:CompetitionChecklist.Count
    $percentage = [Math]::Round(($completed / $total) * 100, 1)
    
    return [PSCustomObject]@{
        Completed = $completed
        Total = $total
        Percentage = $percentage
        Items = $Global:CompetitionChecklist
    }
}

function Show-CompetitionChecklist {
    Write-Host "`n=== CCDC COMPETITION-DAY CHECKLIST ===" -ForegroundColor Cyan
    Write-Host "Run through this as your tool executes each phase.`n" -ForegroundColor White
    
    foreach ($item in $Global:CompetitionChecklist) {
        $status = if ($item.Status) { "[X]" } else { "[ ]" }
        $color = if ($item.Status) { "Green" } else { "Yellow" }
        Write-Host "$($item.ID.ToString().PadLeft(2)). $status $($item.Task)" -ForegroundColor $color
    }
    
    $summary = Get-ChecklistStatus
    Write-Host "`nProgress: $($summary.Completed)/$($summary.Total) ($($summary.Percentage)%)" -ForegroundColor Cyan
}

# Security Helper Functions
function Get-SecureRandom {
    param([int]$Length = 12)
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $bytes = New-Object byte[] $Length
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return ([Convert]::ToBase64String($bytes) -replace '[/+=]', '').Substring(0, $Length)
}

function Get-HoneypotPassword {
    param([string]$AccountName)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $seed = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$AccountName-$env:COMPUTERNAME"))
    $sha256.Dispose()
    return [Convert]::ToBase64String($seed).Substring(0,24) + "!"
}

function Get-SafeString {
    param([string]$Input)
    if ([string]::IsNullOrEmpty($Input)) { return "" }
    return [System.Text.RegularExpressions.Regex]::Replace($Input, '[^\w\-\.]', '')
}

function Read-SafeXml {
    param([string]$Path)
    if (-not (Test-Path $Path)) { throw "XML not found: $Path" }
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create($Path, $settings)
    $xml = [xml]::new()
    $xml.Load($reader)
    $reader.Close()
    return $xml
}

function Stop-ProcessSafe {
    param([int]$Id, [string]$Name)
    for ($i = 0; $i -lt 3; $i++) {
        $proc = Get-Process -Id $Id -ErrorAction SilentlyContinue
        if (-not $proc) { return $true }
        try {
            Stop-Process -Id $Id -Force -ErrorAction Stop
            return $true
        } catch {
            if ($i -lt 2) { Start-Sleep -Milliseconds (100 * [Math]::Pow(2, $i + 1)) }
        }
    }
    return $false
}

function Export-EventIDReference {
    $eventReference = @"
CCDC 2026 - Key Event ID Reference
These are the Windows event IDs your detection module must watch.

EVENT ID | LOG      | MEANING                        | RED TEAM RELEVANCE
---------|----------|--------------------------------|-------------------
"@

    foreach ($eventId in $Global:CriticalEventIDs.Keys | Sort-Object) {
        $event = $Global:CriticalEventIDs[$eventId]
        $eventReference += "`n$($eventId.ToString().PadRight(8)) | $($event.Log.PadRight(8)) | $($event.Description.PadRight(30)) | $($event.Relevance)"
    }
    
    $eventReference | Out-File "$Global:LogPath\EventID_Reference.txt"
    Write-CCDCLog "Event ID reference exported to $Global:LogPath\EventID_Reference.txt" "INFO"
}