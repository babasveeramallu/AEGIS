# Phase 0 - System Identification Engine
# This is the brain of the tool. Before any hardening or detection logic executes,
# the identification engine runs a series of lightweight probes and produces a structured system profile.

function Invoke-SystemIdentification {
    Write-SecLog "Starting system identification probes..." "INFO"
    
    $profile = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        OS = ""
        DetectedRole = "UNKNOWN"
        Roles = @()
        ListenPorts = @()
        Services = @()
        IIS = $false
        FTP = $false
        IsWorkstation = $false
        Confidence = 0.0
        ScoringServices = @()
        TimeSource = ""
        CertificateStores = @()
        BackupCompleted = $false
        RollbackAvailable = $false
    }
    
    try {
        # Signal 1: OS Version
        $osInfo = Get-CimInstance Win32_OperatingSystem
        $profile.OS = "$($osInfo.Caption) (Build $($osInfo.BuildNumber))"
        Write-SecLog "OS Detected: $($profile.OS)" "INFO"
        
        # Signal 2: Computer Name Analysis
        Write-SecLog "Computer Name: $($profile.ComputerName)" "INFO"
        
        # Signal 3: Installed Roles (Server only)
        if ($osInfo.ProductType -ne 1) { # Not workstation
            try {
                $windowsFeatures = Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed" }
                $profile.Roles = $windowsFeatures | Select-Object -ExpandProperty Name
                Write-SecLog "Installed Roles: $($profile.Roles -join ', ')" "INFO"
            } catch {
                Write-SecLog "Could not query Windows Features (likely not Server OS)" "WARN"
            }
        } else {
            $profile.IsWorkstation = $true
            Write-SecLog "Workstation OS detected" "INFO"
        }
        
        # Signal 4: Listening Ports
        $listeningPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique
        $profile.ListenPorts = $listeningPorts
        Write-SecLog "Listening Ports: $($listeningPorts -join ', ')" "INFO"
        
        # Signal 5: Running Services
        $runningServices = Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object -ExpandProperty Name
        $profile.Services = $runningServices
        Write-SecLog "Running Services Count: $($runningServices.Count)" "INFO"
        
        # Signal 6: AD Membership Check
        try {
            $adInfo = Get-ADComputer -Identity $env:COMPUTERNAME -ErrorAction Stop
            Write-SecLog "AD Member: $($adInfo.DistinguishedName)" "INFO"
        } catch {
            Write-SecLog "Not domain-joined or AD module not available" "INFO"
        }
        
        # Signal 7: IIS Installation
        if (Test-Path "C:\inetpub") {
            $profile.IIS = $true
            try {
                Import-Module WebAdministration -ErrorAction SilentlyContinue
                $websites = Get-Website -ErrorAction SilentlyContinue
                if ($websites) {
                    Write-SecLog "IIS Websites: $($websites.Count)" "INFO"
                }
            } catch {
                Write-SecLog "IIS detected but WebAdministration module not available" "WARN"
            }
        }
        
        # Signal 8: FTP Installation
        if ($runningServices -contains "FTPSVC") {
            $profile.FTP = $true
            Write-SecLog "FTP Service detected" "INFO"
        }
        
        # Signal 9: Time Source
        try {
            $timeStatus = w32tm /query /status 2>$null
            if ($timeStatus) {
                $profile.TimeSource = ($timeStatus | Select-String "Source:").ToString().Split(":")[1].Trim()
                Write-SecLog "Time Source: $($profile.TimeSource)" "INFO"
            }
        } catch {
            Write-SecLog "Could not query time source" "WARN"
        }
        
        # Signal 10: Certificate Store
        try {
            $certs = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.NotAfter -gt (Get-Date) }
            $profile.CertificateStores = $certs | ForEach-Object {
                [PSCustomObject]@{
                    Subject = $_.Subject
                    Expiry = $_.NotAfter
                    Thumbprint = $_.Thumbprint
                }
            }
            Write-SecLog "Valid Certificates: $($certs.Count)" "INFO"
        } catch {
            Write-SecLog "Could not query certificate store" "WARN"
        }
        
        # Role Detection Logic
        $profile = Invoke-RoleDetection -Profile $profile
        
        # Scoring Services Detection
        $profile.ScoringServices = Get-ScoringServices -Profile $profile
        
        Write-SecLog "System identification complete. Role: $($profile.DetectedRole), Confidence: $($profile.Confidence)" "SUCCESS"
        return $profile
        
    } catch {
        Write-SecLog "Error during system identification: $($_.Exception.Message)" "ERROR"
        return $profile
    }
}

function Invoke-RoleDetection {
    param([PSCustomObject]$Profile)
    
    $confidence = 0.0
    $detectedRole = "UNKNOWN"
    
    # Active Directory + DNS Detection
    if (($Profile.Roles -contains "AD-Domain-Services") -or 
        ($Profile.Services -contains "ADDSEXPORT") -or
        ($Profile.Services -contains "DNS")) {
        
        $confidence += 0.4
        if ($Profile.ListenPorts -contains 53) { $confidence += 0.2 }
        if ($Profile.ListenPorts -contains 389) { $confidence += 0.2 }
        if ($Profile.ListenPorts -contains 636) { $confidence += 0.1 }
        if ($Profile.Services -contains "Netlogon") { $confidence += 0.1 }
        
        if ($confidence -ge 0.90) {
            $detectedRole = "ActiveDirectory_DNS"
        }
    }
    
    # Web Server Detection
    elseif ($Profile.IIS -and ($Profile.ListenPorts -contains 80 -or $Profile.ListenPorts -contains 443)) {
        $confidence += 0.5
        if ($Profile.Services -contains "W3SVC") { $confidence += 0.2 }
        if ($Profile.ListenPorts -contains 443) { $confidence += 0.15 }
        if ($Profile.ListenPorts -contains 80) { $confidence += 0.1 }
        
        if ($confidence -ge 0.85) {
            $detectedRole = "WebServer"
        }
    }
    
    # FTP Server Detection
    elseif ($Profile.FTP -and $Profile.ListenPorts -contains 21) {
        $confidence += 0.6
        if ($Profile.Services -contains "FTPSVC") { $confidence += 0.25 }
        
        if ($confidence -ge 0.85) {
            $detectedRole = "FTPServer"
        }
    }
    
    # Workstation Detection
    elseif ($Profile.IsWorkstation) {
        $confidence = 0.9
        $detectedRole = "Workstation"
    }
    
    $Profile.DetectedRole = $detectedRole
    $Profile.Confidence = [Math]::Round($confidence, 2)
    
    return $Profile
}

function Get-ScoringServices {
    param([PSCustomObject]$Profile)
    
    $scoringServices = @()
    
    # Common scoring services based on detected role
    switch ($Profile.DetectedRole) {
        "ActiveDirectory_DNS" {
            if ($Profile.ListenPorts -contains 53) { $scoringServices += "DNS:53" }
            if ($Profile.ListenPorts -contains 389) { $scoringServices += "LDAP:389" }
            if ($Profile.ListenPorts -contains 636) { $scoringServices += "LDAPS:636" }
        }
        "WebServer" {
            if ($Profile.ListenPorts -contains 80) { $scoringServices += "HTTP:80" }
            if ($Profile.ListenPorts -contains 443) { $scoringServices += "HTTPS:443" }
        }
        "FTPServer" {
            if ($Profile.ListenPorts -contains 21) { $scoringServices += "FTP:21" }
            if ($Profile.ListenPorts -contains 990) { $scoringServices += "FTPS:990" }
        }
    }
    
    # Universal services
    if ($Profile.ListenPorts -contains 3389) { $scoringServices += "RDP:3389" }
    if ($Profile.ListenPorts -contains 25) { $scoringServices += "SMTP:25" }
    if ($Profile.ListenPorts -contains 110) { $scoringServices += "POP3:110" }
    
    return $scoringServices
}