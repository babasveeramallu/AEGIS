# Security Vulnerability Scanner & Malware Detection Module
# Comprehensive system security assessment and threat detection

function Invoke-SecurityVulnerabilityAssessment {
    param([switch]$DeepScan = $false)
    
    Write-CCDCLog "Starting comprehensive security vulnerability assessment..." "INFO"
    
    $vulnerabilities = @{
        Critical = @()
        High = @()
        Medium = @()
        Low = @()
        Malware = @()
        Suspicious = @()
    }
    
    try {
        # 1. Code injection vulnerabilities in our own scripts
        Test-ScriptVulnerabilities -VulnReport $vulnerabilities
        
        # 2. System-wide malware scan
        Invoke-SystemMalwareScan -VulnReport $vulnerabilities
        
        # 3. Network-based threats
        Test-NetworkThreats -VulnReport $vulnerabilities
        
        # 4. Registry-based persistence
        Test-RegistryPersistence -VulnReport $vulnerabilities
        
        # 5. File system anomalies
        Test-FileSystemAnomalies -VulnReport $vulnerabilities
        
        # 6. Process hollowing and injection
        Test-ProcessAnomalies -VulnReport $vulnerabilities
        
        # 7. Kernel-level threats
        if ($DeepScan) {
            Test-KernelThreats -VulnReport $vulnerabilities
        }
        
        # Generate security report
        $totalThreats = $vulnerabilities.Critical.Count + $vulnerabilities.High.Count + $vulnerabilities.Medium.Count + $vulnerabilities.Malware.Count
        
        if ($totalThreats -gt 0) {
            Write-CCDCLog "SECURITY ASSESSMENT COMPLETE: $totalThreats threats detected" "ERROR"
            Export-SecurityReport -Vulnerabilities $vulnerabilities
        } else {
            Write-CCDCLog "Security assessment complete - no threats detected" "SUCCESS"
        }
        
        return $vulnerabilities
        
    } catch {
        Write-CCDCLog "Security assessment failed: $($_.Exception.Message)" "ERROR"
        return $vulnerabilities
    }
}

function Test-ScriptVulnerabilities {
    param($VulnReport)
    
    Write-CCDCLog "Scanning for script vulnerabilities..." "INFO"
    
    try {
        # Check our own scripts for security issues
        $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
        $scripts = Get-ChildItem "$scriptPath\*.ps1" -Recurse
        
        foreach ($script in $scripts) {
            $content = Get-Content $script.FullName -Raw
            
            # Check for dangerous patterns
            $dangerousPatterns = @{
                "Invoke-Expression" = "Code injection risk"
                "IEX" = "Code injection risk"
                "Add-Type.*CSharp" = "Unsafe code compilation"
                "System.Net.WebClient" = "Unvalidated web requests"
                "DownloadString" = "Remote code execution risk"
                "ConvertTo-SecureString.*AsPlainText" = "Plaintext password exposure"
                "Write-Host.*password" = "Password disclosure in logs"
                "-ExecutionPolicy Bypass" = "Security policy bypass"
            }
            
            foreach ($pattern in $dangerousPatterns.Keys) {
                if ($content -match $pattern) {
                    $VulnReport.Medium += [PSCustomObject]@{
                        Type = "Script Vulnerability"
                        File = $script.FullName
                        Issue = $dangerousPatterns[$pattern]
                        Pattern = $pattern
                        Severity = "Medium"
                    }
                }
            }
            
            # Check for hardcoded credentials
            if ($content -match "password\s*=\s*[`"'][^`"']+[`"']") {
                $VulnReport.High += [PSCustomObject]@{
                    Type = "Hardcoded Credentials"
                    File = $script.FullName
                    Issue = "Hardcoded password detected"
                    Severity = "High"
                }
            }
        }
        
    } catch {
        Write-CCDCLog "Script vulnerability scan failed: $($_.Exception.Message)" "ERROR"
    }
}

function Invoke-SystemMalwareScan {
    param($VulnReport)
    
    Write-CCDCLog "Performing comprehensive malware scan..." "INFO"
    
    try {
        # 1. Known malware process signatures
        $malwareSignatures = @{
            "mimikatz" = "Credential dumping tool"
            "cobalt" = "Cobalt Strike beacon"
            "meterpreter" = "Metasploit payload"
            "empire" = "PowerShell Empire agent"
            "covenant" = "C# C2 framework"
            "bloodhound" = "AD enumeration tool"
            "sharphound" = "BloodHound collector"
            "rubeus" = "Kerberos abuse tool"
            "kerberoast" = "Kerberos attack tool"
            "asrep" = "AS-REP roasting tool"
            "dcsync" = "DCSync attack tool"
            "psexec" = "Remote execution tool"
            "paexec" = "PsExec alternative"
            "remcom" = "Remote command execution"
            "winexesvc" = "WinEXE service"
            "procdump" = "Process dumping tool"
            "dumpert" = "LSASS dumping tool"
            "nanodump" = "Stealth LSASS dump"
            "pypykatz" = "Python Mimikatz"
            "lazykatz" = "Lazy Mimikatz"
        }
        
        foreach ($process in $processes) {
            $safeName = Get-SafeString -Input $process.Name
            $safePath = if ($process.Path) { Get-SafeString -Input $process.Path } else { "" }
            
            foreach ($signature in $malwareSignatures.Keys) {
                if ($safeName -like "*$signature*" -or $safePath -like "*$signature*") {
                    $VulnReport.Malware += [PSCustomObject]@{
                        Type = "Malware Process"
                        ProcessName = $safeName
                        ProcessId = $process.Id
                        Path = $safePath
                        Description = $malwareSignatures[$signature]
                        Severity = "Critical"
                        Action = "TERMINATE_IMMEDIATELY"
                    }
                    Write-CCDCLog "MALWARE: $safeName - $($malwareSignatures[$signature])" "ERROR"
                }
            }
        }
        
        # 2. Scan for suspicious files
        $suspiciousLocations = @(
            "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA",
            "C:\Windows\Temp", "C:\PerfLogs", "C:\Users\Public",
            "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents"
        )
        
        foreach ($location in $suspiciousLocations) {
            if (Test-Path $location) {
                $recentFiles = Get-ChildItem $location -Recurse -File -ErrorAction SilentlyContinue | 
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
                
                foreach ($file in $recentFiles) {
                    # Check file name against malware signatures
                    foreach ($signature in $malwareSignatures.Keys) {
                        if ($file.Name -like "*$signature*") {
                            $VulnReport.Malware += [PSCustomObject]@{
                                Type = "Malware File"
                                FilePath = $file.FullName
                                FileName = $file.Name
                                Size = $file.Length
                                Created = $file.CreationTime
                                Modified = $file.LastWriteTime
                                Description = $malwareSignatures[$signature]
                                Severity = "Critical"
                                Action = "QUARANTINE"
                            }
                        }
                    }
                    
                    # Check for suspicious file extensions
                    $suspiciousExtensions = @(".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".js", ".jar", ".hta")
                    if ($file.Extension -in $suspiciousExtensions -and $file.Length -gt 1KB) {
                        $VulnReport.Suspicious += [PSCustomObject]@{
                            Type = "Suspicious File"
                            FilePath = $file.FullName
                            Extension = $file.Extension
                            Size = $file.Length
                            Severity = "Medium"
                        }
                    }
                }
            }
        }
        
        # 3. Memory-based malware detection
        $suspiciousMemoryPatterns = @(
            "ReflectiveLoader",
            "VirtualAlloc",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtAllocateVirtualMemory"
        )
        
        # This would require more advanced memory scanning - placeholder for now
        Write-CCDCLog "Memory-based malware detection requires advanced tooling" "INFO"
        
    } catch {
        Write-CCDCLog "Malware scan failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-NetworkThreats {
    param($VulnReport)
    
    Write-CCDCLog "Scanning for network-based threats..." "INFO"
    
    try {
        # 1. Suspicious network connections
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
        
        foreach ($conn in $connections) {
            # Check for connections to suspicious ports
            $suspiciousPorts = @(4444, 4445, 5555, 6666, 7777, 8080, 8443, 9999)
            if ($conn.RemotePort -in $suspiciousPorts) {
                $VulnReport.High += [PSCustomObject]@{
                    Type = "Suspicious Network Connection"
                    LocalAddress = $conn.LocalAddress
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    ProcessId = $conn.OwningProcess
                    Severity = "High"
                }
            }
            
            # Check for connections to non-RFC1918 addresses (potential C2)
            if ($conn.RemoteAddress -notmatch "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)" -and
                $conn.RemoteAddress -ne "0.0.0.0" -and $conn.RemoteAddress -ne "::1") {
                
                $VulnReport.Medium += [PSCustomObject]@{
                    Type = "External Network Connection"
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    ProcessId = $conn.OwningProcess
                    Severity = "Medium"
                }
            }
        }
        
        # 2. Check for rogue network shares
        $shares = Get-SmbShare | Where-Object { $_.Name -notin @("ADMIN$", "C$", "IPC$") }
        foreach ($share in $shares) {
            if ($share.Name -match "(admin|backup|temp|share)" -and $share.FolderEnumerationMode -eq "Unrestricted") {
                $VulnReport.Medium += [PSCustomObject]@{
                    Type = "Suspicious Network Share"
                    ShareName = $share.Name
                    Path = $share.Path
                    Access = $share.FolderEnumerationMode
                    Severity = "Medium"
                }
            }
        }
        
    } catch {
        Write-CCDCLog "Network threat scan failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-RegistryPersistence {
    param($VulnReport)
    
    Write-CCDCLog "Scanning for registry-based persistence..." "INFO"
    
    try {
        $persistenceKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "HKLM:\SYSTEM\CurrentControlSet\Services"
        )
        
        foreach ($keyPath in $persistenceKeys) {
            if (Test-Path $keyPath) {
                $items = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                
                if ($items) {
                    $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                        $value = $_.Value
                        
                        # Check for suspicious patterns
                        if ($value -match "(powershell|cmd|wscript|cscript|rundll32|regsvr32)" -and
                            $value -match "(-enc|-e|downloadstring|iex|invoke-expression)") {
                            
                            $VulnReport.High += [PSCustomObject]@{
                                Type = "Malicious Registry Persistence"
                                RegistryKey = $keyPath
                                ValueName = $_.Name
                                ValueData = $value
                                Severity = "High"
                            }
                        }
                    }
                }
            }
        }
        
    } catch {
        Write-CCDCLog "Registry persistence scan failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-FileSystemAnomalies {
    param($VulnReport)
    
    Write-CCDCLog "Scanning for file system anomalies..." "INFO"
    
    try {
        # Check for files with suspicious attributes
        $systemDirs = @("C:\Windows\System32", "C:\Windows\SysWOW64")
        
        foreach ($dir in $systemDirs) {
            $recentFiles = Get-ChildItem $dir -File -ErrorAction SilentlyContinue | 
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) -and $_.Length -lt 10MB }
            
            foreach ($file in $recentFiles) {
                # Check for unsigned executables in system directories
                if ($file.Extension -in @(".exe", ".dll", ".sys")) {
                    try {
                        $signature = Get-AuthenticodeSignature $file.FullName
                        if ($signature.Status -ne "Valid") {
                            $VulnReport.Medium += [PSCustomObject]@{
                                Type = "Unsigned System File"
                                FilePath = $file.FullName
                                SignatureStatus = $signature.Status
                                Severity = "Medium"
                            }
                        }
                    } catch {
                        # Signature check failed
                    }
                }
            }
        }
        
    } catch {
        Write-CCDCLog "File system anomaly scan failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-ProcessAnomalies {
    param($VulnReport)
    
    Write-CCDCLog "Scanning for process anomalies..." "INFO"
    
    try {
        $processes = Get-Process | Select-Object Name, Id, Path, CommandLine, StartTime
        
        foreach ($process in $processes) {
            $safeName = Get-SafeString -Input $process.Name
            $safePath = if ($process.Path) { Get-SafeString -Input $process.Path } else { "" }
            
            if ($safeName -in @("svchost", "explorer", "winlogon", "csrss") -and 
                $safePath -and -not $safePath.StartsWith("C:\Windows")) {
                $VulnReport.High += [PSCustomObject]@{
                    Type = "Process Hollowing Suspected"
                    ProcessName = $safeName
                    ProcessId = $process.Id
                    SuspiciousPath = $safePath
                    Severity = "High"
                }
            }
        }
        
    } catch {
        Write-CCDCLog "Process anomaly scan failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-KernelThreats {
    param($VulnReport)
    
    Write-CCDCLog "Scanning for kernel-level threats..." "INFO"
    
    try {
        # Check for suspicious drivers
        $drivers = Get-WindowsDriver -Online -All -ErrorAction SilentlyContinue
        $suspiciousDrivers = @(
            "capcom.sys", "gdrv.sys", "dbutil_2_3.sys", "mimidrv.sys",
            "procexp152.sys", "winring0x64.sys", "cpuz141_x64.sys"
        )
        
        foreach ($driver in $drivers) {
            $driverName = Split-Path $driver.Driver -Leaf
            if ($suspiciousDrivers -contains $driverName.ToLower()) {
                $VulnReport.Critical += [PSCustomObject]@{
                    Type = "Malicious Kernel Driver"
                    DriverName = $driverName
                    DriverPath = $driver.Driver
                    Version = $driver.Version
                    Severity = "Critical"
                }
            }
        }
        
    } catch {
        Write-CCDCLog "Kernel threat scan failed: $($_.Exception.Message)" "ERROR"
    }
}

function Export-SecurityReport {
    param($Vulnerabilities)
    
    $reportPath = "$Global:LogPath\Security_Assessment_$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    
    $report = [PSCustomObject]@{
        Timestamp = Get-Date
        ComputerName = $env:COMPUTERNAME
        TotalThreats = ($Vulnerabilities.Critical.Count + $Vulnerabilities.High.Count + $Vulnerabilities.Medium.Count + $Vulnerabilities.Malware.Count)
        Summary = @{
            Critical = $Vulnerabilities.Critical.Count
            High = $Vulnerabilities.High.Count
            Medium = $Vulnerabilities.Medium.Count
            Low = $Vulnerabilities.Low.Count
            Malware = $Vulnerabilities.Malware.Count
            Suspicious = $Vulnerabilities.Suspicious.Count
        }
        Findings = $Vulnerabilities
    }
    
    $report | ConvertTo-Json -Depth 10 | Out-File $reportPath
    Write-CCDCLog "Security report exported: $reportPath" "INFO"
}

function Invoke-ThreatMitigation {
    param($Vulnerabilities)
    
    Write-CCDCLog "Starting threat mitigation..." "WARN"
    
    foreach ($malware in $Vulnerabilities.Malware) {
        if ($malware.Type -eq "Malware Process" -and $malware.Action -eq "TERMINATE_IMMEDIATELY") {
            if (Stop-ProcessSafe -Id $malware.ProcessId -Name $malware.ProcessName) {
                Write-CCDCLog "Terminated: $($malware.ProcessName)" "SUCCESS"
            }
        }
    }
    
    # Quarantine malware files
    $quarantinePath = "$Global:LogPath\Quarantine"
    if (!(Test-Path $quarantinePath)) { New-Item -Path $quarantinePath -ItemType Directory -Force | Out-Null }
    
    foreach ($malware in $Vulnerabilities.Malware) {
        if ($malware.Type -eq "Malware File" -and $malware.Action -eq "QUARANTINE") {
            try {
                $quarantineFile = "$quarantinePath\$(Split-Path $malware.FilePath -Leaf).quarantine"
                Move-Item $malware.FilePath $quarantineFile -Force
                Write-CCDCLog "Quarantined malware file: $($malware.FilePath)" "SUCCESS"
            } catch {
                Write-CCDCLog "Failed to quarantine file: $($malware.FilePath)" "ERROR"
            }
        }
    }
}