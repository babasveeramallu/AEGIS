# Enhanced System Identification - Advanced Security State Detection
# Based on professor recommendations for deeper system analysis

function Invoke-AdvancedSystemAnalysis {
    param([PSCustomObject]$SystemProfile)
    
    Write-SecLog "Starting advanced security state analysis..." "INFO"
    
    # Enhanced system profile with security state
    $advancedProfile = [PSCustomObject]@{
        # Original profile data
        BaseProfile = $SystemProfile
        
        # Advanced security analysis
        LocalAdminGroups = Get-LocalAdministratorAnalysis
        LSAProtectionState = Get-LSAProtectionState
        NTLMConfiguration = Get-NTLMConfiguration
        AuditPolicyState = Get-AuditPolicyState
        VBSState = Get-VirtualizationBasedSecurityState
        KernelDrivers = Get-HighRiskKernelDrivers
        DefenderASRState = Get-DefenderASRState
        CipherSuiteState = Get-CipherSuiteState
        
        # Threat landscape analysis
        SuspiciousProcesses = Get-SuspiciousProcessAnalysis
        NetworkConnections = Get-SuspiciousNetworkConnections
        RegistryPersistence = Get-RegistryPersistenceCheck
        
        # Honeypot readiness
        HoneypotOpportunities = Get-HoneypotOpportunities
    }
    
    # Generate security posture score
    $advancedProfile.SecurityPostureScore = Calculate-SecurityPostureScore -Profile $advancedProfile
    
    Write-SecLog "Advanced system analysis completed" "SUCCESS"
    return $advancedProfile
}

function Get-LocalAdministratorAnalysis {
    Write-SecLog "Analyzing local administrator groups..." "INFO"
    
    try {
        $adminAnalysis = @{
            LocalAdmins = @()
            NestedGroups = @()
            UnexpectedUsers = @()
            ServiceAccounts = @()
        }
        
        # Get local administrators
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        
        foreach ($admin in $admins) {
            $adminInfo = [PSCustomObject]@{
                Name = $admin.Name
                ObjectClass = $admin.ObjectClass
                PrincipalSource = $admin.PrincipalSource
                SID = $admin.SID
                IsBuiltIn = $admin.SID.Value.EndsWith("-500") -or $admin.SID.Value.EndsWith("-544")
                IsServiceAccount = $admin.Name -match "^(NT SERVICE|NT AUTHORITY)"
                IsUnexpected = $false
            }
            
            # Flag unexpected users
            if (-not $adminInfo.IsBuiltIn -and -not $adminInfo.IsServiceAccount -and $admin.ObjectClass -eq "User") {
                $adminInfo.IsUnexpected = $true
                $adminAnalysis.UnexpectedUsers += $adminInfo
            }
            
            if ($admin.ObjectClass -eq "Group") {
                $adminAnalysis.NestedGroups += $adminInfo
            }
            
            $adminAnalysis.LocalAdmins += $adminInfo
        }
        
        Write-SecLog "Found $($adminAnalysis.LocalAdmins.Count) administrators, $($adminAnalysis.UnexpectedUsers.Count) unexpected" "INFO"
        return $adminAnalysis
        
    } catch {
        Write-SecLog "Failed to analyze local administrators: $($_.Exception.Message)" "ERROR"
        return @{ Error = $_.Exception.Message }
    }
}

function Get-LSAProtectionState {
    Write-SecLog "Checking LSASS protection state..." "INFO"
    
    try {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $lsaState = @{
            RunAsPPL = $false
            ProcessProtected = $false
            RestrictedAdminDisabled = $false
            AuditModeEnabled = $false
        }
        
        # Check RunAsPPL setting
        $runAsPPL = Get-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue
        if ($runAsPPL -and $runAsPPL.RunAsPPL -eq 1) {
            $lsaState.RunAsPPL = $true
        }
        
        # Check if LSASS is actually running as protected process
        $lsassProcess = Get-Process -Name "lsass" -ErrorAction SilentlyContinue
        if ($lsassProcess) {
            # This is a simplified check - in reality, you'd need WMI or other methods
            $lsaState.ProcessProtected = $lsaState.RunAsPPL
        }
        
        # Check Restricted Admin settings
        $restrictedAdmin = Get-ItemProperty -Path $lsaPath -Name "DisableRestrictedAdmin" -ErrorAction SilentlyContinue
        if ($restrictedAdmin -and $restrictedAdmin.DisableRestrictedAdmin -eq 0) {
            $lsaState.RestrictedAdminDisabled = $false
        } else {
            $lsaState.RestrictedAdminDisabled = $true
        }
        
        Write-SecLog "LSASS Protection: RunAsPPL=$($lsaState.RunAsPPL), Protected=$($lsaState.ProcessProtected)" "INFO"
        return $lsaState
        
    } catch {
        Write-SecLog "Failed to check LSASS protection: $($_.Exception.Message)" "ERROR"
        return @{ Error = $_.Exception.Message }
    }
}

function Get-NTLMConfiguration {
    Write-SecLog "Analyzing NTLM configuration..." "INFO"
    
    try {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $msvPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        
        $ntlmConfig = @{
            NTLMv1Enabled = $true  # Assume worst case
            NTLMv2EnforcementLevel = 0
            NTLMRestricted = $false
            LMCompatibilityLevel = 0
        }
        
        # Check LM Compatibility Level
        $lmCompat = Get-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
        if ($lmCompat) {
            $ntlmConfig.LMCompatibilityLevel = $lmCompat.LmCompatibilityLevel
            if ($lmCompat.LmCompatibilityLevel -ge 3) {
                $ntlmConfig.NTLMv1Enabled = $false
            }
        }
        
        # Check NTLM restrictions
        $ntlmRestrict = Get-ItemProperty -Path $lsaPath -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
        if ($ntlmRestrict -and $ntlmRestrict.RestrictSendingNTLMTraffic -gt 0) {
            $ntlmConfig.NTLMRestricted = $true
        }
        
        # Check minimum security settings
        $minClientSec = Get-ItemProperty -Path $msvPath -Name "NtlmMinClientSec" -ErrorAction SilentlyContinue
        if ($minClientSec) {
            $ntlmConfig.NTLMv2EnforcementLevel = $minClientSec.NtlmMinClientSec
        }
        
        $riskLevel = if ($ntlmConfig.NTLMv1Enabled) { "HIGH" } elseif (-not $ntlmConfig.NTLMRestricted) { "MEDIUM" } else { "LOW" }
        Write-SecLog "NTLM Risk Level: $riskLevel (v1Enabled=$($ntlmConfig.NTLMv1Enabled), Restricted=$($ntlmConfig.NTLMRestricted))" "INFO"
        
        return $ntlmConfig
        
    } catch {
        Write-SecLog "Failed to analyze NTLM configuration: $($_.Exception.Message)" "ERROR"
        return @{ Error = $_.Exception.Message }
    }
}

function Get-AuditPolicyState {
    Write-SecLog "Checking audit policy configuration..." "INFO"
    
    try {
        # Get current audit policy
        $auditOutput = auditpol /get /category:* 2>$null
        
        $auditState = @{
            AccountLogon = "Not Configured"
            AccountManagement = "Not Configured"
            DirectoryServiceAccess = "Not Configured"
            ObjectAccess = "Not Configured"
            PolicyChange = "Not Configured"
            PrivilegeUse = "Not Configured"
            System = "Not Configured"
            LogonLogoff = "Not Configured"
            ComplianceScore = 0
        }
        
        if ($auditOutput) {
            foreach ($line in $auditOutput) {
                if ($line -match "Account Logon.*Success and Failure") { $auditState.AccountLogon = "Success and Failure"; $auditState.ComplianceScore++ }
                if ($line -match "Account Management.*Success and Failure") { $auditState.AccountManagement = "Success and Failure"; $auditState.ComplianceScore++ }
                if ($line -match "Directory Service Access.*Success and Failure") { $auditState.DirectoryServiceAccess = "Success and Failure"; $auditState.ComplianceScore++ }
                if ($line -match "Object Access.*Success and Failure") { $auditState.ObjectAccess = "Success and Failure"; $auditState.ComplianceScore++ }
            }
        }
        
        $auditState.CompliancePercentage = [Math]::Round(($auditState.ComplianceScore / 8) * 100, 1)
        Write-SecLog "Audit Policy Compliance: $($auditState.CompliancePercentage)%" "INFO"
        
        return $auditState
        
    } catch {
        Write-SecLog "Failed to check audit policy: $($_.Exception.Message)" "ERROR"
        return @{ Error = $_.Exception.Message }
    }
}

function Get-VirtualizationBasedSecurityState {
    Write-SecLog "Checking Virtualization-Based Security state..." "INFO"
    
    try {
        $vbsState = @{
            Supported = $false
            Enabled = $false
            CredentialGuard = $false
            HVCI = $false
            SecureBoot = $false
        }
        
        # Check if VBS is supported
        $vbsInfo = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
        if ($vbsInfo) {
            $vbsState.Supported = $true
            
            # Check various VBS features
            if ($vbsInfo.VirtualizationBasedSecurityStatus -eq 2) {
                $vbsState.Enabled = $true
            }
            
            if ($vbsInfo.LsaCfgCredGuardStatus -eq 1) {
                $vbsState.CredentialGuard = $true
            }
            
            if ($vbsInfo.CodeIntegrityPolicyEnforcementStatus -eq 1) {
                $vbsState.HVCI = $true
            }
            
            if ($vbsInfo.SecureBootStatus -eq 1) {
                $vbsState.SecureBoot = $true
            }
        }
        
        Write-SecLog "VBS State: Supported=$($vbsState.Supported), Enabled=$($vbsState.Enabled), CredGuard=$($vbsState.CredentialGuard)" "INFO"
        return $vbsState
        
    } catch {
        Write-SecLog "Failed to check VBS state: $($_.Exception.Message)" "ERROR"
        return @{ Error = $_.Exception.Message }
    }
}

function Get-HighRiskKernelDrivers {
    Write-SecLog "Scanning for high-risk kernel drivers..." "INFO"
    
    try {
        # Known high-risk or suspicious drivers
        $suspiciousDrivers = @(
            "capcom.sys", "gdrv.sys", "dbutil_2_3.sys", "mimidrv.sys",
            "procexp152.sys", "winring0x64.sys", "cpuz141_x64.sys"
        )
        
        $riskDrivers = @()
        $allDrivers = Get-WindowsDriver -Online -All -ErrorAction SilentlyContinue
        
        foreach ($driver in $allDrivers) {
            $driverName = Split-Path $driver.Driver -Leaf
            
            if ($suspiciousDrivers -contains $driverName.ToLower()) {
                $riskDrivers += [PSCustomObject]@{
                    Name = $driverName
                    Path = $driver.Driver
                    Version = $driver.Version
                    Date = $driver.Date
                    RiskLevel = "HIGH"
                    Reason = "Known vulnerable/suspicious driver"
                }
            }
        }
        
        # Also check running drivers
        $runningDrivers = Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq "Running" }
        foreach ($driver in $runningDrivers) {
            if ($suspiciousDrivers -contains $driver.Name.ToLower()) {
                $riskDrivers += [PSCustomObject]@{
                    Name = $driver.Name
                    Path = $driver.PathName
                    State = $driver.State
                    RiskLevel = "CRITICAL"
                    Reason = "Suspicious driver currently running"
                }
            }
        }
        
        if ($riskDrivers.Count -gt 0) {
            Write-SecLog "ALERT: Found $($riskDrivers.Count) high-risk kernel drivers!" "ERROR"
        } else {
            Write-SecLog "No high-risk kernel drivers detected" "SUCCESS"
        }
        
        return $riskDrivers
        
    } catch {
        Write-SecLog "Failed to scan kernel drivers: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Get-HoneypotOpportunities {
    Write-SecLog "Identifying honeypot deployment opportunities..." "INFO"
    
    try {
        $opportunities = @{
            ADHoneypotAccounts = @()
            FileSystemTraps = @()
            NetworkShares = @()
            RegistryTraps = @()
            ServiceTraps = @()
        }
        
        # AD Honeypot opportunities (if domain controller)
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            
            # Suggest honeypot account names based on environment
            $suggestedNames = @(
                "svc_backup", "admin_temp", "service_account", "backup_admin",
                "sql_service", "web_admin", "ftp_service", "monitoring_svc"
            )
            
            foreach ($name in $suggestedNames) {
                try {
                    $existingUser = Get-ADUser -Identity $name -ErrorAction Stop
                    # User exists, skip
                } catch {
                    # User doesn't exist, good honeypot candidate
                    $opportunities.ADHoneypotAccounts += $name
                }
            }
        } catch {
            # Not a domain controller or AD module not available
        }
        
        # File system trap opportunities
        $trapLocations = @(
            "C:\Backup", "C:\Temp\Passwords", "C:\Scripts\Admin",
            "C:\Users\Public\Documents\Confidential", "C:\inetpub\logs\sensitive"
        )
        
        foreach ($location in $trapLocations) {
            if (-not (Test-Path $location)) {
                $opportunities.FileSystemTraps += $location
            }
        }
        
        # Network share traps
        $shareTraps = @("Admin$", "Backup", "Scripts", "Logs")
        $existingShares = Get-SmbShare | Select-Object -ExpandProperty Name
        
        foreach ($share in $shareTraps) {
            if ($share -notin $existingShares) {
                $opportunities.NetworkShares += $share
            }
        }
        
        Write-SecLog "Honeypot opportunities: $($opportunities.ADHoneypotAccounts.Count) AD accounts, $($opportunities.FileSystemTraps.Count) file traps" "INFO"
        return $opportunities
        
    } catch {
        Write-SecLog "Failed to identify honeypot opportunities: $($_.Exception.Message)" "ERROR"
        return @{}
    }
}

function Calculate-SecurityPostureScore {
    param([PSCustomObject]$Profile)
    
    $score = 0
    $maxScore = 100
    
    # LSASS Protection (20 points)
    if ($Profile.LSAProtectionState.RunAsPPL) { $score += 20 }
    
    # NTLM Configuration (15 points)
    if (-not $Profile.NTLMConfiguration.NTLMv1Enabled) { $score += 10 }
    if ($Profile.NTLMConfiguration.NTLMRestricted) { $score += 5 }
    
    # Audit Policy (15 points)
    $score += ($Profile.AuditPolicyState.ComplianceScore / 8) * 15
    
    # VBS Features (20 points)
    if ($Profile.VBSState.Enabled) { $score += 10 }
    if ($Profile.VBSState.CredentialGuard) { $score += 5 }
    if ($Profile.VBSState.HVCI) { $score += 5 }
    
    # Local Admin Security (10 points)
    if ($Profile.LocalAdminGroups.UnexpectedUsers.Count -eq 0) { $score += 10 }
    
    # Kernel Driver Risk (10 points)
    if ($Profile.KernelDrivers.Count -eq 0) { $score += 10 }
    
    # ASR Rules (10 points)
    if ($Profile.DefenderASRState.RulesEnabled -gt 10) { $score += 10 }
    
    return [Math]::Round($score, 1)
}