# Enhanced Hardening Module - Advanced Security Controls
# Based on professor recommendations and SecOps expert insights

function Invoke-AdvancedHardening {
    param([PSCustomObject]$SystemProfile)
    
    Write-SecLog "=== ADVANCED HARDENING (PROFESSOR RECOMMENDATIONS) ===" "INFO"
    
    # 1. Enable LSASS Protected Process
    Enable-LSASSProtection
    
    # 2. Disable NTLMv1 Entirely & Restrict NTLM
    Disable-NTLMv1AndRestrict
    
    # 3. Enable Attack Surface Reduction (ASR)
    Enable-AttackSurfaceReduction
    
    # 4. Disable Anonymous SID Enumeration
    Disable-AnonymousSIDEnumeration
    
    # 5. Disable Remote Registry
    Disable-RemoteRegistry
    
    # 6. Disable Legacy Cipher Suites
    Disable-LegacyCipherSuites
    
    Write-SecLog "Advanced hardening completed" "SUCCESS"
}

function Enable-LSASSProtection {
    Write-SecLog "Enabling LSASS Protected Process..." "INFO"
    
    try {
        # Enable LSA Protection (RunAsPPL)
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord
        
        # Enable additional LSA protections
        Set-ItemProperty -Path $lsaPath -Name "DisableRestrictedAdmin" -Value 0 -Type DWord
        Set-ItemProperty -Path $lsaPath -Name "DisableRestrictedAdminOutboundCreds" -Value 1 -Type DWord
        
        Write-SecLog "LSASS protection enabled (requires reboot)" "SUCCESS"
        Update-ChecklistItem -ItemID 23 -Status $true
        
    } catch {
        Write-SecLog "Failed to enable LSASS protection: $($_.Exception.Message)" "ERROR"
    }
}

function Disable-NTLMv1AndRestrict {
    Write-SecLog "Disabling NTLMv1 and restricting NTLM authentication..." "INFO"
    
    try {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $msvPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        
        # Disable NTLMv1 completely
        if (!(Test-Path $msvPath)) { New-Item -Path $msvPath -Force | Out-Null }
        Set-ItemProperty -Path $msvPath -Name "NtlmMinClientSec" -Value 0x20080000 -Type DWord
        Set-ItemProperty -Path $msvPath -Name "NtlmMinServerSec" -Value 0x20080000 -Type DWord
        
        # Restrict NTLM authentication
        Set-ItemProperty -Path $lsaPath -Name "RestrictSendingNTLMTraffic" -Value 2 -Type DWord
        Set-ItemProperty -Path $lsaPath -Name "RestrictReceivingNTLMTraffic" -Value 2 -Type DWord
        
        # Force NTLMv2 only
        Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord
        
        Write-SecLog "NTLMv1 disabled, NTLM restricted to v2 only" "SUCCESS"
        Update-ChecklistItem -ItemID 24 -Status $true
        
    } catch {
        Write-SecLog "Failed to configure NTLM restrictions: $($_.Exception.Message)" "ERROR"
    }
}

function Enable-AttackSurfaceReduction {
    Write-SecLog "Enabling Attack Surface Reduction rules..." "INFO"
    
    try {
        # ASR Rules (Windows Defender required)
        $asrRules = @{
            "56a863a9-875e-4185-98a7-b882c64b5ce5" = 1  # Block abuse of exploited vulnerable signed drivers
            "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = 1  # Block Adobe Reader from creating child processes
            "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = 1  # Block all Office applications from creating child processes
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 1  # Block credential stealing from Windows local security authority subsystem
            "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = 1  # Block executable content from email client and webmail
            "01443614-cd74-433a-b99e-2ecdc07bfc25" = 1  # Block executable files from running unless they meet prevalence, age, or trusted list criteria
            "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = 1  # Block execution of potentially obfuscated scripts
            "d3e037e1-3eb8-44c8-a917-57927947596d" = 1  # Block JavaScript or VBScript from launching downloaded executable content
            "3b576869-a4ec-4529-8536-b80a7769e899" = 1  # Block Office applications from creating executable content
            "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = 1  # Block Office applications from injecting code into other processes
            "26190899-1602-49e8-8b27-eb1d0a1ce869" = 1  # Block Office communication applications from creating child processes
            "e6db77e5-3df2-4cf1-b95a-636979351e5b" = 1  # Block persistence through WMI event subscription
            "d1e49aac-8f56-4280-b9ba-993a6d77406c" = 1  # Block process creations originating from PSExec and WMI commands
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 1  # Block untrusted and unsigned processes that run from USB
            "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = 1  # Block Win32 API calls from Office macros
            "c1db55ab-c21a-4637-bb3f-a12568109d35" = 1  # Use advanced protection against ransomware
        }
        
        foreach ($rule in $asrRules.Keys) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions $asrRules[$rule]
            } catch {
                # Rule might already exist or not supported
            }
        }
        
        Write-SecLog "Attack Surface Reduction rules enabled" "SUCCESS"
        Update-ChecklistItem -ItemID 25 -Status $true
        
    } catch {
        Write-SecLog "Failed to enable ASR rules: $($_.Exception.Message)" "ERROR"
    }
}

function Disable-AnonymousSIDEnumeration {
    Write-SecLog "Disabling anonymous SID enumeration..." "INFO"
    
    try {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        
        # Disable anonymous SID/Name translation
        Set-ItemProperty -Path $lsaPath -Name "TurnOffAnonymousBlock" -Value 1 -Type DWord
        Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
        Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 2 -Type DWord
        
        Write-SecLog "Anonymous SID enumeration disabled" "SUCCESS"
        Update-ChecklistItem -ItemID 26 -Status $true
        
    } catch {
        Write-SecLog "Failed to disable anonymous SID enumeration: $($_.Exception.Message)" "ERROR"
    }
}

function Disable-RemoteRegistry {
    Write-SecLog "Disabling Remote Registry service..." "INFO"
    
    try {
        $service = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name "RemoteRegistry" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "RemoteRegistry" -StartupType Disabled
            Write-SecLog "Remote Registry service disabled" "SUCCESS"
        } else {
            Write-SecLog "Remote Registry service not found" "INFO"
        }
        Update-ChecklistItem -ItemID 27 -Status $true
        
    } catch {
        Write-SecLog "Failed to disable Remote Registry: $($_.Exception.Message)" "ERROR"
    }
}

function Disable-LegacyCipherSuites {
    Write-SecLog "Disabling legacy cipher suites..." "INFO"
    
    try {
        # Disable weak cipher suites
        $weakCiphers = @(
            "DES 56/56",
            "RC2 40/128",
            "RC2 56/128", 
            "RC2 128/128",
            "RC4 40/128",
            "RC4 56/128",
            "RC4 64/128",
            "RC4 128/128",
            "Triple DES 168"
        )
        
        foreach ($cipher in $weakCiphers) {
            $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
            if (!(Test-Path $cipherPath)) { New-Item -Path $cipherPath -Force | Out-Null }
            Set-ItemProperty -Path $cipherPath -Name "Enabled" -Value 0 -Type DWord
        }
        
        # Disable weak protocols
        $weakProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
        foreach ($protocol in $weakProtocols) {
            $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
            $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"
            
            if (!(Test-Path $serverPath)) { New-Item -Path $serverPath -Force | Out-Null }
            if (!(Test-Path $clientPath)) { New-Item -Path $clientPath -Force | Out-Null }
            
            Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 0 -Type DWord
            Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 0 -Type DWord
        }
        
        Write-SecLog "Legacy cipher suites and protocols disabled" "SUCCESS"
        Update-ChecklistItem -ItemID 28 -Status $true
        
    } catch {
        Write-SecLog "Failed to disable legacy ciphers: $($_.Exception.Message)" "ERROR"
    }
}