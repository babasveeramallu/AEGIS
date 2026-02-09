# Inject Response Modules
# Fixes for Inject 08, 09, 29 (all scored 0)

function Invoke-StartupFileSecurity {
    Write-SecLog "Securing startup files and scripts..." "INFO"
    
    $startupLocations = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    $startupItems = @()
    
    # Registry startup items
    foreach ($regPath in $startupLocations | Where-Object { $_ -like "HKLM:*" -or $_ -like "HKCU:*" }) {
        if (Test-Path $regPath) {
            $items = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $filePath = if ($_.Value -match '"([^"]+)"') { $matches[1] } else { $_.Value }
                $startupItems += [PSCustomObject]@{
                    Location = $regPath
                    Type = "Registry"
                    Name = $_.Name
                    Value = $_.Value
                    Hash = if (Test-Path $filePath -ErrorAction SilentlyContinue) { 
                        (Get-FileHash $filePath -ErrorAction SilentlyContinue).Hash 
                    } else { "N/A" }
                }
            }
        }
    }
    
    # File system startup items
    foreach ($folderPath in $startupLocations | Where-Object { $_ -notlike "HK*" }) {
        if (Test-Path $folderPath) {
            Get-ChildItem $folderPath -File -ErrorAction SilentlyContinue | ForEach-Object {
                $startupItems += [PSCustomObject]@{
                    Location = $folderPath
                    Type = "File"
                    Name = $_.Name
                    Value = $_.FullName
                    Hash = (Get-FileHash $_.FullName).Hash
                }
            }
        }
    }
    
    # Export startup inventory
    $reportPath = "$Global:LogPath\Reports\Startup_Files_Inventory_$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    $startupItems | Export-Csv $reportPath -NoTypeInformation
    
    Write-SecLog "Startup files inventoried: $($startupItems.Count) items" "SUCCESS"
    Write-SecLog "Report: $reportPath" "INFO"
    
    return $startupItems
}

function Enable-PrecisionTimeLogging {
    Write-SecLog "Configuring precision time synchronization..." "INFO"
    
    try {
        # Stop Windows Time service
        Stop-Service w32time -Force -ErrorAction SilentlyContinue
        
        # Configure reliable NTP servers
        w32tm /config /manualpeerlist:"time.windows.com,time.nist.gov,pool.ntp.org" /syncfromflags:manual /reliable:YES /update
        
        # Start Windows Time service
        Start-Service w32time
        
        # Force immediate sync
        w32tm /resync /force
        
        # Verify time sync
        $timeStatus = w32tm /query /status
        if ($timeStatus -match "Source:") {
            $source = ($timeStatus | Select-String "Source:").ToString().Split(":")[1].Trim()
            Write-SecLog "Time synchronized with: $source" "SUCCESS"
        }
        
        # Configure high-resolution timestamps
        $auditPath = "HKLM:\SYSTEM\CurrentControlSet\Control\TimeProviders\NtpClient"
        Set-ItemProperty -Path $auditPath -Name "SpecialPollInterval" -Value 900 -Type DWord -ErrorAction SilentlyContinue
        
        # Enable audit logging with timestamps
        auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
        auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
        
        Write-SecLog "Precision time logging enabled" "SUCCESS"
        
    } catch {
        Write-SecLog "Precision time configuration failed: $($_.Exception.Message)" "ERROR"
    }
}

function Export-FirewallSecurityPolicy {
    Write-SecLog "Exporting firewall security policy..." "INFO"
    
    try {
        $exportPath = "$Global:LogPath\Reports\Firewall_Policy_$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        New-Item -Path $exportPath -ItemType Directory -Force | Out-Null
        
        # Export Windows Firewall policy
        netsh advfirewall export "$exportPath\firewall_complete.wfw"
        
        # Export detailed rule list
        Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Enabled | 
            Export-Csv "$exportPath\firewall_rules.csv" -NoTypeInformation
        
        # Export profile settings
        Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | 
            Export-Csv "$exportPath\firewall_profiles.csv" -NoTypeInformation
        
        # Export port filter details
        Get-NetFirewallPortFilter | Export-Csv "$exportPath\firewall_ports.csv" -NoTypeInformation
        
        # Create human-readable summary
        $summary = @"
Firewall Security Policy Export
Generated: $(Get-Date)
Computer: $env:COMPUTERNAME

Total Rules: $((Get-NetFirewallRule).Count)
Enabled Rules: $((Get-NetFirewallRule | Where-Object Enabled -eq $true).Count)
Inbound Block Rules: $((Get-NetFirewallRule | Where-Object {$_.Direction -eq "Inbound" -and $_.Action -eq "Block"}).Count)
Outbound Block Rules: $((Get-NetFirewallRule | Where-Object {$_.Direction -eq "Outbound" -and $_.Action -eq "Block"}).Count)

Profile Status:
$(Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Out-String)
"@
        
        $summary | Out-File "$exportPath\SUMMARY.txt"
        
        Write-SecLog "Firewall policy exported: $exportPath" "SUCCESS"
        
    } catch {
        Write-SecLog "Firewall export failed: $($_.Exception.Message)" "ERROR"
    }
}
