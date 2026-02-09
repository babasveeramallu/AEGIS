# Phase 0.5 - Backup & Rollback Module
# Every hardening action this tool takes must be undoable.
# If a change breaks a scoring service, the tool needs to put things back exactly the way they were.

function Test-SafePath {
    param([string]$Path, [string]$AllowedBase)
    
    try {
        $resolvedPath = [System.IO.Path]::GetFullPath($Path)
        $resolvedBase = [System.IO.Path]::GetFullPath($AllowedBase)
        
        # Prevent path traversal
        if (-not $resolvedPath.StartsWith($resolvedBase, [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
        
        # Prevent UNC paths
        if ($resolvedPath.StartsWith("\\")) {
            return $false
        }
        
        return $true
    } catch {
        return $false
    }
}

function Invoke-SystemBackup {
    param([PSCustomObject]$SystemProfile)
    
    Write-SecLog "Starting system backup process..." "INFO"
    
    $backupTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupDir = "$Global:BackupPath\$backupTimestamp"
    
    # Validate backup path to prevent path traversal
    if (-not (Test-SafePath -Path $backupDir -AllowedBase $Global:BackupPath)) {
        Write-SecLog "Invalid backup path detected: potential path traversal" "ERROR"
        return $false
    }
    
    try {
        # Create backup directory
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        Write-SecLog "Created backup directory: $backupDir" "INFO"
        
        # 1. Windows Firewall Rules (All systems)
        Write-SecLog "Backing up Windows Firewall rules..." "INFO"
        $firewallBackup = "$backupDir\firewall_backup.wfw"
        if (-not (Test-SafePath -Path $firewallBackup -AllowedBase $backupDir)) {
            Write-SecLog "Invalid firewall backup path" "ERROR"
            return $false
        }
        netsh advfirewall export $firewallBackup | Out-Null
        if (Test-Path $firewallBackup) {
            Write-SecLog "Firewall rules backed up successfully" "SUCCESS"
        } else {
            Write-SecLog "Failed to backup firewall rules" "ERROR"
            return $false
        }
        
        # 2. Registry Keys (All systems)
        Write-SecLog "Backing up critical registry keys..." "INFO"
        $registryKeys = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell",
            "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        )
        
        foreach ($key in $registryKeys) {
            try {
                $keyName = $key.Split('\')[-1]
                $regFile = "$backupDir\registry_$keyName.reg"
                reg export $key $regFile /y 2>$null
                if (Test-Path $regFile) {
                    Write-SecLog "Registry key $keyName backed up" "INFO"
                }
            } catch {
                Write-SecLog "Could not backup registry key: $key" "WARN"
            }
        }
        
        # 3. Service Start States (All systems)
        Write-SecLog "Backing up service states..." "INFO"
        $services = Get-Service | Select-Object Name, Status, StartType
        $services | Export-Clixml "$backupDir\services_state.xml"
        Write-SecLog "Service states backed up" "SUCCESS"
        
        # 4. IIS Configuration (Web Server only)
        if ($SystemProfile.IIS) {
            Write-SecLog "Backing up IIS configuration..." "INFO"
            try {
                # Backup applicationHost.config
                $iisConfig = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
                if (Test-Path $iisConfig) {
                    Copy-Item $iisConfig "$backupDir\applicationHost.config.bak"
                    Write-SecLog "IIS applicationHost.config backed up" "SUCCESS"
                }
                
                # Create IIS backup using appcmd
                $backupName = "SecOps-Backup-$backupTimestamp"
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" add backup $backupName
                Write-SecLog "IIS configuration backup created: $backupName" "SUCCESS"
                
                # Store backup name for rollback
                $backupName | Out-File "$backupDir\iis_backup_name.txt"
                
            } catch {
                Write-SecLog "IIS backup failed: $($_.Exception.Message)" "ERROR"
            }
        }
        
        # 5. GPO Export (AD Server only)
        if ($SystemProfile.DetectedRole -eq "ActiveDirectory_DNS") {
            Write-SecLog "Backing up Group Policy Objects..." "INFO"
            try {
                Import-Module GroupPolicy -ErrorAction SilentlyContinue
                $gpoBackupDir = "$backupDir\GPO"
                New-Item -Path $gpoBackupDir -ItemType Directory -Force | Out-Null
                
                $gpos = Get-GPO -All
                foreach ($gpo in $gpos) {
                    try {
                        Backup-GPO -Guid $gpo.Id -Path $gpoBackupDir | Out-Null
                        Write-SecLog "GPO backed up: $($gpo.DisplayName)" "INFO"
                    } catch {
                        Write-SecLog "Failed to backup GPO: $($gpo.DisplayName)" "WARN"
                    }
                }
                Write-SecLog "GPO backup completed" "SUCCESS"
            } catch {
                Write-SecLog "GPO backup failed: $($_.Exception.Message)" "WARN"
            }
        }
        
        # 6. FTP Site Configuration (FTP Server only)
        if ($SystemProfile.FTP) {
            Write-SecLog "Backing up FTP configuration..." "INFO"
            try {
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" list site /config > "$backupDir\ftp_sites_config.txt"
                Write-SecLog "FTP configuration backed up" "SUCCESS"
            } catch {
                Write-SecLog "FTP backup failed: $($_.Exception.Message)" "WARN"
            }
        }
        
        # 7. System Restore Point (Workstation only)
        if ($SystemProfile.IsWorkstation) {
            Write-SecLog "Creating system restore point..." "INFO"
            try {
                Checkpoint-Computer -Description "SecOps-Tool-Backup-$backupTimestamp" -RestorePointType "MODIFY_SETTINGS"
                Write-SecLog "System restore point created" "SUCCESS"
            } catch {
                Write-SecLog "System restore point creation failed: $($_.Exception.Message)" "WARN"
            }
        }
        
        # 8. Current Windows Defender Configuration
        Write-SecLog "Backing up Windows Defender configuration..." "INFO"
        try {
            $defenderPrefs = Get-MpPreference
            $defenderPrefs | Export-Clixml "$backupDir\defender_config.xml"
            Write-SecLog "Windows Defender configuration backed up" "SUCCESS"
        } catch {
            Write-SecLog "Defender backup failed: $($_.Exception.Message)" "WARN"
        }
        
        # Create backup manifest
        $manifest = [PSCustomObject]@{
            BackupTimestamp = $backupTimestamp
            BackupDirectory = $backupDir
            SystemProfile = $SystemProfile
            BackupComponents = @(
                "Firewall Rules",
                "Registry Keys", 
                "Service States",
                "Windows Defender Config"
            )
        }
        
        if ($SystemProfile.IIS) { $manifest.BackupComponents += "IIS Configuration" }
        if ($SystemProfile.FTP) { $manifest.BackupComponents += "FTP Configuration" }
        if ($SystemProfile.DetectedRole -eq "ActiveDirectory_DNS") { $manifest.BackupComponents += "Group Policy Objects" }
        if ($SystemProfile.IsWorkstation) { $manifest.BackupComponents += "System Restore Point" }
        
        $manifest | Export-Clixml "$backupDir\backup_manifest.xml"
        
        # Store latest backup path globally
        $Global:LatestBackupPath = $backupDir
        
        Write-SecLog "System backup completed successfully" "SUCCESS"
        Write-SecLog "Backup location: $backupDir" "INFO"
        
        return $true
        
    } catch {
        Write-SecLog "Critical error during backup: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Invoke-SystemRollback {
    param([string]$BackupPath = $Global:LatestBackupPath)
    
    if (-not $BackupPath -or -not (Test-Path $BackupPath)) {
        Write-SecLog "No valid backup path found. Cannot perform rollback." "ERROR"
        return $false
    }
    
    Write-SecLog "Starting system rollback from: $BackupPath" "WARN"
    
    try {
        $manifestPath = "$BackupPath\backup_manifest.xml"
        if (Test-Path $manifestPath) {
            $manifest = Import-Clixml $manifestPath
            Write-SecLog "Loaded backup manifest from $($manifest.BackupTimestamp)" "INFO"
        } else {
            Write-SecLog "No backup manifest found. Proceeding with standard rollback." "WARN"
        }
        
        # 1. Restore Firewall Rules
        $firewallBackup = "$BackupPath\firewall_backup.wfw"
        if (Test-Path $firewallBackup) {
            Write-SecLog "Restoring firewall rules..." "INFO"
            netsh advfirewall import $firewallBackup | Out-Null
            Write-SecLog "Firewall rules restored" "SUCCESS"
        }
        
        # 2. Restore Registry Keys
        Write-SecLog "Restoring registry keys..." "INFO"
        Get-ChildItem "$BackupPath\registry_*.reg" | ForEach-Object {
            try {
                reg import $_.FullName /y 2>$null
                Write-SecLog "Registry restored: $($_.Name)" "INFO"
            } catch {
                Write-SecLog "Failed to restore registry: $($_.Name)" "WARN"
            }
        }
        
        # 3. Restore Service States
        $servicesBackup = "$BackupPath\services_state.xml"
        if (Test-Path $servicesBackup) {
            Write-SecLog "Restoring service states..." "INFO"
            $originalServices = Import-Clixml $servicesBackup
            foreach ($service in $originalServices) {
                try {
                    $currentService = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
                    if ($currentService -and $currentService.Status -ne $service.Status) {
                        if ($service.Status -eq "Running") {
                            Start-Service -Name $service.Name -ErrorAction SilentlyContinue
                        } elseif ($service.Status -eq "Stopped") {
                            Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                        }
                    }
                } catch {
                    Write-SecLog "Could not restore service: $($service.Name)" "WARN"
                }
            }
            Write-SecLog "Service states restored" "SUCCESS"
        }
        
        # 4. Restore IIS Configuration
        $iisBackupName = "$BackupPath\iis_backup_name.txt"
        if (Test-Path $iisBackupName) {
            $backupName = Get-Content $iisBackupName
            Write-SecLog "Restoring IIS configuration: $backupName" "INFO"
            try {
                & "$env:SystemRoot\System32\inetsrv\appcmd.exe" restore backup $backupName
                Write-SecLog "IIS configuration restored" "SUCCESS"
            } catch {
                Write-SecLog "IIS restore failed: $($_.Exception.Message)" "ERROR"
            }
        }
        
        # 5. Restore Group Policy Objects with backup verification
        $gpoBackupDir = "$BackupPath\GPO"
        
        if (-not (Test-SafePath -Path $gpoBackupDir -AllowedBase $BackupPath)) {
            Write-SecLog "Invalid GPO backup path detected" "ERROR"
            return $false
        }
        
        if (Test-Path $gpoBackupDir) {
            Write-SecLog "Restoring Group Policy Objects..." "INFO"
            try {
                Import-Module GroupPolicy -ErrorAction Stop
                $backups = Get-ChildItem $gpoBackupDir -Directory
                
                foreach ($backup in $backups) {
                    $backupId = $backup.Name
                    try {
                        $manifestPath = "$gpoBackupDir\$backupId\manifest.xml"
                        
                        if (-not (Test-SafePath -Path $manifestPath -AllowedBase $gpoBackupDir)) {
                            Write-SecLog "Invalid manifest path detected: $backupId" "ERROR"
                            continue
                        }
                        
                        if (Test-Path $manifestPath) {
                            $manifestXml = Read-SafeXml -Path $manifestPath
                            
                            if ($manifestXml.Backup.BackupInst.ID.InnerText -eq $backupId) {
                                Restore-GPO -BackupId $backupId -Path $gpoBackupDir -ErrorAction Stop
                                Write-SecLog "Restored GPO: $backupId" "SUCCESS"
                            } else {
                                Write-SecLog "Backup manifest validation failed for $backupId" "ERROR"
                            }
                        } else {
                            Write-SecLog "No manifest found for backup $backupId, skipping" "WARN"
                        }
                    } catch {
                        Write-SecLog "Failed to restore GPO $backupId - $($_.Exception.Message)" "ERROR"
                    }
                }
                
                try {
                    gpupdate /force
                    Write-SecLog "GPO refresh initiated" "SUCCESS"
                } catch {
                    Write-SecLog "GPO refresh failed" "WARN"
                }
                
                Write-SecLog "GPO restoration completed" "SUCCESS"
            } catch {
                Write-SecLog "GPO restore failed: $($_.Exception.Message)" "ERROR"
            }
        }
        
        # 6. Restore Windows Defender Configuration
        $defenderBackup = "$BackupPath\defender_config.xml"
        if (Test-Path $defenderBackup) {
            Write-SecLog "Restoring Windows Defender configuration..." "INFO"
            try {
                $defenderConfig = Import-Clixml $defenderBackup
                # Restore key settings
                Set-MpPreference -DisableRealtimeMonitoring $defenderConfig.DisableRealtimeMonitoring
                Write-SecLog "Windows Defender configuration restored" "SUCCESS"
            } catch {
                Write-SecLog "Defender restore failed: $($_.Exception.Message)" "WARN"
            }
        }
        
        Write-SecLog "System rollback completed" "SUCCESS"
        Write-SecLog "Please verify all scoring services are operational" "WARN"
        
        return $true
        
    } catch {
        Write-SecLog "Critical error during rollback: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-BackupHistory {
    if (-not (Test-Path $Global:BackupPath)) {
        Write-SecLog "No backup directory found" "WARN"
        return @()
    }
    
    $backups = Get-ChildItem $Global:BackupPath -Directory | ForEach-Object {
        $manifestPath = "$($_.FullName)\backup_manifest.xml"
        if (Test-Path $manifestPath) {
            $manifest = Import-Clixml $manifestPath
            [PSCustomObject]@{
                Timestamp = $manifest.BackupTimestamp
                Path = $_.FullName
                Components = $manifest.BackupComponents
                SystemRole = $manifest.SystemProfile.DetectedRole
            }
        }
    } | Sort-Object Timestamp -Descending
    
    return $backups
}