#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remove SecOps Branding - Replace with Generic Terms
    
.DESCRIPTION
    Removes all SecOps references from scripts and replaces with generic security terms
#>

Write-Host "Removing SecOps branding from all files..." -ForegroundColor Yellow

$replacements = @(
    @("Write-SecLog", "Write-SecLog"),
    @("System-Backups", "System-Backups"),
    @("Security-Logs", "Security-Logs"),
    @("FW-Allow-", "FW-Allow-"),
    @("SecAdmin", "SecAdmin"),
    @("security-tool.log", "security-tool.log"),
    @("SecOps", "SecOps"),
    @("SecOps", "secops")
)

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$files = Get-ChildItem $scriptPath -Recurse -Include *.ps1,*.md,*.txt,*.bat -File
$filesModified = 0

foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw
    $modified = $false
    
    foreach ($pair in $replacements) {
        if ($content -match [regex]::Escape($pair[0])) {
            $content = $content -replace [regex]::Escape($pair[0]), $pair[1]
            $modified = $true
        }
    }
    
    if ($modified) {
        $content | Set-Content $file.FullName -NoNewline
        Write-Host "  Updated: $($file.Name)" -ForegroundColor Green
        $filesModified++
    }
}

Write-Host "`nBranding removal complete!" -ForegroundColor Green
Write-Host "Files modified: $filesModified" -ForegroundColor Cyan
Write-Host "`nNew naming convention:" -ForegroundColor Yellow
Write-Host "  SecOps → SecOps" -ForegroundColor White
Write-Host "  C:\Security-Logs → C:\Security-Logs" -ForegroundColor White
Write-Host "  C:\System-Backups → C:\System-Backups" -ForegroundColor White
Write-Host "  Write-SecLog → Write-SecLog" -ForegroundColor White
