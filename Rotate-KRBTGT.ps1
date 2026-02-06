#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Rotate KRBTGT password to invalidate Golden Tickets
    
.DESCRIPTION
    Resets KRBTGT account password once to break Kerberos ticket persistence
    WARNING: May cause brief authentication issues - use carefully during competition
#>

param(
    [switch]$Force
)

function Rotate-KRBTGTPassword {
    Write-Host "`n[KRBTGT PASSWORD ROTATION]" -ForegroundColor Yellow
    Write-Host "This will invalidate all Kerberos tickets in the domain" -ForegroundColor Yellow
    Write-Host "Services may experience brief authentication delays`n" -ForegroundColor Red
    
    if (-not $Force) {
        $confirm = Read-Host "Continue? (yes/NO)"
        if ($confirm -ne "yes") {
            Write-Host "Cancelled" -ForegroundColor Gray
            return
        }
    }
    
    try {
        # Get KRBTGT account
        $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet
        
        Write-Host "`nCurrent KRBTGT password last set: $($krbtgt.PasswordLastSet)" -ForegroundColor Cyan
        
        # Generate cryptographically secure password
        Add-Type -AssemblyName System.Web
        $newPassword = [System.Web.Security.Membership]::GeneratePassword(128, 32)
        $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
        
        # Reset password
        Write-Host "Rotating KRBTGT password..." -ForegroundColor Yellow
        Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword $securePassword
        
        # Verify
        $krbtgtAfter = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet
        Write-Host "`n[SUCCESS] KRBTGT password rotated" -ForegroundColor Green
        Write-Host "New password set: $($krbtgtAfter.PasswordLastSet)" -ForegroundColor Green
        
        Write-Host "`nNOTE: Rotate again in 10+ hours for complete Golden Ticket mitigation" -ForegroundColor Cyan
        Write-Host "(Requires 2 rotations due to password history)" -ForegroundColor Gray
        
        # Log the rotation
        $logEntry = "[$(Get-Date)] KRBTGT password rotated by $env:USERNAME"
        $logEntry | Out-File "C:\CCDC-Logs\krbtgt_rotation.log" -Append
        
    } catch {
        Write-Host "`n[ERROR] Failed to rotate KRBTGT: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Check if running on Domain Controller
$isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4

if (-not $isDC) {
    Write-Host "[ERROR] This script must run on a Domain Controller" -ForegroundColor Red
    exit 1
}

Rotate-KRBTGTPassword
