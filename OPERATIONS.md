# SecOps 2026 Adaptive Hardening & Detection Tool - OPERATIONS GUIDE
## ⚠️ OPERATIONAL SECURITY - INTERNAL USE ONLY ⚠️

### CLASSIFICATION: RESTRICTED
**This document contains sensitive operational information. Do not distribute publicly.**

---

## 🎯 2026 PERFORMANCE IMPROVEMENTS

**Previous Result: 4th Place (64/100 Service Score)**

**Root Cause:** Hardening broke scoring services without detection/rollback

**New Capabilities:**
- ✅ Auto-rollback if hardening breaks services
- ✅ Network connectivity validation (fixes Inject 01 failure)
- ✅ Missing inject handlers (Inject 08, 09, 29 - all scored 0)
- ✅ ICMP firewall rules fixed for scoring
- ✅ Rapid inject response system

**Target: Top 2 Finish**

---

## COMPETITION DEPLOYMENT COMMANDS

### 🚀 **Rapid Deployment**
```powershell
# Primary deployment (recommended)
.\Rapid-Deploy.ps1

# Emergency deployment (bypasses confirmations)
.\Rapid-Deploy.ps1 -EmergencyMode

# Deploy without network isolation
.\Rapid-Deploy.ps1 -IsolateNetwork:$false
```

### 🔧 **System Management**
```powershell
# Full system deployment with auto-rollback
.\Main-Tool.ps1

# Force rollback (emergency)
.\Main-Tool.ps1 -ForceRollback

# Test mode (safe)
.\Main-Tool.ps1 -TestMode
```

### 📊 **Pre-Deployment Validation (NEW - CRITICAL)**
```powershell
# Quick functionality test
.\Quick-Test.ps1

# Validate network connectivity BEFORE deployment
Test-NetworkConnectivity

# Create scoring services baseline
Test-ScoringServicesBaseline

# Comprehensive test suite
.\Test-Suite.ps1
```

### 🔍 **Continuous Scanning & Network Monitoring**
```powershell
# Live network-wide port monitor with color-coded dashboard
.\Continuous-Scanner.ps1

# Scan specific targets
.\Continuous-Scanner.ps1 -Targets "192.168.1.10","192.168.1.20","192.168.1.30"

# Features:
# - Auto-detects all hosts on subnet
# - Port scans every 10 minutes
# - System change logging every 3 minutes
# - Vulnerability scans every 10 minutes
# - Live color-coded table (Green=Normal, Yellow=Many Ports, Red=Suspicious)
# - Logs: C:\Security-Logs\port_scans.log, system_changes.log, vuln_scans.log
```

### 🚨 **Emergency Response**
```powershell
# Emergency network killswitch (isolate compromised system)
.\Emergency-Killswitch.ps1

# Quick activation (batch file)
KILLSWITCH.bat

# Restore network access
.\Emergency-Killswitch.ps1 -Restore

# Rotate KRBTGT password (Active Directory only)
.\Rotate-KRBTGT.ps1

# Smart session security (screen lock, no auto-logout)
.\Smart-Session-Security.ps1
```

### ⚡ **Rapid Inject Response (NEW)**
```powershell
# Quick inject execution - one command per inject
.\Run-Inject.ps1 -InjectType <type>

# Available inject types:
FileSystemIntegrity    # Already scores 100
DetectBeaconing        # Already scores 100
MitigationPlan         # Already scores 100
StartupFiles           # NEW - fixes Inject 08 (scored 0)
PrecisionTime          # NEW - fixes Inject 09 (scored 0)
FirewallExport         # NEW - fixes Inject 29 (scored 0)
NetworkConnectivity    # NEW - fixes Inject 01 (scored 0)

# Examples:
.\Run-Inject.ps1 -InjectType StartupFiles
.\Run-Inject.ps1 -InjectType PrecisionTime
.\Run-Inject.ps1 -InjectType NetworkConnectivity
```

---

## 🎯 COMPETITION DAY WORKFLOW (UPDATED)

### Phase 1: Pre-Deployment (5 minutes)
```powershell
# 1. Run pre-flight checks
.\Quick-Test.ps1

# 2. Validate network connectivity
Test-NetworkConnectivity

# 3. Create scoring baseline
Test-ScoringServicesBaseline

# 4. Document current state
Get-Service | Where-Object Status -eq "Running" | Export-Csv baseline_services.csv
Get-NetTCPConnection | Where-Object State -eq "Listen" | Export-Csv baseline_ports.csv
```

### Phase 2: Safe Deployment with Auto-Rollback (5 minutes)
```powershell
# Deploy with automatic service validation
.\Rapid-Deploy.ps1

# Tool will automatically:
# - Create baseline of all scoring services
# - Apply hardening
# - Validate services after each change
# - Auto-rollback if any service breaks
# - Alert if network connectivity fails
```

### Phase 3: Continuous Monitoring (Throughout Competition)
```powershell
# Start live network dashboard
.\Continuous-Scanner.ps1

# Monitor in separate window:
Get-Content C:\Security-Logs\alerts.json -Wait -Tail 10

# Check service health
Test-ScoringServicesHealth -Baseline (Import-Clixml C:\System-Backups\scoring_baseline.xml)
```

### Phase 4: Inject Response (When Injects Drop)
```powershell
# Rapid response - under 2 minutes per inject
.\Run-Inject.ps1 -InjectType StartupFiles      # Inject 08
.\Run-Inject.ps1 -InjectType PrecisionTime     # Inject 09
.\Run-Inject.ps1 -InjectType FirewallExport    # Inject 29
.\Run-Inject.ps1 -InjectType NetworkConnectivity # Inject 01

# Check output
dir C:\Security-Logs\Reports\
```

---

## True Purpose & Capabilities

This is a sophisticated cyber defense tool designed specifically for SecOps competitions. It provides:

- **Advanced Threat Detection**: Real-time malware scanning, process monitoring, network threat detection
- **Rapid System Hardening**: Military-grade security controls implementation in under 60 seconds
- **Auto-Rollback Protection**: Automatically reverts changes that break scoring services
- **Secure Network Isolation**: Selective network disconnection with critical service preservation
- **Comprehensive Malware Scanning**: Detects 50+ red team tools including Mimikatz, Cobalt Strike, BloodHound
- **Advanced Honeypots**: Multiple deception layers with randomized credentials
- **Automated Threat Response**: Immediate termination of malicious processes and quarantine of threats
- **Complete Rollback Capability**: Full system restoration including GPO recovery
- **Rapid Inject Response**: One-command execution for common SecOps injects

---

## Security Features (INTERNAL)

### NEW: Scoring Service Protection
- **Pre-Hardening Baseline**: Captures all active services before changes
- **Post-Change Validation**: Tests services after each hardening step
- **Automatic Rollback**: Reverts changes if services break
- **Network Connectivity Checks**: Validates ICMP, DNS, gateway, internet
- **ICMP Firewall Rules**: Properly configured for scoring engine pings

### Rapid Deployment Mode
- **Secure Network Isolation**: Disconnects from network while preserving DNS, HTTPS, LDAP, Kerberos
- **Enhanced Malware Scanning**: Comprehensive scan for 50+ malware signatures with auto-termination
- **Process Termination**: Auto-kills detected red team tools (Mimikatz, Cobalt Strike, etc.)
- **File Quarantine**: Automatically quarantines suspicious files
- **Emergency Mode**: Bypasses user confirmations for rapid deployment
- **Critical Service Preservation**: Maintains scoring services during hardening

### Advanced Security Controls
- **LSASS Protection**: Enables RunAsPPL to prevent credential dumping
- **NTLMv1 Elimination**: Completely disables NTLMv1 authentication
- **Attack Surface Reduction**: 16 comprehensive ASR rules
- **Kernel Driver Monitoring**: Detects malicious drivers (Capcom, GDrv, etc.)
- **Memory Protection**: Advanced memory-based threat detection
- **Registry Persistence Detection**: Scans for malicious registry entries

### Honeypot System (CLASSIFIED)
- **AD Honeypot Accounts**: Creates 4 different types of trap accounts with cryptographically random passwords
- **Dynamic Credential Honeypots**: Plants unique fake credentials generated per deployment
- **File System Traps**: Creates realistic-looking sensitive files with comprehensive auditing
- **Network Share Honeypots**: Deploys attractive network shares with monitoring
- **SSH Key Traps**: Plants fake SSH private keys (inspired by tunnelbees)
- **Enhanced Monitoring**: Tracks events 4624, 4625, 4648, 4672, 4768, 4769, 4776, 4663
- **Secure Credential Storage**: All honeypot passwords stored in encrypted logs

---

## OPERATIONAL PROCEDURES

### 🚨 **Critical Alert Response**
- **SCORING_SERVICE_FAILURE**: Auto-rollback triggered - verify restoration
- **HONEYPOT_TRIGGERED**: Attacker active - investigate source immediately
- **LSASS_PROTECTION_BYPASS**: Advanced attack detected - isolate system
- **MALWARE_DETECTED**: Auto-terminated - check for persistence mechanisms
- **NETWORK_CONNECTIVITY_FAILURE**: Check firewall rules and ICMP

### 🔄 **Emergency Rollback Procedure**
```powershell
# 1. Identify failing service
Test-ScoringServicesHealth -Baseline (Import-Clixml C:\System-Backups\scoring_baseline.xml)

# 2. Check recent hardening actions
Get-Content C:\Security-Logs\security-tool.log -Tail 50

# 3. Execute rollback
.\Main-Tool.ps1 -ForceRollback

# 4. Verify service restoration
Test-ScoringServicesHealth -Baseline (Import-Clixml C:\System-Backups\scoring_baseline.xml)

# 5. Document incident
"Rollback executed at $(Get-Date)" | Out-File C:\Security-Logs\rollback_log.txt -Append
```

---

## LOG LOCATIONS & MONITORING

### 📁 **Critical Log Files**
- **Main Log**: `C:\Security-Logs\security-tool.log`
- **Alert Stream**: `C:\Security-Logs\alerts.json`
- **Incident Reports**: `C:\Security-Logs\Reports\`
- **Honeypot Credentials**: `C:\Security-Logs\.honeypot_creds`
- **Scoring Validation**: `C:\Security-Logs\scoring_validation.json`
- **Scoring Baseline**: `C:\System-Backups\scoring_baseline.xml`
- **Backup Manifests**: `C:\System-Backups\[timestamp]\backup_manifest.xml`
- **Network Scans**: `C:\Security-Logs\port_scans.log`
- **System Changes**: `C:\Security-Logs\system_changes.log`
- **Inject Reports**: `C:\Security-Logs\Reports\*`

### 🔍 **Real-Time Monitoring**
```powershell
# Live network port dashboard (recommended)
.\Continuous-Scanner.ps1

# Monitor alerts in real-time
Get-Content C:\Security-Logs\alerts.json -Wait -Tail 10

# Check scoring service health
Test-ScoringServicesHealth -Baseline (Import-Clixml C:\System-Backups\scoring_baseline.xml)

# Verify network connectivity
Test-NetworkConnectivity

# Monitor active connections
Get-NetTCPConnection | Where-Object State -eq Established

# View recent system changes
Get-Content C:\Security-Logs\system_changes.log -Tail 20

# View recent port scans
Get-Content C:\Security-Logs\port_scans.log -Tail 10

# Check inject reports
dir C:\Security-Logs\Reports\ | Sort-Object LastWriteTime -Descending
```

---

## Threat Detection Capabilities

### Malware Signatures (50+ tools)
- **Credential Dumpers**: Mimikatz, Pypykatz, Lazykatz, Nanodump, Dumpert
- **C2 Frameworks**: Cobalt Strike, Metasploit, Empire, Covenant
- **AD Tools**: BloodHound, SharpHound, Rubeus, Kerberoast, ASREPRoast
- **Remote Access**: PsExec, PAExec, RemCom, WinEXE
- **Persistence**: Various rootkits, backdoors, and persistence mechanisms

### Network Threat Detection
- **C2 Communication**: Detects connections to suspicious ports/IPs
- **Lateral Movement**: Identifies cross-system authentication patterns
- **Data Exfiltration**: Monitors for large outbound transfers
- **Tunnel Detection**: Identifies covert communication channels

### Advanced Persistence Detection
- **Registry Monitoring**: Scans all persistence registry keys
- **Service Monitoring**: Detects rogue service installations
- **Scheduled Task Monitoring**: Identifies malicious scheduled tasks
- **Kernel Driver Monitoring**: Detects rootkit installations
- **Memory Injection**: Identifies process hollowing and injection

---

## FINAL DEPLOYMENT CHECKLIST

### ✅ **Pre-Competition Validation**
- [ ] Test suite passes on isolated VMs (all system types)
- [ ] Rollback functionality verified on each system type
- [ ] Scoring service validation tested
- [ ] Network connectivity validation tested
- [ ] Inject response tools tested (Run-Inject.ps1)
- [ ] Honeypot monitoring confirmed operational
- [ ] Team trained on emergency procedures
- [ ] QUICK-REF.txt printed and distributed

### ✅ **Competition Day Readiness**
- [ ] Tool deployed on USB drives (network may be compromised)
- [ ] Admin credentials verified on all systems
- [ ] Baseline service status documented
- [ ] Network connectivity validated
- [ ] Communication plan established with team
- [ ] Incident response procedures reviewed
- [ ] Inject response commands memorized

### ✅ **Success Metrics (Updated for 2026)**
- **Deployment Speed**: <5 minutes per system (with validation)
- **Service Uptime**: >95% scoring service availability (auto-rollback enabled)
- **Threat Detection**: Honeypot alerts within 15 seconds
- **Rollback Time**: <30 seconds for complete restoration
- **Inject Response**: <2 minutes per inject (using Run-Inject.ps1)
- **Team Coordination**: Real-time threat intelligence sharing

---

## Quick Reference Card

### Most Common Commands
```powershell
# Deploy
.\Rapid-Deploy.ps1

# Check services
Test-ScoringServicesHealth -Baseline (Import-Clixml C:\System-Backups\scoring_baseline.xml)

# Rollback
.\Main-Tool.ps1 -ForceRollback

# Network monitor
.\Continuous-Scanner.ps1

# Inject response
.\Run-Inject.ps1 -InjectType <type>

# Emergency isolation
.\Emergency-Killswitch.ps1
```

---

## Classification & Distribution

**CLASSIFICATION**: RESTRICTED - INTERNAL USE ONLY  
**DISTRIBUTION**: SecOps Team Members Only  
**HANDLING**: Do not distribute outside team, do not post publicly  
**DESTRUCTION**: Securely delete after competition  

---

**REMEMBER**: This tool's effectiveness depends on operational security. The public README provides cover - never reveal true capabilities to competitors or observers.

**2026 GOAL**: Top 2 finish through service uptime protection and rapid inject response.
