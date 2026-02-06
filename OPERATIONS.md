# CCDC 2026 Adaptive Hardening & Detection Tool - INTERNAL DOCUMENTATION
## ⚠️ OPERATIONAL SECURITY - INTERNAL USE ONLY ⚠️

### CLASSIFICATION: RESTRICTED
**This document contains sensitive operational information. Do not distribute publicly.**
## COMPETITION DEPLOYMENT COMMANDS

### 🚀 **Rapid Deployment**
```powershell
# Primary deployment (recommended)
.\QuickSetup.ps1

# Emergency deployment (bypasses confirmations)
.\QuickSetup.ps1 -EmergencyMode

# Deploy without network isolation
.\QuickSetup.ps1 -IsolateNetwork:$false
```

### 🔧 **System Management**
```powershell
# Full system deployment
.\SystemManager.ps1

# Force rollback (emergency)
.\SystemManager.ps1 -ForceRollback

# Test mode (safe)
.\SystemManager.ps1 -TestMode
```

### 📊 **Monitoring & Status**
```powershell
# Quick functionality test
.\Quick-Test.ps1

# Comprehensive test suite
.\Test-Suite.ps1

# Check scoring services
Get-ScoringStatus | Format-Table

# Monitor honeypots
Get-HoneypotStatus | Format-List
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
# - Logs: C:\CCDC-Logs\port_scans.log, system_changes.log, vuln_scans.log
```

### 🚨 **Emergency Response**
```powershell
# Emergency network killswitch (isolate compromised system)
.\Reset.ps1

# Quick activation (batch file)
reset.bat

# Restore network access
.\Reset.ps1 -Restore

# Rotate KRBTGT password (Active Directory only)
.\Rotate-KRBTGT.ps1

# Smart session security (screen lock, no auto-logout)
.\Smart-Session-Security.ps1
```

## True Purpose & Capabilities

This is a sophisticated cyber defense tool designed specifically for CCDC competitions. It provides:

- **Advanced Threat Detection**: Real-time malware scanning, process monitoring, network threat detection
- **Rapid System Hardening**: Military-grade security controls implementation in under 60 seconds
- **Secure Network Isolation**: Selective network disconnection with critical service preservation
- **Comprehensive Malware Scanning**: Detects 50+ red team tools including Mimikatz, Cobalt Strike, BloodHound
- **Advanced Honeypots**: Multiple deception layers with randomized credentials
- **Automated Threat Response**: Immediate termination of malicious processes and quarantine of threats
- **Complete Rollback Capability**: Full system restoration including GPO recovery

## Security Features (INTERNAL)

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

### Honeypot System (CLASSIFIED) - SECURITY HARDENED
- **AD Honeypot Accounts**: Creates 4 different types of trap accounts with cryptographically random passwords
- **Dynamic Credential Honeypots**: Plants unique fake credentials generated per deployment
- **File System Traps**: Creates realistic-looking sensitive files with comprehensive auditing
- **Network Share Honeypots**: Deploys attractive network shares with monitoring
- **SSH Key Traps**: Plants fake SSH private keys (inspired by tunnelbees)
- **Enhanced Monitoring**: Tracks events 4624, 4625, 4648, 4672, 4768, 4769, 4776, 4663
- **Secure Credential Storage**: All honeypot passwords stored in encrypted logs

### Threat Intelligence Integration
Based on intelligence from:
- **Jake Ginesin** (2024 CCDC National Winner) - tunnelbees SSH honeypot techniques
- **David Cowen** (CRA Forensic Services) - Advanced forensic countermeasures  
- **Alex Levinson** - Red team tactics and methodologies

## Operational Security Measures

### Code Obfuscation
- Public README provides cover story as "Windows Optimization Tool"
- True capabilities hidden from casual inspection
- Logging uses randomized paths to avoid detection
- Network isolation prevents C2 communication during deployment

### Anti-Analysis Features
- Rapid deployment prevents detailed analysis
- Network isolation blocks exfiltration
- Comprehensive malware scanning before execution
- Process monitoring detects analysis tools

### Stealth Operations
- Logs stored in randomized Windows temp directories
- Honeypots appear as legitimate accounts/files
- Detection rules designed to catch red team tools without false positives
- Automated cleanup of deployment artifacts

## OPERATIONAL PROCEDURES

### 🎯 **Competition Day Checklist**
1. **Pre-Deployment** (5 minutes)
   - Run `Quick-Test.ps1` on each system
   - Verify admin privileges and PowerShell version
   - Check network connectivity baseline
   - Print notes.txt for reference

2. **Rapid Deployment** (2 minutes per system)
   - Execute `QuickSetup.ps1` on all Windows systems
   - Monitor for HONEYPOT_TRIGGERED alerts
   - Verify scoring services remain operational
   - Document any deployment issues

3. **Continuous Monitoring** (Throughout competition)
   - Watch `C:\CCDC-Logs\alerts.json` for critical alerts
   - Monitor honeypot access attempts
   - Track security posture improvements
   - Coordinate threat intelligence with team

### 🚨 **Critical Alert Response**
- **HONEYPOT_TRIGGERED**: Attacker active - investigate source immediately
- **SCORING_SERVICE_FAILURE**: Check rollback correlation - may need restoration
- **LSASS_PROTECTION_BYPASS**: Advanced attack detected - isolate system
- **MALWARE_DETECTED**: Auto-terminated - check for persistence mechanisms

### 🔄 **Emergency Rollback Procedure**
1. Identify failing service: `Get-ScoringStatus`
2. Check recent hardening actions for correlation
3. Execute rollback: `SystemManager.ps1 -ForceRollback`
4. Verify service restoration
5. Document incident for analysis

## LOG LOCATIONS & MONITORING

### 📁 **Critical Log Files**
- **Main Log**: `C:\CCDC-Logs\ccdc-tool.log`
- **Alert Stream**: `C:\CCDC-Logs\alerts.json`
- **Incident Reports**: `C:\CCDC-Logs\Reports\`
- **Honeypot Credentials**: `C:\CCDC-Logs\.honeypot_creds`
- **Scoring Validation**: `C:\CCDC-Logs\scoring_validation.json`
- **Backup Manifests**: `C:\CCDC-Backups\[timestamp]\backup_manifest.xml`

### 🔍 **Real-Time Monitoring**
```powershell
# Live network port dashboard (recommended)
.\Continuous-Scanner.ps1

# Monitor alerts in real-time
Get-Content C:\CCDC-Logs\alerts.json -Wait -Tail 10

# Check honeypot status
Get-HoneypotStatus

# Verify scoring services
Get-ScoringStatus | Where-Object Success -eq $false

# Monitor active connections
Get-NetTCPConnection | Where-Object State -eq Established

# View recent system changes
Get-Content C:\CCDC-Logs\system_changes.log -Tail 20

# View recent port scans
Get-Content C:\CCDC-Logs\port_scans.log -Tail 10
```

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

## FINAL DEPLOYMENT CHECKLIST

### ✅ **Pre-Competition Validation**
- [ ] Test suite passes on isolated VMs (all system types)
- [ ] Rollback functionality verified on each system type
- [ ] Honeypot monitoring confirmed operational
- [ ] Scoring service validation tested
- [ ] Team trained on emergency procedures
- [ ] QUICK-REF.txt printed and distributed

### ✅ **Competition Day Readiness**
- [ ] Tool deployed on USB drives (network may be compromised)
- [ ] Admin credentials verified on all systems
- [ ] Baseline service status documented
- [ ] Communication plan established with team
- [ ] Incident response procedures reviewed

### ✅ **Success Metrics**
- **Deployment Speed**: <2 minutes per system
- **Service Uptime**: >95% scoring service availability
- **Threat Detection**: Honeypot alerts within 15 seconds
- **Rollback Time**: <30 seconds for complete restoration
- **Team Coordination**: Real-time threat intelligence sharing

## Classification & Distribution

**CLASSIFICATION**: RESTRICTED - INTERNAL USE ONLY
**DISTRIBUTION**: CCDC Team Members Only
**HANDLING**: Do not distribute outside team, do not post publicly
**DESTRUCTION**: Securely delete after competition

---

**REMEMBER**: This tool's effectiveness depends on operational security. The public README provides cover - never reveal true capabilities to competitors or observers.
