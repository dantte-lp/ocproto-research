# Cisco Secure Client Deployment Guide

**Analysis Date:** 2025-10-29
**Purpose:** Complete deployment procedures for ocserv-compatible environments

## Deployment Methods

### 1. Predeploy (Out-of-Band)

**Platforms**: Windows (MSI), macOS (PKG), Linux (RPM/DEB/script)

**Windows Silent Install**:
```cmd
msiexec /i cisco-secure-client-win-5.1.x.x-core-vpn-predeploy-k9.msi ^
  /norestart /passive /lvx* install.log

REM Disable VPN (standalone modules)
msiexec /i cisco-secure-client-win-5.1.x.x-core-vpn-predeploy-k9.msi ^
  /norestart /passive PRE_DEPLOY_DISABLE_VPN=1

REM Disable Customer Experience Feedback
msiexec /i cisco-secure-client-win-5.1.x.x-core-vpn-predeploy-k9.msi ^
  /norestart /passive DISABLE_CUSTOMER_EXPERIENCE_FEEDBACK=1

REM Lockdown (prevent service stop)
msiexec /i cisco-secure-client-win-5.1.x.x-core-vpn-predeploy-k9.msi ^
  /norestart /passive LOCKDOWN=1
```

**macOS Install**:
```bash
sudo installer -pkg cisco-secure-client-macos-5.1.x.x.pkg -target /
```

**Linux Install** (Script):
```bash
tar -xzf cisco-secure-client-linux64-5.1.x.x-core-vpn-predeploy-k9.tar.gz
cd cisco-secure-client-linux64-5.1.x.x-core-vpn-predeploy-k9
sudo ./install.sh
```

**Linux Install** (RPM):
```bash
sudo rpm -ivh cisco-secure-client-linux64-5.1.x.x-core-vpn-predeploy-k9.rpm
```

**Linux Install** (DEB):
```bash
sudo dpkg -i cisco-secure-client-linux64-5.1.x.x-core-vpn-predeploy-k9.deb
sudo apt-get install -f  # Fix dependencies
```

### 2. Web Deploy

**Flow**:
1. User connects to ASA/FTD portal
2. Downloads Downloader component
3. Downloader fetches client matching OS
4. Auto-installs and establishes VPN

**Limitations**:
- Windows ARM64: Webdeploy removed in 5.1.2.42 (use predeploy)
- macOS 5.1.1.42+: Requires admin privileges

### 3. Cloud Management

**Flow**:
1. Execute `csc-deployment.exe` from Cloud Management UI
2. Installs Cloud Management service
3. Deploys configured modules

## Pre-Deployment File Structure

### Windows

**Profile Location**:
```
%ProgramData%\Cisco\Cisco Secure Client\VPN\Profile\
  - AnyConnectProfile.xml
  - AnyConnectProfile.xsd
```

**Module-Specific**:
```
%ProgramData%\Cisco\Cisco Secure Client\
  ├── VPN\Profile\           (VPN profiles)
  ├── Network Access Manager\newConfigFiles\  (NAM profiles)
  ├── ISE Posture\           (Posture profiles)
  ├── NVM\                   (NVM profiles)
  └── Umbrella\              (Umbrella profiles + OrgInfo.json)
```

### macOS / Linux

**Profile Location**:
```
/opt/cisco/secureclient/vpn/profile/
  - AnyConnectProfile.xml
  - AnyConnectProfile.xsd
```

**Module-Specific**:
```
/opt/cisco/secureclient/
  ├── vpn/profile/           (VPN profiles)
  ├── nam/profile/           (NAM profiles)
  ├── posture/profile/       (Posture profiles)
  └── umbrella/              (Umbrella profiles)
```

## Post-Installation Configuration

### Windows Registry Settings

**Disable IGTK** (WPA3 workaround):
```reg
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NativeWifiP\Parameters
  DisableIGTK = REG_DWORD 1
```

**WFP Sublayer Weight**:
```cmd
"C:\Program Files (x86)\Cisco\Cisco Secure Client\DART\acsocktool.exe" -slwm 5
```

### Linux Certificate Store

**PEM Store** (default):
```bash
# System CA certificates
ls /etc/ssl/certs/
```

**NSS Store** (optional):
```bash
# Create NSS database
mkdir -p ~/.cisco/certificates/nssdb
certutil -N -d sql:~/.cisco/certificates/nssdb
```

### macOS System Extensions

**Approve Extensions**:
```
System Settings > Privacy & Security > Extensions
  - Allow: Cisco Secure Client
  - Allow: Cisco Zero Trust Access (if ZTA module installed)
```

## Firewall Requirements

**Required Ports**:
| Protocol | Port | Direction | Purpose |
|----------|------|-----------|---------|
| TCP | 443 | Outbound | SSL/TLS VPN (CSTP) |
| UDP | 443 | Outbound | DTLS VPN |
| TCP | 500 | Outbound | IKEv2 (if IPsec) |
| UDP | 500 | Outbound | IKEv2 |
| UDP | 4500 | Outbound | IKEv2 NAT-T |

## Troubleshooting

**Windows**: Check event log
```cmd
eventvwr.msc
  Application and Services Logs > Cisco > AnyConnect
```

**macOS**: Check console logs
```bash
log show --predicate 'process == "Cisco Secure Client"' --last 1h
```

**Linux**: Check syslog
```bash
journalctl -u cisco-secure-client-daemon.service -f
```

---

**End of Document**
