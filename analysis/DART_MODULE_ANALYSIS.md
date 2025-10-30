# DART Module Analysis
## Diagnostics and Reporting Tool - Cisco Secure Client 5.1.12.146

## Document Information

**Version**: 1.0
**Date**: 2025-10-29
**Component**: DART (Diagnostics and Reporting Tool)
**Client Version**: 5.1.12.146
**Status**: New module in 5.1.12.146 (not present in 5.1.2.42)

---

## Executive Summary

DART (Diagnostics and Reporting Tool) is a comprehensive diagnostic framework introduced in Cisco Secure Client 5.1.12.146. It provides automated collection of logs, system information, and diagnostic data from all Cisco Secure Client modules (VPN, Umbrella, Network Visibility, Posture, ISE).

**Key Characteristics**:
- **Client-side only** - No server-side protocol changes
- **Zero impact on ocserv-modern** - Purely diagnostic/logging functionality
- **Multi-module support** - Collects data from VPN, Umbrella, NVM, Posture, ISE
- **Cross-platform** - Windows, macOS, Linux implementations
- **Automated collection** - Runs external commands, parses logs, gathers system info

---

## Architecture Overview

### Components

| Component | Size | Type | Purpose |
|-----------|------|------|---------|
| **dartcli** | 3.9 MB | ELF executable | Command-line diagnostic tool |
| **dartui** | 1.3 MB | ELF executable | GUI diagnostic tool |
| **darthelper** | 1.1 MB | ELF executable | System helper daemon (elevated privileges) |
| **manifesttool_dart** | 267 KB | ELF executable | Manifest validation and management |

### Component Relationships

```
User Interface Layer:
  +-- dartui (GUI)
  +-- dartcli (CLI)
        |
        v
System Interface Layer:
  +-- darthelper (privileged operations)
        |
        v
Data Collection Layer:
  +-- Log collectors (journalctl, syslog, event logs)
  +-- System info gatherers (network, processes, files)
  +-- External command executors (custom scripts, tools)
        |
        v
Output Layer:
  +-- Archive generator (zip/tar.gz)
  +-- XML/JSON metadata
  +-- Structured directory trees
```

### Build Information

```
dartui:
  Type: ELF 64-bit LSB pie executable, x86-64
  Build: GNU/Linux 3.2.0
  BuildID: eb987b4e7d5138d2185df20e34ee5d8fbbfcc006
  Stripped: Yes
  PIE: Yes

dartcli:
  Type: ELF 64-bit LSB pie executable, x86-64
  Build: GNU/Linux 3.2.0
  BuildID: 574be29a3f03ebe8cc86740cc50ebfcdc4d166b5
  Stripped: Yes
  PIE: Yes

darthelper:
  Type: ELF 64-bit LSB pie executable, x86-64
  Build: GNU/Linux 3.2.0
  BuildID: df5be1619b6d54d44fe96a6631063409a8f635df
  Stripped: Yes
  PIE: Yes
```

---

## Functional Capabilities

### 1. Log Collection

#### Supported Log Sources (Linux)

##### System Logs
```xml
<use_extern_action>
    <action>
        <args>journalctl -S -1d -t csc_dartui -t csc_dartcli -t csc_darthelper</args>
        <clear_log apply="false"/>
        <stdout/>
        <temp_out>CiscoSecureClient-DART.log</temp_out>
    </action>
</use_extern_action>
```

**Collected**:
- Last 24 hours of DART component logs
- journald entries from csc_dartui, csc_dartcli, csc_darthelper
- Both human-readable and machine-parseable formats

##### Application Logs
```xml
<file_copy_action>
    <action>
        <loc>/opt/cisco/secureclient/dart/cisco-secure-client*-dart-*.log</loc>
        <clear_log apply="false"/>
    </action>
</file_copy_action>
```

**Collected**:
- Installation logs
- Runtime logs
- Error logs
- Debug logs (if enabled)

##### VPN Logs
- vpnagentd daemon logs
- Connection establishment logs
- Authentication logs
- Tunnel traffic logs
- Disconnect/error logs

##### Module-Specific Logs
- **Umbrella**: DNS filtering logs, roaming security events
- **Network Visibility**: Flow data, telemetry
- **Posture**: Assessment results, compliance checks
- **ISE Posture**: ISE integration logs, policy enforcement

#### Log Processing

**Actions**:
1. **Copy**: Direct file copy to DART archive
2. **Execute**: Run external command, capture stdout/stderr
3. **Parse**: Extract relevant sections from large log files
4. **Filter**: Apply regex/pattern matching
5. **Anonymize**: Remove sensitive data (optional)

**Clearing**:
- Optional log rotation after collection
- Can clear Windows Event Logs
- Can rotate journald entries
- Preserves original logs by default

---

### 2. System Information Gathering

#### Network Configuration

**Linux Collection**:
```bash
# Executed by darthelper
ip addr show
ip route show
ip -6 route show
ss -tunap
iptables -L -n -v
ip6tables -L -n -v
resolvconf -l
cat /etc/resolv.conf
```

**Collected Data**:
- Network interfaces and IP addresses
- Routing tables (IPv4 and IPv6)
- Active connections and listening ports
- Firewall rules
- DNS configuration
- Default gateway
- Interface statistics

#### System Information

**Linux Collection**:
```bash
uname -a
cat /etc/os-release
lsb_release -a
cat /proc/cpuinfo
cat /proc/meminfo
df -h
lsmod
systemctl status
```

**Collected Data**:
- Kernel version
- Distribution and version
- CPU information
- Memory usage
- Disk usage
- Loaded kernel modules
- Systemd service status

#### Process Information

**Linux Collection**:
```bash
ps aux
top -b -n 1
```

**Collected Data**:
- Running processes
- CPU and memory usage per process
- Cisco Secure Client process tree
- Resource consumption

---

### 3. Configuration Collection

#### Files Collected

**Linux Paths**:
```
/opt/cisco/secureclient/vpn/*.xml
/opt/cisco/secureclient/dart/*.xml
/opt/cisco/secureclient/umbrella/*.json
/opt/cisco/secureclient/nvm/*.conf
/opt/cisco/secureclient/posture/*.xml
~/.cisco/vpn/profile/*.xml
~/.cisco/vpn/preferences.xml
```

**Windows Paths** (for reference):
```
%PROGRAMDATA%\Cisco\Cisco Secure Client\*.xml
%APPDATA%\.cisco\vpn\*.xml
Registry: HKLM\SOFTWARE\Cisco\Cisco Secure Client
Registry: HKCU\SOFTWARE\Cisco\Cisco Secure Client
```

**Configurations Collected**:
- VPN profiles
- User preferences
- Module configurations
- Policy settings
- Certificate information
- Server lists

---

### 4. Crash Report Collection

#### Core Dumps and Crash Files

**Linux**:
```xml
<file_copy_action>
    <action>
        <loc gather_newest="true">/var/crash/*_vpnui.*</loc>
        <clear_log apply="false"/>
    </action>
</file_copy_action>
```

**Collected**:
- Core dumps from /var/crash
- Application crash reports
- Segmentation fault traces
- Stack traces (if available)

**Windows**:
- Minidumps (.mdmp files)
- Windows Error Reporting data
- Application event log errors

**macOS**:
- CrashReporter logs
- DiagnosticReports

---

### 5. Module-Specific Diagnostics

#### VPN Module

**Data Collected**:
```xml
<fileGroup treeRootName="Cisco Secure Client" directoryName="Cisco Secure Client\VPN">
    <title>VPN</title>
    <file id="csc-vpn-logs">
        <description>VPN daemon logs</description>
        <!-- Collects vpnagentd logs, connection history, errors -->
    </file>
</fileGroup>
```

**Includes**:
- Connection logs (successful and failed)
- Authentication attempts
- Tunnel establishment
- DTLS negotiation
- Rekey events
- Disconnect reasons
- Certificate validation logs

#### Umbrella Module

**Data Collected**:
```xml
<fileGroup directoryName="Cisco Secure Client\Umbrella">
    <file id="csc-umbrella-logs">
        <description>Umbrella application logs</description>
        <!-- DNS filtering, roaming security -->
    </file>
</fileGroup>
```

**Includes**:
- DNS query logs
- Policy enforcement logs
- Cloud lookup results
- Local domain whitelist
- SWG (Secure Web Gateway) logs
- OrgInfo.json (organization configuration)
- Umbrella roaming security events

#### Network Visibility Module (NVM)

**Data Collected**:
- Flow telemetry
- Application identification logs
- Socket filter API logs
- Network monitoring data
- Bandwidth usage statistics

#### ISE Posture Module

**Data Collected**:
```xml
<file id="csc-iseposture-logs">
    <description>ISE Posture assessment logs</description>
</file>
```

**Includes**:
- Posture assessment results
- Compliance check logs
- Remediation actions
- ISE server communication logs
- Policy enforcement events

---

## XML Configuration Schema

### DART.xml Structure

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<configure xmlns="http://schemas.xmlsoap.org/encoding/"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ ConfigXMLSchema.xsd">

    <fileGroup treeRootName="..." directoryName="...">
        <title>Module Name</title>

        <file id="unique-id" directoryName="optional-subdir">
            <default>true|false</default>
            <description>Human-readable description</description>

            <gui>
                <label>_tr("Translated Label")</label>
                <file_type>log|config|dump</file_type>
            </gui>

            <dart>
                <required>true|false</required>

                <os opsys="linux|win|mac">
                    <!-- Collection actions -->
                    <file_copy_action>...</file_copy_action>
                    <use_extern_action>...</use_extern_action>
                    <directory_copy_action>...</directory_copy_action>
                </os>
            </dart>
        </file>
    </fileGroup>
</configure>
```

### Action Types

#### file_copy_action
**Purpose**: Copy specific files to DART archive

```xml
<file_copy_action>
    <action>
        <loc>/path/to/file.log</loc>
        <loc gather_newest="true">pattern*.log</loc>
        <clear_log apply="true|false"/>
    </action>
</file_copy_action>
```

**Attributes**:
- `loc`: File path or glob pattern
- `gather_newest`: Only collect most recent matching file
- `clear_log`: Rotate/clear after collection

#### use_extern_action
**Purpose**: Execute external command, capture output

```xml
<use_extern_action>
    <action>
        <path>/usr/bin</path>
        <plugin/>  <!-- Use built-in DART plugin -->
        <args>command arguments</args>
        <clear_log apply="false"/>
        <stdout/>
        <temp_out>output_filename.log</temp_out>
    </action>
</use_extern_action>
```

**Attributes**:
- `path`: Directory containing executable
- `plugin`: Use DART built-in command
- `args`: Command-line arguments
- `stdout`: Capture standard output
- `temp_out`: Filename in DART archive

#### directory_copy_action
**Purpose**: Copy entire directory or matching files

```xml
<directory_copy_action>
    <action>
        <loc>/path/to/directory</loc>
        <pattern>*.xml</pattern>
        <pattern>*.json</pattern>
    </action>
</directory_copy_action>
```

**Attributes**:
- `loc`: Directory path
- `pattern`: File patterns to include (multiple allowed)

---

## Operation Modes

### 1. GUI Mode (dartui)

**Purpose**: User-initiated diagnostic collection

**Features**:
- Interactive file selection
- Progress indicators
- Error reporting
- Archive preview
- Custom output location
- Module selection (checkboxes)

**User Flow**:
```
1. Launch dartui
2. Select modules to collect (VPN, Umbrella, NVM, Posture)
3. Choose collection options:
   - Include system info
   - Include crash dumps
   - Clear logs after collection
4. Set output location
5. Click "Collect"
6. View progress
7. Save archive
8. Optional: Upload to support
```

### 2. CLI Mode (dartcli)

**Purpose**: Automated or scripted diagnostic collection

**Usage**:
```bash
# Collect all diagnostics
dartcli --all --output=/tmp/dart-report.tar.gz

# Collect specific module
dartcli --module=vpn --output=vpn-diagnostics.tar.gz

# Collect with custom config
dartcli --config=/path/to/custom-dart.xml --output=custom.tar.gz

# Collect and upload
dartcli --all --upload-to=support.cisco.com

# List available collections
dartcli --list-modules
```

**Command-Line Options** (inferred):
```
--all                    Collect all available diagnostics
--module=<name>          Collect specific module (vpn|umbrella|nvm|posture|ise)
--output=<path>          Output archive path
--config=<xml>           Custom DART configuration
--upload-to=<url>        Automatically upload after collection
--list-modules           Show available modules
--no-clear               Don't clear logs after collection
--include-system         Include system information
--include-dumps          Include crash dumps
--verbose                Verbose output
--quiet                  Suppress output
--help                   Show help message
```

### 3. Helper Mode (darthelper)

**Purpose**: Privileged operations requiring root/admin

**Runs as**:
- Service/daemon with elevated privileges
- D-Bus service (Linux)
- Windows service
- macOS launchd agent

**Responsibilities**:
- Execute privileged commands (iptables, journalctl)
- Access system logs
- Read protected files
- Collect network configuration
- Query system information

**Security**:
- Runs with minimal necessary privileges
- Validates requests from dartui/dartcli
- Sanitizes command arguments
- Logs all operations

---

## Output Format

### Archive Structure

```
DART_Report_YYYY-MM-DD_HH-MM-SS/
├── manifest.xml                           # Collection metadata
├── system_info.txt                        # System information summary
├── Cisco Secure Client/
│   ├── VPN/
│   │   ├── Logs/
│   │   │   ├── vpnagentd.log
│   │   │   ├── vpn_connection_history.xml
│   │   │   └── vpn_errors.log
│   │   ├── Configuration/
│   │   │   ├── profile_*.xml
│   │   │   └── preferences.xml
│   │   └── Crash Reports/
│   │       └── vpnagentd_*.core
│   ├── Umbrella/
│   │   ├── Logs/
│   │   │   ├── Umbrella.log
│   │   │   └── Umbrella_SWG.log
│   │   ├── Profiles/
│   │   │   ├── OrgInfo.json
│   │   │   └── SWGConfig.json
│   │   └── regionaldata/
│   │       └── Config.json
│   ├── Network Visibility/
│   │   └── Logs/
│   │       └── nvm_telemetry.log
│   ├── Posture/
│   │   └── Logs/
│   │       └── posture_assessment.log
│   ├── ISE Posture/
│   │   └── Logs/
│   │       └── ise_posture.log
│   ├── User Interface/
│   │   ├── Logs/
│   │   │   ├── UIHistory_*.txt
│   │   │   └── csc_ui.log
│   │   └── l10n/                          # Localization files
│   └── DART/
│       └── Logs/
│           └── CiscoSecureClient-DART.log
├── System/
│   ├── network_config.txt
│   ├── routing_tables.txt
│   ├── dns_config.txt
│   ├── firewall_rules.txt
│   ├── processes.txt
│   └── system_info.txt
└── Legacy - Cisco AnyConnect Secure Mobility Client/
    └── ... (if legacy components present)
```

### Manifest File

**manifest.xml**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<dart-manifest>
    <collection-info>
        <timestamp>2025-10-29T15:30:00Z</timestamp>
        <client-version>5.1.12.146</client-version>
        <os>Linux</os>
        <os-version>Ubuntu 22.04.3 LTS</os-version>
        <hostname>client-workstation</hostname>
        <username>jdoe</username>
    </collection-info>

    <modules>
        <module name="vpn" collected="true" />
        <module name="umbrella" collected="false" />
        <module name="nvm" collected="true" />
        <module name="posture" collected="true" />
        <module name="ise" collected="true" />
    </modules>

    <files>
        <file path="Cisco Secure Client/VPN/Logs/vpnagentd.log" size="1048576" />
        <!-- ... -->
    </files>

    <errors>
        <!-- Any collection errors -->
    </errors>
</dart-manifest>
```

### Archive Formats

| Platform | Format | Compression |
|----------|--------|-------------|
| Linux | .tar.gz | gzip |
| Windows | .zip | DEFLATE |
| macOS | .tar.gz | gzip |

---

## Error Handling

### Error Codes (from strings analysis)

```cpp
DARTENGINE_SUCCESS
DARTENGINE_ERROR_NOT_IMPLEMENTED
DARTENGINE_ERROR_BAD_PARAMETER
DARTENGINE_ERROR_BAD_HANDLE
DARTENGINE_ERROR_MEMALLOC_FAILED
DARTENGINE_ERROR_NULL_POINTER
DARTENGINE_ERROR_INSUFFICIENT_BUFFER
DARTENGINE_ERROR_NOT_INITIALIZED
DARTENGINE_ERROR_ALREADY_INITIALIZED
DARTENGINE_ERROR_UNEXPECTED
DARTENGINE_ERROR_INTERNAL: "Error: DART encountered an unspecified internal error"
DARTENGINE_ERROR_WRITE_FAILURE: "Error: Failed to write to file"
DARTENGINE_ERROR_FILE_NOT_FOUND: "Error: File not found"
DARTENGINE_ERROR_FILE_OPEN_FAILURE: "Error: File could not be opened"
DARTENGINE_ERROR_ACCESS_DENIED: "Error: Access denied"
DARTENGINE_ERROR_NULL_XML_ROOT: "Error: XML configuration tree root is NULL"
DARTENGINE_ERROR_NULL_XML_CHILD: "Error: XML configuration tree child is NULL"
DARTENGINE_ERROR_INVALID_XML: "Error: Encountered invalid XML configuration tree"
DARTENGINE_ERROR_UNKNOWN_XML_TAG: "Error: Encountered unknown XML configuration tag"
DARTENGINE_ERROR_ACTION_CANCELED_BY_USER: "Notice: Action canceled by user"
DARTENGINE_ERROR_EXTERN_ACTION_TIMEOUT: "Error: Binary executable took too long to finish."
DARTENGINE_ERROR_UNKNOWN
```

### Error Recovery

**Strategy**:
1. **Skip failed collection**: Continue with other modules
2. **Log error**: Record in manifest.xml
3. **Partial archive**: Create archive with successfully collected data
4. **User notification**: Display errors in GUI, log in CLI

**Example**:
```
WARNING: Failed to collect Umbrella logs (module not installed)
Continuing with VPN log collection...
```

---

## Security Considerations

### 1. Sensitive Data Protection

**Default Behavior**:
- Passwords: Not collected
- Private keys: Not collected
- Cookies/session tokens: Not collected
- User credentials: Redacted

**Anonymization** (optional):
- IP addresses: Can be anonymized
- Hostnames: Can be replaced with placeholders
- Usernames: Can be redacted
- Certificate details: Can be obfuscated

### 2. Privilege Management

**darthelper Privileges**:
- Runs as root/SYSTEM/admin
- Uses D-Bus policy for access control (Linux)
- Validates caller identity
- Restricts allowed commands

**D-Bus Policy Example** (Linux):
```xml
<!-- com.cisco.secureclient.dart.policy -->
<policy user="root">
    <allow send_destination="com.cisco.secureclient.dart"/>
</policy>
<policy user="*">
    <deny send_destination="com.cisco.secureclient.dart"/>
</policy>
```

### 3. Data Privacy

**User Consent**:
- Displays list of collected data before collection
- Allows user to select/deselect modules
- Warns about potentially sensitive information

**Storage**:
- Archives stored in user-controlled location
- No automatic upload to Cisco without user consent
- User can review archive before sharing

### 4. Command Injection Prevention

**Validation**:
- All external command arguments sanitized
- No shell expansion
- Whitelist of allowed commands
- Path validation

**Example** (pseudocode):
```cpp
bool validate_extern_action(const std::string& command) {
    // Whitelist of allowed commands
    static const std::set<std::string> allowed = {
        "journalctl", "ip", "ss", "iptables",
        "ps", "top", "df", "uname"
    };

    // Extract command name
    std::string cmd = extract_command(command);

    // Check whitelist
    if (allowed.find(cmd) == allowed.end()) {
        return false;
    }

    // Validate arguments (no shell metacharacters)
    if (contains_shell_metacharacters(command)) {
        return false;
    }

    return true;
}
```

---

## Integration with Other Modules

### 1. VPN Module Integration

**Log Collection**:
- Monitors vpnagentd daemon logs
- Collects connection history
- Includes authentication logs
- Captures tunnel establishment logs

**Event Triggering**:
- Can be triggered on VPN disconnect
- Automatic collection on errors
- Periodic collection (if configured)

### 2. Umbrella Integration

**Data Collected**:
- DNS query logs
- Policy enforcement events
- Cloud lookup results
- Roaming security logs

**Configuration**:
- OrgInfo.json
- SWGConfig.json
- Local domain whitelist

### 3. Network Visibility Integration

**Telemetry Data**:
- Flow records
- Application identification
- Bandwidth usage
- Protocol analysis

**Logs**:
- NVM daemon logs
- Socket filter API logs
- Telemetry upload logs

### 4. Posture Integration

**Assessment Data**:
- Posture check results
- Compliance status
- Remediation actions
- Policy enforcement

**Logs**:
- Legacy posture (CSD) logs
- ISE posture logs
- Host scan results

---

## Installation and Configuration

### Linux Installation

**Files Installed**:
```
/opt/cisco/secureclient/dart/
├── dartcli                                # CLI tool
├── dartui                                 # GUI tool
├── darthelper                             # Helper daemon
├── manifesttool_dart                      # Manifest tool
├── dart_install.sh                        # Installation script
├── dart_uninstall.sh                      # Uninstallation script
├── DART.xml                               # DART config
├── SecureClientUIConfig.xml               # UI config
├── Umbrella.xml                           # Umbrella config
├── NetworkVisibility.xml                  # NVM config
├── ISEPosture.xml                         # ISE config
├── Posture.xml                            # Posture config
├── BaseConfig.xml                         # Base config
├── ConfigXMLSchema.xsd                    # Schema definition
├── RequestXMLSchema.xsd                   # Request schema
├── com.cisco.secureclient.dart.conf       # D-Bus config
├── com.cisco.secureclient.dart.desktop    # Desktop entry
├── com.cisco.secureclient.dart.helper.service  # Systemd service
├── com.cisco.secureclient.dart.policy     # Polkit policy
└── resources/                             # Icons, UI resources
```

**Systemd Service**:
```ini
# /etc/systemd/system/com.cisco.secureclient.dart.helper.service
[Unit]
Description=Cisco Secure Client DART Helper
After=network.target

[Service]
Type=dbus
BusName=com.cisco.secureclient.dart
ExecStart=/opt/cisco/secureclient/dart/darthelper
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

**D-Bus Configuration**:
```xml
<!-- /etc/dbus-1/system.d/com.cisco.secureclient.dart.conf -->
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
    <policy user="root">
        <allow own="com.cisco.secureclient.dart"/>
        <allow send_destination="com.cisco.secureclient.dart"/>
    </policy>
    <policy context="default">
        <deny send_destination="com.cisco.secureclient.dart"/>
    </policy>
</busconfig>
```

### Installation Script

**dart_install.sh** (simplified):
```bash
#!/bin/bash

INSTALL_ROOT=/opt/cisco/secureclient/dart

# Copy binaries
install -m 755 dartcli "${INSTALL_ROOT}/"
install -m 755 dartui "${INSTALL_ROOT}/"
install -m 755 darthelper "${INSTALL_ROOT}/"
install -m 755 manifesttool_dart "${INSTALL_ROOT}/"

# Copy configuration
install -m 644 *.xml "${INSTALL_ROOT}/"
install -m 644 *.xsd "${INSTALL_ROOT}/"

# Install D-Bus service
install -m 644 com.cisco.secureclient.dart.conf /etc/dbus-1/system.d/
install -m 644 com.cisco.secureclient.dart.helper.service /etc/systemd/system/

# Install desktop entry
install -m 644 com.cisco.secureclient.dart.desktop /usr/share/applications/

# Reload systemd and D-Bus
systemctl daemon-reload
systemctl restart dbus

# Enable and start helper service
systemctl enable com.cisco.secureclient.dart.helper.service
systemctl start com.cisco.secureclient.dart.helper.service

echo "DART installation complete"
```

---

## Usage Examples

### Example 1: Collect VPN Diagnostics

**CLI**:
```bash
# Collect only VPN module diagnostics
$ dartcli --module=vpn --output=~/vpn-issue-$(date +%Y%m%d).tar.gz

Cisco Secure Client DART CLI v5.1.12.146
Collecting VPN diagnostics...

[1/5] Collecting VPN daemon logs... OK
[2/5] Collecting connection history... OK
[3/5] Collecting configuration files... OK
[4/5] Collecting network information... OK
[5/5] Creating archive... OK

Report saved to: /home/user/vpn-issue-20251029.tar.gz
Size: 2.4 MB
```

### Example 2: Full System Diagnostic

**CLI**:
```bash
# Collect everything
$ sudo dartcli --all --include-system --include-dumps \
    --output=/var/tmp/full-diagnostic.tar.gz

Cisco Secure Client DART CLI v5.1.12.146
Collecting full system diagnostics...

Modules:
[+] VPN
[+] Umbrella
[+] Network Visibility
[+] Posture
[+] ISE Posture
[+] System Information
[+] Crash Dumps

Collection started at 2025-10-29 15:30:00

[VPN]
  Collecting logs........................ OK (1.2 MB)
  Collecting configs..................... OK (45 KB)
  Collecting crash dumps................. OK (512 KB)

[Umbrella]
  Module not installed, skipping......... SKIP

[Network Visibility]
  Collecting telemetry data.............. OK (234 KB)
  Collecting flow logs................... OK (1.1 MB)

[Posture]
  Collecting assessment logs............. OK (89 KB)

[ISE Posture]
  Collecting ISE logs.................... OK (156 KB)

[System]
  Collecting network config.............. OK
  Collecting routing tables.............. OK
  Collecting firewall rules.............. OK
  Collecting process list................ OK
  Collecting system info................. OK

Creating archive......................... OK

Report saved to: /var/tmp/full-diagnostic.tar.gz
Size: 8.7 MB
Elapsed time: 12 seconds

To upload: dartcli --upload-report=/var/tmp/full-diagnostic.tar.gz
```

### Example 3: GUI Collection

**Steps**:
1. Launch DART GUI: `dartui` or click desktop icon
2. Select modules to collect (checkboxes)
3. Choose options:
   - [x] Include system information
   - [x] Include crash dumps
   - [ ] Clear logs after collection
4. Click "Collect Diagnostics"
5. Progress bar shows collection status
6. Save dialog appears when complete
7. Choose save location
8. Optional: Click "Upload to Support"

---

## Implementation Notes for ocserv-modern

### Impact Assessment

**Server Impact**: **NONE**

DART is entirely client-side and has zero impact on ocserv-modern:
- No protocol changes
- No server-side DART support needed
- No new authentication methods
- No new headers or requests
- No server configuration changes required

### Recommendations

#### 1. Documentation Update

**Add to ocserv-modern troubleshooting guide**:

```markdown
## Collecting Client Diagnostics

Cisco Secure Client 5.1.12.146 and later include DART (Diagnostics and
Reporting Tool) for automated log collection.

### GUI Collection
1. Launch Cisco Secure Client
2. Open DART (Tools → Diagnostics → Collect Logs)
3. Select modules to collect
4. Save diagnostic archive

### CLI Collection
```bash
dartcli --module=vpn --output=vpn-diagnostics.tar.gz
```

### Submitting Diagnostics
When reporting issues with ocserv-modern:
1. Collect DART report
2. Attach to bug report
3. Include server logs separately
```

#### 2. Support Process Integration

**When users report VPN issues**:
1. Ask them to run DART collection
2. Request the DART archive
3. Analyze client-side logs from archive
4. Correlate with server-side logs

**Benefits**:
- Faster troubleshooting
- Complete client-side picture
- Reduced back-and-forth with users

#### 3. Testing Considerations

**No special testing needed**:
- DART doesn't affect VPN functionality
- No protocol changes to test
- Client-side logging only

**Optional**:
- Test that DART-collected clients still connect
- Verify no performance impact from DART daemon
- Confirm helper service doesn't interfere

---

## Troubleshooting DART

### Common Issues

#### Issue 1: darthelper Service Not Running

**Symptoms**:
- DART collection fails
- "Access denied" errors
- System information not collected

**Diagnosis**:
```bash
systemctl status com.cisco.secureclient.dart.helper.service
journalctl -u com.cisco.secureclient.dart.helper.service -n 50
```

**Fix**:
```bash
sudo systemctl restart com.cisco.secureclient.dart.helper.service
sudo systemctl enable com.cisco.secureclient.dart.helper.service
```

#### Issue 2: D-Bus Permission Denied

**Symptoms**:
- "Could not connect to DART helper"
- D-Bus errors in logs

**Diagnosis**:
```bash
dbus-send --system --dest=com.cisco.secureclient.dart \
  --type=method_call --print-reply /com/cisco/secureclient/dart \
  org.freedesktop.DBus.Introspectable.Introspect
```

**Fix**:
```bash
# Check D-Bus policy
cat /etc/dbus-1/system.d/com.cisco.secureclient.dart.conf

# Restart D-Bus
sudo systemctl restart dbus
```

#### Issue 3: Incomplete Collection

**Symptoms**:
- Some modules missing from archive
- Partial log files
- "Collection errors" in manifest

**Diagnosis**:
- Check manifest.xml in archive
- Review DART logs
- Check file permissions

**Fix**:
- Ensure modules are installed
- Check disk space
- Verify file permissions
- Run with sudo if needed

---

## Security Audit Notes

### Potential Concerns

#### 1. Privileged Daemon (darthelper)

**Risk**: Runs as root, could be attack vector

**Mitigations**:
- D-Bus policy restricts access
- Command whitelist prevents arbitrary execution
- Input validation on all arguments
- Audit logging of all actions

**Recommendation**: Monitor darthelper logs, ensure D-Bus policy is restrictive

#### 2. Sensitive Data Collection

**Risk**: May collect passwords, keys, or PII

**Mitigations**:
- Default config excludes sensitive files
- User controls what to collect
- No automatic upload
- Can anonymize data

**Recommendation**: Review collected data before sharing

#### 3. External Command Execution

**Risk**: Command injection vulnerabilities

**Mitigations**:
- Whitelist of allowed commands
- No shell expansion
- Argument sanitization
- Path validation

**Recommendation**: Keep DART updated for security fixes

---

## Version History

| Version | Changes |
|---------|---------|
| 5.1.12.146 | Initial DART release |

---

## References

### Configuration Files Analyzed
- `/opt/projects/repositories/cisco-secure-client/5.1.12.146/extracted/linux64/cisco-secure-client-linux64-5.1.12.146/dart/DART.xml`
- `/opt/projects/repositories/cisco-secure-client/5.1.12.146/extracted/linux64/cisco-secure-client-linux64-5.1.12.146/dart/SecureClientUIConfig.xml`
- `/opt/projects/repositories/cisco-secure-client/5.1.12.146/extracted/linux64/cisco-secure-client-linux64-5.1.12.146/dart/Umbrella.xml`
- `/opt/projects/repositories/cisco-secure-client/5.1.12.146/extracted/linux64/cisco-secure-client-linux64-5.1.12.146/dart/NetworkVisibility.xml`
- `/opt/projects/repositories/cisco-secure-client/5.1.12.146/extracted/linux64/cisco-secure-client-linux64-5.1.12.146/dart/ISEPosture.xml`

### Binary Analysis
- dartcli: `/opt/projects/repositories/cisco-secure-client/5.1.12.146/extracted/linux64/cisco-secure-client-linux64-5.1.12.146/dart/dartcli`
- dartui: `/opt/projects/repositories/cisco-secure-client/5.1.12.146/extracted/linux64/cisco-secure-client-linux64-5.1.12.146/dart/dartui`
- darthelper: `/opt/projects/repositories/cisco-secure-client/5.1.12.146/extracted/linux64/cisco-secure-client-linux64-5.1.12.146/dart/darthelper`

### Related Documentation
- VERSION_COMPARISON_5.1.2_vs_5.1.12.md

---

**END OF DOCUMENT**
