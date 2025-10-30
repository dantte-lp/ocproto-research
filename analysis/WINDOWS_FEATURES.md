# Cisco Secure Client 5.1.2.42 - Windows-Specific Features Analysis

**Analysis Date:** 2025-10-29
**Target Version:** Cisco Secure Client 5.1.2.42
**Platform:** Windows (x86/x64/ARM64)
**Purpose:** Cross-platform ocserv understanding and Linux/macOS equivalent implementations

---

## Executive Summary

This document analyzes Windows-specific features of Cisco Secure Client 5.1.2.42, focusing on:

1. **Start-Before-Logon (SBL)** - VPN establishment before Windows user login
2. **Management Tunnel** - Always-on administrative connectivity separate from user tunnel
3. **Credential Provider Integration** - Deep Windows authentication integration
4. **Windows Service Architecture** - Multi-service daemon structure
5. **Registry Configuration** - System-level settings and policies
6. **Network Provider Order** - Windows networking stack integration

While these features are Windows-specific, understanding their architecture helps design equivalent capabilities for Linux/macOS ocserv implementations.

---

## 1. Start-Before-Logon (SBL)

### 1.1 Feature Overview

**Start-Before-Logon** allows the VPN connection to be established **before** a user logs into Windows, enabling:
- **Domain authentication** over VPN
- **Group Policy** application before logon
- **Roaming profile** access
- **Remote desktop** to machines without local accounts

### 1.2 Discovery from Reverse Engineering

#### String Evidence:

```c
// From libvpnapi.so (Linux build includes Windows logic)
"Exiting. Bypassing start before logon."
"The requested authentication type is not supported during Start Before Logon."
"Start VPN before user logon to computer"
"UseStartBeforeLogon"
"The user may not accept server certificate when in start before logon"

// From vpnagentd
"Start Before Logon Component"
```

#### XML Profile Configuration:

```xml
<UseStartBeforeLogon UserControllable="true">true</UseStartBeforeLogon>
<WindowsLogonEnforcement>SingleLogon</WindowsLogonEnforcement>
<WindowsVPNEstablishment>LocalUsersOnly</WindowsVPNEstablishment>
```

**Options:**
- `UseStartBeforeLogon`: Enable/disable SBL
- `WindowsLogonEnforcement`:
  - `SingleLogon` - Only one user logged in at a time
  - `SingleLocalLogon` - Only local users
  - `SingleLogonNoRemote` - No remote desktop sessions
- `WindowsVPNEstablishment`:
  - `LocalUsersOnly` - Only establish VPN for local accounts
  - `AllUsers` - Establish for domain and local accounts

### 1.3 Windows Architecture

```
┌────────────────────────────────────────────────────────────┐
│              Windows Boot Sequence with SBL                │
└────────────────────────────────────────────────────────────┘

1. Windows Boot
   ↓
2. Network Drivers Load
   ↓
3. vpnagentd Service Starts (System context)
   ↓
4. SBL Triggers VPN Connection
   ├─ Read cached credentials (encrypted)
   ├─ Establish VPN tunnel
   └─ Wait for connection success
   ↓
5. Winlogon.exe Loads
   ↓
6. Credential Provider UI (acwincredprov.dll)
   ├─ Shows VPN status
   ├─ Allows manual disconnect
   └─ Passes credentials to Windows
   ↓
7. User Authentication (over VPN)
   ├─ Domain Controller contacted via VPN
   └─ Kerberos/NTLM auth
   ↓
8. User Session Starts
   ├─ Group Policy applied (from DC over VPN)
   └─ Roaming profile downloaded (over VPN)
```

### 1.4 Windows Components

#### A. Credential Provider (acwincredprov.dll)

**Purpose:** Replace or augment Windows default credential provider

**Functions:**
- Display VPN connection status at logon screen
- Show "Connect" button for manual VPN initiation
- Pass credentials securely to VPN agent
- Coordinate with Winlogon for seamless auth

**Registry Key:**
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\
{Cisco-GUID-Here}
```

#### B. GINA (Legacy Windows XP/2000)

**Note:** GINA (Graphical Identification and Authentication) is **deprecated** since Windows Vista. Cisco likely still ships GINA for legacy support.

**File:** `acgina.dll`

**Replacement:** Credential Provider architecture (Vista+)

#### C. VPN Service (vpnagentd.exe / vpnagent.exe)

**Service Name:** `vpnagent`
**Display Name:** `Cisco Secure Client Agent`
**Start Type:** Automatic (Delayed Start)
**Account:** Local System

**Responsibilities:**
- Start VPN connection before user logon
- Manage tunnel lifecycle
- Communicate with credential provider
- Store encrypted credentials for auto-connect

### 1.5 Start-Before-Logon Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Windows SBL Flow                         │
└─────────────────────────────────────────────────────────────┘

[System Boot]
     |
     v
[vpnagentd.exe starts as SYSTEM]
     |
     v
[Check SBL policy from profile XML]
     |
     +---> [SBL disabled] ──> [Wait for user logon]
     |
     +---> [SBL enabled]
           |
           v
     [Load cached credentials]
     (Encrypted with DPAPI + machine key)
           |
           v
     [Establish VPN connection]
     ├─ HTTPS to VPN gateway
     ├─ AggAuth XML (if configured)
     ├─ Certificate auth (machine cert)
     └─ DTLS tunnel setup
           |
           v
     [VPN Connected - Network Routes Applied]
           |
           v
     [Signal Winlogon: Network Ready]
           |
           v
     [Winlogon displays credential provider]
     [acwincredprov.dll shows VPN status]
           |
           v
     [User enters credentials]
           |
           v
     [Credential provider passes creds to:]
     ├─ Windows (for local/domain auth)
     └─ vpnagentd (for VPN session binding)
           |
           v
     [Domain Controller authenticates user over VPN]
           |
           v
     [Windows logon succeeds]
     [VPN tunnel persists for user session]
```

### 1.6 Credential Storage and Encryption

**Windows DPAPI (Data Protection API):**

```c
// Pseudocode from reverse engineering
// Cisco uses DPAPI for credential encryption

typedef struct {
    uint8_t encrypted_username[256];
    uint8_t encrypted_password[256];
    uint8_t encrypted_domain[128];
    DWORD encryption_flags;  // CRYPTPROTECT_LOCAL_MACHINE
    GUID machine_guid;       // Bind to specific machine
} cached_credentials_t;

// Storage location (Windows Registry)
HKLM\SOFTWARE\Cisco\Cisco Secure Client\VPN\CachedCredentials

// Encryption uses:
// - Machine-specific key (hardware-bound)
// - Local System account context
// - No user-specific encryption (must work before user logon)
```

### 1.7 Linux/macOS Equivalent

**Challenge:** Linux/macOS lack direct SBL equivalent because:
- No "credential provider" architecture
- Different authentication flows (PAM, etc.)
- No pre-login network access standard

**Possible Approaches:**

#### A. Linux PAM Module

```
┌────────────────────────────────────────────────────┐
│    Linux Start-Before-Logon Equivalent             │
└────────────────────────────────────────────────────┘

[GDM/LightDM Display Manager Starts]
     |
     v
[Custom PAM module: pam_ocserv_preauth.so]
     |
     v
[Check if VPN should be established]
├─ Read /etc/ocserv/preauth.conf
├─ Load machine certificate
└─ Check network availability
     |
     v
[Establish VPN connection]
├─ Use machine certificate auth
├─ openconnect --background
└─ Wait for tun0 interface
     |
     v
[VPN Connected - Signal PAM success]
     |
     v
[Display Manager shows login screen]
[Show VPN status indicator]
     |
     v
[User authenticates]
[VPN tunnel remains for session]
```

#### B. macOS LaunchDaemon

```xml
<!-- /Library/LaunchDaemons/com.example.vpn.preauth.plist -->
<dict>
    <key>Label</key>
    <string>com.example.vpn.preauth</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/vpn-preauth</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StartInterval</key>
    <integer>0</integer>  <!-- Run once at boot -->
</dict>
```

### 1.8 C23 Implementation Concept (Linux PAM Module)

```c
// File: pam_ocserv_preauth.c
// Linux PAM module for pre-authentication VPN
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdbool.h>

typedef struct {
    char vpn_server[256];
    char machine_cert_path[512];
    char ca_cert_path[512];
    bool require_vpn;
    uint32_t connection_timeout;
} preauth_config_t;

/**
 * Load configuration from /etc/ocserv/preauth.conf
 */
[[nodiscard]]
static int load_preauth_config(preauth_config_t *config) {
    if (config == nullptr) {
        return -1;
    }

    FILE *fp = fopen("/etc/ocserv/preauth.conf", "r");
    if (fp == nullptr) {
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp) != nullptr) {
        // Parse key=value
        char *equals = strchr(line, '=');
        if (equals != nullptr) {
            *equals = '\0';
            const char *key = line;
            const char *value = equals + 1;

            // Trim newline
            value[strcspn(value, "\n")] = '\0';

            if (strcmp(key, "vpn_server") == 0) {
                strncpy(config->vpn_server, value, sizeof(config->vpn_server) - 1);
            } else if (strcmp(key, "machine_cert") == 0) {
                strncpy(config->machine_cert_path, value, sizeof(config->machine_cert_path) - 1);
            } else if (strcmp(key, "ca_cert") == 0) {
                strncpy(config->ca_cert_path, value, sizeof(config->ca_cert_path) - 1);
            } else if (strcmp(key, "require_vpn") == 0) {
                config->require_vpn = (strcmp(value, "true") == 0);
            } else if (strcmp(key, "timeout") == 0) {
                config->connection_timeout = atoi(value);
            }
        }
    }

    fclose(fp);
    return 0;
}

/**
 * Establish VPN connection using openconnect
 */
[[nodiscard]]
static int establish_preauth_vpn(const preauth_config_t *config) {
    if (config == nullptr || config->vpn_server[0] == '\0') {
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Child process: exec openconnect
        char *args[] = {
            "/usr/sbin/openconnect",
            "--background",
            "--certificate", (char *)config->machine_cert_path,
            "--cafile", (char *)config->ca_cert_path,
            "--non-inter",
            "--protocol", "anyconnect",
            (char *)config->vpn_server,
            nullptr
        };

        execv(args[0], args);
        _exit(1);  // exec failed
    } else if (pid > 0) {
        // Parent: wait for connection with timeout
        int status;
        struct timespec timeout = {
            .tv_sec = config->connection_timeout,
            .tv_nsec = 0
        };

        // Wait for child to establish connection
        // In real implementation, check for tun0 interface up
        sleep(config->connection_timeout);

        // Check if VPN interface exists
        if (access("/sys/class/net/tun0", F_OK) == 0) {
            return 0;  // VPN connected
        }

        return -1;  // Connection failed
    }

    return -1;
}

/**
 * PAM authentication handler
 */
PAM_EXTERN int pam_sm_authenticate(
    pam_handle_t *pamh,
    int flags,
    int argc,
    const char **argv
) {
    preauth_config_t config = {0};

    // Load configuration
    if (load_preauth_config(&config) != 0) {
        pam_syslog(pamh, LOG_ERR, "Failed to load preauth configuration");
        return PAM_IGNORE;  // Don't block login
    }

    // Establish VPN if required
    if (config.require_vpn) {
        pam_syslog(pamh, LOG_INFO, "Establishing pre-authentication VPN to %s",
                   config.vpn_server);

        if (establish_preauth_vpn(&config) != 0) {
            pam_syslog(pamh, LOG_ERR, "Failed to establish VPN connection");
            return PAM_AUTH_ERR;  // Block login if VPN required
        }

        pam_syslog(pamh, LOG_INFO, "VPN connection established successfully");
    }

    return PAM_SUCCESS;
}

// Other required PAM functions
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
```

---

## 2. Management Tunnel

### 2.1 Feature Overview

The **Management Tunnel** is a separate, always-on VPN tunnel that:
- Establishes **before** the user tunnel
- Provides **limited** network access (management only)
- Remains active **even if user disconnects**
- Used for **MDM**, **compliance checks**, **software updates**

### 2.2 Discovery from Reverse Engineering

#### String Evidence:

```c
// From vpnagentd
"CNotifyAgentPreTunnelTlv"  // "PreTunnel" = Management Tunnel
"SetHostRequiresProxyWithAlwaysOn"
"SetHostMightRequireProxyWithAlwaysOn"
"enforceSingleAlwaysOnProfile"
"GetAlwaysOnPreferences"
"SetAlwaysOnVPN"

// Connection types
enum ALWAYS_ON_VPN {
    ALWAYS_ON_DISABLED,
    ALWAYS_ON_MANAGEMENT_ONLY,
    ALWAYS_ON_FULL_TUNNEL
};
```

### 2.3 Management Tunnel Architecture

```
┌────────────────────────────────────────────────────────┐
│         Cisco Secure Client - Dual Tunnel              │
└────────────────────────────────────────────────────────┘

┌─────────────────────────────────────┐
│      vpnagentd (Service)            │
│  ┌───────────────────────────────┐  │
│  │   Management Tunnel           │  │
│  │   (Always-On)                 │  │
│  │  ┌─────────────────────────┐  │  │
│  │  │ tun0 / cscotun0         │  │  │
│  │  │ Limited routes:         │  │  │
│  │  │  - MDM server           │  │  │
│  │  │  - Update server        │  │  │
│  │  │  - Compliance server    │  │  │
│  │  └─────────────────────────┘  │  │
│  └───────────────────────────────┘  │
│                                      │
│  ┌───────────────────────────────┐  │
│  │   User Tunnel                 │  │
│  │   (On-Demand)                 │  │
│  │  ┌─────────────────────────┐  │  │
│  │  │ tun1 / cscotun1         │  │  │
│  │  │ Full routes:            │  │  │
│  │  │  - Corporate network    │  │  │
│  │  │  - All resources        │  │  │
│  │  └─────────────────────────┘  │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

### 2.4 Configuration

**XML Profile:**

```xml
<ClientInitialization>
  <AutomaticVPNPolicy>true</AutomaticVPNPolicy>
  <AlwaysOn>
    <Enabled>true</Enabled>
    <ManagementTunnel>true</ManagementTunnel>
    <TrustedNetworkPolicy>Disconnect</TrustedNetworkPolicy>
  </AlwaysOn>
</ClientInitialization>
```

**Server-Side Configuration (ASA/FTD):**

```
group-policy ManagementTunnel attributes
  vpn-simultaneous-logins 2
  split-tunnel-policy tunnelspecified
  split-tunnel-network-list value ManagementRoutes

access-list ManagementRoutes permit ip any host 10.0.0.5  (MDM server)
access-list ManagementRoutes permit ip any host 10.0.0.10 (Update server)
```

### 2.5 Use Cases

| Use Case | Description | Management Tunnel | User Tunnel |
|----------|-------------|-------------------|-------------|
| **MDM Check-in** | Device compliance verification | ✓ Always on | - Optional |
| **Software Updates** | Corporate app/OS updates | ✓ Always on | - Optional |
| **Threat Detection** | AV signature updates | ✓ Always on | - Optional |
| **File Sharing** | Access corporate files | - | ✓ On-demand |
| **Email/Calendar** | Outlook, Teams | - | ✓ On-demand |

### 2.6 C23 Implementation Concept (Linux/ocserv)

```c
// File: ocserv-modern/src/tunnel/management_tunnel.c
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef enum {
    TUNNEL_TYPE_MANAGEMENT,
    TUNNEL_TYPE_USER
} tunnel_type_t;

typedef struct {
    tunnel_type_t type;
    int tun_fd;                     // TUN device file descriptor
    char tun_name[16];              // "tun0", "tun1", etc.
    bool is_active;
    time_t established_at;

    // Split routing
    struct in_addr *allowed_networks;
    size_t allowed_networks_count;

    // Management tunnel specific
    bool always_on;
    uint32_t reconnect_interval;    // Seconds
    time_t last_heartbeat;
} vpn_tunnel_t;

typedef struct {
    vpn_tunnel_t management_tunnel;
    vpn_tunnel_t user_tunnel;
    bool management_required;
} dual_tunnel_context_t;

/**
 * Establish management tunnel (always-on)
 */
[[nodiscard]]
int establish_management_tunnel(dual_tunnel_context_t *ctx) {
    if (ctx == nullptr) {
        return -1;
    }

    vpn_tunnel_t *mgmt = &ctx->management_tunnel;
    mgmt->type = TUNNEL_TYPE_MANAGEMENT;
    mgmt->always_on = true;
    mgmt->reconnect_interval = 60;  // Reconnect every 60 seconds if dropped

    // Create TUN device
    mgmt->tun_fd = open("/dev/net/tun", O_RDWR);
    if (mgmt->tun_fd < 0) {
        return -1;
    }

    // Configure TUN device (IFF_TUN, IFF_NO_PI)
    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

    if (ioctl(mgmt->tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
        close(mgmt->tun_fd);
        return -1;
    }

    strncpy(mgmt->tun_name, ifr.ifr_name, sizeof(mgmt->tun_name));

    // Add limited routes for management traffic
    // Only route MDM, update, compliance servers
    struct in_addr mdm_server = { .s_addr = inet_addr("10.0.0.5") };
    struct in_addr update_server = { .s_addr = inet_addr("10.0.0.10") };

    mgmt->allowed_networks = malloc(sizeof(struct in_addr) * 2);
    mgmt->allowed_networks[0] = mdm_server;
    mgmt->allowed_networks[1] = update_server;
    mgmt->allowed_networks_count = 2;

    mgmt->is_active = true;
    mgmt->established_at = time(nullptr);

    return 0;
}

/**
 * Monitor and auto-reconnect management tunnel
 */
[[noreturn]]
void management_tunnel_monitor(dual_tunnel_context_t *ctx) {
    while (true) {
        if (!ctx->management_tunnel.is_active) {
            // Tunnel down, attempt reconnect
            syslog(LOG_WARNING, "Management tunnel down, reconnecting...");
            establish_management_tunnel(ctx);
        }

        // Send heartbeat
        time_t now = time(nullptr);
        if (now - ctx->management_tunnel.last_heartbeat > 30) {
            send_tunnel_heartbeat(&ctx->management_tunnel);
            ctx->management_tunnel.last_heartbeat = now;
        }

        sleep(ctx->management_tunnel.reconnect_interval);
    }
}

/**
 * Establish user tunnel (on-demand)
 */
[[nodiscard]]
int establish_user_tunnel(dual_tunnel_context_t *ctx) {
    if (ctx == nullptr) {
        return -1;
    }

    vpn_tunnel_t *user = &ctx->user_tunnel;
    user->type = TUNNEL_TYPE_USER;
    user->always_on = false;

    // Create second TUN device
    user->tun_fd = open("/dev/net/tun", O_RDWR);
    if (user->tun_fd < 0) {
        return -1;
    }

    struct ifreq ifr = {0};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun1", IFNAMSIZ);

    if (ioctl(user->tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
        close(user->tun_fd);
        return -1;
    }

    strncpy(user->tun_name, ifr.ifr_name, sizeof(user->tun_name));

    // Add full routing (default route)
    // Route all corporate traffic through tun1

    user->is_active = true;
    user->established_at = time(nullptr);

    return 0;
}
```

---

## 3. Windows Service Architecture

### 3.1 Service Hierarchy

```
┌──────────────────────────────────────────────────────┐
│            Windows Service Architecture              │
└──────────────────────────────────────────────────────┘

[Services Console (services.msc)]
    |
    ├─ vpnagent (Cisco Secure Client Agent)
    │   ├─ Type: Own Process
    │   ├─ Start: Automatic (Delayed)
    │   ├─ Account: Local System
    │   └─ Binary: C:\Program Files\Cisco\Secure Client\vpnagent.exe
    │
    ├─ csc_vpnagent (Legacy name, may still exist)
    │
    └─ cscServiceProxy (Helper service)
        ├─ Type: Own Process
        ├─ Start: Manual
        └─ Account: Local System
```

### 3.2 Service Communication

```
┌────────────────────────────────────────────────────┐
│      Inter-Process Communication (IPC)             │
└────────────────────────────────────────────────────┘

[vpnui.exe (GUI)]
     |
     | Named Pipe: \\.\pipe\vpnagent
     v
[vpnagent.exe (Service)]
     |
     ├──> Network Stack (TUN/TAP driver)
     ├──> Credential Provider (Logon)
     └──> Registry (Configuration)
```

**IPC Mechanism:** Windows Named Pipes

```c
// Pseudocode from reverse engineering
HANDLE pipe = CreateFile(
    "\\\\.\\pipe\\vpnagent",
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    0,
    NULL
);

// Message structure (from IPC TLV classes)
typedef struct {
    uint32_t message_id;    // IPC_MESSAGE_ID enum
    uint32_t length;
    uint8_t data[];
} ipc_message_t;

// Message types (from reverse engineering)
enum IPC_MESSAGE_ID {
    IPC_CONNECT_REQUEST,
    IPC_DISCONNECT_REQUEST,
    IPC_STATUS_UPDATE,
    IPC_USER_AUTH_REQUEST,
    IPC_CERT_AUTH_REQUEST,
    IPC_STATS_REQUEST,
    // ... many more
};
```

### 3.3 Linux/systemd Equivalent

```ini
# /etc/systemd/system/ocserv-agent.service
[Unit]
Description=OCServ VPN Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/sbin/ocserv-agent --daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/run/ocserv /var/log/ocserv

[Install]
WantedBy=multi-user.target
```

**IPC via Unix Domain Sockets:**

```c
// File: ocserv-modern/src/ipc/unix_socket_ipc.c
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define OCSERV_SOCKET_PATH "/var/run/ocserv/agent.sock"

/**
 * Create IPC socket for daemon
 */
[[nodiscard]]
int create_ipc_socket(void) {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, OCSERV_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Remove existing socket file
    unlink(OCSERV_SOCKET_PATH);

    if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock_fd);
        return -1;
    }

    if (listen(sock_fd, 5) < 0) {
        close(sock_fd);
        return -1;
    }

    // Set permissions (0600 - owner only)
    chmod(OCSERV_SOCKET_PATH, 0600);

    return sock_fd;
}

/**
 * Client connects to daemon
 */
[[nodiscard]]
int connect_to_daemon(void) {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, OCSERV_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}
```

---

## 4. Registry Configuration

### 4.1 Key Registry Locations

```
HKEY_LOCAL_MACHINE\SOFTWARE\Cisco\Cisco Secure Client\
    ├─ InstallPath (REG_SZ)
    ├─ Version (REG_SZ)
    └─ VPN\
        ├─ LastHostAddress (REG_SZ)
        ├─ CachedCredentials (REG_BINARY, encrypted)
        ├─ UseStartBeforeLogon (REG_DWORD)
        ├─ AlwaysOnVPN (REG_DWORD)
        └─ Profiles\
            └─ {profile-name}.xml (REG_SZ, path)

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\
    ├─ vpnagent\
    │   ├─ Type (REG_DWORD) = 0x10 (Win32OwnProcess)
    │   ├─ Start (REG_DWORD) = 0x2 (Automatic)
    │   ├─ ErrorControl (REG_DWORD) = 0x1 (Normal)
    │   └─ ImagePath (REG_EXPAND_SZ) = "C:\...\vpnagent.exe"
    │
    └─ csc_vpnagent\ (Alias)

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order\
    └─ ProviderOrder (REG_SZ) = "CiscoVPN,LanmanWorkstation,..."
```

### 4.2 Linux Configuration File Equivalent

```ini
# /etc/ocserv/agent.conf

[Installation]
install_path = /usr/lib/ocserv
version = 5.1.2

[VPN]
last_host = vpn.example.com
use_start_before_logon = true
always_on_vpn = true

[Profiles]
profile_dir = /etc/ocserv/profiles
default_profile = corporate.xml

[Credentials]
# Encrypted credentials stored in:
# /var/lib/ocserv/cached_creds (mode 0600)
credential_storage = /var/lib/ocserv/cached_creds

[Security]
# Use Linux Keyring for secret storage
use_kernel_keyring = true
keyring_description = "ocserv:vpn-secrets"
```

---

## 5. Network Provider Order

### 5.1 Windows Network Provider Architecture

Windows uses **Network Providers** for:
- UNC path resolution (\\server\share)
- Network drive mapping
- Authentication forwarding

**Cisco VPN Network Provider** ensures:
- UNC paths resolve **over VPN** before local network
- Drive mappings work transparently
- Windows Explorer shows remote shares correctly

### 5.2 Registry Configuration

```
HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order\
  ProviderOrder = "CiscoVPN,LanmanWorkstation,WebClient"

HKLM\SYSTEM\CurrentControlSet\Services\CiscoVPN\NetworkProvider\
  Name (REG_SZ) = "Cisco Secure Client VPN"
  ProviderPath (REG_SZ) = "C:\Program Files\Cisco\Secure Client\vpnprovider.dll"
  Class (REG_DWORD) = 0x2
```

### 5.3 Linux SMB/CIFS Equivalent

```bash
# /etc/nsswitch.conf - Name Service Switch
# Controls resolution order

hosts:      files vpn dns mdns4_minimal [NOTFOUND=return] myhostname
networks:   files vpn
protocols:  db files
services:   db files vpn
```

**Custom VPN resolver:**

```c
// File: /usr/lib/ocserv/nss_vpn.so.2
// NSS (Name Service Switch) plugin for VPN-first resolution

#include <nss.h>
#include <netdb.h>

enum nss_status _nss_vpn_gethostbyname_r(
    const char *name,
    struct hostent *result,
    char *buffer,
    size_t buflen,
    int *errnop,
    int *h_errnop
) {
    // Check if VPN is active
    if (!is_vpn_active()) {
        return NSS_STATUS_NOTFOUND;
    }

    // Query DNS over VPN tunnel
    struct in_addr addr;
    if (resolve_via_vpn(name, &addr) == 0) {
        // Fill result structure
        result->h_name = (char *)name;
        result->h_addrtype = AF_INET;
        result->h_length = sizeof(struct in_addr);
        // ... fill remaining fields
        return NSS_STATUS_SUCCESS;
    }

    return NSS_STATUS_NOTFOUND;
}
```

---

## 6. Conclusion

### 6.1 Windows Feature Summary

| Feature | Purpose | Linux/macOS Equivalent |
|---------|---------|----------------------|
| **Start-Before-Logon** | VPN before user authentication | PAM module + Display Manager integration |
| **Management Tunnel** | Always-on admin connectivity | Dual TUN devices + systemd service |
| **Credential Provider** | Logon screen integration | GDM/LightDM plugin |
| **Windows Service** | Background daemon | systemd service |
| **Registry Config** | System settings storage | /etc/ocserv/*.conf files |
| **Network Provider** | UNC path routing | NSS (Name Service Switch) plugin |

### 6.2 Implementation Priority for ocserv

**HIGH Priority:**
1. **Management Tunnel** - Dual tunnel support with split routing
2. **Always-On VPN** - Reconnect logic and health monitoring
3. **systemd Integration** - Service management and auto-start

**MEDIUM Priority:**
4. **PAM Module** - Pre-authentication VPN (Linux SBL equivalent)
5. **Configuration Files** - Registry-equivalent storage
6. **IPC via Unix Sockets** - GUI ↔ daemon communication

**LOW Priority:**
7. **NSS Plugin** - VPN-first name resolution
8. **Display Manager Plugin** - Show VPN status at login screen

### 6.3 Cross-Platform Considerations

**Challenge:** Direct Windows feature ports not always feasible
**Solution:** Implement **equivalent functionality** with platform-native APIs

**Example:**
- Windows: Credential Provider DLL
- Linux: PAM module
- macOS: Authorization Plugin

All achieve same goal: **VPN before user authentication**

---

**Document Revision:** 1.0
**Author:** Reverse Engineering Analysis Team
**Target:** ocserv-modern C23 implementation with cross-platform understanding
