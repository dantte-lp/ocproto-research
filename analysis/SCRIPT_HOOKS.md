# Script Hooks - Implementation Guide

**Analysis Date:** 2025-10-29
**Purpose:** On-connect/disconnect script executor for ocserv (C23)

## Script Types

### 1. OnConnect Script

**Execution**: When VPN session establishes

**Use Cases**:
- Mount network drives
- Add static routes
- Update firewall rules
- Launch applications
- Trigger Group Policy refresh

**Example** (Windows VBScript):
```vbs
' OnConnect_mountdrives.vbs
Set objShell = CreateObject("WScript.Shell")
objShell.Run "net use Z: \\server\share /persistent:no", 0, True
objShell.LogEvent 0, "VPN: Mounted network drives"
```

**Example** (Linux Bash):
```bash
#!/bin/bash
# OnConnect_routes.sh
ip route add 192.168.100.0/24 via 10.0.0.1 dev tun0
logger "VPN: Added static routes"
```

### 2. OnDisconnect Script

**Execution**: When VPN session terminates

**Use Cases**:
- Unmount network drives
- Remove static routes
- Restore firewall rules
- Close applications

**Example** (Windows):
```vbs
' OnDisconnect_cleanup.vbs
Set objShell = CreateObject("WScript.Shell")
objShell.Run "net use Z: /delete /yes", 0, True
objShell.LogEvent 0, "VPN: Unmounted network drives"
```

**Example** (Linux):
```bash
#!/bin/bash
# OnDisconnect_cleanup.sh
ip route del 192.168.100.0/24
logger "VPN: Removed static routes"
```

## Script Configuration

### Profile XML

```xml
<ClientInitialization>
  <OnConnectScript>OnConnect_script.vbs</OnConnectScript>
  <OnDisconnectScript>OnDisconnect_script.vbs</OnDisconnectScript>
  <TerminateScriptOnNextEvent>true</TerminateScriptOnNextEvent>
</ClientInitialization>
```

**TerminateScriptOnNextEvent**:
- `true`: Kill running script if next event occurs
- `false`: Let script complete before next event

## Script Locations

**Windows**: `%ALLUSERSPROFILE%\Cisco\Cisco Secure Client\VPN\Script\`

**macOS / Linux**: `/opt/cisco/secureclient/vpn/script/`

**Naming Convention**: `OnConnect_<name>.ext` or `OnDisconnect_<name>.ext`

## C23 Implementation

```c
// ocserv-modern/src/vpn/script_executor.c

#include <sys/wait.h>
#include <signal.h>

#define SCRIPT_DIR_LINUX "/opt/cisco/secureclient/vpn/script/"
#define SCRIPT_TIMEOUT_SEC 60

typedef enum {
    SCRIPT_EVENT_CONNECT,
    SCRIPT_EVENT_DISCONNECT,
    SCRIPT_EVENT_RECONNECT,
    SCRIPT_EVENT_UPDATE
} script_event_t;

typedef struct {
    pid_t pid;                  // Running script PID
    time_t start_time;          // Script start time
    script_event_t event;       // Event type
    bool terminate_on_next;     // Terminate if next event occurs
} script_state_t;

// C23: Execute script
[[nodiscard]] int execute_script(
    struct worker_st *ws,
    const char *script_name,
    script_event_t event
) {
    if (ws == nullptr || script_name == nullptr) {
        return -EINVAL;
    }

    char script_path[PATH_MAX];
    snprintf(script_path, sizeof(script_path), "%s%s",
             SCRIPT_DIR_LINUX, script_name);

    // Check if script exists and is executable
    if (access(script_path, X_OK) != 0) {
        mslog(ws, nullptr, LOG_WARNING,
              "Script not found or not executable: %s", script_path);
        return -ENOENT;
    }

    pid_t pid = fork();
    if (pid < 0) {
        return -errno;
    }

    if (pid == 0) {
        // Child process: execute script
        
        // Set environment variables
        setenv("CISCO_VPN_USERNAME", ws->username, 1);
        setenv("CISCO_VPN_SERVER", ws->server_hostname, 1);
        setenv("CISCO_VPN_IP", ws->assigned_ip, 1);
        setenv("CISCO_VPN_EVENT",
               (event == SCRIPT_EVENT_CONNECT) ? "connect" : "disconnect", 1);

        // Execute script
        execl(script_path, script_name, (char *)nullptr);

        // If execl returns, error occurred
        _exit(127);
    }

    // Parent process: track script
    ws->script_state.pid = pid;
    ws->script_state.start_time = time(nullptr);
    ws->script_state.event = event;

    mslog(ws, nullptr, LOG_INFO,
          "Script started: %s (PID %d)", script_name, pid);

    return 0;
}

// C23: Check script timeout
void check_script_timeout(struct worker_st *ws) {
    if (ws->script_state.pid == 0) {
        return;  // No script running
    }

    time_t now = time(nullptr);
    if ((now - ws->script_state.start_time) > SCRIPT_TIMEOUT_SEC) {
        mslog(ws, nullptr, LOG_WARNING,
              "Script timeout, killing PID %d", ws->script_state.pid);

        kill(ws->script_state.pid, SIGTERM);
        sleep(1);
        kill(ws->script_state.pid, SIGKILL);

        ws->script_state.pid = 0;
    }
}

// C23: Wait for script completion (or timeout)
int wait_for_script(struct worker_st *ws, int timeout_sec) {
    if (ws->script_state.pid == 0) {
        return 0;  // No script running
    }

    for (int i = 0; i < timeout_sec; i++) {
        int status;
        pid_t result = waitpid(ws->script_state.pid, &status, WNOHANG);

        if (result == ws->script_state.pid) {
            // Script completed
            ws->script_state.pid = 0;
            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                mslog(ws, nullptr, LOG_INFO,
                      "Script completed with exit code %d", exit_code);
                return exit_code;
            }
            return -1;
        }

        sleep(1);
    }

    // Timeout
    mslog(ws, nullptr, LOG_WARNING, "Script did not complete within timeout");
    return -ETIMEDOUT;
}

// C23: Terminate running script (on next event)
void terminate_script_on_event(struct worker_st *ws) {
    if (ws->script_state.pid == 0) {
        return;
    }

    if (ws->script_state.terminate_on_next) {
        mslog(ws, nullptr, LOG_INFO,
              "Terminating running script (PID %d) due to new event",
              ws->script_state.pid);

        kill(ws->script_state.pid, SIGTERM);
        usleep(500000);  // Wait 500ms
        kill(ws->script_state.pid, SIGKILL);

        ws->script_state.pid = 0;
    }
}
```

## Security Considerations

**Script Validation**:
- Verify script is in authorized directory
- Check execute permissions (Linux: `chmod +x`)
- Consider digital signature verification (future enhancement)

**Privilege Level**:
- Scripts run in user context (not root/SYSTEM)
- Cannot perform privileged operations without sudo/UAC

**Sandboxing**:
- No sandboxing implemented (scripts have full user privileges)
- Consider using AppArmor/SELinux profiles for containment

---

**End of Document**
