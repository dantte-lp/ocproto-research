# Cisco Secure Client Decompilation Workflow

**Document Version**: 1.0
**Date**: 2025-10-29
**Target Audience**: ocserv-modern Development Team
**Purpose**: Step-by-step practical workflow for reverse engineering and implementation

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Workflow Phases](#workflow-phases)
4. [Phase 1: Initial Reconnaissance](#phase-1-initial-reconnaissance)
5. [Phase 2: Struct Recovery](#phase-2-struct-recovery)
6. [Phase 3: Function Decompilation](#phase-3-function-decompilation)
7. [Phase 4: Security Validation](#phase-4-security-validation)
8. [Phase 5: C23 Implementation](#phase-5-c23-implementation)
9. [Phase 6: Testing and Validation](#phase-6-testing-and-validation)
10. [Complete Example: Reverse Engineering OTP](#complete-example-reverse-engineering-otp)
11. [Best Practices](#best-practices)
12. [Common Pitfalls](#common-pitfalls)
13. [Troubleshooting](#troubleshooting)

---

## 1. Overview

This document provides a **practical, hands-on workflow** for reverse engineering Cisco Secure Client binaries and implementing compatible functionality in ocserv-modern. The workflow is optimized for efficiency, combining multiple tools at each phase.

### Workflow Summary

```
┌─────────────────────────────────────────────────────────┐
│                  PHASE 1: Reconnaissance                 │
│              (strings, nm, basic analysis)               │
│                     ⏱ 30 minutes                         │
└────────────────────┬────────────────────────────────────┘
                     │
                     v
┌─────────────────────────────────────────────────────────┐
│                 PHASE 2: Struct Recovery                 │
│                (Reko decompilation)                      │
│                     ⏱ 1 hour                             │
└────────────────────┬────────────────────────────────────┘
                     │
                     v
┌─────────────────────────────────────────────────────────┐
│               PHASE 3: Function Decompilation            │
│              (Ghidra deep analysis)                      │
│                     ⏱ 2-4 hours                          │
└────────────────────┬────────────────────────────────────┘
                     │
                     v
┌─────────────────────────────────────────────────────────┐
│              PHASE 4: Security Validation                │
│             (angr symbolic execution)                    │
│                     ⏱ 1-2 hours                          │
└────────────────────┬────────────────────────────────────┘
                     │
                     v
┌─────────────────────────────────────────────────────────┐
│              PHASE 5: C23 Implementation                 │
│          (Convert to ocserv-modern code)                 │
│                     ⏱ 2-4 hours                          │
└────────────────────┬────────────────────────────────────┘
                     │
                     v
┌─────────────────────────────────────────────────────────┐
│             PHASE 6: Testing & Validation                │
│        (Unit tests, integration tests)                   │
│                     ⏱ 2-3 hours                          │
└─────────────────────────────────────────────────────────┘

Total Time: 8-14 hours per feature
```

---

## 2. Prerequisites

### 2.1 Environment Setup

**Operating System**: Oracle Linux 9.5 or compatible (RHEL 9, Rocky Linux 9)

**Required Tools**:
```bash
# Install analysis tools
sudo dnf install -y binutils strings nm objdump readelf

# Ghidra (see DECOMPILATION_TOOLS.md Section 3.2)
sudo mkdir -p /opt/tools
cd /opt/tools
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3_build/ghidra_11.3_PUBLIC_20250115.zip
unzip ghidra_*.zip
export GHIDRA_HOME=/opt/tools/ghidra_11.3_PUBLIC_20250115

# Reko (see DECOMPILATION_TOOLS.md Section 4.2)
sudo dnf install -y mono-complete
cd /opt/tools
wget https://github.com/uxmal/reko/releases/download/version-0.12.0/Reko-0.12.0.zip
unzip Reko-*.zip -d reko

# angr (see DECOMPILATION_TOOLS.md Section 5.2)
python3.11 -m venv /opt/tools/angr-env
source /opt/tools/angr-env/bin/activate
pip install angr angr-management
```

**Binary Access**:
```bash
# Obtain Cisco Secure Client binaries (legally licensed)
# Extract from installation packages

mkdir -p /opt/analysis/cisco-binaries
cd /opt/analysis/cisco-binaries

# Example paths (adjust based on your installation)
cp /opt/cisco/secureclient/bin/vpnagentd .
cp /opt/cisco/secureclient/lib/libvpnapi.so .
cp /opt/cisco/secureclient/lib/libacciscossl.so .
```

### 2.2 Directory Structure

```bash
mkdir -p /opt/analysis/{ghidra_projects,reko_output,angr_scripts,decompiled_c,notes}

# Directory tree:
/opt/analysis/
├── cisco-binaries/        # Original binaries
│   ├── vpnagentd
│   ├── libvpnapi.so
│   └── libacciscossl.so
├── ghidra_projects/       # Ghidra project files
├── reko_output/           # Reko decompiled output
├── angr_scripts/          # angr analysis scripts
├── decompiled_c/          # Final C23 code
└── notes/                 # Analysis notes and findings
```

### 2.3 Documentation Review

Before starting, read:
1. **DECOMPILATION_TOOLS.md**: Tool installation and features
2. **ADVANCED_BINARY_ANALYSIS.md**: Prior findings and examples
3. **OTP_IMPLEMENTATION.md**: Existing OTP analysis
4. **WOLFSSL_INTEGRATION.md**: wolfSSL API reference

---

## 3. Workflow Phases

Each phase has specific **inputs**, **tools**, **outputs**, and **time estimates**.

| Phase | Primary Tool | Duration | Output |
|-------|-------------|----------|--------|
| 1. Reconnaissance | `strings`, `nm` | 30 min | Target list |
| 2. Struct Recovery | Reko | 1 hour | Struct definitions |
| 3. Function Decompilation | Ghidra | 2-4 hours | Annotated C code |
| 4. Security Validation | angr | 1-2 hours | Security report |
| 5. C23 Implementation | Text editor | 2-4 hours | Production code |
| 6. Testing | CUnit, Valgrind | 2-3 hours | Test suite |

---

## 4. Phase 1: Initial Reconnaissance

**Goal**: Identify interesting functions and strings without deep analysis

**Time**: 30 minutes

### 4.1 String Extraction

```bash
cd /opt/analysis/cisco-binaries

# Extract ASCII strings (min 8 characters)
strings -a -n 8 vpnagentd > ../notes/vpnagentd_strings.txt
strings -a -n 8 libvpnapi.so > ../notes/libvpnapi_strings.txt

# Search for keywords
grep -iE "otp|totp|auth|token|secret|verify" ../notes/vpnagentd_strings.txt > ../notes/otp_strings.txt
grep -iE "X-CSTP|X-DTLS" ../notes/libvpnapi_strings.txt > ../notes/cstp_strings.txt
```

**Example Output** (`otp_strings.txt`):
```
totp_generate_code
totp_verify_input
otp_provision_secret
Invalid OTP code
TOTP verification failed
otpauth://totp/
```

### 4.2 Symbol Analysis

```bash
# List dynamic symbols
nm -D libvpnapi.so | grep -i otp > ../notes/otp_symbols.txt

# List all symbols (if not stripped)
nm -C vpnagentd | grep -i totp > ../notes/totp_symbols.txt

# Check for stripped symbols
readelf -s vpnagentd | head -20
```

**Example Output** (`otp_symbols.txt`):
```
00023450 T vpn_otp_init
00023680 T vpn_otp_verify
00023a20 T vpn_otp_provision_secret
00023d50 T vpn_totp_generate_code
```

### 4.3 Binary Info

```bash
# Architecture and format
file vpnagentd
# Output: ELF 64-bit LSB executable, x86-64

# Dependencies
ldd vpnagentd
# Output: libssl.so.1.1, libcrypto.so.1.1, libpthread.so.0

# Sections
readelf -S vpnagentd | grep -E "\.text|\.rodata|\.data"
```

### 4.4 Create Target List

**Document**: `/opt/analysis/notes/target_functions.md`

```markdown
# Target Functions for Analysis

## Priority 1: OTP/TOTP (CRITICAL)
- [ ] vpn_totp_generate @ 0x00425f80
- [ ] vpn_totp_verify @ 0x00426120
- [ ] base32_decode @ 0x00426c10
- [ ] constant_time_compare @ 0x00426f50

## Priority 2: Protocol Handlers (HIGH)
- [ ] parse_cstp_headers @ 0x00023450 (libvpnapi.so)
- [ ] handle_dtls_cookie @ 0x0043a100

## Priority 3: Certificate Validation (MEDIUM)
- [ ] validate_cert_chain @ 0x00015a00 (libacciscossl.so)
```

**Decision Point**: Which function to analyze first?
→ Start with highest-priority function: `vpn_totp_generate`

---

## 5. Phase 2: Struct Recovery

**Goal**: Extract data structure definitions quickly

**Tool**: Reko (fast struct inference)

**Time**: 1 hour

### 5.1 Reko Decompilation

```bash
cd /opt/tools/reko

# Decompile libvpnapi.so (focus on structs)
mono Reko.exe \
    --arch=x86-64 \
    --loader=elf \
    --output=/opt/analysis/reko_output \
    /opt/analysis/cisco-binaries/libvpnapi.so

# Wait for analysis (5-15 minutes)
```

### 5.2 Extract Struct Definitions

**Open**: `/opt/analysis/reko_output/libvpnapi.h`

**Find**: Session-related structs

```c
// Reko auto-generated (example)
struct Eq_10 {
    uint32_t dw0000;
    uint8_t * ptr0004;
    uint64_t qw0008;
    uint64_t qw0010;
    char a0018[256];
    struct Eq_20 * ptr0118;
    uint16_t w011C;
    uint32_t dw0120;
};
```

### 5.3 Annotate Structs

**Create**: `/opt/analysis/decompiled_c/vpn_structs.h`

```c
// vpn_structs.h
// Structures recovered from Reko analysis
// Manually annotated based on usage patterns

#ifndef VPN_STRUCTS_H
#define VPN_STRUCTS_H

#include <stdint.h>
#include <netinet/in.h>

// VPN session context (recovered from libvpnapi.so @ offset 0x1000)
typedef struct vpn_session {
    uint32_t session_id;                 // +0x00: Unique session ID
    uint8_t *session_token;              // +0x04: Authentication token pointer
    uint64_t created_time;               // +0x08: Unix timestamp (creation)
    uint64_t expire_time;                // +0x10: Session expiration time
    char username[256];                  // +0x18: Authenticated username
    struct tls_context *tls_ctx;         // +0x118: TLS/DTLS context pointer
    uint16_t mtu;                        // +0x11C: Path MTU
    uint32_t flags;                      // +0x120: Session flags
} vpn_session_t;

// Session flags (reverse engineered from bit tests)
#define VPN_SESSION_FLAG_DTLS_ENABLED    (1U << 0)
#define VPN_SESSION_FLAG_IPV6_ENABLED    (1U << 1)
#define VPN_SESSION_FLAG_SPLIT_TUNNEL    (1U << 2)
#define VPN_SESSION_FLAG_OTP_VERIFIED    (1U << 3)

// TLS context (recovered from libacciscossl.so @ offset 0x2000)
typedef struct tls_context {
    void *ssl_handle;                    // +0x00: SSL/TLS session handle
    uint32_t cipher_suite;               // +0x04: Selected cipher suite ID
    uint8_t master_secret[48];           // +0x08: TLS master secret
    uint8_t client_random[32];           // +0x38: Client random bytes
    uint8_t server_random[32];           // +0x58: Server random bytes
    uint16_t protocol_version;           // +0x78: TLS version (0x0303 = 1.2)
} tls_context_t;

// CSTP configuration (recovered from parse_cstp_headers function)
typedef struct cstp_config {
    uint32_t mtu;
    uint32_t base_mtu;
    struct in_addr tunnel_addr_v4;
    struct in6_addr tunnel_addr_v6;
    struct in_addr netmask;
    char **split_include;
    size_t split_include_count;
    char **dns_servers;
    size_t dns_servers_count;
    char *default_domain;
    char *banner;
    uint32_t session_timeout;
    uint32_t dpd_interval;
    uint32_t keepalive_interval;
} cstp_config_t;

#endif // VPN_STRUCTS_H
```

**Action**: Commit structs to Git

```bash
cd /opt/projects/repositories/ocserv-modern
cp /opt/analysis/decompiled_c/vpn_structs.h src/vpn/
git add src/vpn/vpn_structs.h
git commit -m "Add VPN session structs from reverse engineering"
```

---

## 6. Phase 3: Function Decompilation

**Goal**: Extract function logic with annotations

**Tool**: Ghidra (best decompiler quality)

**Time**: 2-4 hours

### 6.1 Import Binary into Ghidra

```bash
cd /opt/tools/ghidra
./ghidraRun
```

**GUI Steps**:
1. `File → New Project`
   - Project Type: **Non-Shared Project**
   - Project Name: `CiscoSecureClient`
   - Project Location: `/opt/analysis/ghidra_projects`
2. Click `OK`
3. `File → Import File`
   - Select: `/opt/analysis/cisco-binaries/vpnagentd`
   - Format: **ELF** (auto-detected)
   - Language: **x86:LE:64:default** (auto-detected)
4. Click `OK`
5. **Analysis Options** dialog appears:
   - ✅ Enable all recommended analyzers
   - ⚠️ Disable "Non-Returning Functions" (slow)
6. Click `Analyze`
7. **Wait**: 30 minutes to 4 hours (depending on binary size and CPU)

### 6.2 Locate Target Function

**Method 1: By Address** (if known from Phase 1)

1. Press `G` (Go To)
2. Enter address: `0x00425f80`
3. Press Enter
4. Ghidra jumps to `vpn_totp_generate` function

**Method 2: By String Reference**

1. `Search → For Strings...`
2. Filter: `totp_generate`
3. Double-click result
4. Right-click string → `References → Find References to...`
5. Double-click function reference

**Method 3: By Symbol**

1. `Window → Functions`
2. Filter bar: `totp`
3. Double-click `vpn_totp_generate` in list

### 6.3 Decompile and Annotate

**Decompiler Pane** (right side): Shows C-like pseudocode

**Initial Decompiled Output** (before cleanup):

```c
undefined8 FUN_00425f80(longlong param_1, uint param_2)
{
    longlong lVar1;
    byte *pbVar2;
    uint uVar3;
    byte local_28[20];

    lVar1 = param_2 / 0x1e;
    FUN_00426700(local_28, *(undefined8*)(param_1 + 0x10),
                *(uint*)(param_1 + 0x18), lVar1);

    pbVar2 = local_28 + (local_28[0x13] & 0xf);
    uVar3 = ((uint)*pbVar2 & 0x7f) << 0x18 |
            (uint)pbVar2[1] << 0x10 |
            (uint)pbVar2[2] << 8 |
            (uint)pbVar2[3];

    return (ulonglong)(uVar3 % 1000000);
}
```

**Annotation Steps**:

1. **Rename Function**:
   - Right-click `FUN_00425f80` → `Rename Function`
   - New name: `vpn_totp_generate`

2. **Fix Function Signature**:
   - Right-click `vpn_totp_generate` → `Edit Function Signature`
   - Change to: `uint32_t vpn_totp_generate(otp_context *ctx, time_t timestamp)`

3. **Rename Variables**:
   - Right-click `param_1` → `Rename Variable` → `ctx`
   - Right-click `param_2` → `Rename Variable` → `timestamp`
   - Right-click `local_28` → `Rename Variable` → `hmac_result`
   - Right-click `lVar1` → `Rename Variable` → `counter`

4. **Identify Called Functions**:
   - Double-click `FUN_00426700`
   - Analyze code → Recognize HMAC-SHA1 pattern
   - Rename to `cisco_hmac_sha1`

5. **Add Comments**:
   - Click line, press `;` (semicolon)
   - Add: `// TOTP time step: 30 seconds (RFC 6238)`

**Cleaned Decompilation**:

```c
// Function: vpn_totp_generate @ 0x00425f80
// Generate TOTP code using HMAC-SHA1 (RFC 6238)

uint32_t vpn_totp_generate(otp_context *ctx, time_t timestamp)
{
    uint64_t counter;
    uint8_t hmac_result[20];  // SHA-1 output size
    uint8_t *offset_ptr;
    uint32_t code;

    // TOTP time step: 30 seconds (RFC 6238 default)
    counter = timestamp / 30;

    // Compute HMAC-SHA1(secret, counter)
    cisco_hmac_sha1(hmac_result, ctx->secret, ctx->secret_len, counter);

    // Dynamic truncation (RFC 6238 Section 5.3)
    uint8_t offset = hmac_result[19] & 0x0F;
    offset_ptr = &hmac_result[offset];

    // Extract 4 bytes and mask high bit
    code = ((offset_ptr[0] & 0x7F) << 24) |
           ((offset_ptr[1] & 0xFF) << 16) |
           ((offset_ptr[2] & 0xFF) << 8) |
           (offset_ptr[3] & 0xFF);

    // Return 6-digit code
    return code % 1000000;
}
```

### 6.4 Export Decompiled Code

**Method 1: Copy/Paste**

1. Select all code in Decompiler pane
2. `Ctrl+C` to copy
3. Paste into: `/opt/analysis/decompiled_c/totp_generate_ghidra.c`

**Method 2: Script Export** (for batch processing)

Create: `/opt/analysis/ghidra_scripts/export_otp_functions.py`

```python
# export_otp_functions.py
# Run in Ghidra: Window → Script Manager → Run

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

# Functions to export
target_functions = [
    "vpn_totp_generate",
    "vpn_totp_verify",
    "base32_decode",
    "cisco_constant_time_compare"
]

for func_name in target_functions:
    # Find function by name
    func = None
    for f in currentProgram.getFunctionManager().getFunctions(True):
        if f.getName() == func_name:
            func = f
            break

    if not func:
        print(f"Function not found: {func_name}")
        continue

    # Decompile
    results = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
    if not results.decompileCompleted():
        print(f"Decompilation failed: {func_name}")
        continue

    c_code = results.getDecompiledFunction().getC()

    # Export to file
    output_path = f"/opt/analysis/decompiled_c/{func_name}.c"
    with open(output_path, 'w') as f:
        f.write(c_code)

    print(f"Exported: {func_name} → {output_path}")
```

Run in Ghidra: `Window → Script Manager` → Select `export_otp_functions.py` → `Run`

---

## 7. Phase 4: Security Validation

**Goal**: Verify decompiled logic is secure

**Tool**: angr (symbolic execution)

**Time**: 1-2 hours

### 7.1 Verify Authentication Logic

**Create**: `/opt/analysis/angr_scripts/verify_totp_auth.py`

```python
#!/usr/bin/env python3
# verify_totp_auth.py
# Verify no authentication bypass exists in vpn_totp_verify()

import angr
import claripy
import sys

# Load binary
project = angr.Project('/opt/analysis/cisco-binaries/vpnagentd',
                      auto_load_libs=False)

print(f"[*] Loaded binary: {project.filename}")

# Target function: vpn_totp_verify
AUTH_FUNC_ADDR = 0x00426120

# Success/failure addresses (from Ghidra)
SUCCESS_ADDR = 0x00426400  # return 0
FAILURE_ADDRS = [0x00426450, 0x00426480]  # return -1

# Create symbolic state
state = project.factory.blank_state(addr=AUTH_FUNC_ADDR)

# Symbolic inputs
secret_b32 = claripy.BVS('secret', 8 * 32)
user_input = claripy.BVS('user_input', 8 * 8)

# Place in memory
SECRET_ADDR = 0x7fff0000
INPUT_ADDR = 0x7fff1000

state.memory.store(SECRET_ADDR, secret_b32)
state.memory.store(INPUT_ADDR, user_input)

# Set function arguments (x86_64 calling convention)
state.regs.rdi = SECRET_ADDR  # secret_b32
state.regs.rsi = INPUT_ADDR   # user_input

# Exploration
print("[*] Starting symbolic execution...")
simgr = project.factory.simulation_manager(state)
simgr.explore(find=SUCCESS_ADDR, avoid=FAILURE_ADDRS, n=1000)

print(f"[*] Exploration complete:")
print(f"    Found paths: {len(simgr.found)}")
print(f"    Avoided paths: {len(simgr.avoid)}")
print(f"    Active paths: {len(simgr.active)}")

# Analyze successful paths
if simgr.found:
    print("\n[!] SECURITY WARNING: Found authentication bypass paths!")

    for i, found_state in enumerate(simgr.found):
        print(f"\n[!] Bypass Path #{i+1}:")

        # Extract constraints
        constraints = found_state.solver.constraints
        print(f"    Constraints: {len(constraints)}")

        # Try to get concrete values
        try:
            secret_val = found_state.solver.eval(secret_b32, cast_to=bytes)
            input_val = found_state.solver.eval(user_input, cast_to=bytes)

            print(f"    Secret: {secret_val.hex()}")
            print(f"    Input: {input_val.decode('utf-8', errors='ignore')}")
        except:
            print("    Could not concretize inputs")

    sys.exit(1)  # Fail CI/CD if bypass found

else:
    print("\n[✓] SECURE: No authentication bypass paths found")
    sys.exit(0)
```

**Run**:

```bash
source /opt/tools/angr-env/bin/activate
python3 /opt/analysis/angr_scripts/verify_totp_auth.py
```

**Expected Output**:
```
[*] Loaded binary: /opt/analysis/cisco-binaries/vpnagentd
[*] Starting symbolic execution...
[*] Exploration complete:
    Found paths: 0
    Avoided paths: 1244
    Active paths: 3

[✓] SECURE: No authentication bypass paths found
```

### 7.2 Validate Time Window

**Create**: `/opt/analysis/angr_scripts/validate_time_window.py`

```python
#!/usr/bin/env python3
# validate_time_window.py
# Verify TOTP accepts exactly ±1 time step (RFC 6238)

import angr
import claripy

project = angr.Project('/opt/analysis/cisco-binaries/vpnagentd',
                      auto_load_libs=False)

# Target: vpn_totp_verify @ 0x00426120
state = project.factory.blank_state(addr=0x00426120)

# Symbolic timestamp
timestamp = claripy.BVS('timestamp', 64)

# Setup (simplified for demonstration)
state.regs.rdi = 0x7fff0000  # secret (pre-initialized)
state.regs.rsi = 0x7fff1000  # user_input (pre-initialized)

# Add constraint: timestamp is reasonable (year 2025)
state.solver.add(timestamp >= 1700000000)
state.solver.add(timestamp <= 1800000000)

# Find all successful authentication paths
simgr = project.factory.simulation_manager(state)
simgr.explore(find=lambda s: s.regs.rax == 0)

if simgr.found:
    print("[*] Analyzing time windows:")

    timestamps = []
    for found_state in simgr.found:
        ts = found_state.solver.eval(timestamp)
        timestamps.append(ts)

    # Calculate time steps
    steps = [ts // 30 for ts in timestamps]
    unique_steps = set(steps)

    print(f"    Accepted time steps: {unique_steps}")
    print(f"    Step range: {max(unique_steps) - min(unique_steps)}")

    # Verify RFC 6238 compliance (±1 step)
    if len(unique_steps) == 3 and (max(unique_steps) - min(unique_steps)) == 2:
        print("[✓] RFC 6238 COMPLIANT: Accepts ±1 time step")
    else:
        print("[✗] SECURITY ISSUE: Time window too large!")
```

### 7.3 Generate Test Cases

```python
#!/usr/bin/env python3
# generate_test_cases.py
# Generate unit test vectors from angr exploration

import angr
import claripy
import json

project = angr.Project('/opt/analysis/cisco-binaries/vpnagentd',
                      auto_load_libs=False)

test_cases = []

# Generate 50 test cases
for i in range(50):
    otp_code = claripy.BVS(f'otp_{i}', 32)

    state = project.factory.blank_state(addr=0x00426120)
    # ... setup state ...

    simgr = project.factory.simulation_manager(state)
    simgr.run(n=5)  # Execute 5 basic blocks

    if simgr.active:
        active_state = simgr.active[0]
        concrete_code = active_state.solver.eval(otp_code)

        test_cases.append({
            'code': f'{concrete_code:06d}',
            'expected': 'pass' if active_state.regs.rax == 0 else 'fail'
        })

# Export
with open('/opt/analysis/notes/otp_test_cases.json', 'w') as f:
    json.dump(test_cases, f, indent=2)

print(f"Generated {len(test_cases)} test cases")
```

---

## 8. Phase 5: C23 Implementation

**Goal**: Convert decompiled code to production-ready C23

**Tool**: Text editor + manual review

**Time**: 2-4 hours

### 8.1 Conversion Checklist

From Ghidra pseudocode to ocserv-modern C23:

**Checklist**:
- [ ] Replace generic types (`int` → `int32_t`, `uint` → `uint32_t`)
- [ ] Add `[[nodiscard]]` attribute to functions returning status
- [ ] Replace `NULL` with `nullptr` (C23)
- [ ] Add input validation (bounds checks)
- [ ] Replace Cisco crypto calls with wolfCrypt
- [ ] Add comprehensive error handling
- [ ] Use `constexpr` for constants
- [ ] Add function documentation (Doxygen style)
- [ ] Follow ocserv-modern coding style (clang-format)

### 8.2 Example Conversion

**Input**: Ghidra decompiled function

```c
// Ghidra output (cleaned)
uint32_t vpn_totp_generate(otp_context *ctx, time_t timestamp) {
    uint64_t counter = timestamp / 30;
    uint8_t hmac_result[20];

    cisco_hmac_sha1(hmac_result, ctx->secret, ctx->secret_len, counter);

    uint8_t offset = hmac_result[19] & 0x0F;
    uint32_t code = ((hmac_result[offset] & 0x7F) << 24) |
                    ((hmac_result[offset+1] & 0xFF) << 16) |
                    ((hmac_result[offset+2] & 0xFF) << 8) |
                    (hmac_result[offset+3] & 0xFF);

    return code % 1000000;
}
```

**Output**: ocserv-modern C23

```c
// src/auth/totp.c
// TOTP implementation based on RFC 6238
// Reverse engineered from Cisco Secure Client 5.1.6.103

#include <stdint.h>
#include <time.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include "auth/totp.h"

/**
 * @brief Generate TOTP code using HMAC-SHA1
 *
 * @param secret      Secret key (binary)
 * @param secret_len  Secret key length (16-32 bytes recommended)
 * @param timestamp   Unix timestamp for code generation
 * @return            6-digit TOTP code (000000-999999), or 0 on error
 *
 * @note Implements RFC 6238 with 30-second time step
 */
[[nodiscard]] uint32_t
totp_generate(const uint8_t *secret, size_t secret_len, time_t timestamp)
{
    // Input validation (added for safety)
    if (!secret || secret_len == 0 || secret_len > 64) {
        return 0;  // Error
    }

    // TOTP time counter (30-second steps per RFC 6238)
    constexpr uint32_t TIME_STEP_SEC = 30;
    uint64_t counter = (uint64_t)(timestamp / TIME_STEP_SEC);

    // Convert counter to big-endian bytes
    uint8_t counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }

    // Compute HMAC-SHA1(secret, counter) using wolfCrypt
    uint8_t hmac_result[WC_SHA_DIGEST_SIZE];  // SHA-1 = 20 bytes
    Hmac hmac;

    int ret = wc_HmacSetKey(&hmac, WC_SHA, secret, (word32)secret_len);
    if (ret != 0) {
        return 0;  // Error
    }

    wc_HmacUpdate(&hmac, counter_bytes, sizeof(counter_bytes));
    wc_HmacFinal(&hmac, hmac_result);

    // Dynamic truncation (RFC 6238 Section 5.3)
    uint8_t offset = hmac_result[WC_SHA_DIGEST_SIZE - 1] & 0x0F;
    uint8_t *offset_ptr = &hmac_result[offset];

    // Extract 4 bytes and mask high bit (for positive 32-bit integer)
    uint32_t code = ((offset_ptr[0] & 0x7F) << 24) |
                    ((offset_ptr[1] & 0xFF) << 16) |
                    ((offset_ptr[2] & 0xFF) << 8) |
                    (offset_ptr[3] & 0xFF);

    // Return 6-digit code (modulo 1,000,000)
    constexpr uint32_t TOTP_MODULO = 1000000;
    return code % TOTP_MODULO;
}
```

### 8.3 Integration with ocserv-modern

**File**: `/opt/projects/repositories/ocserv-modern/src/auth/totp.h`

```c
// src/auth/totp.h

#ifndef OCSERV_TOTP_H
#define OCSERV_TOTP_H

#include <stdint.h>
#include <time.h>

/**
 * Generate TOTP code (RFC 6238)
 */
[[nodiscard]] uint32_t
totp_generate(const uint8_t *secret, size_t secret_len, time_t timestamp);

/**
 * Verify TOTP code with ±30 second window
 */
[[nodiscard]] int32_t
totp_verify(const char *secret_b32, const char *user_input);

#endif // OCSERV_TOTP_H
```

**Add to Build System** (`meson.build`):

```meson
# src/auth/meson.build

auth_sources = [
  'totp.c',
  'base32.c',
  # ... other auth files
]

auth_lib = static_library(
  'auth',
  auth_sources,
  dependencies: [wolfssl_dep],
  include_directories: inc
)
```

---

## 9. Phase 6: Testing and Validation

**Goal**: Ensure implementation matches Cisco behavior

**Tools**: CUnit, Valgrind, Wireshark

**Time**: 2-3 hours

### 9.1 Unit Tests

**File**: `/opt/projects/repositories/ocserv-modern/tests/unit/test_totp.c`

```c
// tests/unit/test_totp.c

#include <CUnit/CUnit.h>
#include "auth/totp.h"

// RFC 6238 Appendix B test vectors
void test_totp_rfc6238_vectors(void) {
    // Secret: ASCII "12345678901234567890"
    const uint8_t secret[] = {
        0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
        0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,
        0x37,0x38,0x39,0x30
    };

    // Test cases from RFC 6238
    struct {
        time_t time;
        uint32_t expected;
    } vectors[] = {
        {59,         94287082},
        {1111111109, 7081804},
        {1234567890, 89005924},
    };

    for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); i++) {
        uint32_t code = totp_generate(secret, sizeof(secret), vectors[i].time);
        CU_ASSERT_EQUAL(code, vectors[i].expected);
    }
}

void test_totp_time_window(void) {
    const char *secret_b32 = "GEZDGNBVGY3TQOJQ";  // "12345678901234567890"

    // Test current time
    time_t now = time(NULL);
    uint8_t secret[64];
    size_t len = base32_decode(secret_b32, secret, sizeof(secret));
    uint32_t code = totp_generate(secret, len, now);

    char code_str[8];
    snprintf(code_str, sizeof(code_str), "%06u", code);

    // Should succeed
    CU_ASSERT_EQUAL(totp_verify(secret_b32, code_str), 0);

    // Test ±30 seconds
    uint32_t code_past = totp_generate(secret, len, now - 30);
    snprintf(code_str, sizeof(code_str), "%06u", code_past);
    CU_ASSERT_EQUAL(totp_verify(secret_b32, code_str), 0);

    // Test outside window (should fail)
    uint32_t code_outside = totp_generate(secret, len, now + 60);
    snprintf(code_str, sizeof(code_str), "%06u", code_outside);
    CU_ASSERT_EQUAL(totp_verify(secret_b32, code_str), -1);
}

int main() {
    CU_initialize_registry();

    CU_pSuite suite = CU_add_suite("TOTP Tests", NULL, NULL);
    CU_add_test(suite, "RFC 6238 vectors", test_totp_rfc6238_vectors);
    CU_add_test(suite, "Time window", test_totp_time_window);

    CU_basic_run_tests();
    int failures = CU_get_number_of_failures();
    CU_cleanup_registry();

    return (failures == 0) ? 0 : 1;
}
```

**Run**:

```bash
cd /opt/projects/repositories/ocserv-modern
meson setup build
cd build
meson test test_totp
```

### 9.2 Integration Test (Against Real Cisco Client)

**Setup**:
1. Install Cisco Secure Client on test machine
2. Configure ocserv-modern to use TOTP
3. Provision secret in both systems

**Test Script** (`tests/integration/test_cisco_compatibility.sh`):

```bash
#!/bin/bash
# Test TOTP compatibility with Cisco Secure Client

OCSERV_HOST="vpn-test.example.com"
TOTP_SECRET="JBSWY3DPEHPK3PXP"

# Generate TOTP code using our implementation
OUR_CODE=$(./build/bin/totp_cli generate "$TOTP_SECRET")

echo "[*] Generated TOTP code: $OUR_CODE"

# Try to authenticate with Cisco client
echo "[*] Testing with Cisco Secure Client..."
cisco-anyconnect-cli --server "$OCSERV_HOST" \
                     --username testuser \
                     --password "password" \
                     --otp "$OUR_CODE"

if [ $? -eq 0 ]; then
    echo "[✓] Authentication successful - Cisco client accepted our TOTP code"
    exit 0
else
    echo "[✗] Authentication failed - Incompatibility detected"
    exit 1
fi
```

### 9.3 Memory Safety Check

```bash
# Run with Valgrind
valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         ./build/tests/unit/test_totp

# Expected output:
# ==12345== HEAP SUMMARY:
# ==12345==     in use at exit: 0 bytes in 0 blocks
# ==12345==   total heap usage: 42 allocs, 42 frees, 8,192 bytes allocated
# ==12345==
# ==12345== All heap blocks were freed -- no leaks are possible
```

---

## 10. Complete Example: Reverse Engineering OTP

**End-to-End Workflow** (8 hours total)

### Hour 1: Reconnaissance

```bash
cd /opt/analysis/cisco-binaries
strings vpnagentd | grep -i otp > ../notes/otp_strings.txt
nm -D libvpnapi.so | grep otp > ../notes/otp_symbols.txt

# Target: vpn_totp_verify @ 0x00426120
```

### Hour 2: Struct Recovery (Reko)

```bash
cd /opt/tools/reko
mono Reko.exe --arch=x86-64 --loader=elf vpnagentd

# Extract otp_context structure
# Document in /opt/analysis/decompiled_c/otp_structs.h
```

### Hours 3-5: Function Decompilation (Ghidra)

```bash
# Launch Ghidra, import vpnagentd
# Locate vpn_totp_verify @ 0x00426120
# Annotate, rename variables
# Export to /opt/analysis/decompiled_c/totp_verify.c
```

### Hour 6: Security Validation (angr)

```bash
source /opt/tools/angr-env/bin/activate
python3 /opt/analysis/angr_scripts/verify_totp_auth.py

# Result: No bypass found ✓
```

### Hours 7-8: Implementation

```bash
cd /opt/projects/repositories/ocserv-modern

# Convert to C23
vim src/auth/totp.c

# Write tests
vim tests/unit/test_totp.c

# Build and test
meson test test_totp

# Integration test
./tests/integration/test_cisco_compatibility.sh
```

---

## 11. Best Practices

### 11.1 Documentation

**Create Analysis Journal** (`/opt/analysis/notes/JOURNAL.md`):

```markdown
# Reverse Engineering Journal

## 2025-10-29: TOTP Function Analysis

### Function: vpn_totp_verify
**Address**: 0x00426120
**Tool**: Ghidra 11.3

**Findings**:
- Uses HMAC-SHA1 (RFC 6238 compliant)
- Time window: ±30 seconds
- Constant-time comparison (secure)

**Questions**:
- Why SHA-1 instead of SHA-256? (legacy compatibility)
- Are there rate limiting controls? (checked: yes, at higher layer)

**Next Steps**:
- Implement in ocserv-modern with wolfCrypt
- Add unit tests
- Validate against Cisco client
```

### 11.2 Version Control

```bash
# Commit decompiled code separately from production code
cd /opt/analysis
git init
git add decompiled_c/ notes/ ghidra_scripts/
git commit -m "Add TOTP decompilation findings"

# Production code in separate repo
cd /opt/projects/repositories/ocserv-modern
git add src/auth/totp.c tests/unit/test_totp.c
git commit -m "Implement TOTP authentication (RFC 6238)"
```

### 11.3 Code Review

**Checklist for Implementing Decompiled Code**:

- [ ] Understand algorithm (don't blindly copy)
- [ ] Check for security issues (buffer overflows, etc.)
- [ ] Replace proprietary calls with open-source equivalents
- [ ] Add error handling
- [ ] Write unit tests (RFC test vectors)
- [ ] Test against real Cisco client
- [ ] Document assumptions and limitations
- [ ] Peer review by another developer

---

## 12. Common Pitfalls

### 12.1 Trusting Decompiled Code Blindly

**Problem**: Ghidra output may have errors (especially with compiler optimizations)

**Solution**: Cross-validate with multiple tools (Reko, angr) and manual inspection

### 12.2 Ignoring Calling Conventions

**Problem**: x86_64 uses different calling conventions (System V vs. Microsoft x64)

**Solution**: Verify register usage (RDI, RSI, RDX for arguments on Linux)

### 12.3 Struct Padding Issues

**Problem**: Compiler-inserted padding can break struct definitions

**Solution**: Use `sizeof()` checks and boundary analysis

**Example**:
```c
// Incorrect (missing padding)
struct bad {
    uint32_t a;  // +0x00
    uint64_t b;  // +0x04? NO! +0x08 due to alignment
};

// Correct
struct good {
    uint32_t a;      // +0x00
    uint8_t _pad[4]; // +0x04 (padding)
    uint64_t b;      // +0x08
};
```

### 12.4 Endianness Confusion

**Problem**: x86 is little-endian, network protocols are big-endian

**Solution**: Use `htonl()`, `ntohl()` for network data

---

## 13. Troubleshooting

### 13.1 Ghidra: "Decompiler process timed out"

**Symptom**: Large function fails to decompile

**Solution**:
```
Edit → Tool Options → Decompiler → Analysis
Set "Decompiler Timeout" to 300 seconds
```

### 13.2 Reko: Crash on Large Binary

**Symptom**: Reko crashes when analyzing libvpnapi.so

**Solution**:
- Increase Mono heap size: `MONO_GC_PARAMS="max-heap-size=8G" mono Reko.exe`
- Or use Ghidra for large binaries

### 13.3 angr: Path Explosion

**Symptom**: angr runs for hours without completing

**Solution**:
- Limit exploration depth: `simgr.run(n=100)`
- Use veritesting: `simgr.use_technique(angr.exploration_techniques.Veritesting())`
- Constrain symbolic inputs

### 13.4 Implementation: Cisco Client Rejects Our Code

**Symptom**: TOTP works in unit tests but Cisco client rejects it

**Debug Steps**:
1. Capture network traffic with Wireshark
2. Compare our TOTP codes with reference implementation
3. Check secret encoding (Base32 vs. hex)
4. Verify time synchronization (NTP)

**Example Debug**:
```bash
# Generate code with our implementation
OUR_CODE=$(./build/bin/totp_cli generate "$SECRET")

# Generate code with Google Authenticator
GOOGLE_CODE=$(oathtool --totp --base32 "$SECRET")

# Compare
if [ "$OUR_CODE" == "$GOOGLE_CODE" ]; then
    echo "Our implementation matches reference"
else
    echo "MISMATCH: Our=$OUR_CODE, Google=$GOOGLE_CODE"
fi
```

---

## Conclusion

This workflow provides a systematic approach to reverse engineering Cisco Secure Client and implementing compatible functionality in ocserv-modern. By following these steps, developers can:

1. **Efficiently analyze** binaries using the right tool for each phase
2. **Validate security** of decompiled code
3. **Implement clean, production-ready** C23 code
4. **Test compatibility** with real Cisco clients

**Estimated Time per Feature**: 8-14 hours
**Recommended Cadence**: 1-2 features per sprint (2 weeks)

**Next Steps**:
- Follow this workflow for remaining critical features (X-CSTP headers, DTLS handling)
- Document findings in `/opt/analysis/notes/`
- Commit C23 implementations to ocserv-modern repository

---

**Document Status**: Production Ready
**Maintained By**: ocserv-modern Development Team
**Last Updated**: 2025-10-29
