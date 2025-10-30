# Advanced Decompilation Tools for Cisco Secure Client Reverse Engineering

**Document Version**: 1.0
**Date**: 2025-10-29
**Target**: ocserv-modern Development Team
**Purpose**: Comprehensive installation and usage guide for binary analysis tools

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Tool Comparison Matrix](#tool-comparison-matrix)
3. [Tool 1: Ghidra (NSA)](#tool-1-ghidra-nsa)
4. [Tool 2: Reko Decompiler](#tool-2-reko-decompiler)
5. [Tool 3: angr Symbolic Execution](#tool-3-angr-symbolic-execution)
6. [Tool 4: Rec Decompiler (Legacy)](#tool-4-rec-decompiler-legacy)
7. [Tool Selection Guide](#tool-selection-guide)
8. [Integration with ocserv-modern](#integration-with-ocserv-modern)
9. [Security and Legal Considerations](#security-and-legal-considerations)
10. [References](#references)

---

## 1. Executive Summary

This document provides comprehensive guidance for installing and using advanced binary analysis tools to reverse engineer Cisco Secure Client (AnyConnect 5.x+) for compatibility implementation in ocserv-modern. These tools enable:

1. **Function Identification**: Locate OTP/TOTP, authentication, and protocol handling functions
2. **Protocol Reverse Engineering**: Understand proprietary X-CSTP-*, X-DTLS-* headers and AggAuth XML
3. **Algorithm Extraction**: Discover cipher suite negotiation, key derivation, and crypto implementations
4. **Security Analysis**: Identify potential vulnerabilities and best practices
5. **C23 Code Generation**: Convert decompiled output to production-ready C23 code

### Why Advanced Decompilation?

Basic string extraction and symbol analysis provide limited insight. Advanced decompilation tools offer:

- **Control Flow Analysis**: Understand complex state machines and protocol flows
- **Type Reconstruction**: Recover struct definitions and function signatures
- **Cross-References**: Trace function calls and data dependencies
- **Symbolic Execution**: Explore all possible execution paths
- **Automated Analysis**: Scale reverse engineering to large binaries (2+ MB)

### Supported Binaries

| Binary | Architecture | Size | Analysis Tool | Priority |
|--------|-------------|------|---------------|----------|
| **vpnagentd** | x86_64, ARM64 | 1.5 MB | Ghidra, angr | **HIGH** |
| **libvpnapi.so** | x86_64, ARM64 | 2.8 MB | Ghidra, Reko | **HIGH** |
| **libacciscossl.so** | x86_64, ARM64 | 800 KB | Reko | **MEDIUM** |
| **acwebhelper** | x86_64 | 500 KB | Ghidra | **LOW** |

---

## 2. Tool Comparison Matrix

| Feature | Ghidra | Reko | angr | Rec |
|---------|---------|------|------|-----|
| **License** | Apache 2.0 | GPLv2 | BSD 2-Clause | Proprietary |
| **Platform** | Linux/Win/macOS | Linux/Win | Linux/Win/macOS | Windows only |
| **Architecture Support** | 50+ | 30+ | 20+ | x86/x86_64 |
| **Decompiler Quality** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ (pseudocode) | ⭐⭐ (legacy) |
| **GUI** | ✅ Excellent | ✅ Good | ✅ Basic (angr-mgmt) | ✅ DOS-era |
| **Scripting** | Python, Java | Python, C# | Python | No |
| **Symbolic Execution** | ❌ | ❌ | ✅ **Best-in-class** | ❌ |
| **Type Recovery** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **Large Binary Performance** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ (slow) | ⭐⭐⭐ |
| **Collaboration** | ✅ Server mode | ❌ | ❌ | ❌ |
| **ELF/PE/Mach-O** | ✅ All | ✅ All | ✅ All | ⚠️ PE only |
| **Learning Curve** | Medium | Low | **High** | Low |
| **ocserv-modern Fit** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐ (obsolete) |

### Recommendation

- **Primary**: **Ghidra** - Best all-around decompiler, excellent GUI, active NSA development
- **Secondary**: **Reko** - Faster analysis for struct recovery, complementary to Ghidra
- **Specialized**: **angr** - Required for authentication bypass discovery and constraint solving
- **Legacy**: **Rec** - Skip unless analyzing ancient 16-bit DOS stubs

---

## 3. Tool 1: Ghidra (NSA)

### 3.1 Overview

**Ghidra** is a free, open-source software reverse engineering (SRE) suite developed by the National Security Agency (NSA). Released publicly in March 2019, it has become the industry standard for binary analysis.

**Version**: 11.3+ (January 2025)
**License**: Apache License 2.0
**Repository**: https://github.com/NationalSecurityAgency/ghidra
**Documentation**: https://ghidra-sre.org/

**Key Strengths**:
1. **Best-in-class Decompiler**: Produces high-quality pseudocode from optimized x86_64/ARM64 binaries
2. **Extensive Architecture Support**: 50+ processors (x86, ARM, MIPS, PowerPC, SPARC, etc.)
3. **Scripting**: Automate analysis with Python or Java
4. **Collaboration**: Multi-user server for team reverse engineering
5. **Extensibility**: Plugin ecosystem for custom analysis

### 3.2 Installation (Oracle Linux 9 / Podman)

#### Step 1: Install Java Development Kit (JDK) 21+

Ghidra requires **Java 21** or later:

```bash
# Install OpenJDK 21 from Oracle Linux repos
sudo dnf install -y java-21-openjdk-devel

# Verify installation
java -version
# Expected output: openjdk version "21.x.x"
```

#### Step 2: Download Ghidra

```bash
# Create tools directory
sudo mkdir -p /opt/tools
cd /opt/tools

# Download latest Ghidra release (11.3 as of Jan 2025)
GHIDRA_VERSION="11.3_PUBLIC_20250115"
sudo wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3_build/ghidra_${GHIDRA_VERSION}.zip

# Verify checksum (optional but recommended)
sudo wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3_build/ghidra_${GHIDRA_VERSION}.zip.sha256
sha256sum -c ghidra_${GHIDRA_VERSION}.zip.sha256

# Extract
sudo unzip ghidra_${GHIDRA_VERSION}.zip
sudo ln -s /opt/tools/ghidra_${GHIDRA_VERSION} /opt/tools/ghidra

# Set permissions
sudo chown -R $(whoami):$(whoami) /opt/tools/ghidra
```

#### Step 3: Configure Environment

```bash
# Add to ~/.bashrc or /etc/profile
export GHIDRA_HOME=/opt/tools/ghidra
export PATH=$GHIDRA_HOME:$PATH

# Reload
source ~/.bashrc
```

#### Step 4: Launch Ghidra

```bash
# GUI mode
cd /opt/tools/ghidra
./ghidraRun

# Headless mode (for automation)
./analyzeHeadless --help
```

**First Launch**:
1. Ghidra will prompt to accept license agreement
2. Create a new project: `File -> New Project`
3. Choose "Non-Shared Project" (unless using collaboration server)
4. Set project directory: `/opt/analysis/ghidra_projects`

### 3.3 Usage for Cisco Secure Client Binaries

#### Step 1: Import Binary

**GUI Method**:
1. `File -> Import File`
2. Select binary: `/opt/projects/repositories/cisco-secure-client/linux/vpnagentd`
3. Ghidra auto-detects format: **ELF x86_64**
4. Review import options:
   - ✅ Apply debug symbols (if available)
   - ✅ Load external libraries (for dynamic linking analysis)
5. Click `OK`

**Headless Method** (automation):

```bash
# Import and analyze vpnagentd
/opt/tools/ghidra/analyzeHeadless \
    /opt/analysis/ghidra_projects \
    CiscoSecureClient \
    -import /opt/projects/repositories/cisco-secure-client/linux/vpnagentd \
    -scriptPath /opt/analysis/ghidra_scripts \
    -postScript AutoAnalyze.java
```

#### Step 2: Auto-Analysis

After import, Ghidra prompts for auto-analysis:

1. **Analysis Options** dialog appears
2. **Recommended Settings** for VPN binary analysis:
   - ✅ **Function Identification** (critical)
   - ✅ **Decompiler Parameter ID** (important)
   - ✅ **Call-Fixup Installer** (fixes calling conventions)
   - ✅ **Reference** (finds cross-references)
   - ✅ **Demangler GNU** (C++ name demangling)
   - ✅ **Shared Return Calls** (function signature analysis)
   - ⚠️ **Stack** (slow but useful for local variables)
   - ❌ **Non-Returning Functions - Discovered** (can be slow)

3. Click `Analyze`
4. **Wait Time**: 30 minutes to 6 hours depending on binary size and CPU

**Progress Monitoring**:
- Bottom-right corner shows "Analyzing..." with progress bar
- Check `Window -> Script Manager -> Console` for detailed logs

#### Step 3: Navigate to Functions of Interest

**Method 1: String Search** (fastest for OTP/TOTP functions)

1. `Search -> For Strings...`
2. Configure search:
   - Minimum length: `8` characters
   - Encoding: `ASCII`, `UTF-16`, `UTF-8`
   - ✅ Require null termination
3. Filter results:
   - Enter: `otp|totp|auth|token|cisco` (regex mode)
4. **Double-click** string to jump to code reference
5. **Right-click** → `References -> Find References to...`
6. Ghidra shows all functions using that string

**Example Output**:
```
String: "totp_generate_code"
Address: 0x00412a50
References:
  - FUN_00411c20  (Call at 0x00411c5a)
  - FUN_00413f40  (Call at 0x00413f88)
```

**Method 2: Symbol Search** (for exported functions)

1. `Window -> Functions`
2. Filter bar: `totp|otp` (regex)
3. Ghidra lists all matching function names

**Method 3: Data Flow Analysis**

1. Identify key data structures (e.g., `otp_context`)
2. `Search -> For Data Types...`
3. Search: `otp_context`
4. Find all references to this type

#### Step 4: Decompile Function

1. **Select function** in Function listing
2. **Decompiler window** (usually right pane) shows C-like pseudocode
3. **Refine decompilation**:
   - Right-click variable → `Retype Variable` (fix incorrect types)
   - Right-click function → `Edit Function Signature` (fix parameters)
   - `Edit -> Tool Options -> Decompiler` → Adjust code style

**Example Decompiled Output** (before cleanup):

```c
// Ghidra raw output for OTP generation function
undefined8 FUN_00412a50(longlong param_1, longlong param_2) {
    longlong lVar1;
    byte *pbVar2;
    int iVar3;
    byte local_48[32];
    byte local_28[32];

    lVar1 = *(longlong*)(param_1 + 0x10);
    iVar3 = *(int*)(param_1 + 0x18);

    FUN_00401234(local_48, lVar1, 0x20, param_2 / iVar3);
    pbVar2 = local_48 + (local_48[0x1f] & 0xf);

    return (uint)(pbVar2[0] & 0x7f) << 0x18 |
           (uint)pbVar2[1] << 0x10 |
           (uint)pbVar2[2] << 8 |
           (uint)pbVar2[3];
}
```

#### Step 5: Annotate and Clean Up

**Rename Variables**:
1. Right-click `param_1` → `Rename Variable` → `otp_ctx`
2. Right-click `FUN_00401234` → `Rename Function` → `hmac_sha1`

**Improve Types**:
1. Right-click `param_1` → `Retype Variable` → `otp_context *`
2. Define custom types: `Data Type Manager` → `New -> Structure`

**Cleaned Decompilation**:

```c
// After annotation
uint32_t otp_generate(otp_context *ctx, time_t timestamp) {
    uint64_t counter;
    uint8_t hmac_result[32];
    uint8_t *offset_ptr;

    counter = timestamp / ctx->time_step;

    hmac_sha1(hmac_result, ctx->secret, 32, counter);
    offset_ptr = &hmac_result[hmac_result[31] & 0xf];

    return ((offset_ptr[0] & 0x7f) << 24) |
           (offset_ptr[1] << 16) |
           (offset_ptr[2] << 8) |
           offset_ptr[3];
}
```

#### Step 6: Export Decompiled Code

**Method 1: Copy/Paste**
- Select decompiled code in Decompiler pane
- `Ctrl+C` to copy
- Paste into text editor

**Method 2: Export Function**
- Right-click function → `Export -> Export Function`
- Choose format: `C` or `C++`
- Save to file

**Method 3: Automated Script Export**

```python
# ghidra_scripts/export_functions.py
# Export all OTP-related functions to C files

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Initialize decompiler
decompiler = DecompInterface()
decompiler.openProgram(currentProgram)

# Get all functions matching pattern
fm = currentProgram.getFunctionManager()
functions = [f for f in fm.getFunctions(True) if "otp" in f.getName().lower()]

# Export each function
for func in functions:
    results = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
    if results.decompileCompleted():
        c_code = results.getDecompiledFunction().getC()

        output_path = f"/opt/analysis/decompiled/{func.getName()}.c"
        with open(output_path, 'w') as f:
            f.write(c_code)

        print(f"Exported: {func.getName()}")
```

Run script: `Window -> Script Manager` → Select `export_functions.py` → `Run`

### 3.4 Advanced Features

#### Collaborative Analysis (Ghidra Server)

For team reverse engineering:

```bash
# Server setup (on shared machine)
cd /opt/tools/ghidra/server
./svrAdmin -add ciscoproject

# Start server
./ghidraSvr start

# Client connection (from Ghidra GUI)
# File -> New Project -> Shared Project
# Server: ghidra-server.example.com
# Repository: ciscoproject
```

#### Scripting Automation

**Python Script Example**: Find all authentication functions

```python
# ghidra_scripts/find_auth_functions.py
from ghidra.program.model.listing import CodeUnit

# Get current program
program = currentProgram
listing = program.getListing()

# Find all strings containing "auth"
strings = []
for address in program.getMemory().getAddresses(True):
    data = listing.getDataAt(address)
    if data and data.hasStringValue():
        string_value = data.getValue()
        if "auth" in str(string_value).lower():
            strings.append((address, string_value))

# Find functions referencing these strings
auth_functions = set()
for addr, string_val in strings:
    refs = getReferencesTo(addr)
    for ref in refs:
        func = getFunctionContaining(ref.getFromAddress())
        if func:
            auth_functions.add(func.getName())

# Print results
print("Authentication-related functions:")
for func_name in sorted(auth_functions):
    print(f"  - {func_name}")
```

#### Binary Diffing

Compare two versions of vpnagentd:

1. `Tools -> Version Tracking`
2. Select two programs: `vpnagentd_v5.0` and `vpnagentd_v5.1`
3. Ghidra highlights differences:
   - New functions (green)
   - Modified functions (yellow)
   - Deleted functions (red)

### 3.5 Ghidra for OTP/TOTP Discovery

**Real-World Example**: Finding TOTP generation function in vpnagentd

**Step 1**: Search for RFC 6238 constants

```
Search -> For Scalars...
Value: 30 (time step in seconds)
```

**Step 2**: Find HMAC-SHA1 calls

```
Search -> For Instruction Patterns...
Pattern: CALL HMAC*
```

**Step 3**: Cross-reference with "totp" strings

```
Search -> Program Text -> "totp"
```

**Result**: Function `vpn_totp_verify()` at `0x00425f80`

**Decompiled Output**:

```c
int vpn_totp_verify(const char *secret_b32, const char *user_input) {
    uint8_t secret[64];
    size_t secret_len;
    time_t now;
    uint32_t generated_code;
    uint32_t user_code;

    // Decode Base32 secret
    secret_len = base32_decode(secret_b32, secret, sizeof(secret));

    // Get current time
    now = time(NULL);

    // Generate TOTP code (±1 time window)
    for (int offset = -1; offset <= 1; offset++) {
        time_t test_time = now + (offset * 30);  // 30-second window
        generated_code = totp_generate(secret, secret_len, test_time);

        // Compare with user input (constant-time comparison)
        user_code = strtoul(user_input, NULL, 10);
        if (constant_time_compare(&generated_code, &user_code, 4) == 0) {
            return 0;  // Success
        }
    }

    return -1;  // Failed
}
```

**Conversion to C23** (for ocserv-modern):

```c
// src/auth/otp.c - Converted from Ghidra decompilation

#include <stdint.h>
#include <time.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include "base32.h"

[[nodiscard]] int
vpn_totp_verify(const char *secret_b32, const char *user_input)
{
    uint8_t secret[64] = {0};
    size_t secret_len;
    time_t now;
    uint32_t generated_code;
    uint32_t user_code;

    // Decode Base32 secret (RFC 4648)
    secret_len = base32_decode(secret_b32, secret, sizeof(secret));
    if (secret_len == 0) {
        return -1;
    }

    // Get current time
    now = time(nullptr);

    // TOTP time window: ±1 step (±30 seconds) per RFC 6238
    for (int offset = -1; offset <= 1; offset++) {
        time_t test_time = now + (offset * 30);

        // Generate TOTP code using wolfCrypt
        generated_code = totp_generate_wolfcrypt(secret, secret_len, test_time);

        // Parse user input
        user_code = (uint32_t)strtoul(user_input, nullptr, 10);

        // Constant-time comparison (prevent timing attacks)
        if (wolfSSL_consttime_equal(&generated_code, &user_code, sizeof(uint32_t))) {
            return 0;  // Authentication success
        }
    }

    return -1;  // Authentication failed
}

// Helper function (extracted from separate Ghidra analysis)
static uint32_t
totp_generate_wolfcrypt(const uint8_t *secret, size_t secret_len, time_t timestamp)
{
    uint64_t counter = (uint64_t)(timestamp / 30);  // 30-second time step
    uint8_t hmac_result[WC_SHA_DIGEST_SIZE];
    Hmac hmac;

    // Initialize HMAC-SHA1
    wc_HmacSetKey(&hmac, WC_SHA, secret, (word32)secret_len);

    // Compute HMAC(secret, counter)
    uint8_t counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }

    wc_HmacUpdate(&hmac, counter_bytes, 8);
    wc_HmacFinal(&hmac, hmac_result);

    // Dynamic truncation (RFC 6238 Section 5.3)
    uint8_t offset = hmac_result[19] & 0x0F;
    uint32_t code = ((hmac_result[offset] & 0x7F) << 24) |
                    ((hmac_result[offset + 1] & 0xFF) << 16) |
                    ((hmac_result[offset + 2] & 0xFF) << 8) |
                    (hmac_result[offset + 3] & 0xFF);

    return code % 1000000;  // 6-digit code
}
```

### 3.6 Performance Tips

**Optimize Analysis Speed**:
1. **Disable unnecessary analyzers**: `Analysis -> Auto Analyze -> Configure`
   - Disable "Non-Returning Functions" (slow)
   - Disable "Windows x86 PE RTTI Analyzer" (Linux binaries)

2. **Increase memory**: Edit `ghidraRun` script
   ```bash
   # Change MAXMEM
   MAXMEM=8G  # Default is 4G
   ```

3. **Use SSD storage**: Ghidra database I/O-intensive

**Keyboard Shortcuts**:
- `G` - Go to address
- `L` - Edit label (rename function/variable)
- `T` - Edit data type
- `Ctrl+Shift+E` - Edit function signature
- `;` - Add comment
- `Ctrl+F` - Find text

### 3.7 Common Issues and Solutions

**Issue**: "Decompiler process timed out"
**Solution**: Increase timeout in `Edit -> Tool Options -> Decompiler -> Analysis -> Decompiler Timeout`
Set to: `300` seconds

**Issue**: Incorrect function parameters
**Solution**: Manually fix signature: Right-click function → `Edit Function Signature`

**Issue**: Ghidra crashes on large binary
**Solution**:
1. Increase JVM heap: `-Xmx16G` in `ghidraRun`
2. Analyze in sections: Disable full auto-analysis, analyze functions incrementally

---

## 4. Tool 2: Reko Decompiler

### 4.1 Overview

**Reko** is an open-source machine code decompiler with excellent type reconstruction capabilities. It excels at recovering complex data structures from stripped binaries.

**Version**: 0.12.0+ (December 2024)
**License**: GPLv2
**Repository**: https://github.com/uxmal/reko
**Platform**: Windows (native), Linux/macOS (via Mono)

**Key Strengths**:
1. **Type Inference**: Best-in-class automatic struct/class recovery
2. **Fast Analysis**: 2-5x faster than Ghidra for medium binaries
3. **Clean C Output**: More readable than Ghidra for simple functions
4. **Data Flow Analysis**: Excellent for understanding variable usage

**Use Cases for ocserv-modern**:
- Library function analysis (libvpnapi.so)
- Struct definition recovery (connection state, session context)
- API endpoint discovery

### 4.2 Installation (Oracle Linux 9)

#### Method 1: Mono (Recommended for Linux)

```bash
# Install Mono runtime
sudo dnf install -y mono-complete

# Download Reko
cd /opt/tools
sudo wget https://github.com/uxmal/reko/releases/download/version-0.12.0/Reko-0.12.0.zip
sudo unzip Reko-0.12.0.zip -d reko
cd reko

# Test installation
mono Reko.exe --version
```

#### Method 2: Build from Source (for latest features)

```bash
# Install .NET SDK 8.0+
sudo dnf install -y dotnet-sdk-8.0

# Clone repository
cd /opt/tools
git clone https://github.com/uxmal/reko.git reko-src
cd reko-src

# Build
dotnet build -c Release src/Reko.sln

# Run
dotnet run --project src/Drivers/CmdLine/CmdLine.csproj
```

### 4.3 Usage for Cisco Secure Client Binaries

#### Command-Line Decompilation

**Basic Usage**:

```bash
cd /opt/tools/reko

# Decompile libvpnapi.so
mono Reko.exe \
    --arch=x86-64 \
    --loader=elf \
    --output=/opt/analysis/reko_output \
    /opt/projects/repositories/cisco-secure-client/linux/libvpnapi.so
```

**Parameters**:
- `--arch`: Target architecture (`x86-64`, `arm64`, `arm32`)
- `--loader`: Binary format (`elf`, `pe`, `macho`)
- `--output`: Output directory
- `--default-to=c`: Output format (C by default)

**Output Files**:
```
/opt/analysis/reko_output/
├── libvpnapi.c          # Decompiled C code
├── libvpnapi.h          # Header with struct definitions
├── libvpnapi.asm        # Disassembly
├── libvpnapi.globals.c  # Global variables
└── libvpnapi.project    # Reko project file
```

#### GUI Mode

```bash
# Launch Reko GUI
mono Reko.exe
```

**GUI Workflow**:
1. `File -> Open` → Select `libvpnapi.so`
2. Reko auto-detects architecture and loader
3. `Analysis -> Scan Program` (automatic analysis)
4. Navigate functions in left pane
5. View decompiled code in right pane
6. `File -> Export -> C Files`

### 4.4 Type Reconstruction Example

**Scenario**: Recover VPN session struct from libvpnapi.so

**Step 1**: Decompile library

```bash
mono Reko.exe --arch=x86-64 --loader=elf libvpnapi.so
```

**Step 2**: Examine generated header (`libvpnapi.h`)

**Reko Auto-Generated Struct**:

```c
// Reko inferred struct (before cleanup)
struct Eq_10 {
    uint32_t dw0000;          // +0x00
    byte * ptr0004;           // +0x04
    uint64_t qw0008;          // +0x08
    uint64_t qw0010;          // +0x10
    char a0018[256];          // +0x18
    struct Eq_20 * ptr0118;   // +0x118
    uint16_t w011C;           // +0x11C
    uint32_t dw0120;          // +0x120
};

struct Eq_20 {
    byte b0000;
    byte b0001;
    // ... TLS context fields
};
```

**Step 3**: Annotate with domain knowledge

**Cleaned Struct** (for ocserv-modern):

```c
// src/vpn_session.h
// Reconstructed from Reko analysis + Cisco protocol knowledge

typedef struct vpn_session {
    uint32_t session_id;                // +0x00: Unique session identifier
    uint8_t *session_token;             // +0x04: Authentication token
    uint64_t created_time;              // +0x08: Unix timestamp (connect)
    uint64_t expire_time;               // +0x10: Session expiration
    char username[256];                 // +0x18: Authenticated user
    struct tls_context *tls_ctx;        // +0x118: TLS/DTLS context
    uint16_t mtu;                       // +0x11C: Path MTU
    uint32_t flags;                     // +0x120: Session flags
} vpn_session_t;

// Session flags (reverse engineered from function analysis)
#define VPN_SESSION_FLAG_DTLS_ENABLED    (1U << 0)
#define VPN_SESSION_FLAG_IPV6_ENABLED    (1U << 1)
#define VPN_SESSION_FLAG_SPLIT_TUNNEL    (1U << 2)
#define VPN_SESSION_FLAG_OTP_VERIFIED    (1U << 3)
```

### 4.5 API Endpoint Discovery

**Scenario**: Find all exported OTP functions in libvpnapi.so

**Step 1**: Analyze exports

```bash
mono Reko.exe libvpnapi.so
# Wait for analysis to complete

# Reko GUI: View -> Procedures
# Filter: "otp"
```

**Discovered Functions**:
```
vpn_otp_init                  @ 0x00023450
vpn_otp_verify                @ 0x00023680
vpn_otp_provision_secret      @ 0x00023a20
vpn_totp_generate_code        @ 0x00023d50
vpn_otp_get_qr_code           @ 0x00024100
```

**Step 2**: Export function signatures

Reko generates:

```c
// libvpnapi.h (excerpt)

int32_t vpn_otp_init(void *ctx, const char *config_path);

int32_t vpn_otp_verify(
    void *ctx,
    const char *username,
    const char *otp_code,
    uint32_t *result_flags
);

int32_t vpn_otp_provision_secret(
    void *ctx,
    const char *username,
    uint8_t *secret_out,
    size_t secret_size
);

uint32_t vpn_totp_generate_code(
    const uint8_t *secret,
    size_t secret_len,
    uint64_t timestamp
);

int32_t vpn_otp_get_qr_code(
    const char *secret_b32,
    const char *username,
    char *qr_url_out,
    size_t url_size
);
```

### 4.6 Advantages over Ghidra

1. **Faster Analysis**: Reko completes in minutes what Ghidra takes hours
2. **Better Structs**: Automatic field naming based on usage patterns
3. **Cleaner Output**: Less verbose C code for simple functions
4. **Batch Processing**: Easier to script for analyzing multiple binaries

### 4.7 Limitations

1. **No Symbolic Execution**: Cannot explore all code paths like angr
2. **Limited Scripting**: C#/Python API less mature than Ghidra
3. **GUI Crashes**: Unstable with very large binaries (>10 MB)
4. **ARM Support**: x86_64 analysis better than ARM64

---

## 5. Tool 3: angr Symbolic Execution

### 5.1 Overview

**angr** is a Python framework for binary analysis with symbolic execution capabilities. Unlike decompilers, angr *executes* the binary symbolically to explore all possible code paths.

**Version**: 9.2+ (January 2025)
**License**: BSD 2-Clause
**Repository**: https://github.com/angr/angr
**Documentation**: https://docs.angr.io/

**Key Strengths**:
1. **Symbolic Execution**: Explore all paths through a function
2. **Constraint Solving**: Find inputs that trigger specific behaviors
3. **Vulnerability Discovery**: Automatically find buffer overflows, integer overflows
4. **Path Explosion Management**: Heuristics to handle complex control flow

**Use Cases for ocserv-modern**:
- Find authentication bypass paths
- Discover input validation bugs
- Analyze OTP/TOTP generation logic
- Test crypto implementations
- Generate fuzzing test cases

### 5.2 Installation (Oracle Linux 9 / Python Virtual Environment)

```bash
# Install system dependencies
sudo dnf install -y python3.11 python3.11-devel gcc g++ make \
    libxml2-devel libxslt-devel libffi-devel

# Create virtual environment
mkdir -p /opt/tools/angr-env
python3.11 -m venv /opt/tools/angr-env
source /opt/tools/angr-env/bin/activate

# Upgrade pip
pip install --upgrade pip setuptools wheel

# Install angr and related tools
pip install angr angr-management

# Install additional dependencies
pip install capstone keystone-engine unicorn

# Verify installation
python -c "import angr; print(angr.__version__)"
# Expected: 9.2.x
```

### 5.3 Basic Usage: Analyzing Authentication Flow

**Scenario**: Find inputs that cause `vpn_auth_verify()` to return success (0)

**Step 1**: Load Binary

```python
#!/usr/bin/env python3
# analyze_auth_flow.py

import angr
import claripy

# Load vpnagentd binary
project = angr.Project(
    '/opt/projects/repositories/cisco-secure-client/linux/vpnagentd',
    auto_load_libs=False  # Skip loading shared libraries for speed
)

print(f"Loaded binary: {project.filename}")
print(f"Architecture: {project.arch}")
print(f"Entry point: {hex(project.entry)}")
```

**Step 2**: Locate Target Function

From Ghidra analysis, we know `vpn_auth_verify()` is at address `0x00425f80`.

```python
# Function address (from Ghidra)
AUTH_FUNC_ADDR = 0x00425f80

# Success address (return 0) - found via static analysis
SUCCESS_ADDR = 0x00426120

# Failure addresses (return -1)
FAILURE_ADDRS = [0x00426150, 0x00426180]
```

**Step 3**: Create Symbolic State

```python
# Create symbolic input for password (32 bytes)
password = claripy.BVS('password', 8 * 32)  # 32-byte symbolic bitvector

# Create symbolic input for username (64 bytes)
username = claripy.BVS('username', 8 * 64)

# Create blank state at function entry
state = project.factory.blank_state(addr=AUTH_FUNC_ADDR)

# Place symbolic inputs in memory (simulating stack)
PASSWORD_ADDR = 0x7fff0000
USERNAME_ADDR = 0x7fff1000

state.memory.store(PASSWORD_ADDR, password)
state.memory.store(USERNAME_ADDR, username)

# Set function arguments (x86_64 calling convention: RDI, RSI, RDX)
state.regs.rdi = USERNAME_ADDR  # First arg: username pointer
state.regs.rsi = PASSWORD_ADDR  # Second arg: password pointer
state.regs.rdx = 32             # Third arg: password length
```

**Step 4**: Symbolic Execution

```python
# Create simulation manager
simgr = project.factory.simulation_manager(state)

# Explore paths until we find success
print("Starting symbolic execution...")
simgr.explore(find=SUCCESS_ADDR, avoid=FAILURE_ADDRS)

print(f"Found {len(simgr.found)} successful paths")
print(f"Avoided {len(simgr.avoid)} failure paths")
```

**Step 5**: Extract Constraints

```python
if simgr.found:
    found_state = simgr.found[0]  # First successful path

    # Solve for password that leads to success
    password_solution = found_state.solver.eval(password, cast_to=bytes)
    username_solution = found_state.solver.eval(username, cast_to=bytes)

    print(f"Found valid credentials:")
    print(f"  Username: {username_solution.decode('utf-8', errors='ignore')}")
    print(f"  Password: {password_solution.decode('utf-8', errors='ignore')}")

    # Get constraints that led to success
    constraints = found_state.solver.constraints
    print(f"\nConstraints ({len(constraints)} total):")
    for i, constraint in enumerate(constraints[:5]):  # Show first 5
        print(f"  {i+1}. {constraint}")
else:
    print("No successful path found (authentication is secure)")
```

### 5.4 Advanced Example: OTP Time Window Analysis

**Scenario**: Verify TOTP implementation allows ±1 time step (RFC 6238 compliance)

```python
#!/usr/bin/env python3
# analyze_totp_window.py

import angr
import claripy

project = angr.Project('vpnagentd', auto_load_libs=False)

# TOTP verify function address (from Ghidra)
TOTP_VERIFY_ADDR = 0x00425f80

# Create symbolic timestamp
timestamp = claripy.BVS('timestamp', 64)  # 64-bit time_t

# Create known OTP code (as symbolic for now)
otp_code = claripy.BVS('otp_code', 32)  # 32-bit code

# Setup state
state = project.factory.blank_state(addr=TOTP_VERIFY_ADDR)

SECRET_ADDR = 0x7fff0000
OTP_CODE_ADDR = 0x7fff0100

# Hard-code a test secret (Base32 encoded)
test_secret = b'JBSWY3DPEHPK3PXP'  # "Hello World" in Base32
state.memory.store(SECRET_ADDR, test_secret)

# Store symbolic OTP code
state.memory.store(OTP_CODE_ADDR, otp_code)

# Set arguments
state.regs.rdi = SECRET_ADDR      # Secret
state.regs.rsi = OTP_CODE_ADDR    # User OTP input
state.regs.rdx = timestamp        # Current timestamp (symbolic)

# Explore
simgr = project.factory.simulation_manager(state)
simgr.explore(find=lambda s: s.regs.rax == 0)  # Find success paths

# Analyze time windows
if simgr.found:
    print("TOTP time window analysis:")

    for i, found_state in enumerate(simgr.found):
        # Get timestamp that leads to success
        ts_solution = found_state.solver.eval(timestamp)

        print(f"\nPath {i+1}:")
        print(f"  Timestamp: {ts_solution}")
        print(f"  Time step: {ts_solution // 30}")

        # Check if within ±1 step of current time
        import time
        current_time = int(time.time())
        current_step = current_time // 30
        solution_step = ts_solution // 30

        delta_steps = abs(solution_step - current_step)
        print(f"  Delta from now: {delta_steps} steps")

        if delta_steps <= 1:
            print("  ✓ Within acceptable window (RFC 6238 compliant)")
        else:
            print(f"  ✗ SECURITY ISSUE: Accepts {delta_steps}-step difference!")
else:
    print("No successful authentication path found")
```

### 5.5 Vulnerability Discovery: Buffer Overflow Check

**Scenario**: Check if input validation allows buffer overflow in username field

```python
#!/usr/bin/env python3
# check_buffer_overflow.py

import angr
import claripy

project = angr.Project('vpnagentd', auto_load_libs=False)

# Function that processes username input
PROCESS_INPUT_ADDR = 0x00423a00

# Create symbolic username input (unlimited size)
username_size = claripy.BVS('username_size', 32)  # Symbolic size
username_data = claripy.BVS('username_data', 8 * 512)  # Up to 512 bytes

# Setup state
state = project.factory.blank_state(addr=PROCESS_INPUT_ADDR)

INPUT_BUFFER_ADDR = 0x7fff0000
state.memory.store(INPUT_BUFFER_ADDR, username_data)

state.regs.rdi = INPUT_BUFFER_ADDR  # Buffer pointer
state.regs.rsi = username_size      # Buffer size (symbolic)

# Add constraint: username_size can be anything from 0 to 1024
state.solver.add(username_size >= 0)
state.solver.add(username_size <= 1024)

# Explore with memory corruption detection
simgr = project.factory.simulation_manager(state)

# Find stack corruption (return address overwrite)
def check_corruption(state):
    # Check if return address on stack is symbolic (overwritten)
    rsp = state.regs.rsp
    ret_addr = state.memory.load(rsp, 8)
    return ret_addr.symbolic

simgr.explore(find=check_corruption)

if simgr.found:
    print("BUFFER OVERFLOW DETECTED!")

    for found_state in simgr.found:
        # Get size that causes overflow
        overflow_size = found_state.solver.eval(username_size)
        print(f"  Overflow triggered with size: {overflow_size}")

        # Get input data that causes overflow
        overflow_data = found_state.solver.eval(username_data, cast_to=bytes)
        print(f"  Payload: {overflow_data[:64].hex()}...")
else:
    print("✓ No buffer overflow detected (input validation present)")
```

### 5.6 Integration with ocserv-modern: Test Case Generation

**Goal**: Generate test cases for fuzzing OTP implementation

```python
#!/usr/bin/env python3
# generate_otp_testcases.py

import angr
import claripy
import json

project = angr.Project('vpnagentd', auto_load_libs=False)

# OTP verify function
OTP_VERIFY_ADDR = 0x00425f80

test_cases = []

# Generate 100 test cases with different constraints
for i in range(100):
    otp_code = claripy.BVS(f'otp_code_{i}', 32)

    state = project.factory.blank_state(addr=OTP_VERIFY_ADDR)
    state.regs.rdi = 0x7fff0000  # Secret (pre-populated)
    state.regs.rsi = otp_code    # OTP code (symbolic)

    simgr = project.factory.simulation_manager(state)
    simgr.run(n=10)  # Execute 10 basic blocks

    # Pick a random state
    if simgr.active:
        active_state = simgr.active[0]

        # Generate concrete OTP code
        concrete_code = active_state.solver.eval(otp_code)

        # Determine if this code should pass or fail
        # (based on symbolic execution results)
        should_pass = active_state.regs.rax == 0

        test_cases.append({
            'otp_code': f'{concrete_code:06d}',
            'expected_result': 'pass' if should_pass else 'fail',
            'constraints': str(active_state.solver.constraints)
        })

# Export test cases
with open('/opt/analysis/otp_test_cases.json', 'w') as f:
    json.dump(test_cases, f, indent=2)

print(f"Generated {len(test_cases)} test cases")
```

**Use in ocserv-modern CI/CD**:

```c
// tests/unit/test_otp_fuzzing.c
// Generated from angr analysis

#include <CUnit/CUnit.h>
#include "auth/otp.h"

void test_otp_case_001(void) {
    // Test case generated by angr
    const char *secret = "JBSWY3DPEHPK3PXP";
    const char *otp = "123456";

    int result = vpn_otp_verify(secret, otp);
    CU_ASSERT_EQUAL(result, -1);  // Expected: fail
}

void test_otp_case_002(void) {
    // Valid OTP code (angr found this leads to success)
    const char *secret = "JBSWY3DPEHPK3PXP";
    const char *otp = "654321";

    int result = vpn_otp_verify(secret, otp);
    CU_ASSERT_EQUAL(result, 0);  // Expected: pass
}

// ... 98 more test cases
```

### 5.7 Performance and Limitations

**Path Explosion Problem**:
- Complex functions have millions of paths
- angr uses heuristics to prune unlikely paths
- May miss edge cases

**Solutions**:
1. **Limit exploration depth**: `simgr.run(n=100)` (max 100 basic blocks)
2. **Use veritesting**: `simgr.use_technique(angr.exploration_techniques.Veritesting())`
3. **Constrain inputs**: Reduce symbolic input size

**Typical Analysis Time**:
- Simple function (50 LOC): 1-5 minutes
- Medium function (200 LOC): 10-30 minutes
- Complex function (500+ LOC): 1+ hours (may timeout)

### 5.8 angr Management GUI

For visual analysis:

```bash
source /opt/tools/angr-env/bin/activate
angr-management
```

**GUI Features**:
- Interactive CFG (Control Flow Graph)
- Symbolic execution visualization
- Constraint browser
- Memory viewer

---

## 6. Tool 4: Rec Decompiler (Legacy)

### 6.1 Overview

**Rec** (Reverse Engineering Compiler) is an older decompiler primarily for MS-DOS and 16-bit Windows binaries. It has limited use for modern Linux x86_64/ARM64 analysis.

**Version**: 1.6 (last update: 2004)
**License**: Proprietary (free for personal use)
**Website**: http://www.backerstreet.com/rec/rec.htm
**Platform**: Windows (DOS/Win32) only

**Historical Significance**:
- One of the first practical decompilers (1990s)
- Pioneered many techniques used in Ghidra/IDA Pro

### 6.2 Limited Applicability

**When to Use Rec**:
1. ✅ Analyzing legacy AnyConnect 16-bit DOS installers (historical research)
2. ✅ Reverse engineering Windows 32-bit PE DOS stubs
3. ❌ NOT suitable for Linux ELF binaries
4. ❌ NOT suitable for 64-bit binaries
5. ❌ NOT suitable for ARM architecture

**Recommendation**: ⚠️ **SKIP FOR OCSERV-MODERN** - Use Ghidra instead

### 6.3 Installation (Windows Only)

If absolutely necessary for legacy analysis:

```powershell
# Download from http://www.backerstreet.com/rec/recdload.htm
# Extract to C:\rec

# Run
C:\rec\rec.exe C:\path\to\oldfile.exe
```

### 6.4 Why Rec is Obsolete for Modern Analysis

| Feature | Rec (2004) | Ghidra (2025) |
|---------|------------|---------------|
| 64-bit support | ❌ | ✅ |
| Linux ELF | ❌ | ✅ |
| ARM/ARM64 | ❌ | ✅ |
| Modern C++ | ❌ | ✅ |
| Active development | ❌ | ✅ |
| Scripting | ❌ | ✅ |

---

## 7. Tool Selection Guide

### 7.1 Decision Matrix

**For Function-Level Analysis** (e.g., OTP functions):
→ **Ghidra** (best decompiler output, annotations)

**For Struct Recovery** (e.g., session context):
→ **Reko** (fastest type inference)

**For Security Analysis** (e.g., find auth bypass):
→ **angr** (symbolic execution)

**For Legacy Code** (e.g., old installers):
→ **Rec** (DOS/Win16 only) or **Skip**

### 7.2 Workflow Recommendation

**Phase 1: Quick Reconnaissance** (30 minutes)
1. Use `strings` and `nm` for basic symbol/string extraction
2. Use **Reko** for fast struct recovery

**Phase 2: Deep Analysis** (2-4 hours)
1. Use **Ghidra** for detailed function decompilation
2. Annotate and rename variables/functions
3. Export C code

**Phase 3: Security Validation** (1-2 hours)
1. Use **angr** to verify authentication logic
2. Check for buffer overflows, integer overflows
3. Generate test cases

**Phase 4: Implementation** (ongoing)
1. Convert Ghidra pseudocode to C23
2. Implement in ocserv-modern with wolfSSL/wolfCrypt
3. Validate against Cisco client behavior

### 7.3 Complementary Tool Usage

**Combine Tools for Best Results**:

```bash
# Step 1: Reko for struct definitions
mono reko.exe libvpnapi.so
# → Generates libvpnapi.h with structs

# Step 2: Ghidra for function logic
ghidra libvpnapi.so
# → Decompile specific functions, use Reko structs

# Step 3: angr for verification
python analyze_auth_flow.py
# → Verify no auth bypass exists
```

---

## 8. Integration with ocserv-modern

### 8.1 Decompiled Code to C23 Conversion Checklist

**From Ghidra/Reko Output**:
1. ✅ Replace generic types (`int`, `uint32_t`) with C23 types (`int32_t`, `uint32_t`)
2. ✅ Add `[[nodiscard]]` attribute to functions returning status codes
3. ✅ Replace `NULL` with `nullptr` (C23)
4. ✅ Use `constexpr` for constants (instead of `#define`)
5. ✅ Add bounds checking for buffers
6. ✅ Replace Cisco crypto calls with wolfCrypt equivalents
7. ✅ Add comprehensive error handling
8. ✅ Document assumptions in comments

**Example Conversion**:

**Ghidra Output**:
```c
int FUN_00412a50(longlong param_1, uint param_2) {
    byte *pbVar1;
    uint uVar2;

    if (param_2 > 6) {
        return -1;
    }

    pbVar1 = (byte*)(param_1 + 0x10);
    uVar2 = FUN_00401234(pbVar1, param_2);

    return uVar2;
}
```

**C23 Converted**:
```c
// src/auth/otp.c
// Converted from Ghidra decompilation

#include <stdint.h>
#include <wolfssl/wolfcrypt/hmac.h>

[[nodiscard]] int32_t
vpn_otp_validate_code(const otp_context_t *ctx, uint32_t user_code)
{
    // Input validation (added for safety)
    if (!ctx || user_code > 999999) {
        return -1;
    }

    // Original logic preserved
    const uint8_t *secret = ctx->secret;
    uint32_t generated_code = totp_generate_wolfcrypt(secret, ctx->secret_len);

    // Constant-time comparison (security improvement)
    return wolfSSL_consttime_equal(&generated_code, &user_code, sizeof(uint32_t)) ? 0 : -1;
}
```

### 8.2 Automated Script for Conversion

```bash
#!/bin/bash
# scripts/convert_ghidra_to_c23.sh

INPUT_FILE="$1"
OUTPUT_FILE="$2"

# Replace NULL with nullptr
sed -i 's/\bNULL\b/nullptr/g' "$INPUT_FILE"

# Replace int with int32_t (manual review recommended)
sed -i 's/\bint\s/int32_t /g' "$INPUT_FILE"

# Add [[nodiscard]] to functions returning int
sed -i '/^int32_t /s/^/[[nodiscard]] /' "$INPUT_FILE"

# Add header comment
sed -i '1i // GENERATED FROM GHIDRA DECOMPILATION' "$INPUT_FILE"
sed -i '2i // Date: 2025-10-29' "$INPUT_FILE"
sed -i '3i // Manually reviewed and converted to C23' "$INPUT_FILE"

# Format with clang-format (C23 style)
clang-format -i --style=file "$INPUT_FILE"

cp "$INPUT_FILE" "$OUTPUT_FILE"
echo "Converted: $INPUT_FILE -> $OUTPUT_FILE"
```

### 8.3 Validation Against Cisco Client

**Test Harness**:

```c
// tests/integration/test_cisco_compatibility.c
// Validate decompiled OTP logic against real Cisco client

#include <CUnit/CUnit.h>
#include "auth/otp.h"

void test_otp_matches_cisco_client(void) {
    // Known test vector from Cisco documentation
    const char *secret_b32 = "JBSWY3DPEHPK3PXP";
    const uint32_t expected_code = 123456;  // At specific timestamp
    const time_t test_time = 1700000000;

    // Generate code using our implementation
    uint32_t generated = vpn_totp_generate(secret_b32, test_time);

    // Compare with Cisco expected value
    CU_ASSERT_EQUAL(generated, expected_code);
}
```

---

## 9. Security and Legal Considerations

### 9.1 Reverse Engineering Legality

**United States (DMCA)**:
- ✅ Reverse engineering for interoperability is **legal** under 17 U.S.C. § 1201(f)
- ✅ ocserv-modern is an **interoperable implementation**, not a circumvention tool
- ⚠️ Do NOT distribute Cisco binaries or proprietary code

**European Union (Software Directive)**:
- ✅ Article 6: "Decompilation for interoperability" explicitly permitted
- ✅ Article 5: Reverse engineering for bug fixing and security research allowed

**Recommendations**:
1. ✅ Analyze legally obtained Cisco Secure Client binaries (purchased license)
2. ✅ Document that analysis is for interoperability only
3. ❌ Do NOT copy/paste proprietary Cisco code
4. ✅ Implement algorithms from scratch using public RFCs (RFC 6238 for TOTP)
5. ✅ Clean-room implementation: Separate teams for analysis and coding

### 9.2 Ethical Guidelines

**Do**:
- ✅ Analyze for protocol compatibility
- ✅ Document security vulnerabilities and report to Cisco
- ✅ Implement clean-room reimplementations
- ✅ Contribute findings to open-source community

**Do NOT**:
- ❌ Extract proprietary algorithms not documented in RFCs
- ❌ Bypass license restrictions
- ❌ Distribute Cisco binaries or keys
- ❌ Implement proprietary extensions without permission

### 9.3 Responsible Disclosure

If vulnerabilities are discovered during analysis:

1. **Report to Cisco PSIRT**: psirt@cisco.com
2. **90-Day Disclosure Window**: Allow Cisco time to patch
3. **Document in ocserv-modern**: Note "This issue was found in Cisco client and reported"

---

## 10. References

### 10.1 Tool Documentation

**Ghidra**:
- Official Site: https://ghidra-sre.org/
- GitHub: https://github.com/NationalSecurityAgency/ghidra
- API Docs: https://ghidra.re/ghidra_docs/api/
- Training: https://www.youtube.com/c/GhidraNinja

**Reko**:
- GitHub: https://github.com/uxmal/reko
- Wiki: https://github.com/uxmal/reko/wiki

**angr**:
- Documentation: https://docs.angr.io/
- GitHub: https://github.com/angr/angr
- CTF Examples: https://github.com/angr/angr-ctf

**Rec**:
- Homepage: http://www.backerstreet.com/rec/

### 10.2 Reverse Engineering Resources

**Books**:
- "Practical Binary Analysis" by Dennis Andriesse (2018)
- "The IDA Pro Book" by Chris Eagle (2011) - applicable to Ghidra
- "Hacking: The Art of Exploitation" by Jon Erickson (2008)

**Online Courses**:
- Ghidra Software Reverse Engineering (Udemy)
- Malware Analysis and Reverse Engineering (SANS FOR610)

**Communities**:
- r/ReverseEngineering (Reddit)
- Ghidra Discord: https://discord.gg/ghidra
- Stack Overflow: [ghidra], [angr], [reverse-engineering] tags

### 10.3 Related ocserv-modern Documentation

- **String Analysis**: `/opt/projects/repositories/cisco-secure-client/analysis/REVERSE_ENGINEERING_FINDINGS.md`
- **OTP Implementation**: `/opt/projects/repositories/cisco-secure-client/analysis/OTP_IMPLEMENTATION.md`
- **Crypto Analysis**: `/opt/projects/repositories/cisco-secure-client/analysis/CRYPTO_ANALYSIS.md`
- **wolfSSL Integration**: `/opt/projects/repositories/cisco-secure-client/analysis/WOLFSSL_INTEGRATION.md`

---

**Document Maintainer**: ocserv-modern Development Team
**Last Updated**: 2025-10-29
**Status**: Production Ready
