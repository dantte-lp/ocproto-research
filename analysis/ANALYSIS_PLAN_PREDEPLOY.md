# Cisco Secure Client Predeploy Package Analysis Plan

**Project**: WolfGuard VPN - OpenConnect Protocol Reverse Engineering
**Scope**: Standalone installer packages (predeploy) across 4 major versions
**Legal Basis**: DMCA §1201(f) - Reverse Engineering for Interoperability
**Duration**: 6 weeks (240 hours estimated)
**Priority**: High (Critical for protocol implementation)
**Status**: 🔄 **READY TO START**

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope Definition](#scope-definition)
3. [Binary Inventory](#binary-inventory)
4. [Analysis Phases](#analysis-phases)
5. [Week-by-Week Timeline](#week-by-week-timeline)
6. [Deliverables](#deliverables)
7. [Tool Requirements](#tool-requirements)
8. [Risk Mitigation](#risk-mitigation)
9. [Success Criteria](#success-criteria)

---

## Executive Summary

### Objective

Conduct comprehensive reverse engineering analysis of Cisco Secure Client **predeploy packages** (standalone installers) across 4 major versions (4.9.06037, 4.10.08029, 5.0.05040, 5.1.12.146) to extract:

1. **VPN protocol implementation** (CSTP, DTLS, TLS 1.2/1.3)
2. **Authentication flows** (certificate, SAML, EAP-FAST, smartcard)
3. **Cryptographic implementations** (cipher suites, key exchange, certificates)
4. **Module architecture** (VPN core, Secure Firewall Posture, DART, NVM, ISE Posture)
5. **Binary structure and dependencies** (libraries, frameworks, system integration)

### Why Predeploy Packages?

Predeploy packages are **self-contained, standalone installers** that include:
- All VPN core binaries (vpnagentd, vpnui, vpndownloader, vpnagent)
- Security modules (Secure Firewall Posture/HostScan, ISE Posture)
- Diagnostic tools (DART)
- Network Visibility Module (NVM)
- Additional modules (Umbrella, ThousandEyes in 5.x)

**Advantages:**
- ✅ Complete feature set (no server-side dependencies)
- ✅ Version-consistent binaries (no incremental updates)
- ✅ Easier extraction and analysis (single package per platform)
- ✅ Represents production deployment scenario

### Expected Outcomes

1. **Protocol Specification Document**: Detailed CSTP/DTLS/TLS 1.3 implementation guide
2. **Cipher Suite Matrix**: Version-by-version comparison of supported algorithms
3. **Authentication Flow Diagrams**: Sequence diagrams for all auth methods
4. **Cryptographic Analysis**: Key exchange, certificate validation, session management
5. **Binary Catalog**: Complete dependency mapping and library usage
6. **WolfGuard Implementation Roadmap**: Prioritized feature list for ocserv integration

---

## Scope Definition

### In Scope

#### Platforms

| Platform | Version Coverage | Package Types | Priority |
|----------|------------------|---------------|----------|
| **Linux x86_64** | All 4 versions (4.9, 4.10, 5.0, 5.1) | .tar.gz predeploy | **Highest** |
| **Linux ARM64** | 5.1 only | .tar.gz predeploy | **High** |
| **Windows x64** | All 4 versions | .msi predeploy | **Medium** |
| **macOS Intel** | All 4 versions | .pkg/.dmg predeploy | **Medium** |
| **macOS ARM (M1/M2)** | 4.10, 5.0, 5.1 | .pkg Universal Binary | **Low** |
| **Windows ARM64** | 4.9, 5.0, 5.1 (4.10 removed) | .msi predeploy | **Low** |

**Rationale**: Linux x86_64 prioritized as WolfGuard/ocserv primary target platform; ARM64/Windows/macOS for cross-platform compatibility validation.

#### Binary Components

**High Priority** (VPN Core):
- `vpnagentd` - VPN daemon (main protocol implementation)
- `vpnui` - User interface (connection logic, auth flows)
- `vpndownloader` - Update mechanism
- `vpnagent` - Helper process
- `libvpnapi.so` / `vpnapi.dll` - VPN API library
- `libacciscossl.so` / `acciscossl.dll` - Cisco SSL/TLS library (**CRITICAL**)
- `libacciscocrypto.so` / `acciscocrypto.dll` - Crypto library (**CRITICAL**)

**Medium Priority** (Security Modules):
- `aciseposture` / `ciscod.exe` - ISE Posture client
- `acwebhelper` / `acwebhelper.exe` - Web-based authentication helper
- `manifesttool` - Certificate/manifest validation
- `cscan` / `cscan.exe` - Secure Firewall Posture scanner

**Low Priority** (Utilities):
- `acinstallhelper` - Installation helper
- `vpndownloader-cli` - CLI update tool
- `dart` / `DART.exe` - Diagnostic tool
- `nvm` / `nvm.exe` - Network Visibility Module

#### Analysis Depth

| Component | Analysis Level | Tools | Estimated Hours |
|-----------|----------------|-------|-----------------|
| **libacciscossl.so** | Deep (function-level decompilation) | IDA Pro | 60h |
| **vpnagentd** | Deep (protocol flows, state machines) | IDA Pro | 50h |
| **vpnui** | Medium (auth flows, UI logic) | Ghidra | 30h |
| **libacciscocrypto.so** | Deep (crypto implementations) | IDA Pro | 40h |
| **ISE Posture** | Medium (posture assessment protocol) | Ghidra | 20h |
| **Secure Firewall Posture** | Low (scanner logic overview) | Ghidra | 10h |
| **DART** | Low (diagnostic data collection) | Ghidra | 10h |
| **NVM** | Medium (IPFIX telemetry protocol) | Ghidra | 20h |

**Total**: ~240 hours (6 weeks @ 40h/week)

### Out of Scope

❌ **Webdeploy packages** (covered in separate ANALYSIS_PLAN_WEBDEPLOY.md)
❌ **Utils packages** (Profile Editor, VPN API SDK - covered in ANALYSIS_PLAN_UTILS.md)
❌ **Mobile platforms** (Android, iOS - separate analysis required)
❌ **Source code review** (proprietary; binary-only analysis)
❌ **Dynamic runtime analysis** (requires licensed ASA headend)
❌ **Exploit development** (defensive research only)

---

## Binary Inventory

### Package Distribution

| Version | Linux x64 | Linux ARM64 | Windows x64 | Windows ARM64 | macOS Intel | macOS ARM | Total Size |
|---------|-----------|-------------|-------------|---------------|-------------|-----------|------------|
| **4.9.06037** | ✅ 95 MB | ❌ | ✅ 110 MB | ✅ 18 MB | ✅ 31 MB | ❌ | **254 MB** |
| **4.10.08029** | ✅ 101 MB | ❌ | ✅ 119 MB | ❌ **REMOVED** | ✅ 35 MB | ✅ 35 MB | **290 MB** |
| **5.0.05040** | ✅ 108 MB | ❌ | ✅ 125 MB | ✅ 19 MB | ✅ 38 MB | ❌ | **290 MB** |
| **5.1.12.146** | ✅ 322 MB | ✅ **NEW** 201 MB | ✅ 378 MB | ❌ **REMOVED** | ✅ 99 MB | ✅ 99 MB | **1.1 GB** |
| **Total** | **626 MB** | **201 MB** | **732 MB** | **37 MB** | **203 MB** | **134 MB** | **1.93 GB** |

:::info Git Ignored
All binary packages are git-ignored per `.gitignore`. Stored locally at:
```
/opt/projects/repositories/cisco-secure-client/binaries/
```
:::

### Package Naming Convention

```
cisco-secure-client-{platform}-{version}-predeploy-k9.{ext}

Examples:
- cisco-secure-client-linux64-5.1.12.146-predeploy-k9.tar.gz
- cisco-secure-client-win-5.1.12.146-predeploy-k9.msi
- cisco-secure-client-macos-5.1.12.146-predeploy-k9.pkg
- cisco-secure-client-linux-arm64-5.1.12.146-predeploy-k9.tar.gz
```

**Note**: "k9" suffix indicates cryptographic ("crypto") export restrictions (legacy Cisco naming).

---

## Analysis Phases

### Phase 1: Reconnaissance (Week 1)

**Objective**: Extract and catalog all binaries, identify dependencies, map module architecture.

#### Activities

1. **Package Extraction** (8 hours)
   - Extract all 14 predeploy packages (4 versions × 3-4 platforms each)
   - Verify integrity (checksums, signatures)
   - Catalog file structures, manifests, metadata

2. **Binary Classification** (12 hours)
   - Identify executable types (ELF, PE, Mach-O)
   - Detect architecture (x86_64, ARM64, x86)
   - Classify by purpose (VPN core, security module, utility)
   - Extract version strings, build timestamps

3. **Dependency Mapping** (12 hours)
   - Use `ldd`, `otool -L`, `dumpbin /DEPENDENTS` to list shared libraries
   - Identify system dependencies (OpenSSL, Boost, Qt, GTK, glibc)
   - Detect proprietary Cisco libraries (acciscossl, acciscocrypto, vpnapi)
   - Map inter-module dependencies

4. **Symbol Extraction** (8 hours)
   - Extract exported symbols from all libraries
   - Identify function naming conventions
   - Map public API surfaces (vpnapi, libacciscossl)
   - Detect debug symbols (if present)

#### Deliverables

- [x] `BINARY_CATALOG_PREDEPLOY.md` - Complete inventory with metadata
- [x] `DEPENDENCY_MATRIX.md` - Cross-reference of library dependencies
- [x] `MODULE_ARCHITECTURE.md` - Component interaction diagram
- [ ] `SYMBOL_INVENTORY.csv` - Exported functions database

#### Tools

- `file` - File type detection
- `strings` - String extraction
- `ldd` / `otool` / `dumpbin` - Dependency analysis
- `nm` / `objdump` / `readelf` - Symbol extraction
- `binwalk` - Embedded file detection

---

### Phase 2: Static Decompilation (Weeks 2-3)

**Objective**: Decompile high-priority binaries, reconstruct function logic, identify protocol handlers.

#### Week 2: libacciscossl.so (CRITICAL - TLS/DTLS Implementation)

**Focus**: Cisco's custom SSL/TLS library - likely wraps OpenSSL with Cisco-specific cipher suites and TLS 1.3 extensions.

**Activities** (40 hours):

1. **IDA Pro Setup** (4 hours)
   - Load `libacciscossl.so.5.1.12.146` (latest version)
   - Configure FLIRT signatures (if available)
   - Set up function naming conventions
   - Create IDA database snapshot

2. **TLS Handshake Analysis** (12 hours)
   - Locate `SSL_connect`, `SSL_accept` equivalents
   - Trace ClientHello generation (cipher suite selection)
   - Analyze ServerHello processing (version negotiation)
   - Identify Certificate validation logic
   - Map key exchange functions (DHE, ECDHE, PSK)

3. **Cipher Suite Implementation** (12 hours)
   - Identify supported cipher suites (TLS 1.2 and TLS 1.3)
   - Locate AES-GCM, ChaCha20-Poly1305 implementations
   - Analyze cipher preference ordering
   - Document fallback mechanisms

4. **DTLS 1.2 Implementation** (8 hours)
   - Locate DTLS-specific functions (retransmission, replay protection)
   - Analyze DTLS handshake differences vs. TLS
   - Identify cookie exchange mechanism
   - Map MTU handling and fragmentation

5. **Session Management** (4 hours)
   - Analyze session resumption (session ID, session tickets)
   - Identify session caching mechanisms
   - Document renegotiation handling

#### Week 3: vpnagentd (VPN Daemon - Protocol Core)

**Focus**: Main VPN protocol implementation - CSTP tunnel, DTLS data channel, authentication.

**Activities** (50 hours):

1. **IDA Pro Setup** (4 hours)
   - Load `vpnagentd` binary (version 5.1.12.146)
   - Identify main entry point, initialization routines
   - Map process architecture (threads, event loops)

2. **CSTP Tunnel Implementation** (16 hours)
   - Locate HTTPS POST `/CSCOSSLC/tunnel` handler
   - Analyze CONNECT request formatting
   - Identify X-CSTP-* header processing
   - Map tunnel establishment state machine
   - Document keepalive mechanisms

3. **DTLS Data Channel** (12 hours)
   - Locate DTLS socket initialization
   - Analyze DTLS handshake sequencing
   - Identify data plane packet encapsulation
   - Map NAT-T handling (UDP port 4500)
   - Document fallback to CSTP-only mode

4. **Authentication Flows** (12 hours)
   - Trace certificate-based authentication
   - Analyze SAML external browser flow
   - Identify EAP-FAST message exchange
   - Map machine authentication (Windows registry)
   - Document smartcard CAPI/CryptoTokenKit integration

5. **Routing and Split Tunneling** (6 hours)
   - Analyze route injection logic
   - Identify split-include/split-exclude processing
   - Map DNS resolution handling
   - Document IPv6 dual-stack support

#### Deliverables

- [ ] `LIBACCISCOSSL_ANALYSIS.md` - TLS/DTLS library documentation (50+ pages)
- [ ] `VPNAGENTD_PROTOCOL.md` - CSTP/DTLS protocol specification (60+ pages)
- [ ] `TLS13_CIPHER_SUITES.md` - Version 5.x TLS 1.3 implementation details
- [ ] `DTLS_STATE_MACHINE.md` - DTLS session lifecycle diagrams
- [ ] `AUTH_FLOWS.md` - Authentication sequence diagrams (all methods)
- [ ] IDA Pro databases (.i64) for both binaries

#### Tools

- **IDA Pro 9.2** (primary)
- Hex-Rays Decompiler (C pseudocode generation)
- IDAPython scripts (automated analysis)

---

### Phase 3: Cross-Version Comparison (Week 4)

**Objective**: Compare protocol implementations across 4 versions, identify TLS 1.3 additions, track cipher suite evolution.

#### Activities

1. **Binary Diffing** (12 hours)
   - Use BinDiff to compare vpnagentd across versions
   - Identify new functions in 5.0.x (TLS 1.3 debut)
   - Track removed functions (deprecated ciphers)
   - Map refactored code sections

2. **TLS 1.2 vs. TLS 1.3 Analysis** (12 hours)
   - Compare libacciscossl 4.10 (TLS 1.2 only) vs. 5.0 (TLS 1.3)
   - Identify TLS 1.3 PSK/resumption changes
   - Analyze 0-RTT implementation (if present)
   - Document fallback behavior

3. **Cipher Suite Evolution** (8 hours)
   - Extract cipher suite lists from all versions
   - Compare 4.9 → 4.10 → 5.0 → 5.1 changes
   - Identify deprecated ciphers (DES, 3DES, RC4)
   - Document new TLS 1.3 suites (AES-GCM-128/256)

4. **Authentication Changes** (8 hours)
   - Compare SAML implementation across versions
   - Identify FIDO2/WebAuthN additions (5.0+)
   - Analyze post-quantum PPK (5.1.x only)
   - Track smartcard API changes

#### Deliverables

- [ ] `PROTOCOL_EVOLUTION.md` - Version-by-version protocol changes
- [ ] `TLS_MIGRATION_GUIDE.md` - 4.x → 5.x TLS upgrade guide
- [ ] `CIPHER_SUITE_MATRIX.csv` - Comprehensive cipher support matrix
- [ ] `BINDE_REPORT.html` - Binary diff visualizations

#### Tools

- **BinDiff** (Zynamics/Google)
- **Diaphora** (IDA Pro plugin)
- **radiff2** (radare2 binary diff)

---

### Phase 4: Cryptographic Analysis (Week 5)

**Objective**: Deep dive into cryptographic implementations, validate security properties, identify potential weaknesses.

#### Activities

1. **libacciscocrypto.so Analysis** (16 hours)
   - Decompile AES-GCM implementation
   - Analyze ECDH/ECDHE key exchange
   - Identify HKDF/PBKDF2 usage (key derivation)
   - Check random number generation (RNG/CSPRNG)

2. **Certificate Validation** (8 hours)
   - Trace X.509 certificate parsing
   - Analyze trust anchor validation
   - Identify CRL/OCSP checking
   - Document certificate pinning (if present)

3. **Key Management** (8 hours)
   - Locate master secret derivation
   - Analyze session key generation
   - Identify key rotation mechanisms
   - Check Perfect Forward Secrecy (PFS) enforcement

4. **Post-Quantum Cryptography** (8 hours - 5.1.x only)
   - Analyze IKEv2 PPK implementation (RFC 8784)
   - Identify quantum-resistant algorithms (if any)
   - Document hybrid mode (PSK + PPK)
   - Assess quantum readiness

#### Deliverables

- [ ] `CRYPTO_ANALYSIS.md` - Cryptographic implementation audit (40+ pages)
- [ ] `CERTIFICATE_VALIDATION.md` - X.509 validation logic
- [ ] `KEY_DERIVATION.md` - Session key generation spec
- [ ] `POST_QUANTUM_ASSESSMENT.md` - IKEv2 PPK analysis (5.1.x)

#### Tools

- **IDA Pro 9.2**
- **Cryptool** (cipher identification)
- **OpenSSL CLI** (certificate parsing)

---

### Phase 5: Module Analysis (Week 6)

**Objective**: Analyze secondary modules (ISE Posture, NVM, DART, Secure Firewall Posture) for completeness.

#### Activities

1. **ISE Posture Client** (12 hours)
   - Analyze posture assessment protocol
   - Identify compliance check mechanisms
   - Document remediation actions
   - Map ISE server communication

2. **Network Visibility Module (NVM)** (12 hours)
   - Analyze IPFIX/NetFlow telemetry collection
   - Identify mDTLS collector authentication (5.1.x)
   - Document data privacy controls
   - Map flow export format

3. **Secure Firewall Posture** (8 hours)
   - Analyze HostScan → Secure Firewall Posture migration (5.0+)
   - Identify OPSWAT engine integration
   - Document antivirus/firewall detection
   - Map compliance reporting

4. **DART** (8 hours)
   - Analyze diagnostic data collection
   - Identify log aggregation mechanisms
   - Document privacy controls
   - Map export format (.zip bundle)

#### Deliverables

- [ ] `ISE_POSTURE_PROTOCOL.md` - ISE Posture assessment specification
- [ ] `NVM_TELEMETRY.md` - Network Visibility Module protocol
- [ ] `SECURE_FIREWALL_POSTURE.md` - Posture scanning implementation
- [ ] `DART_DIAGNOSTICS.md` - DART data collection spec

#### Tools

- **Ghidra 11.3** (bulk analysis)
- **radare2** (quick binary inspection)
- **Wireshark** (protocol validation - if ASA available)

---

## Week-by-Week Timeline

### Week 1: Reconnaissance and Inventory

| Day | Focus | Hours | Deliverables |
|-----|-------|-------|--------------|
| Mon | Package extraction, integrity verification | 8h | 14 extracted packages |
| Tue | Binary classification, architecture detection | 8h | Binary inventory spreadsheet |
| Wed | Dependency mapping (ldd/otool analysis) | 8h | Dependency matrix |
| Thu | Symbol extraction, API surface mapping | 8h | Symbol inventory database |
| Fri | Module architecture diagram, documentation | 8h | `MODULE_ARCHITECTURE.md` |

**Milestone**: Complete binary catalog with all dependencies mapped

---

### Week 2: libacciscossl.so Deep Dive (TLS/DTLS)

| Day | Focus | Hours | Deliverables |
|-----|-------|-------|--------------|
| Mon | IDA Pro setup, TLS handshake location | 8h | IDA database initialized |
| Tue | ClientHello/ServerHello analysis | 8h | Handshake sequence diagram |
| Wed | Cipher suite implementation mapping | 8h | Cipher function catalog |
| Thu | DTLS 1.2 specific analysis | 8h | DTLS state machine |
| Fri | Session management, documentation | 8h | `LIBACCISCOSSL_ANALYSIS.md` (draft) |

**Milestone**: TLS 1.2/1.3 and DTLS 1.2 protocol handlers identified

---

### Week 3: vpnagentd Protocol Core

| Day | Focus | Hours | Deliverables |
|-----|-------|-------|--------------|
| Mon | IDA Pro setup, main loop analysis | 8h | Process architecture diagram |
| Tue | CSTP tunnel implementation (HTTPS POST /CSCOSSLC/tunnel) | 8h | CSTP spec (partial) |
| Wed | DTLS data channel, NAT-T handling | 8h | DTLS data plane spec |
| Thu | Authentication flows (cert, SAML, EAP-FAST) | 8h | Auth sequence diagrams |
| Fri | Routing, split tunneling, documentation | 8h | `VPNAGENTD_PROTOCOL.md` (draft) |

**Milestone**: Complete CSTP/DTLS protocol specification

---

### Week 4: Cross-Version Comparison

| Day | Focus | Hours | Deliverables |
|-----|-------|-------|--------------|
| Mon | Binary diffing (4.9 vs. 4.10 vs. 5.0 vs. 5.1) | 8h | BinDiff report |
| Tue | TLS 1.2 vs. TLS 1.3 comparison | 8h | TLS migration guide |
| Wed | Cipher suite evolution analysis | 8h | Cipher suite matrix |
| Thu | Authentication changes across versions | 8h | Auth migration guide |
| Fri | Documentation consolidation | 8h | `PROTOCOL_EVOLUTION.md` |

**Milestone**: Version comparison matrix complete

---

### Week 5: Cryptographic Deep Dive

| Day | Focus | Hours | Deliverables |
|-----|-------|-------|--------------|
| Mon | libacciscocrypto.so AES-GCM implementation | 8h | Crypto function catalog |
| Tue | ECDH/ECDHE key exchange analysis | 8h | Key exchange spec |
| Wed | Certificate validation logic | 8h | `CERTIFICATE_VALIDATION.md` |
| Thu | Post-quantum crypto (5.1.x IKEv2 PPK) | 8h | Post-quantum assessment |
| Fri | Crypto audit, security recommendations | 8h | `CRYPTO_ANALYSIS.md` |

**Milestone**: Cryptographic implementation validated

---

### Week 6: Module Analysis and Final Documentation

| Day | Focus | Hours | Deliverables |
|-----|-------|-------|--------------|
| Mon | ISE Posture client protocol analysis | 8h | `ISE_POSTURE_PROTOCOL.md` |
| Tue | NVM telemetry collection, mDTLS | 8h | `NVM_TELEMETRY.md` |
| Wed | Secure Firewall Posture scanner | 8h | `SECURE_FIREWALL_POSTURE.md` |
| Thu | DART diagnostics, documentation | 8h | `DART_DIAGNOSTICS.md` |
| Fri | Final review, consolidation, WolfGuard roadmap | 8h | **PROJECT COMPLETE** |

**Milestone**: All deliverables finalized, ready for WolfGuard implementation

---

## Deliverables

### Technical Documentation

#### Phase 1: Reconnaissance
- [x] **`BINARY_CATALOG_PREDEPLOY.md`** (10-15 pages)
  - Complete inventory of all predeploy binaries
  - File sizes, architectures, build dates
  - Package contents and manifests

- [x] **`DEPENDENCY_MATRIX.md`** (8-12 pages)
  - Cross-reference of library dependencies
  - System vs. proprietary libraries
  - Version-specific dependency changes

- [x] **`MODULE_ARCHITECTURE.md`** (6-10 pages)
  - Component interaction diagram
  - Process communication (IPC, sockets)
  - Module lifecycle (startup, shutdown)

- [ ] **`SYMBOL_INVENTORY.csv`** (spreadsheet)
  - Exported function database
  - Symbol naming conventions
  - API surface mapping

#### Phase 2-3: Protocol Analysis
- [ ] **`LIBACCISCOSSL_ANALYSIS.md`** (50-70 pages)
  - TLS 1.2/1.3 handshake implementation
  - DTLS 1.2 specifics
  - Cipher suite selection logic
  - Session management
  - Function reference (200+ functions)

- [ ] **`VPNAGENTD_PROTOCOL.md`** (60-80 pages)
  - CSTP tunnel specification
  - DTLS data channel
  - Authentication flows (all methods)
  - Routing and split tunneling
  - Error handling

- [ ] **`PROTOCOL_EVOLUTION.md`** (20-30 pages)
  - Version-by-version changes (4.9 → 4.10 → 5.0 → 5.1)
  - Breaking changes
  - New features
  - Deprecated functionality

- [ ] **`TLS_MIGRATION_GUIDE.md`** (15-20 pages)
  - TLS 1.2 → TLS 1.3 changes
  - Cipher suite updates
  - Server requirements (ASA 9.19.1+)

#### Phase 4: Cryptography
- [ ] **`CRYPTO_ANALYSIS.md`** (40-50 pages)
  - AES-GCM, ChaCha20-Poly1305 implementations
  - ECDH/ECDHE key exchange
  - HKDF/PBKDF2 key derivation
  - RNG/CSPRNG analysis
  - Security assessment

- [ ] **`CERTIFICATE_VALIDATION.md`** (12-18 pages)
  - X.509 parsing and validation
  - Trust anchor management
  - CRL/OCSP checking
  - Certificate pinning

- [ ] **`POST_QUANTUM_ASSESSMENT.md`** (10-15 pages - 5.1.x only)
  - IKEv2 PPK (RFC 8784) implementation
  - Quantum-resistant algorithms
  - Hybrid mode analysis

#### Phase 5: Modules
- [ ] **`ISE_POSTURE_PROTOCOL.md`** (15-20 pages)
  - Posture assessment protocol
  - Compliance checks
  - Remediation actions

- [ ] **`NVM_TELEMETRY.md`** (12-18 pages)
  - IPFIX/NetFlow collection
  - mDTLS authentication (5.1.x)
  - Privacy controls

- [ ] **`SECURE_FIREWALL_POSTURE.md`** (10-15 pages)
  - HostScan migration (5.0+)
  - OPSWAT integration
  - Compliance reporting

- [ ] **`DART_DIAGNOSTICS.md`** (8-12 pages)
  - Data collection mechanisms
  - Log aggregation
  - Export format

### WolfGuard Implementation Artifacts

- [ ] **`WOLFGUARD_IMPLEMENTATION_ROADMAP.md`** (25-35 pages)
  - Prioritized feature list
  - wolfSSL 5.8.2+ integration guide
  - C23 coding standards
  - Compatibility matrix (Cisco Secure Client versions)

- [ ] **`CSTP_PROTOCOL_SPEC_WOLFSSL.md`** (30-40 pages)
  - CSTP protocol specification for ocserv
  - wolfSSL-specific implementation notes
  - TLS 1.3 configuration guide

- [ ] **`DTLS_PROTOCOL_SPEC_WOLFSSL.md`** (25-35 pages)
  - DTLS 1.2 protocol for ocserv
  - wolfSSL DTLS configuration
  - NAT-T handling

### IDA Pro Databases

- [ ] `libacciscossl_v5.1.12.146.i64` - TLS/DTLS library (60+ MB)
- [ ] `vpnagentd_v5.1.12.146.i64` - VPN daemon (80+ MB)
- [ ] `vpnui_v5.1.12.146.i64` - VPN UI (40+ MB)
- [ ] `libacciscocrypto_v5.1.12.146.i64` - Crypto library (30+ MB)

**Total Documentation**: ~450-650 pages (12-18 MB markdown)

---

## Tool Requirements

### Reverse Engineering Tools

#### IDA Pro 9.2 (Primary - Deep Analysis)

**License**: Commercial ($2,800 - already owned)

**Usage**:
- TLS/DTLS library decompilation (libacciscossl.so)
- VPN daemon protocol analysis (vpnagentd)
- Crypto library audit (libacciscocrypto.so)

**Plugins**:
- Hex-Rays Decompiler (x86_64, ARM64)
- BinDiff (cross-version comparison)
- Diaphora (binary diffing)
- IDA Python scripts (automation)

**System Requirements**:
- 16 GB RAM minimum (32 GB recommended for large binaries)
- 100 GB disk space (IDA databases)

---

#### Ghidra 11.3 (Secondary - Batch Analysis)

**License**: Open Source (NSA)

**Usage**:
- Bulk binary analysis (ISE Posture, NVM, DART)
- UI component decompilation (vpnui)
- Utility analysis (acinstallhelper, manifesttool)

**Extensions**:
- RetDec (additional decompiler)
- Ghidra Server (collaborative analysis)

**System Requirements**:
- 8 GB RAM minimum
- 50 GB disk space

---

### Binary Analysis Utilities

| Tool | Version | Purpose |
|------|---------|---------|
| **radare2** | Latest | Quick binary inspection, symbol extraction |
| **binwalk** | 2.3+ | Embedded file detection, firmware extraction |
| **strings** | GNU | String extraction, version detection |
| **file** | 5.x | File type identification |
| **ldd** | GNU | Linux library dependencies |
| **otool** | macOS | macOS library dependencies |
| **dumpbin** | MSVC | Windows library dependencies |
| **readelf** | GNU | ELF header analysis |
| **objdump** | GNU | Disassembly, symbol tables |
| **nm** | GNU | Symbol extraction |

---

### Containerization (Reproducible Environment)

**Platform**: Buildah + Podman + Skopeo (OCI-compliant)

**Base Image**: `registry.access.redhat.com/ubi9/ubi:latest`

**Tools Container** (`cisco-re-tools:latest`):
```dockerfile
FROM registry.access.redhat.com/ubi9/ubi:latest

RUN dnf install -y \
    binutils file binwalk strings \
    gdb strace ltrace \
    python3.12 python3-pip \
    ghidra radare2

RUN pip3 install --no-cache-dir \
    angr capstone unicorn pefile lief

WORKDIR /workspace
```

**Container Volumes**:
- `/workspace/binaries` (read-only) - Git-ignored binary packages
- `/workspace/analysis` (read-write) - Analysis output
- `/workspace/re-output` (volume) - IDA Pro databases

**Usage**:
```bash
podman-compose -f reverse-engineering-tools/compose.yaml up -d
podman exec -it cisco-re-workspace bash
```

---

## Risk Mitigation

### Technical Risks

#### Risk 1: Binary Obfuscation / Anti-Reversing

**Likelihood**: Medium
**Impact**: High
**Mitigation**:
- Use IDA Pro's advanced deobfuscation plugins (HexRaysCodeXplorer)
- Apply pattern matching for common obfuscation techniques
- Leverage Ghidra's decompiler as alternative view
- Compare multiple versions for unobfuscated references

**Contingency**: If critical functions are obfuscated beyond analysis, focus on protocol-level behavior via dynamic analysis (Wireshark + test ASA).

---

#### Risk 2: Missing Debug Symbols

**Likelihood**: High (production binaries typically stripped)
**Impact**: Medium
**Mitigation**:
- Use FLIRT signatures for standard library detection
- Apply naming conventions based on string references
- Leverage Hex-Rays variable recovery
- Cross-reference with public API documentation

**Contingency**: Accept longer analysis time for manual function identification.

---

#### Risk 3: Proprietary Cryptographic Libraries

**Likelihood**: Medium
**Impact**: High
**Mitigation**:
- Identify calls to standard crypto libraries (OpenSSL, Mbed TLS)
- Use known algorithm signatures (AES S-boxes, ECDH curves)
- Validate implementations against RFC specifications
- Test cipher suite negotiation via Wireshark (if ASA available)

**Contingency**: Implement black-box testing with test ASA headend to validate cryptographic behavior.

---

### Legal Risks

#### Risk 4: DMCA §1201 Violation Claims

**Likelihood**: Low (defensive posture, documented exemption)
**Impact**: Very High
**Mitigation**:
- Maintain DMCA §1201(f) compliance documentation
- No circumvention of access controls (legitimate license used)
- No distribution of proprietary binaries
- Document interoperability purpose (WolfGuard/ocserv)
- No exploit development (defensive research only)

**Legal Defense**:
```
17 U.S.C. § 1201(f) - Reverse Engineering

(1) Notwithstanding the provisions of subsection (a)(1)(A), a person who has lawfully obtained
    the right to use a copy of a computer program may circumvent a technological measure that
    effectively controls access to a particular portion of that program for the sole purpose of
    identifying and analyzing those elements of the program that are necessary to achieve
    interoperability of an independently created computer program with other programs.
```

**Compliance**:
- ✅ Lawful license to Cisco Secure Client (enterprise deployment)
- ✅ Purpose: Interoperability with WolfGuard/ocserv (independent VPN server)
- ✅ No distribution of circumvention tools
- ✅ Documentation for interoperability only

---

### Project Management Risks

#### Risk 5: Schedule Overrun

**Likelihood**: Medium
**Impact**: Medium
**Mitigation**:
- Prioritize critical components (libacciscossl, vpnagentd)
- Define minimum viable deliverables (MVP)
- Weekly progress reviews
- Time-box analysis phases (40h/week strict limit)

**Contingency**: Defer low-priority modules (DART, Secure Firewall Posture) to follow-up analysis.

---

#### Risk 6: Tool Licensing / Access

**Likelihood**: Low (IDA Pro already licensed)
**Impact**: High
**Mitigation**:
- Maintain IDA Pro license compliance
- Use Ghidra as fallback (open source, no restrictions)
- Document analysis methodology for reproducibility

**Contingency**: Pivot to Ghidra-only analysis if IDA Pro license issues arise.

---

## Success Criteria

### Mandatory Deliverables (Must Have)

- [x] Complete binary inventory (all 14 packages cataloged)
- [ ] TLS/DTLS protocol specification (libacciscossl analysis)
- [ ] CSTP tunnel specification (vpnagentd HTTPS POST handler)
- [ ] Authentication flow diagrams (all methods: cert, SAML, EAP-FAST)
- [ ] Cipher suite matrix (4 versions compared)
- [ ] Cryptographic implementation audit (libacciscocrypto analysis)
- [ ] WolfGuard implementation roadmap (wolfSSL integration guide)

**Gate**: All 7 mandatory deliverables complete before proceeding to ANALYSIS_PLAN_WEBDEPLOY.md.

---

### Optional Deliverables (Nice to Have)

- [ ] ISE Posture protocol specification
- [ ] NVM telemetry collection spec
- [ ] Secure Firewall Posture analysis
- [ ] DART diagnostics spec
- [ ] Post-quantum crypto assessment (5.1.x)
- [ ] Binary diffing reports (BinDiff/Diaphora)

**Status**: Best-effort; may be deferred to follow-up analysis if time-constrained.

---

### Quality Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Documentation Completeness** | 100% of mandatory deliverables | Checklist completion |
| **Technical Accuracy** | 0 protocol misinterpretations | Peer review + Wireshark validation |
| **Code Coverage** | &gt;80% of libacciscossl functions analyzed | IDA Pro function coverage report |
| **Reproducibility** | 100% of analysis reproducible | Documented tools + procedures |
| **WolfGuard Readiness** | Roadmap complete with priorities | Stakeholder review |

---

## Next Steps

### Immediate Actions (Week 1 Start)

1. ✅ **Binary Inventory Complete** (already done in BINARY_INVENTORY.md)
2. ⏳ **Extract all 14 predeploy packages** (4 versions × 3-4 platforms)
   ```bash
   cd /opt/projects/repositories/cisco-secure-client/binaries
   for pkg in */cisco-secure-client-*-predeploy-k9.*; do
     echo "Extracting $pkg..."
     # Linux: tar xzf
     # Windows: 7z x (MSI)
     # macOS: xar -xf (PKG)
   done
   ```
3. ⏳ **Set up RE container environment**
   ```bash
   cd reverse-engineering-tools
   make build
   make run
   ```
4. ⏳ **Initialize IDA Pro workspace**
   ```bash
   mkdir -p /opt/projects/repositories/cisco-secure-client/analysis/ida-databases
   ```

### Dependency on Other Tasks

- **Task 11 (ANALYSIS_PLAN_WEBDEPLOY.md)**: Should wait until predeploy analysis identifies common protocol functions
- **Task 12 (ANALYSIS_PLAN_UTILS.md)**: Can proceed in parallel (independent scope)
- **Task 14 (Phase 1 Begin)**: Requires this plan approved and Week 1 kickoff

---

## Approval and Sign-Off

**Status**: 🔄 **DRAFT - AWAITING APPROVAL**

**Author**: Claude (reverse-engineering-analyzer agent)
**Date**: 2025-10-30
**Version**: 1.0

**Approver**: _[User to confirm start]_
**Approval Date**: _[Pending]_

**Changes from Original Request**:
- Scoped to predeploy packages only (per user requirement)
- Prioritized Linux x86_64 (WolfGuard target platform)
- 6-week timeline (240 hours @ 40h/week)
- Added containerization (Buildah/Podman per user preference)
- Excluded webdeploy/utils (separate plans)

---

**Ready to begin?** Confirm approval to start **Week 1: Reconnaissance** immediately.
