# Cisco Secure Client Webdeploy Package Analysis Plan

**Project**: WolfGuard VPN - OpenConnect Protocol Reverse Engineering
**Scope**: Server-side web deployment packages (webdeploy) across 4 major versions
**Legal Basis**: DMCA §1201(f) - Reverse Engineering for Interoperability
**Duration**: 4 weeks (160 hours estimated)
**Priority**: Medium (Secondary to predeploy; focuses on server-side ASA integration)
**Status**: 🔄 **READY TO START** (after ANALYSIS_PLAN_PREDEPLOY.md Week 3 completion)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope Definition](#scope-definition)
3. [Binary Inventory](#binary-inventory)
4. [Analysis Phases](#analysis-phases)
5. [Week-by-Week Timeline](#week-by-week-timeline)
6. [Deliverables](#deliverables)
7. [Tool Requirements](#tool-requirements)
8. [Integration with Predeploy Analysis](#integration-with-predeploy-analysis)
9. [Success Criteria](#success-criteria)

---

## Executive Summary

### Objective

Analyze Cisco Secure Client **webdeploy packages** (server-side ASA-hosted deployment) across 4 major versions (4.9.06037, 4.10.08029, 5.0.05040, 5.1.12.146) to understand:

1. **ASA-side deployment mechanisms** (how ASA delivers client binaries via HTTPS)
2. **Web-based installation flows** (ActiveX → Java → Browser-based)
3. **Automatic update protocols** (version checking, incremental updates)
4. **Server-client communication** (configuration push, policy enforcement)
5. **Web authentication helpers** (acwebhelper, external browser SAML)

### Why Webdeploy Packages?

Webdeploy packages are **server-side components** deployed on Cisco ASA/FTD appliances for:
- **Browser-based VPN client installation** (legacy: ActiveX, Java Web Start; modern: manual download)
- **Automatic client updates** (vpndownloader polling ASA for newer versions)
- **Configuration distribution** (XML profiles, split tunneling rules, auth settings)
- **Platform-specific binary serving** (ASA detects client OS, serves appropriate installer)

**Key Differences from Predeploy:**
- ❌ **NOT self-contained** (requires ASA headend)
- ✅ **Server-side perspective** (how ASA serves clients)
- ✅ **Update mechanisms** (incremental package delivery)
- ✅ **Web authentication components** (acwebhelper, SAML external browser)

**Analysis Focus**:
- ASA web deployment protocol (HTTPS URLs, client version detection)
- vpndownloader update mechanism (version polling, package downloads)
- acwebhelper (web-based auth - SAML, OAuth, external browser)
- Configuration XML parsing and enforcement

### Expected Outcomes

1. **Webdeploy Protocol Specification**: How ASA serves client binaries and updates
2. **Update Mechanism Analysis**: vpndownloader automatic update protocol
3. **Web Authentication Flow**: acwebhelper SAML/OAuth integration
4. **Configuration Distribution**: XML profile format and client-side parsing
5. **WolfGuard Server Integration Guide**: How ocserv should serve client updates (if desired)

---

## Scope Definition

### In Scope

#### Platforms

| Platform | Version Coverage | Package Types | Priority |
|----------|------------------|---------------|----------|
| **Linux x86_64** | All 4 versions (4.9, 4.10, 5.0, 5.1) | .tar.gz webdeploy | **High** |
| **Windows x64** | All 4 versions | .zip webdeploy | **Medium** |
| **macOS Intel** | All 4 versions | .pkg webdeploy | **Low** |

**Rationale**: Linux prioritized as WolfGuard target; Windows/macOS for reference.

#### Binary Components

**High Priority** (Web Deployment):
- `vpndownloader` / `vpndownloader.exe` - Automatic update client (**CRITICAL**)
- `acwebhelper` / `acwebhelper.exe` - Web-based authentication helper (**CRITICAL**)
- `update.txt` / `update.xml` - Update manifest (version, URLs, checksums)

**Medium Priority** (Configuration):
- `*.xml` - VPN profile templates
- `AnyConnectLocalPolicy.xml` - Client-side policy enforcement
- `SystemConfiguration.xml` - System-level settings

**Low Priority** (Legacy):
- `*.cab` - ActiveX controls (deprecated, removed in 5.0+)
- `*.jar` - Java Web Start launcher (deprecated)
- `setup.exe` - Windows web installer wrapper

#### Analysis Depth

| Component | Analysis Level | Tools | Estimated Hours |
|-----------|----------------|-------|-----------------|
| **vpndownloader** | Deep (update protocol) | IDA Pro / Ghidra | 40h |
| **acwebhelper** | Deep (SAML/OAuth flows) | IDA Pro / Ghidra | 40h |
| **update.txt/xml** | High (manifest parsing) | Manual | 20h |
| **XML profiles** | Medium (schema documentation) | Manual + xmllint | 20h |
| **Legacy ActiveX/Java** | Low (historical reference) | Ghidra | 10h |
| **ASA integration testing** | Medium (protocol validation) | Wireshark + test ASA | 30h |

**Total**: ~160 hours (4 weeks @ 40h/week)

### Out of Scope

❌ **Predeploy packages** (covered in ANALYSIS_PLAN_PREDEPLOY.md)
❌ **Utils packages** (Profile Editor, VPN API SDK - covered in ANALYSIS_PLAN_UTILS.md)
❌ **Core VPN protocol** (libacciscossl, vpnagentd - already analyzed in predeploy)
❌ **ASA configuration** (server-side setup; outside reverse engineering scope)
❌ **Mobile webdeploy** (Android/iOS use different mechanisms)

---

## Binary Inventory

### Package Distribution

| Version | Linux x64 | Windows x64 | macOS Intel | Total Size |
|---------|-----------|-------------|-------------|------------|
| **4.9.06037** | 93 MB | 108 MB | 29 MB | **230 MB** |
| **4.10.08029** | 99 MB | 117 MB | 33 MB | **249 MB** |
| **5.0.05040** | 106 MB | 123 MB | 36 MB | **265 MB** |
| **5.1.12.146** | 320 MB | 376 MB | 97 MB | **793 MB** |
| **Total** | **618 MB** | **724 MB** | **195 MB** | **1.54 GB** |

**Note**: Sizes similar to predeploy but packaged differently (ZIP/TAR archives for ASA deployment).

### Package Naming Convention

```
cisco-secure-client-{platform}-{version}-webdeploy-k9.{ext}

Examples:
- cisco-secure-client-linux64-5.1.12.146-webdeploy-k9.tar.gz
- cisco-secure-client-win-5.1.12.146-webdeploy-k9.zip
- cisco-secure-client-macos-5.1.12.146-webdeploy-k9.pkg
```

### Key Files in Webdeploy Packages

**Update Mechanism:**
```
binaries/vpndownloader
binaries/vpndownloader.exe
update.txt                    # Update manifest (4.x - text format)
update.xml                    # Update manifest (5.x - XML format)
version.xml                   # Client version metadata
```

**Web Authentication:**
```
binaries/acwebhelper
binaries/acwebhelper.exe
saml/                         # SAML authentication templates
```

**Configuration:**
```
profiles/                     # VPN profile templates
  profile_template.xml
  AnyConnectLocalPolicy.xml   # Client-side policy
  SystemConfiguration.xml     # System settings
```

**Legacy (4.x only):**
```
ActiveX/                      # Deprecated (removed in 5.0+)
  vpnweb.cab                  # ActiveX web installer
Java/                         # Deprecated
  anyconnect.jar              # Java Web Start launcher
```

---

## Analysis Phases

### Phase 1: Package Extraction and Cataloging (Week 1 - Days 1-2)

**Objective**: Extract all webdeploy packages, catalog contents, compare with predeploy.

#### Activities

1. **Package Extraction** (8 hours)
   - Extract 12 webdeploy packages (4 versions × 3 platforms)
   - Compare directory structures with predeploy packages
   - Identify webdeploy-specific files (update.txt, acwebhelper)

2. **Binary Classification** (8 hours)
   - Categorize binaries (update client, web helper, legacy)
   - Identify version-specific additions (ThousandEyes in 5.0+)
   - Document deprecated components (ActiveX, Java Web Start)

**Deliverables**:
- [x] `WEBDEPLOY_INVENTORY.md` - Complete package catalog
- [ ] `WEBDEPLOY_VS_PREDEPLOY.md` - Comparison matrix

**Tools**: `file`, `strings`, `unzip`, `tar`

---

### Phase 2: Update Mechanism Analysis (Week 1 Day 3 - Week 2)

**Objective**: Reverse engineer vpndownloader automatic update protocol.

#### vpndownloader Deep Dive (40 hours)

**Critical Questions**:
1. How does vpndownloader check for updates? (HTTP GET to ASA URL?)
2. What is the update manifest format? (update.txt vs. update.xml)
3. How are incremental updates handled? (full package vs. delta patches?)
4. How are updates verified? (digital signatures, checksums?)
5. What is the fallback mechanism if update fails?

**Analysis Tasks**:

1. **Protocol Reverse Engineering** (16 hours)
   - Load vpndownloader binary in IDA Pro/Ghidra
   - Locate HTTP client functions (libcurl, native HTTP)
   - Identify ASA URL construction (version checking endpoint)
   - Trace manifest download and parsing

2. **Manifest Format Analysis** (12 hours)
   - Parse update.txt (4.x text format):
     ```
     version=5.1.12.146
     url=https://asa.example.com/+CSCOE+/sdesktop/vpnagent.msi
     sha256=abc123...
     ```
   - Parse update.xml (5.x XML format):
     ```xml
     <update>
       <version>5.1.12.146</version>
       <platform>win-x64</platform>
       <url>https://asa.example.com/+CSCOE+/sdesktop/vpnagent.msi</url>
       <signature>...</signature>
     </update>
     ```
   - Document schema differences across versions

3. **Signature Verification** (8 hours)
   - Identify digital signature validation code
   - Locate certificate pinning (if present)
   - Analyze signature algorithms (RSA-SHA256, ECDSA?)
   - Test signature bypass scenarios (security audit)

4. **Download and Installation** (4 hours)
   - Trace package download logic (resume support, error handling)
   - Identify installation trigger (spawn installer process)
   - Document rollback mechanisms (if update fails)

**Deliverables**:
- [ ] `VPNDOWNLOADER_PROTOCOL.md` (30-40 pages)
- [ ] `UPDATE_MANIFEST_SCHEMA.md` (15-20 pages)
- [ ] `UPDATE_SECURITY_AUDIT.md` (10-15 pages)

**Tools**: IDA Pro / Ghidra, Wireshark (if test ASA available)

---

### Phase 3: Web Authentication Helper Analysis (Week 3)

**Objective**: Reverse engineer acwebhelper SAML/OAuth/external browser authentication.

#### acwebhelper Deep Dive (40 hours)

**Critical Questions**:
1. How does acwebhelper integrate with external browsers? (IPC mechanism?)
2. What is the SAML assertion handling? (XML parsing, signature validation?)
3. How are OAuth tokens managed? (storage, refresh, revocation?)
4. What is the callback mechanism to vpnagentd? (socket, named pipe, HTTP?)
5. How is browser security enforced? (certificate validation, redirect whitelisting?)

**Analysis Tasks**:

1. **Browser Integration** (12 hours)
   - Identify browser launch mechanism (system default, specific browsers)
   - Trace URL construction (SAML IdP redirect, OAuth authorization endpoint)
   - Analyze callback URL handling (localhost listener, deep link)
   - Document cross-platform differences (Windows, macOS, Linux)

2. **SAML Protocol** (12 hours)
   - Locate SAML assertion parsing (XML libraries used)
   - Identify signature validation (X.509 certificates, RSA/ECDSA)
   - Trace attribute extraction (username, groups, session lifetime)
   - Document SAML 2.0 compliance

3. **OAuth 2.0 / OIDC** (8 hours - if implemented)
   - Identify OAuth grant type (Authorization Code, PKCE?)
   - Trace token exchange (access token, refresh token)
   - Analyze token storage (keychain, credential manager, file?)
   - Document OIDC UserInfo endpoint integration

4. **Security Assessment** (8 hours)
   - Test redirect URI validation (open redirect vulnerabilities)
   - Analyze state parameter handling (CSRF protection)
   - Identify code_challenge/code_verifier (PKCE enforcement)
   - Document security best practices vs. implementation

**Deliverables**:
- [ ] `ACWEBHELPER_ARCHITECTURE.md` (25-35 pages)
- [ ] `SAML_AUTHENTICATION_FLOW.md` (20-30 pages)
- [ ] `OAUTH_INTEGRATION.md` (15-20 pages)
- [ ] `WEB_AUTH_SECURITY_AUDIT.md` (12-18 pages)

**Tools**: IDA Pro / Ghidra, Wireshark, Burp Suite (for web auth testing)

---

### Phase 4: Configuration Management (Week 4)

**Objective**: Document XML configuration formats, client-side policy enforcement.

#### Activities

1. **VPN Profile XML Schema** (12 hours)
   - Analyze `profile_template.xml` structure
   - Document connection settings (server URL, protocol, port)
   - Identify authentication config (cert vs. password, SAML settings)
   - Map split tunneling rules (include/exclude domains, IPs)
   - Document DNS settings (custom DNS servers, domain suffixes)

2. **AnyConnectLocalPolicy.xml** (12 hours)
   - Parse client-side policy enforcement
   - Identify restrictions (disable VPN disconnect, force split tunneling)
   - Analyze update policy (auto-update, update URLs, signatures)
   - Document trusted server list (certificate pinning)

3. **SystemConfiguration.xml** (8 hours)
   - Analyze system-level settings
   - Identify UI customization (branding, disclaimers)
   - Document logging configuration (DART, debug levels)
   - Map module enable/disable flags

4. **Cross-Version Schema Evolution** (8 hours)
   - Compare XML schemas across 4.9, 4.10, 5.0, 5.1
   - Identify new elements (TLS 1.3 settings in 5.0+)
   - Document deprecated fields (ActiveX settings in 4.x)
   - Create migration guide for profile updates

**Deliverables**:
- [ ] `VPN_PROFILE_SCHEMA.md` (30-40 pages)
- [ ] `LOCAL_POLICY_REFERENCE.md` (20-30 pages)
- [ ] `SYSTEM_CONFIG_REFERENCE.md` (15-20 pages)
- [ ] `XML_SCHEMA_EVOLUTION.md` (12-18 pages)
- [ ] XML schema files (.xsd) for validation

**Tools**: `xmllint`, `xmlstarlet`, Python xml.etree, manual analysis

---

## Week-by-Week Timeline

### Week 1: Extraction, Inventory, and Update Mechanism Start

| Day | Focus | Hours | Deliverables |
|-----|-------|-------|--------------|
| Mon | Package extraction, cataloging | 8h | Webdeploy inventory |
| Tue | Binary classification, comparison with predeploy | 8h | Webdeploy vs. predeploy matrix |
| Wed | vpndownloader protocol reverse engineering | 8h | HTTP client functions identified |
| Thu | Update manifest parsing (update.txt, update.xml) | 8h | Manifest schema draft |
| Fri | Signature verification analysis | 8h | Update security audit (partial) |

**Milestone**: Update mechanism protocol 50% complete

---

### Week 2: Update Mechanism Completion

| Day | Focus | Hours | Deliverables |
|-----|-------|-------|--------------|
| Mon | Download logic, installation trigger | 8h | Download flow diagram |
| Tue | Error handling, rollback mechanisms | 8h | Update failure recovery spec |
| Wed | Cross-version comparison (4.9 vs. 5.1) | 8h | Protocol evolution notes |
| Thu | Documentation consolidation | 8h | `VPNDOWNLOADER_PROTOCOL.md` (draft) |
| Fri | Testing with Wireshark (if ASA available) | 8h | Protocol validation report |

**Milestone**: Update mechanism fully documented

---

### Week 3: Web Authentication Helper (acwebhelper)

| Day | Focus | Hours | Deliverables |
|-----|-------|-------|--------------|
| Mon | Browser integration, URL construction | 8h | Browser launch mechanism spec |
| Tue | SAML assertion parsing, signature validation | 8h | SAML protocol analysis |
| Wed | OAuth 2.0 / OIDC integration | 8h | OAuth flow diagram |
| Thu | Security assessment (redirect validation, CSRF) | 8h | Security audit findings |
| Fri | Documentation, cross-platform testing | 8h | `ACWEBHELPER_ARCHITECTURE.md` |

**Milestone**: Web authentication fully documented

---

### Week 4: Configuration Management and Final Documentation

| Day | Focus | Hours | Deliverables |
|-----|-------|-------|--------------|
| Mon | VPN profile XML schema analysis | 8h | `VPN_PROFILE_SCHEMA.md` (draft) |
| Tue | AnyConnectLocalPolicy.xml parsing | 8h | `LOCAL_POLICY_REFERENCE.md` |
| Wed | SystemConfiguration.xml, schema evolution | 8h | `SYSTEM_CONFIG_REFERENCE.md` |
| Thu | XSD schema generation, validation testing | 8h | XML schema files (.xsd) |
| Fri | Final review, WolfGuard integration guide | 8h | **PROJECT COMPLETE** |

**Milestone**: All deliverables finalized

---

## Deliverables

### Technical Documentation

#### Phase 1: Inventory
- [x] **`WEBDEPLOY_INVENTORY.md`** (8-12 pages)
  - Complete package catalog
  - File listings, sizes, checksums
  - Version-specific components

- [ ] **`WEBDEPLOY_VS_PREDEPLOY.md`** (6-10 pages)
  - Comparison matrix
  - Unique files in each package type
  - Use case differences

#### Phase 2: Update Mechanism
- [ ] **`VPNDOWNLOADER_PROTOCOL.md`** (30-40 pages)
  - Update checking protocol (HTTP endpoints)
  - Manifest parsing (update.txt, update.xml)
  - Signature verification
  - Download and installation flows

- [ ] **`UPDATE_MANIFEST_SCHEMA.md`** (15-20 pages)
  - Text format (4.x) specification
  - XML schema (5.x) with examples
  - Cross-version migration guide

- [ ] **`UPDATE_SECURITY_AUDIT.md`** (10-15 pages)
  - Signature validation security
  - MITM attack surface
  - Recommendations for WolfGuard

#### Phase 3: Web Authentication
- [ ] **`ACWEBHELPER_ARCHITECTURE.md`** (25-35 pages)
  - Component design
  - Browser integration mechanism
  - IPC with vpnagentd
  - Cross-platform implementation

- [ ] **`SAML_AUTHENTICATION_FLOW.md`** (20-30 pages)
  - SAML 2.0 protocol implementation
  - Assertion parsing and validation
  - Attribute extraction
  - Session lifecycle

- [ ] **`OAUTH_INTEGRATION.md`** (15-20 pages - if implemented)
  - OAuth 2.0 / OIDC flow
  - Token management
  - PKCE enforcement
  - Refresh token handling

- [ ] **`WEB_AUTH_SECURITY_AUDIT.md`** (12-18 pages)
  - Redirect URI validation
  - CSRF protection assessment
  - Code injection risks
  - Security recommendations

#### Phase 4: Configuration
- [ ] **`VPN_PROFILE_SCHEMA.md`** (30-40 pages)
  - Complete XML schema documentation
  - Connection settings reference
  - Split tunneling configuration
  - Authentication settings
  - Example profiles

- [ ] **`LOCAL_POLICY_REFERENCE.md`** (20-30 pages)
  - AnyConnectLocalPolicy.xml specification
  - Policy enforcement mechanisms
  - Update policy settings
  - Trusted server configuration

- [ ] **`SYSTEM_CONFIG_REFERENCE.md`** (15-20 pages)
  - SystemConfiguration.xml schema
  - UI customization options
  - Logging configuration
  - Module enable/disable

- [ ] **`XML_SCHEMA_EVOLUTION.md`** (12-18 pages)
  - Cross-version schema changes (4.9 → 4.10 → 5.0 → 5.1)
  - Deprecated elements
  - New features
  - Migration guide

- [ ] **XML Schema Files** (.xsd)
  - `vpn_profile.xsd` - VPN profile validation schema
  - `local_policy.xsd` - Local policy validation
  - `system_config.xsd` - System configuration

### WolfGuard Integration

- [ ] **`WOLFGUARD_WEBDEPLOY_INTEGRATION.md`** (20-30 pages)
  - Should ocserv support automatic updates? (pros/cons)
  - Client update serving (if desired)
  - Configuration distribution via web
  - SAML/OAuth integration with ocserv

**Total Documentation**: ~250-350 pages (8-12 MB markdown)

---

## Tool Requirements

### Reverse Engineering Tools

**IDA Pro 9.2** (optional - can use Ghidra):
- vpndownloader deep analysis (if time permits)
- acwebhelper decompilation

**Ghidra 11.3** (primary):
- Bulk binary analysis (webdeploy-specific components)
- Faster iteration vs. IDA Pro for medium-priority targets

**radare2** (quick analysis):
- String extraction, symbol listing
- Update manifest URL detection

### XML Analysis Tools

| Tool | Version | Purpose |
|------|---------|---------|
| **xmllint** | libxml2 | Schema validation, pretty-printing |
| **xmlstarlet** | 1.6+ | XPath queries, transformations |
| **Python xml.etree** | 3.12+ | Custom parsing scripts |
| **XSD Generator** | Online | Automatic schema generation from samples |

### Network Analysis

| Tool | Purpose | ASA Required? |
|------|---------|---------------|
| **Wireshark** | vpndownloader HTTP capture | ✅ Yes (test ASA) |
| **Burp Suite** | SAML/OAuth web auth testing | ✅ Yes (test ASA) |
| **curl** | Manual HTTP endpoint testing | ✅ Yes |

**Note**: Full protocol validation requires test ASA headend (not mandatory for initial analysis).

---

## Integration with Predeploy Analysis

### Shared Knowledge

**From Predeploy Analysis** (ANALYSIS_PLAN_PREDEPLOY.md):
- ✅ libacciscossl.so TLS/DTLS implementation (Week 2-3)
- ✅ vpnagentd authentication flows (Week 3)
- ✅ Crypto library analysis (Week 5)

**Used in Webdeploy Analysis**:
- vpndownloader uses same TLS client (libacciscossl.so)
- acwebhelper integrates with vpnagentd auth flows
- Update signature verification uses libacciscocrypto.so

### Timeline Dependency

**Recommended Start**: After Predeploy Week 3 completion
- Reason: Need vpnagentd auth flow understanding for acwebhelper analysis
- Allows parallel progress (predeploy Week 4-6 + webdeploy Week 1-4)

**No Hard Dependency**: Can start webdeploy analysis independently if:
- Focus on update mechanism first (vpndownloader)
- Defer acwebhelper analysis until predeploy auth flows documented

---

## Success Criteria

### Mandatory Deliverables

- [x] Webdeploy package inventory complete
- [ ] vpndownloader update protocol specification
- [ ] Update manifest schema (update.txt, update.xml)
- [ ] acwebhelper SAML authentication flow
- [ ] VPN profile XML schema documentation
- [ ] WolfGuard webdeploy integration recommendations

**Gate**: All 6 mandatory deliverables before proceeding to ANALYSIS_PLAN_UTILS.md.

### Optional Deliverables

- [ ] OAuth/OIDC integration spec (if implemented in acwebhelper)
- [ ] Legacy ActiveX/Java Web Start analysis (historical reference)
- [ ] Update security audit (signature bypass testing)
- [ ] Live ASA testing with Wireshark

### Quality Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Documentation Completeness** | 100% of mandatory deliverables | Checklist |
| **XML Schema Validation** | All sample profiles pass XSD validation | xmllint |
| **Protocol Accuracy** | 0 misinterpretations | Peer review |
| **WolfGuard Readiness** | Clear integration recommendations | Stakeholder review |

---

## Next Steps

### Dependencies

1. ✅ **Predeploy binary inventory** (already complete)
2. ⏳ **Predeploy Week 3 completion** (recommended, not mandatory)
3. ⏳ **Test ASA access** (optional, for live protocol validation)

### Immediate Actions (Week 1 Start)

1. Extract all 12 webdeploy packages
2. Set up Ghidra workspace
3. Begin vpndownloader reverse engineering
4. Parse update manifest samples (update.txt, update.xml)

---

**Status**: 🔄 **DRAFT - READY TO START** (after predeploy analysis foundation)
**Author**: Claude (reverse-engineering-analyzer agent)
**Date**: 2025-10-30
**Version**: 1.0

**Estimated Timeline**: 4 weeks (160 hours)
**Can Start**: Immediately (or after predeploy Week 3 for better context)
