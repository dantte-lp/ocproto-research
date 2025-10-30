# Cisco Secure Client 5.1.2.42 - Reverse Engineering Findings

**Analysis Date**: 2025-10-29
**Client Version**: Cisco Secure Client 5.1.2.42 (Linux x86_64)
**Target Project**: ocserv-modern v2.0.0
**Analysis Purpose**: Protocol interoperability and compatibility

---

## Executive Summary

This document presents comprehensive reverse engineering findings from static analysis of Cisco Secure Client 5.1.2.42 binaries (Linux distribution). The analysis focuses on protocol implementation details, authentication flows, tunnel establishment, and client behavior to ensure 100% compatibility with the ocserv-modern project.

### Key Findings

1. **Protocol Version**: OpenConnect Protocol v1.2 with Cisco-specific extensions
2. **TLS Implementation**: Custom Cisco SSL library (CiscoSSL 1.1.1t.7.2.500) based on OpenSSL
3. **DTLS Support**: DTLS 1.0, 1.2 with planned 1.3 support
4. **Authentication**: Aggregate authentication framework with SAML/SSO support
5. **Always-On VPN**: Comprehensive support with proxy restrictions
6. **Split Tunneling**: DNS and routing split-include/split-exclude mechanisms
7. **DPD (Dead Peer Detection)**: MTU-based and keepalive mechanisms

### Priority Implementation Areas

**HIGH PRIORITY**:
- SAML/SSO aggregate authentication flow
- Always-On VPN with profile enforcement
- Split DNS configuration
- DTLS 1.2 cipher suite compatibility
- Certificate validation strictness

**MEDIUM PRIORITY**:
- MTU DPD (Dead Peer Detection) mechanisms
- Captive portal detection and remediation
- System suspend/resume reconnection logic
- Multi-certificate authentication

**LOW PRIORITY**:
- Telemetry and phone-home features
- Client UI preferences
- Automatic server selection

---

## 1. Binary Analysis Overview

### 1.1 Analyzed Components

| Binary | Size | Type | Purpose |
|--------|------|------|---------|
| `vpnagentd` | 1.0MB | ELF64 PIE | Main VPN service daemon |
| `vpnui` | - | ELF64 PIE | User interface application |
| `acwebhelper` | - | ELF64 PIE | Web authentication helper (SAML/SSO) |
| `libvpnapi.so` | - | Shared Object | Core VPN API library |
| `libvpncommon.so` | - | Shared Object | Common utilities |
| `libvpncommoncrypt.so` | - | Shared Object | Cryptography functions |
| `libacciscossl.so` | - | Shared Object | Cisco SSL/TLS library |
| `libacciscocrypto.so` | - | Shared Object | Cisco Crypto library |

**Build Information**:
- Compiler: GCC for GNU/Linux 2.6.32+
- Architecture: x86-64, Position Independent Executable
- Stripping: All binaries are stripped (no debug symbols)
- Dependencies: Boost, libxml2, custom Cisco libraries

### 1.2 Technology Stack

**Core Libraries**:
- **TLS/Crypto**: Custom CiscoSSL (OpenSSL fork) version 1.1.1t.7.2.500
- **XML Processing**: libxml2
- **HTTP Transport**: Custom libaccurl (curl wrapper)
- **Compression**: LZS, deflate algorithms
- **C++ Framework**: Boost (system, thread, filesystem, regex)

---

## 2. Protocol Implementation Details

### 2.1 HTTP Headers

Cisco Secure Client uses custom HTTP headers prefixed with `X-`:

#### CSTP (Cisco Secure Tunnel Protocol) Headers

```
X-CSTP-Version: <version>
X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.
X-CSTP-Accept-Encoding: lzs,deflate
X-CSTP-Address-Type: IPv6,IPv4
X-CSTP-Full-IPv6-Capability: true
X-CSTP-Hostname: <client-hostname>
X-CSTP-License: mobile
X-CSTP-Local-Address-IP4: <ipv4-addr>
X-CSTP-Local-Address-IP6: <ipv6-addr>
X-CSTP-Remote-Address-IP4: <gateway-ipv4>
X-CSTP-Remote-Address-IP6: <gateway-ipv6>
X-CSTP-Base-MTU: <mtu>
X-CSTP-MTU: <effective-mtu>
X-CSTP-TCP-Keepalive: false
X-CSTP-FIPS-Mode: enabled
```

#### DTLS Headers

```
X-DTLS-CipherSuite: <cipher-suite>
X-DTLS12-CipherSuite: <tls12-cipher>
X-DTLS-Accept-Encoding: lzs
X-DTLS-Master-Secret: <secret>
X-DTLS-Header-Pad-Length: 0
```

#### Authentication Headers

```
X-Aggregate-Auth: <version>
X-AnyConnect-STRAP-Pubkey: <public-key>
X-AnyConnect-STRAP-Verify: <verification>
X-AnyConnect-STRAP-DH-Pubkey: <dh-public-key>
X-Transcend-Version: <version>
```

#### Standard Headers

```
User-Agent: <client-identification>
Cookie: webvpn=<session-cookie>
```

### 2.2 URL Endpoints

#### Portal Endpoints

```
/                               # Initial portal access
/index.html                     # Portal index
/+webvpn+/index.html           # Alternative portal path
/webvpn.html                    # Legacy portal page
```

#### CSCOE (Cisco Secure Client Online Experience) Endpoints

```
/+CSCOE+/sdesktop/scan.xml     # Host scan configuration
/+CSCOE+/sdesktop/wait.html    # Scanning wait page
```

#### Authentication Endpoints

```
/auth                           # Authentication handler (inferred)
config-auth                     # Configuration authentication
group-access                    # Tunnel group access
```

### 2.3 XML Message Structure

Based on string analysis, the client expects/generates XML with these elements:

#### Authentication Messages

```xml
<!-- Auth request (client → server) -->
<auth>
    <!-- credentials -->
</auth>

<!-- Auth response (server → client) -->
<auth>
    <!-- authentication result -->
</auth>

<!-- Complete configuration (server → client) -->
<config>
    <!-- VPN configuration -->
</config>

<!-- Client certificate request -->
<client-cert-request>
    <!-- certificate requirements -->
</client-cert-request>
```

#### Error Handling

- Client expects specific XML document types: `AUTH_REQUEST`, `COMPLETE`
- Missing `<auth>` or `<config>` elements trigger specific error codes
- Session token must be present in tunnel configuration

---

## 3. Authentication Flows

### 3.1 Aggregate Authentication Framework

The client implements an "aggregate authentication" (aggauth) system that supports multiple authentication methods in a single flow.

**Key Components**:
- `X-Aggregate-Auth` header indicates aggregate auth capability
- `aggregate-auth-version` negotiation
- XML-based authentication exchanges
- Support for multi-step authentication (MFA)

**Error Codes Found**:
```
AGGAUTH_ERROR_FAILED_TO_PARSE_XML
AGGAUTH_ERROR_INVALID_XML_DOCUMENT
AGGAUTH_ERROR_UNSUPPORTED_AGGR_AUTH_MSG_TYPE
AGGAUTH_ERROR_PASSWORDS_DONT_MATCH
AGGAUTH_ERROR_PASSWORD_TOO_SHORT
AGGAUTH_ERROR_PIN_INVALID_CHARACTERS
AGGAUTH_ERROR_PINS_DONT_MATCH
AGGAUTH_ERROR_PIN_TOO_LONG
AGGAUTH_ERROR_PIN_TOO_SHORT
```

### 3.2 SAML/SSO Authentication

**Implementation Details**:
- Web-based authentication handled by `acwebhelper` binary
- WebKit-based browser engine for SSO flows
- Cookie extraction from authentication session
- Error: `CONNECTMGR_ERROR_INVALID_SSO_LOGIN_URL` if SSO URL parsing fails

**Cookie Management**:
```c
// Function references found:
soup_cookie_free
soup_cookie_get_name
soup_cookie_get_value
webkit_cookie_manager_get_cookies
webkit_cookie_manager_get_cookies_finish
webkit_cookie_manager_set_accept_policy
webkit_cookie_manager_set_persistent_storage
```

**Storage**:
- SQLite database: `acwebhelper.cookies.sqlite`
- Cookie: `webvpn=<session-token>`
- Additional cookie types: `error_cookie`, `success_with_cookie`

### 3.3 Certificate Authentication

**Client Certificate Handling**:
- Automatic certificate selection support
- Smart card (PKCS#11) integration
- Multiple certificate authentication flows
- Certificate store locations:
  - Linux: User store
  - macOS: Login keychain
  - Windows: User certificate store

**Certificate Validation Strictness**:
```
CERTIFICATE_ERROR_VERIFY_SERVERCERT_FAILED
CERTIFICATE_ERROR_VERIFY_SERVERCERT_FAILED_ASKUSER
CERTIFICATE_ERROR_VERIFY_SERVERCERT_FAILED_UNRECOVERABLE
CERTIFICATE_ERROR_VERIFY_CERT_PIN_CHECK_FAILED
CERTIFICATE_ERROR_VERIFY_KEYSIZE_FAILED
CERTIFICATE_ERROR_VERIFY_SIGNATURE_ALGORITHM_FAILED
CERTIFICATE_ERROR_VERIFY_ENHKEYUSAGE_FAILED
CERTIFICATE_ERROR_VERIFY_SAN_NOT_FOUND
```

**Certificate Pinning**:
- Support for certificate pin lists
- Pin verification against entire certificate chain
- Error if no pin match found: `VERIFY_CERT_PIN_CHECK_FAILED`

### 3.4 Multi-Factor Authentication

**RSA SecurID**:
- Software token support
- Hardware token support
- Automatic token type detection
- Next token code acquisition
- Error handling for token failures

**OTP/TOTP**:
- Token-based authentication detection
- "Acquiring next token code" messages
- Integration with authentication framework

**Other MFA Methods**:
- Duo integration (inferred from error messages)
- SMS/Push notifications support
- RADIUS backend integration

---

## 4. Tunnel Establishment

### 4.1 CSTP (TLS-based Tunnel)

**Connection Sequence**:
1. Initial HTTPS connection to gateway
2. Authentication flow (credentials exchange)
3. Session cookie issuance
4. CONNECT request with session cookie
5. TLS tunnel establishment
6. Configuration exchange
7. Data channel activation

**Protocol Features**:
- **Compression**: LZS, deflate algorithms
- **IPv6**: Full IPv6 capability flag
- **MTU**: Base MTU and effective MTU negotiation
- **Keepalive**: TCP keepalive disabled by default
- **Encoding**: Address type negotiation (IPv4, IPv6)

### 4.2 DTLS (UDP-based Tunnel)

**DTLS Versions Supported**:
- DTLS 1.0
- DTLS 1.2
- DTLS 1.3 (references found, not yet active)

**DTLS-specific Implementation**:
```
DTLSv1
DTLSv1.2
DTLS_client_method
DTLS_method
DTLS_server_method
DTLS_get_data_mtu
DTLS_set_timer_cb
DTLS1 read hello verify request
DTLS1 write hello verify request
```

**Cookie Exchange**:
- HelloVerifyRequest mechanism
- DTLS stateless cookie for DoS protection
- Cookie-based client verification

**Master Secret Sharing**:
- TLS master secret transferred to DTLS
- Header: `X-DTLS-Master-Secret: <secret>`
- Allows DTLS to use same session keys

### 4.3 Cipher Suites

**TLS 1.3 Cipher Suites** (Primary):
```
TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
```

**TLS 1.2 Cipher Suites** (Fallback):
```
ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:
ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:
DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:
AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:
ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:
ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:
DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:
AES128-GCM-SHA256:AES128-SHA256:AES128-SHA
```

**Legacy Support**:
```
DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:
DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:
AES256-SHA:AES128-SHA
```

**Signature Algorithms**:
```
ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:
RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:
RSA+SHA256:RSA+SHA384:RSA+SHA512:RSA+SHA1
```

**Security Requirements**:
- FIPS mode support (X-CSTP-FIPS-Mode header)
- Suite B mode compliance
- Minimum TLS 1.0 for FIPS mode
- Minimum TLS 1.2 for Suite B mode

---

## 5. Always-On VPN Implementation

### 5.1 Core Features

**Always-On Policy**:
- Profile-based enforcement
- Single Always-On profile per system
- Gateway must be defined in profile
- No manual host input when Always-On enabled

**Restrictions**:
```
"Connecting via a proxy is not supported with Always On."
"Clear proxies (all remote), not supported with Always On enabled"
"An untrusted certificate was received while in always-on mode."
```

**Error Messages**:
```
"Host %s was not found in profile. The Always On policy requires
VPN connections to be established only to secure gateways defined
in the profile."

"It may be necessary to connect via a proxy, which is not
supported with Always On."
```

### 5.2 Certificate Validation

When Always-On is enabled:
- **No untrusted certificates** are allowed
- **Strict certificate trust** mode enforced
- **No "ask user"** prompts for certificate errors
- Connection fails immediately on certificate issues

**Error Handling**:
```
CERTIFICATE_ERROR_UNTRUSTED_CERT_DISALLOWED
CERTIFICATE_ERROR_VERIFY_SERVERCERT_FAILED_UNRECOVERABLE
```

### 5.3 Profile Enforcement

**Functions Found**:
```c
ProfileMgr::enforceSingleAlwaysOnProfile
PreferenceMgr::GetAlwaysOnPreferences
CCvcConfig::IsAlwaysOnEnabled
CSessionInfoTlv::SetAlwaysOnVPN
```

**Implementation Requirements**:
- Only one Always-On profile allowed
- Profile must contain gateway list
- No connections to non-profiled gateways
- User cannot override policy

---

## 6. Reconnection and Resilience

### 6.1 Automatic Reconnection

**Reconnection Triggers**:
- System suspend/resume
- Network change detection
- Public proxy redetermination
- Secure gateway IP change
- DTLS rekey failure
- TND (Trusted Network Detection) processing
- Session timeout approaching

**Reconnection Types**:
- **Session-level reconnect**: Full re-authentication
- **Tunnel-level reconnect**: Keep session, new tunnel
- **DTLS reconnect for rekey**: DTLS channel only

**Functions**:
```c
CVpnMgr::OnSystemResume
CVpnMgr::OnSystemSuspend
CVpnMgr::reconnectDelay
CVpnMgr::checkReconnectTimeouts
CTunnelStateMgr::reconnectTunnel
CTlsTunnelMgr::logReconnectForRekey
```

### 6.2 Suspend/Resume Handling

**Fast Startup Detection**:
```
"Fast startup detected with no VPN session, loading cached
VPN configuration."

"Fast startup detected with started VPN session."
```

**Resume Logic**:
```c
CMainThread::systemResumeNoticeCategoryHandler
CMainThread::systemSuspendNoticeCategoryHandler
CMainThread::BlockForSystemSuspend
```

**Resume Checks**:
- Previous tunnel state (`hasTunnel`)
- Session state preservation
- Connected Standby exit detection
- Suspend notice queue management

**Configuration**:
- Profile setting: `AutoReconnectBehavior = ReconnectAfterResume`
- `SuspendOnConnectedStandby` option
- Disconnect on suspend/resume option

### 6.3 Network Change Detection

**Public Proxy Changes**:
```
"Need to redetermine the public proxy, force session level reconnect"
```

**Gateway IP Changes**:
```
"Secure gateway IP addresses have changed, force session level reconnect"
```

**Captive Portal Detection**:
```
"Captive Portal detected"
"Captive portal redirect: %s"
"Cisco Secure Client cannot establish a VPN session because a device
in the network, such as a proxy server or captive portal, is blocking
Internet access."
```

---

## 7. Dead Peer Detection (DPD) and Keepalive

### 7.1 DPD Implementation

**Core DPD Class**:
```c
CTunnelProtocolDpdMgr
CTunnelProtocolDpdMgr::handleDPDRequest
CTunnelProtocolDpdMgr::handleDpdResponse
CTunnelProtocolDpdMgr::handleExpiredDPD
CTunnelProtocolDpdMgr::startTimer
CTunnelProtocolDpdMgr::OnTunnelEstablished
CTunnelProtocolDpdMgr::OnTunnelReadComplete
CTunnelProtocolDpdMgr::OnTunnelWriteComplete
```

### 7.2 MTU-based DPD

**MTU DPD Mechanism**:
```c
CTunnelProtocolDpdMgr::sendMtuDpdRequests
CTunnelProtocolDpdMgr::handleExpiredMtuDPD
CTunnelProtocolDpdMgr::getVpnConfigMtu
CTunnelProtocolDpdMgr::GetDpdBasedMtu
CTunnelProtocolDpdMgr::SetDpdBasedMtu
CTunnelProtocolDpdMgr::GetDpdBasedMtuAdjustment
CTunnelProtocolDpdMgr::SetDpdBasedMtuAdjustment
```

**Process**:
1. Send DPD request frames with varying padding sizes
2. Measure delay when sending MTU DPD requests
3. Determine optimal MTU via DPD handshake
4. Update existing DPD MTU adjustment if needed
5. Complete OMTU (Optimal MTU) detection process

**Messages**:
```
"MTU DPD request frame with padding size %u is sent."
"Processing DPD response with padding size %u"
"Failed to determine the tunnel MTU via DPD handshake"
"The candidate MTU (%u) was previously determined via DPD handshake."
"Updating existing DPD MTU adjustment: %i -> %i"
```

**Metadata Management**:
```
clearMtuDPDRequestData
"MTU DPD request metadata is being deleted before the corresponding
request is sent over tunnel."
```

### 7.3 Keepalive Messages

**Keepalive Functions**:
```c
ITunnelMgr::SendKeepalive
ITunnelProtocol::SendKeepalive
CTunnelStateMgr::SendKeepalive
CCstpProtocol::handleExpiredKeepalive
```

**Configuration**:
- `X-CSTP-TCP-Keepalive: false` (default)
- Separate timer management
- Expired keepalive handling

---

## 8. Split Tunneling and DNS

### 8.1 Split Tunneling

**Split Include/Exclude**:
```
"Added split-include network for tunnel DNS server %s"
"Buffer size reached, skipping remaining %s split-include networks"
```

**Functions**:
```c
CNetworkList (split network management)
```

### 8.2 Split DNS

**DNS Functions**:
```c
CUDPDNS
CUDPDNS::SetQueryResponseFlag
CUDPDNS::IsQuery
CUDPDNS::IsSplitDnsMatch
CUDPDNS::SetResponseCode
CUDPDNS::IsSelectTypeQuery
```

**Implementation**:
- UDP DNS interception
- Query/response flag management
- Split DNS matching against network list
- Response code manipulation
- Select-type query handling

**Match Algorithm**:
```c
IsSplitDnsMatch(
    list<const char*> query_domains,
    const CNetworkList& split_include,
    const CNetworkList& split_exclude
)
```

---

## 9. Client Configuration Profile

### 9.1 XML Profile Structure

Based on `vpn.example.com.xml`:

```xml
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/">
    <ClientInitialization>
        <UseStartBeforeLogon>true</UseStartBeforeLogon>
        <AutomaticCertSelection>false</AutomaticCertSelection>
        <CertificateStore>User</CertificateStore>
        <CertificateStoreMac>Login</CertificateStoreMac>
        <CertificateStoreLinux>User</CertificateStoreLinux>
        <ProxySettings>Native</ProxySettings>
        <AllowLocalProxyConnections>false</AllowLocalProxyConnections>
        <AuthenticationTimeout>30</AuthenticationTimeout>
        <AutoConnectOnStart>true</AutoConnectOnStart>
        <LocalLanAccess>true</LocalLanAccess>
        <DisableCaptivePortalDetection>false</DisableCaptivePortalDetection>
        <IPProtocolSupport>IPv4,IPv6</IPProtocolSupport>
        <AutoReconnect>true
            <AutoReconnectBehavior>ReconnectAfterResume</AutoReconnectBehavior>
        </AutoReconnect>
        <SuspendOnConnectedStandby>true</SuspendOnConnectedStandby>
        <AutoUpdate>true</AutoUpdate>
        <RSASecurIDIntegration>SoftwareToken</RSASecurIDIntegration>
        <WindowsLogonEnforcement>SingleLogon</WindowsLogonEnforcement>
        <LinuxLogonEnforcement>SingleLogon</LinuxLogonEnforcement>
        <AutomaticVPNPolicy>false</AutomaticVPNPolicy>
        <EnableScripting>false</EnableScripting>
        <EnableAutomaticServerSelection>true
            <AutoServerSelectionImprovement>20</AutoServerSelectionImprovement>
            <AutoServerSelectionSuspendTime>4</AutoServerSelectionSuspendTime>
        </EnableAutomaticServerSelection>
        <RetainVpnOnLogoff>false</RetainVpnOnLogoff>
        <CaptivePortalRemediationBrowserFailover>false</CaptivePortalRemediationBrowserFailover>
        <AllowManualHostInput>true</AllowManualHostInput>
    </ClientInitialization>
    <ServerList>
        <HostEntry>
            <HostName>vpn.example.com</HostName>
            <HostAddress>server1.example.com</HostAddress>
            <UserGroup>users</UserGroup>
        </HostEntry>
    </ServerList>
</AnyConnectProfile>
```

### 9.2 Key Configuration Options

**Security Settings**:
- Certificate store selection (User/Machine/Login)
- Automatic certificate selection
- Certificate store override capability
- Strict certificate trust mode

**Network Settings**:
- IP protocol support (IPv4, IPv6, dual-stack)
- Local LAN access
- Proxy settings (Native, None, Manual)
- Allow local proxy connections

**Connection Behavior**:
- Auto-connect on start
- Auto-reconnect behavior
- Suspend on connected standby
- Retain VPN on logoff
- Authentication timeout (seconds)

**Captive Portal**:
- Detection enable/disable
- Browser failover for remediation
- Remediation timeout

**Advanced Features**:
- RSA SecurID integration mode
- Logon enforcement (Single/Multiple)
- Automatic server selection
- Scripting enable/disable
- Always-On VPN policy

---

## 10. Error Codes and Status Messages

### 10.1 Critical Error Categories

**Connection Errors**:
```
CONNECTIFC_ERROR_PROXY_AUTH_REQUIRED
CONNECTIFC_ERROR_CAPTIVE_PORTAL_REDIRECT
CONNECTIFC_ERROR_HTTPS_NOT_ALLOWED
CONNECTIFC_ERROR_HOST_NOT_SPECIFIED
CONNECTIFC_ERROR_HTTP_MAX_REDIRS_EXCEEDED
CONNECTIFC_ERROR_CONNECT_DENIED_BY_AGENT
CONNECTIFC_ERROR_NO_PEER_IP_ADDRESS_IN_CONNECTION_DATA
```

**Transport Errors**:
```
CTRANSPORT_ERROR_HOST_RESOLUTION
CTRANSPORT_ERROR_CONNECT_FAILED
CTRANSPORT_ERROR_NO_INTERNET_CONNECTION
CTRANSPORT_ERROR_CONNECTION_AVAILABLE_BUT_NOT_ACTIVE
CTRANSPORT_ERROR_BAD_GATEWAY
CTRANSPORT_ERROR_PEER_CERT_REJECTED
```

**Protocol Errors**:
```
CSTPPROTOCOL_ERROR_FRAME_OUT_OF_SYNC
CSTPPROTOCOL_ERROR_FRAME_TOO_LARGE
CSTPPROTOCOL_ERROR_DECOMPRESS
CSTPPROTOCOL_ERROR_NO_LICENSE_FROM_HEADEND
```

**Certificate Errors** (see section 3.3 for complete list)

### 10.2 User-Facing Messages

**Connection Issues**:
```
"The secure gateway is responding, but Cisco Secure Client -
AnyConnect VPN could not establish a VPN session. Please retry."

"Cisco Secure Client cannot establish a VPN session because a
device in the network, such as a proxy server or captive portal,
is blocking Internet access."
```

**Session Management**:
```
"Your VPN connection will soon exceed the session time limit.
A new connection will be necessary."

"A VPN reconnect resulted in different configuration settings."
```

**Certificate Issues**:
```
"An untrusted certificate was received while in always-on mode."

"An Untrusted Certificate was received while in strict certificate
trust mode"

"Cisco Secure Client must verify that all loaded components have
been certified by Cisco."
```

---

## 11. Security Features

### 11.1 Certificate Pinning

**Implementation**:
- Pin list management (`CCertHelper::SetCertificatePinList`)
- Pin verification against entire chain
- Failure is unrecoverable error
- No user override in Always-On mode

### 11.2 FIPS Mode

**FIPS Compliance**:
- Header: `X-CSTP-FIPS-Mode: enabled`
- Minimum TLS 1.0 required
- Restricted cipher suites
- FIPS-compliant crypto library

**Non-FIPS Server Detection**:
```
CTRANSPORT_ERROR_NON_FIPS_SERVER_CERT
CERTIFICATE_ERROR_NOT_FIPS_COMPLIANT
```

### 11.3 Integrity Checking

**Component Verification**:
```
"Cisco Secure Client must verify that all loaded components have
been certified by Cisco. Your system does not have the latest root
certificates from Verisign..."
```

**Code Signing**:
- PKCS#7 certificate verification
- Timestamp validation
- Signature verification
- Object name validation (filesigner)

### 11.4 Anti-Tampering

**Binary Protection**:
- Stripped binaries (no debug symbols)
- Position-independent executables (PIE)
- Component integrity checking
- Certificate-based component validation

---

## 12. Implementation Recommendations for ocserv-modern

### 12.1 Critical Compatibility Requirements

**Protocol Headers**:
1. ✅ Implement all `X-CSTP-*` headers exactly as expected
2. ✅ Support `X-DTLS-*` headers for UDP tunnel
3. ✅ Implement `X-Aggregate-Auth` for modern auth flows
4. ✅ Support `X-AnyConnect-STRAP-*` for enhanced security

**Authentication**:
1. ✅ Implement aggregate auth XML framework
2. ✅ Support SAML/SSO with proper cookie handling
3. ✅ Certificate validation with exact error codes
4. ✅ Multi-step authentication flows (MFA)
5. ✅ Session token in tunnel configuration

**Tunnel Establishment**:
1. ✅ DTLS 1.2 with cookie exchange
2. ✅ Master secret sharing between TLS and DTLS
3. ✅ Cipher suite preference matching
4. ✅ MTU negotiation (Base MTU + effective MTU)
5. ✅ Compression algorithm support (LZS, deflate)

**Always-On VPN**:
1. ✅ Profile-based gateway enforcement
2. ✅ Strict certificate validation (no ask-user)
3. ✅ Proxy connection rejection
4. ✅ Single Always-On profile enforcement
5. ✅ Untrusted certificate hard failure

**Reconnection**:
1. ✅ Suspend/resume detection and handling
2. ✅ Network change detection
3. ✅ Session-level vs tunnel-level reconnect
4. ✅ DTLS rekey with fallback to full reconnect
5. ✅ Configurable reconnect behavior

**DPD/Keepalive**:
1. ✅ Standard DPD request/response
2. ✅ MTU-based DPD with padding sizes
3. ✅ Optimal MTU detection via DPD
4. ✅ Keepalive timer management
5. ✅ DPD timeout handling

**Split Tunneling**:
1. ✅ Split-include network configuration
2. ✅ Split-exclude network configuration
3. ✅ Split DNS with UDP interception
4. ✅ DNS query matching algorithm
5. ✅ Response code manipulation

### 12.2 Testing Requirements

**Unit Tests**:
- [ ] All custom HTTP headers parsed correctly
- [ ] XML authentication messages generated properly
- [ ] Error code mapping matches Cisco expectations
- [ ] Certificate validation logic exact match
- [ ] DPD message handling correct

**Integration Tests**:
- [ ] Full authentication flow with Cisco client 5.1.2.42
- [ ] DTLS tunnel establishment with cookie exchange
- [ ] TLS tunnel with all compression options
- [ ] Always-On VPN profile enforcement
- [ ] Suspend/resume reconnection
- [ ] Captive portal detection behavior
- [ ] Split DNS functionality
- [ ] MTU DPD mechanism

**Compatibility Tests**:
- [ ] Cisco Secure Client 5.0.x
- [ ] Cisco Secure Client 5.1.x
- [ ] Cisco Secure Client 5.2.x
- [ ] OpenConnect client 9.x
- [ ] Multiple authentication methods
- [ ] IPv4-only, IPv6-only, dual-stack
- [ ] Various network conditions (proxy, captive portal, etc.)

**Security Tests**:
- [ ] Certificate pinning enforcement
- [ ] Untrusted certificate handling
- [ ] FIPS mode operation
- [ ] Cipher suite negotiation
- [ ] Session security

### 12.3 Known Issues to Handle

**Cisco Client Quirks**:
1. **XML Parsing Strictness**: Exact tag ordering may be required
2. **Certificate Chain Validation**: Order and strictness critical
3. **DTLS Timing**: Cookie exchange timing sensitive
4. **Session Persistence**: Cookie format must match exactly
5. **Error Message Format**: Some clients check exact error strings

**Proxy Handling**:
1. Always-On VPN blocks proxy connections entirely
2. Proxy authentication required before VPN
3. HTTPS-only gateway policy enforcement
4. Captive portal must be handled before VPN

**Network Transitions**:
1. Fast startup with cached configuration
2. Connected Standby handling
3. Public proxy redetermination triggers reconnect
4. Gateway IP change triggers session reconnect

### 12.4 Priority Implementation Order

**Phase 1 - Core Protocol** (Sprint 1-2):
1. HTTP headers (X-CSTP-*, X-DTLS-*)
2. Basic authentication (password, certificate)
3. TLS tunnel establishment
4. Configuration exchange
5. Simple keepalive

**Phase 2 - Advanced Auth** (Sprint 3-4):
1. Aggregate authentication framework
2. SAML/SSO cookie handling
3. Multi-factor authentication
4. Certificate pinning
5. Error code compatibility

**Phase 3 - DTLS Support** (Sprint 5-6):
1. DTLS 1.2 implementation
2. Cookie exchange mechanism
3. Master secret sharing
4. DTLS reconnection
5. Cipher suite compatibility

**Phase 4 - Resilience** (Sprint 7-8):
1. Always-On VPN implementation
2. Suspend/resume handling
3. Automatic reconnection
4. DPD mechanisms (standard + MTU-based)
5. Network change detection

**Phase 5 - Advanced Features** (Sprint 9-10):
1. Split tunneling (routes)
2. Split DNS implementation
3. Captive portal detection
4. MTU optimization
5. Compression (LZS, deflate)

**Phase 6 - Compatibility Testing** (Sprint 11-12):
1. Extensive Cisco client testing
2. Edge case handling
3. Error scenario testing
4. Performance optimization
5. Documentation completion

---

## 13. Open Questions and Further Investigation

### 13.1 Protocol Details Requiring Dynamic Analysis

**Questions**:
1. ❓ Exact XML schema for aggregate authentication messages
2. ❓ Session token format and generation algorithm
3. ❓ Cookie encryption/obfuscation method
4. ❓ DTLS cookie generation algorithm
5. ❓ MTU DPD padding size selection logic
6. ❓ Keepalive interval negotiation
7. ❓ Exact SAML/SSO URL parsing requirements
8. ❓ Certificate pin format and matching algorithm

**Recommended Approach**:
- Network traffic capture with Cisco client
- SSL/TLS key logging for decryption
- Wireshark protocol dissection
- Comparison with OpenConnect client behavior
- Server-side log analysis from production ASA/FTD

### 13.2 Undocumented Features

**Telemetry/Phone-Home**:
- `CPhoneHomeVpn` class references found
- Telemetry data collection unclear
- Privacy implications unknown
- May be disabled in Always-On mode

**STRAP (Secure Transport Authentication Protocol)**:
- X-AnyConnect-STRAP-* headers present
- DH public key exchange mechanism
- Verification method unknown
- May be optional feature

**Transcend**:
- `X-Transcend-Version` header purpose unclear
- No other references found
- May be legacy or experimental feature

---

## 14. Comparison with OpenConnect Client

### 14.1 Similarities

**Both Implement**:
- OpenConnect Protocol v1.2
- CSTP (TLS) and DTLS tunnels
- Aggregate authentication
- SAML/SSO support
- Certificate authentication
- Split tunneling and DNS
- DPD and keepalive

### 14.2 Cisco-Specific Features

**Cisco Client Has**:
1. Always-On VPN with strict enforcement
2. Certificate pinning
3. FIPS mode compliance
4. MTU-based DPD optimization
5. Proprietary STRAP headers
6. Connected Standby handling
7. Component integrity checking
8. Phone-home/telemetry
9. Automatic server selection
10. Pre-tunnel IPC messaging

**OpenConnect Client**:
- More flexible (no Always-On enforcement)
- Open source implementation
- Cross-platform (Linux, BSD, Windows, etc.)
- No telemetry
- Simpler certificate handling
- Community-driven development

### 14.3 Implementation Guidance

**For ocserv-modern**:
- Support both Cisco client AND OpenConnect client
- Implement Cisco-specific features as optional
- Maintain compatibility with both protocols
- Document differences clearly
- Test with both clients extensively

---

## 15. Security and Legal Considerations

### 15.1 Reverse Engineering Ethics

**Purpose**: Interoperability only
- ✅ Creating compatible server implementation
- ✅ Ensuring client compatibility
- ✅ Documenting public protocol behavior
- ✅ No circumvention of security measures
- ✅ No extraction of proprietary algorithms
- ❌ NOT bypassing licensing/protection
- ❌ NOT redistributing Cisco code
- ❌ NOT creating Cisco client clone

### 15.2 Legal Framework

**Applicable Laws**:
- EU: Copyright Directive Article 6 (interoperability exception)
- US: DMCA Section 1201(f) (reverse engineering for interoperability)
- Clean room implementation principles
- No access to Cisco source code

**Documentation**:
- All findings from publicly observable behavior
- Network protocol analysis (legal)
- Binary string extraction (legal for interoperability)
- No decompilation or disassembly beyond static analysis

### 15.3 Best Practices

**For ocserv-modern Project**:
1. Document all reverse engineering methodology
2. Maintain clear separation from Cisco IP
3. Implement from protocol specification, not code
4. Test against official Cisco client only
5. Publish findings for community benefit
6. Respect Cisco trademarks and copyrights
7. No false association with Cisco
8. Clear attribution of sources

---

## 16. Conclusion

This reverse engineering analysis has identified critical implementation details for ensuring Cisco Secure Client 5.1.2.42 compatibility with ocserv-modern v2.0.0. Key findings include:

1. **Complete HTTP header set** for CSTP and DTLS protocols
2. **Aggregate authentication framework** with SAML/SSO support
3. **Always-On VPN implementation** requirements and restrictions
4. **DPD mechanisms** including MTU-based optimization
5. **Cipher suite preferences** and security requirements
6. **Reconnection logic** for network resilience
7. **Split DNS implementation** details
8. **Certificate validation strictness** requirements

The analysis provides actionable implementation guidance organized by priority, enabling systematic development of full Cisco compatibility while maintaining clean-room implementation practices.

### Next Steps

1. **Dynamic Analysis**: Capture live traffic from Cisco client
2. **XML Schema Documentation**: Complete authentication message formats
3. **Implementation**: Follow phased approach (Sections 12.4)
4. **Testing**: Comprehensive compatibility testing matrix
5. **Documentation**: Enhance PROTOCOL_REFERENCE.md with findings

---

**Analyst**: Reverse Engineering Team
**Review Status**: Complete - Static Analysis Phase
**Next Phase**: Dynamic Protocol Analysis
**Target Date**: 2025-11-15

---

## Appendix A: File Locations

### Analyzed Binaries
```
/opt/projects/repositories/cisco-secure-client/cisco-secure-client-linux64-5.1.2.42/vpn/
├── vpnagentd                      # Main VPN daemon
├── vpnui                          # UI application
├── acwebhelper                    # Web authentication
├── acextwebhelper                 # Extended web helper
├── libvpnapi.so                   # Core API
├── libvpncommon.so               # Common utilities
├── libvpncommoncrypt.so          # Crypto functions
├── libvpnagentutilities.so       # Agent utilities
├── libvpnipsec.so                # IPsec support
├── libacciscossl.so              # Cisco SSL/TLS
├── libacciscocrypto.so           # Cisco Crypto
├── libaccurl.so.4.8.0            # HTTP transport
└── libacruntime.so               # Runtime library
```

### Analysis Output
```
/opt/projects/repositories/cisco-secure-client/analysis/
├── linux/
│   ├── static/
│   │   ├── vpnagentd_protocol_strings.txt
│   │   ├── vpnagentd_endpoints.txt
│   │   ├── vpnagentd_xml_tags.txt
│   │   ├── acwebhelper_strings.txt
│   │   └── http_headers.txt
│   └── dynamic/
│       └── (reserved for traffic captures)
└── REVERSE_ENGINEERING_FINDINGS.md (this document)
```

---

## Appendix B: References

1. **Cisco Secure Client 5.1.2.42** - Linux x86_64 distribution
2. **OpenConnect Protocol Draft 04** - https://datatracker.ietf.org/doc/draft-mavrogiannopoulos-openconnect/
3. **ocserv Documentation** - https://ocserv.gitlab.io/www/
4. **OpenConnect Client** - https://www.infradead.org/openconnect/
5. **RFC 8446** - TLS 1.3
6. **RFC 9147** - DTLS 1.3
7. **RFC 6347** - DTLS 1.2

---

*End of Document*
