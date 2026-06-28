# Cisco OpenConnect/AnyConnect Protocol Map (Server + Client)

Static triage: ASAc 9.24.1 lina + FTDv 10.0 lina + CSC 5.1.17 binaries + VPNAPI SDK.
Method: idacli strings+decompile, readelf, nm, SDK headers, web research.
Date: 2026-06-28.

---

## 1. Protocol Architecture

### 1.1 CSTP Frame Format (from `CSTP_fsm_util_message_verify` @ 0x38D68C0)

```
Offset  Size  Field              Value / Notes
0       2     Magic              0x5354 ("ST" LE) — verified as == 21587
2       1     Magic cont.        0x46 ('F') — checked == 70
3       1     Protocol version   Compared to session field at +136
4       2     Payload length     Big-endian (ROL2 + 8 = total frame)
6       1     Frame type         0x00-0x0A valid; 0x0B+ = unknown
7       1     Reserved           Must be 0x00
8       N     Payload            N = payload length
```

Frame types (from `CSTP_fsm_message_process` @ 0x38D4B70):
| Type | Constant | Handler |
|------|----------|---------|
| 0x00 | AC_PKT_DATA | Data payload (IP packet) |
| 0x03 | AC_PKT_DPD_OUT | Dead Peer Detection request |
| 0x04 | AC_PKT_DPD_RESP | Dead Peer Detection response |
| 0x05 | (type 5) | `sub_38D6D50` — DPD/address renew handler |
| 0x07 | AC_PKT_KEEPALIVE | Keepalive |
| 0x08 | AC_PKT_COMPRESSED | Compressed data |
| 0xFF | (type -1/255) | `sub_38D7100` — disconnect/terminate |

### 1.2 DTLS Frame Format

```
Offset  Size  Field
0       1     Frame type (same AC_PKT_* values)
1       N     Payload
```

DTLS has no magic header — 1-byte type prefix only.

### 1.3 AggAuth HTTP Headers

| Header | Direction | Value | Purpose |
|--------|-----------|-------|---------|
| `X-Aggregate-Auth` | C→S | `2` | Client requests AggAuth v2 |
| `X-Aggregate-Auth` | S→C | `1` | Server responds AggAuth v1 (Lua: `ADD_HTTP_RESP_HEADER`) |
| `X-Reason` | S→C | error string | Error/rejection reason |
| `aggregate-auth-version` | XML attr | `2` | XML-level version negotiation |

Lua API in lina portal engine (90+ SESSION_* functions):
- Request: `HTTP_HEADER_BY_NAME("X-Aggregate-Auth")` — check client header
- Response: `ADD_HTTP_RESP_HEADER("X-Aggregate-Auth", "1")` — add response header
- Auth: `SESSION_USERNAME()`, `SESSION_PASSWORD()`, `SESSION_PRIMARY_PASSWORD()`, `SESSION_SECONDARY_PASSWORD()`
- Session: `SESSION_ID()`, `SESSION_MAGIC_STRING()`, `SESSION_MACRO(1)`, `SESSION_TIME()`
- Config: `SESSION_BANNER()`, `SESSION_HOMEPAGE()`, `SESSION_DAP_MESSAGE()`, `SESSION_DAP_REDIRECT_URL()`
- Mode: `SESSION_SVC_ASK_TYPE()` (1=auto-deploy, 2=portal-only, 3=ask), `SESSION_ANYCONNECT_ENABLED()`
- Split: `SESSION_GET_SMART_TUNNEL_SPLITPOLICY()`, `SESSION_GET_SMART_TUNNELED_APPS()`
- Cert: `SESSION_IS_CLIENT_CERT_PRESENT()`, `SESSION_MAP_CERT_TO_GROUP()`
- SSO: `SESSION_IS_SSOASO_ALLOWED()`
- Portal: `SESSION_PORTAL_ENABLED()`, `SESSION_CLIENTLESS()`, `SESSION_NAV_URL()`
- Timeouts: `SESSION_MAX_CONNECT_TIME()`, `SESSION_MAX_IDLE_TIME()`, `SESSION_IDLE_ALERT_INTERVAL()`, `SESSION_END_ALERT_INTERVAL()`
- Security: `get_script_nonce()` — CSP nonce, `SESSION_CHECK_URL()` — URL validation
- Output: `OUT(str)`, `OutParam(path)`, `CUSTOM(path, default)`, `L(key)` — localization

### 1.4 URL Namespace (from lina embedded strings)

| Prefix | Purpose | Count |
|--------|---------|-------|
| `/CSCOSSLC/` | VPN tunnel endpoints | 3 |
| `/+CSCOE+/` | Portal engine pages (Lua-rendered) | 100+ |
| `/+CSCOL+/` | Client-side libraries/plugins | 12 |
| `/+CSCOM+/` | Get resources | 1 |
| `/+CSCOSCEP+/` | SCEP enrollment | 1 |
| `/+CSCOSSE+/` | Server-side events? | 1 |
| `/+CSCOT+/` | Translation tables (i18n) | 2 |
| `/+CSCOU+/` | User assets (images, CSS, JS) | 80+ |
| `/+CSCOCA+/` | Certificate Authority enrollment | 1 |
| `/CACHE/stc/` | Static content from .pkg files | dynamic |

CSCOSSLC tunnel endpoints:
- `/CSCOSSLC/config-auth` — AggAuth XML POST (auth negotiation)
- `/CSCOSSLC/tunnel` — CSTP tunnel (CONNECT method)
- `/CSCOSSLC/` — base path

SAML endpoints:
- `/+CSCOE+/saml/sp/login` — Initiate SAML SSO (`?tgname=<tunnel-group>`)
- `/+CSCOE+/saml/sp/acs` — Assertion Consumer Service (IdP callback)
- `/+CSCOE+/saml/sp/logout` — SAML Single Logout
- `/+CSCOE+/saml/sp/metadata` — SP metadata XML
- `/+CSCOE+/saml_ac_login.html` — AnyConnect SAML login page

Portal auth endpoints (with Lua template mapping from URL router 0x3BBD450):
- `/+CSCOE+/logon.html` → `webvpn_auth/webvpn_logon_page.lua`
- `/+CSCOE+/auth.html` → `webvpn_auth/auth.lua`
- `/+CSCOE+/portal.html` — Post-auth portal
- `/+CSCOE+/svc.html` — SVC/AnyConnect launch page
- `/+CSCOE+/ask.html` — Ask mode (auto-connect vs portal)
- `/+CSCOE+/logout.html` — Logout
- `/+CSCOE+/no_svc.html` — SVC not available
- `/+CSCOE+/session.js` → `webvpn_portal/session_js.lua`
- `/+CSCOE+/http_auth.html` → `webvpn_cte/http_auth.lua`
- `/+CSCOE+/cert.html` — Certificate auth page
- `/+CSCOE+/zt_logon.html` — Zero Trust login

HostScan/Posture:
- `/+CSCOE+/sdesktop/scan.xml` — Host scan config
- `/+CSCOE+/sdesktop/token.xml` — Host scan token
- `/+CSCOE+/sdesktop/tokenrenew.xml` — Token renewal
- `/+CSCOE+/sdesktop/wait.html` — Scanning wait page

### 1.5 Tunnel Establishment Flow

```
Client                              Server (lina)
  |                                    |
  |-- HTTPS GET /                      |
  |   User-Agent: AnyConnect*          |
  |<-- 302 /+CSCOE+/logon.html        |
  |                                    |
  |-- POST /+CSCOE+/logon.html        |  (username/password/SAML)
  |   X-Aggregate-Auth: 2             |  (AggAuth v2 negotiation)
  |<-- config-auth XML response       |
  |                                    |
  |-- CONNECT /CSCOSSLC/tunnel HTTP/1.1|
  |   Cookie: webvpn=<session>         |
  |   X-CSTP-* headers                 |
  |   X-DTLS-* headers                 |
  |   X-AnyConnect-* headers           |
  |<-- HTTP/1.1 200 OK                |
  |   X-CSTP-Address: 10.x.x.x       |
  |   X-CSTP-Netmask: 255.255.255.0  |
  |   X-CSTP-DNS: 8.8.8.8            |
  |   X-DTLS-Port: 443               |
  |   X-DTLS-Session-ID: <64 hex>    |
  |   ... (full header set)            |
  |                                    |
  |== CSTP tunnel active (TLS) ========|
  |-- STF\x01 frames ----------------->|
  |<- STF\x01 frames ------------------|
  |                                    |
  |== DTLS setup (parallel) ===========|
  |-- DTLS ClientHello                 |
  |   SessionID = X-DTLS-Session-ID   |
  |<-- DTLS ServerHello (resume)       |
  |== DTLS tunnel active ===============|
```

---

## 2. X-CSTP Headers (52 headers, ASAc 9.24.1 lina)

All headers identical between ASAc 9.24.1 and FTDv 10.0 — zero protocol-level differences.

### 2.1 Client → Server (Request)

| Header | Purpose | Parser |
|--------|---------|--------|
| X-CSTP-Version | Protocol version ("1") | `webvpn_cstp_parse_request_field` |
| X-CSTP-Hostname | Client hostname | Same |
| X-CSTP-Base-MTU | Link MTU | Same |
| X-CSTP-MTU | Requested tunnel MTU | Same |
| X-CSTP-Address-Type | IPv4/IPv6/both | Same |
| X-CSTP-Full-IPv6-Capability | IPv6 flag | Same |
| X-CSTP-Accept-Encoding | Compression: deflate,lzs,lz4 | `webvpn_cstp_request_accept_encoding` (0x38B25F0) |
| X-CSTP-Protocol | Protocol version | Same |
| X-CSTP-Keep | Keepalive method | Same |

### 2.2 Server → Client (Response, exact string format from lina)

| Header | Example Value | Source |
|--------|---------------|--------|
| `X-CSTP-Address: ` | `10.x.x.x` | `CSTP_fsm_address_request` (0x38D36F0) |
| `X-CSTP-Address-IP6: ` | `fd00::1/128` | Same |
| `X-CSTP-Netmask: ` | `255.255.255.0` | Same |
| `X-CSTP-DNS: ` | `8.8.8.8` (multi) | Config |
| `X-CSTP-DNS-IP6: ` | `2001:4860::` (multi) | Config |
| `X-CSTP-NBNS: ` | WINS server | Config |
| `X-CSTP-Default-Domain: ` | `corp.example.com` | Config |
| `X-CSTP-Split-DNS: ` | `corp.example.com` (multi) | Config |
| `X-CSTP-Banner: ` | login message | Config |
| `X-CSTP-DPD: ` / `X-CSTP-DPD: disabled` | interval sec / off | Config |
| `X-CSTP-Keepalive: ` | interval sec | Config |
| `X-CSTP-Keep: true` / `false` | keepalive on/off | Config |
| `X-CSTP-Idle-Timeout: ` | inactivity sec | Config |
| `X-CSTP-Session-Timeout: ` | max session sec | Config |
| `X-CSTP-Session-Timeout-Alert-Interval: ` | warn before timeout | Config |
| `X-CSTP-Session-Timeout-Remaining: ` | time left sec | Runtime |
| `X-CSTP-Disconnected-Timeout: ` | grace period sec | Config |
| `X-CSTP-Lease-Duration: ` | IP lease sec | Config |
| `X-CSTP-Rekey-Method: new-tunnel` | fixed value | Config |
| `X-CSTP-Rekey-Time: ` | seconds | Config |
| `X-CSTP-MTU: ` (via `Sending X-CSTP-MTU: %d`) | computed MTU | Computed (§4.7) |
| `X-CSTP-Content-Encoding: ` | `deflate` / `lzs` | `webvpn_cstp_generate_content_encoding` (0x38B7460) |
| `X-CSTP-Protocol: ` | protocol version | Config |
| `X-CSTP-Version: ` | CSTP version | Config |
| `X-CSTP-License: accept` / `reject` | license decision | Config |
| `X-CSTP-Homepage: ` | post-login URL | Config |
| `X-CSTP-FW-RULE` / `X-CSTP-FW-RULE-IP6` | ACL rules | `webvpn_svc_parse_acl` (0x3857C70), §4.10 |
| `X-CSTP-Quarantine: ` | quarantine state | DAP |
| `X-CSTP-DAP-User-Message: ` | via `Sending X-CSTP-DAP-User-Message: %s` | DAP |
| `X-CSTP-Post-Auth-XML: ` | auth XML document | AggAuth |
| `X-CSTP-Routing-Filtering-Ignore: true`/`false` | skip routing | Config |
| `X-CSTP-Client-Bypass-Protocol: ` | via `Sending X-CSTP-Client-Bypass-Protocol: %s` | Config |
| `X-CSTP-TCP-Keepalive:` | keepalive flag | Config |
| `X-CSTP-Tunnel-All-DNS: true`/`false` | tunnel all DNS | Config (`split-tunnel-all-dns`) |
| `X-CSTP-Smartcard-Removal-Disconnect: true`/`false` | smartcard policy | Config |
| `X-CSTP-Disable-Always-On-VPN: ` | disable AO | Config |
| `X-CSTP-Local-Address-IP4:` / `IP6:` | local interface | Runtime |
| `X-CSTP-Remote-Address-IP4:` / `IP6:` | remote endpoint | Runtime |
| `X-CSTP-MSIE-Proxy: auto`/`bypass-local`/`none` | proxy mode | Config |
| `X-CSTP-MSIE-Proxy-Exception: ` | proxy exceptions | Config |
| `X-CSTP-MSIE-Proxy-Lockdown: true`/`false` | lock proxy | Config |
| `X-CSTP-MSIE-Proxy-PAC-URL: ` | PAC URL | Config |
| `X-CSTP-MSIE-Proxy-Server: ` | proxy server | Config |
| `X-CSTP-MUS-HOST: ` / `No host configured` | Umbrella MUS | Config |
| `X-CSTP-Address-Type:` | IPv4/IPv6/both | Config |

### 2.3 X-DTLS Headers (11, exact strings from lina)

| Header | Example | Notes |
|--------|---------|-------|
| `X-DTLS-Master-Secret:` | 96 hex chars (48 bytes) | Client→Server, pre-master for session resume |
| `X-DTLS-Session-ID:` | 64 hex chars (32 bytes) | Server→Client, session resume ID |
| `X-DTLS-Port: ` | `443` | Server→Client, UDP port |
| `X-DTLS-MTU: ` | computed | via `Sending X-DTLS-MTU: %d`, §4.7 |
| `X-DTLS-CipherSuite: ` | cipher name | via `Sending X-DTLS-CipherSuite: %s`, can be multi |
| `X-DTLS-Content-Encoding: ` | `lzs` | DTLS compression |
| `X-DTLS-DPD: ` / `disabled` | interval sec | Config |
| `X-DTLS-Keepalive: ` | interval sec | Config |
| `X-DTLS-Rekey-Time: ` | seconds | Config |
| `X-DTLS-Accept-Encoding:` | `lzs` | Client→Server |
| `X-DTLS-` | prefix for parser | Catch-all prefix matching |

**DTLSv1 vs DTLSv1.2**: `Skipping cipher selection using DTLSv1 due to out of order processing of X-DTLS-CipherSuite` — server processes DTLSv1.2 ciphers first, falls back to DTLSv1.

**DTLS Session Establishment (from decompilation)**:
1. Client sends `X-DTLS-Master-Secret: <96 hex chars>` via CSTP tunnel
   - Server parses at `sub_38B1A40`: converts 96 hex → 48 bytes, stores at session+0x50
   - Sets flag session+0x4C = 1 (master secret received)
2. Server generates `X-DTLS-Session-ID: <64 hex chars>`
   - `sub_38B7680`: reads 32 random bytes from session+0x80, hex-encodes via `sub_4017880`
3. Client connects via DTLS using session resumption (SessionID + pre-shared master secret)
4. No full DTLS handshake — session resume only (master secret was shared over TLS)

**Request Header Dispatch Table** (at `off_63B4840`, 24 entries):

| Header | Handler | Len | Notes |
|--------|---------|-----|-------|
| Host: | sub_38B0960 | 5 | Hostname |
| User-Agent: | sub_38B09F0 | 11 | Client UA |
| Cookie: | sub_38B3660 | 7 | Session cookie |
| Cookie2: | sub_38B3660 | 8 | Alt cookie |
| X-CSTP-Hostname: | sub_38B0B10 | 16 | Client hostname |
| X-CSTP-Version: | sub_38B1010 | 15 | CSTP version |
| X-CSTP-Accept-Encoding: | sub_38B25F0 | 23 | Compression negotiation |
| X-DTLS-Accept-Encoding: | sub_38B28F0 | 23 | DTLS compression |
| X-DTLS-Master-Secret: | sub_38B1A40 | 21 | 96 hex → 48 bytes |
| X-CSTP-MTU: | sub_38B1180 | 11 | Client requested MTU |
| X-CSTP-Base-MTU: | sub_38B1290 | 16 | Link MTU |
| X-CSTP-Address-Type: | sub_38B1380 | 20 | IPv4/IPv6/both |
| X-CSTP-Full-IPv6-Capability: | sub_38B1480 | 28 | IPv6 flag |
| X-DTLS-CipherSuite: | sub_38B1BA0 | 19 | DTLSv1 cipher |
| X-CSTP-License: | sub_38B0C30 | 15 | License type |
| X-CSTP-Protocol: | sub_38B0F00 | 16 | Protocol version |
| X-CSTP-TCP-Keepalive: | sub_38B0E00 | 21 | TCP keepalive |
| X-CSTP-Local-Address-IP4: | sub_38B1990 | 25 | Local IP |
| X-CSTP-Local-Address-IP6: | sub_38B18D0 | 25 | Local IPv6 |
| X-CSTP-Remote-Address-IP4: | sub_38B1820 | 26 | Remote IP |
| X-CSTP-Remote-Address-IP6: | sub_38B1770 | 26 | Remote IPv6 |
| X-DTLS12-CipherSuite: | sub_38BA220 | 21 | DTLSv1.2 cipher |
| X-AnyConnect-STRAP-Pubkey: | sub_38B0870 | 26 | STRAP EC key |
| X-AnyConnect-STRAP-Verify: | sub_38B0780 | 26 | STRAP signature |

### 2.4 X-AnyConnect Headers (10)

| Header | Purpose |
|--------|---------|
| X-AnyConnect-Identifier-ClientVersion | Client version string |
| X-AnyConnect-Device-Computer-Name | Device hostname |
| X-AnyConnect-Device-UniqueID | Device UUID |
| X-AnyConnect-Device-UniqueID-Global | Global device ID |
| X-AnyConnect-DeviceType | Device type |
| X-AnyConnect-Platform | Platform (win/mac/linux) |
| X-AnyConnect-PlatformVersion | OS version |
| X-AnyConnect-STRAP-DH-Pubkey | STRAP DH public key |
| X-AnyConnect-STRAP-Pubkey | STRAP public key |
| X-AnyConnect-STRAP-Verify | STRAP verification |

---

## 3. Authentication Flow

### 3.1 ConnectPromptType (from VPNAPI SDK)

| Type | Enum | Description |
|------|------|-------------|
| 0 | CERTIFICATE | Certificate-only auth |
| 1 | CREDENTIALS | Username/password |
| 2 | PROXY | Proxy auth |
| 3 | MANUAL_PKCS12_IMPORT | PKCS12 import |
| 4 | STATUS | Status messages |
| 5 | SINGLESIGNON | Embedded browser SSO |
| 6 | SINGLELOGOUT | SSO logout |
| 7 | LEGACY_SINGLESIGNON | Browser-based SSO (deprecated) |

### 3.2 PromptType

| Type | Description |
|------|-------------|
| Prompt_Input | Label + text value |
| Prompt_Password | Label + masked value |
| Prompt_Banner | Banner text |
| Prompt_Combo | Dropdown choices |
| Prompt_Header | Section header |
| Prompt_Hidden | Hidden field |
| Prompt_CheckBox | Boolean checkbox |
| Prompt_SSO | SSO token prompt |

### 3.3 AggAuth (Aggregate Authentication)

Main handler: `aggregate_auth_process_client_r` @ 0x3B5EBD0 (small dispatcher, calls 0x3BBD450 which is too large to decompile).

Endpoints:
- `/CSCOSSLC/config-auth` — AggAuth XML POST endpoint
- `/CSCOSSLC/tunnel` — CSTP tunnel establishment (CONNECT method)
- `/CSCOSSLC/` — base path for SSL VPN

XML protocol:
```xml
<!-- Client → Server (auth-request) -->
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
  <group-select>tunnel-group-name</group-select>
  <opaque is-for="sg">...</opaque>        <!-- server state token -->
  <auth>
    <username>user</username>
    <password>pass</password>
    <secondary-password>otp</secondary-password>  <!-- MFA/OTP -->
  </auth>
  <host-scan>...</host-scan>              <!-- posture data -->
  <certificate-authentication/>           <!-- cert auth indicator -->
</config-auth>

<!-- Server → Client (auth-reply) -->
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply">
  <auth id="main">                        <!-- main login form -->
    <message>Please login</message>
    <banner>Welcome banner</banner>
    <form-data>...</form-data>
  </auth>
  <!-- or: -->
  <auth id="challenge">...</auth>         <!-- MFA challenge -->
  <auth id="next_passcode">...</auth>     <!-- RSA SecurID -->
  <auth id="next_tokencode">...</auth>    <!-- RSA SecurID -->
  <opaque is-for="sg">...</opaque>        <!-- state roundtrip -->
  <session-token>...</session-token>      <!-- on success -->
  <session-id>...</session-id>
  <error id="13">...</error>              <!-- errors -->
</config-auth>
```

Auth form customization (Lua templates in lina):
- `OutParam("auth-page/form-order/secondary-password")` — MFA field order
- `CUSTOM("auth-page/logon-form/secondary-password-prompt-text", L("2nd Password"))` — prompt text
- `SESSION_MACRO(1)`, `SESSION_MACRO(2)` — dynamic session values
- `SESSION_MAGIC_STRING()` — cache-busting token
- Debug: `[no] debug aggregate-auth {xml | ssl} [<1-255>]`

**AggAuth Message Types** (from `sub_115A9D0` dispatch at [ctx+0x40]):

| Type | Handler | Purpose |
|------|---------|---------|
| 1 | sub_1159B10 | INIT: initial auth, cert processing, session creation |
| 2 | sub_1159530 | AUTH-REPLY: tunnel group lookup, multi-cert, multi-context |
| 3 | sub_11521D0 | CONFIG-REQUEST: AnyConnect identity extensions, DAP attributes |
| 4 | sub_1150BA0 | SESSION-TOKEN: session token validation |
| 6 | sub_1150B10 | POLL: explicitly NOT supported (returns error) |

**AggAuth XML Elements** (from sub_115FBE0):
- Response: `config`, `vpn`, `private`, `vpn-base-config`, `optional-modules`, `base-package-uri`
- Auth: `auth`, `success`, `banner`, `message`, `input` (type: password|text|sso), `name`, `label`
- Session: `session-id`, `session-token`, `opaque` (is-for: sg)
- Crypto: `client-cert-hash`, `server-cert-hash`, `multiple-cert`, `client-cert-request`
- Profile: `vpn-profile-manifest`, `profile`, `file`, `rev`
- Capabilities: `ssl-dhe`, `crypto-supported`, `aggregate-auth-version`, `config-hash`
- SSO: `sso-v2-login`, `sso-v2-token`, `sso-v2-browser-mode`
- RSA: `sdi`, `sdi-via-proxy`
- Posture: `host-scan`, `host-scan-token_status`
- Error: `error` (id, param1, param2)

**DAP Endpoint Attributes** (from CONFIG-REQUEST handler):
```
endpoint.anyconnect.clientversion
endpoint.anyconnect.platform
endpoint.anyconnect.devicetype
endpoint.anyconnect.platformversion
endpoint.anyconnect.deviceuniqueid
endpoint.anyconnect.deviceuniqueidglobal
endpoint.anyconnect.phoneid
endpoint.anyconnect.macaddress
endpoint.anyconnect.useragent
endpoint.anyconnect.publicmacaddress
endpoint.anyconnect.devicecomputername
```

EAP integration:
- `EAP: Authenticating aggregate-auth based secondary cert`
- `EAP: Wait for certificate auth to complete before processing auth-reply`
- `re-auth-request-type` — re-authentication during rekey

SAML endpoints (with Lua templates):
- `/+CSCOE+/saml/sp/login` → `webvpn_auth/samlsplogin.lua`
- `/+CSCOE+/saml/sp/acs` → `webvpn_auth/samlspacs.lua`
- `/+CSCOE+/saml/sp/logout` → `webvpn_auth/samlsplogout.lua`
- `/+CSCOE+/saml/sp/metadata` → `webvpn_auth/samlspmetadata.lua`
- Cookies: `acSamlv2Token`, `acsamlcap`
- Auth types: `saml-only`, `saml-cert`
- SAML login URL format: `%s/+CSCOE+/saml/sp/login?ctx=%s&acsamlcap=v2`
- Embedded browser fallback when client lacks external browser support

**AggAuth State Machine** (P2-A, 240 functions):

Context struct (~520 bytes): +64=request_type_id, +124=cert_received_flag, +352=aggauth_handle (8B),
+384=tunnel_group_ptr, +400=existing_session_ptr, +408=auth_info_ptr, +512=next_state_handler.

State handlers (13):
| Address | State | Trigger |
|---------|-------|---------|
| sub_1159B10 | INIT entry | `<config-auth type="init">` |
| sub_1154260 | INIT-cert | Client has certificate |
| sub_1157B40 | INIT-no-cert | No client certificate |
| sub_1159530 | AUTH-REPLY entry | `<config-auth type="auth-reply">` |
| sub_11517E0 | Regular auth (new) | Open AAA handle |
| sub_11518D0 | Regular auth (existing) | Reuse AAA handle |
| sub_1154BA0 | AAA request | Main AAA request/challenge |
| sub_11555D0 | Multi-cert/SAML | Dispatch multi-cert or SAML |
| sub_1158240 | Multi-cert auth | Multi-cert continuation |
| sub_1156550 | SAML auth | SAML login/poll (4229B) |
| sub_1153590 | TG invalid error | Invalid tunnel group |
| sub_1153730 | Config changed error | Config version mismatch |
| sub_1153320 | Auth timeout error | Auth attempt timed out |

Tunnel group resolution (sub_1161C50, 853B) fallback chain:
cert CN/SAN → direct name → URL extraction → cert alias mapping → iterate all TGs → "DefaultWEBVPNGroup"

TG auth mode bitmask (tg+4168): bit0=cert_auth, bit1=cert_required, bit2=SAML, bit3=multi_cert.
Nine tiny accessor functions (17-20B each): sub_3683F20 through sub_3684080.

User lockout (sub_118D960): 600s auto-expire (non-NGFW), permanent in NGFW mode.
Counter at user+228 (uint16), syslog 6113006.

Error table at off_63B4080 (116 entries): 91=invalid TG, 96=unknown, 99=config changed, 107=auth timeout.

**External SSO (external-sso.pkg, 5.7KB)** — fully reversed:
- JS reads token from cookie `acSamlv2Token` or template `{{AC_SAML_TOKEN}}`
- Platform routing: iOS/macOS→`anyconnectsso://`, Android→`anyconnect://`, Desktop→`http://localhost:29786/api/sso/TOKEN`
- Client version from cookie `acvers`, hardcoded port 29786

### 3.4 Session Cookies

**Primary cookie**: `webvpn=<session_token>`

Creation: `sub_38A3580` (webvpn_session.c) generates token:
```
webvpn=A<06.6X>@<session_index>@<04.4X>@<08.8X><08.8X><08.8X><08.8X><04.4X>
```
- 28 bytes CSPRNG data (`sub_12C4CA0`, per-CPU context)
- Session index embedded in plaintext between `@` delimiters
- Delivered via `Set-Cookie: webvpn=<token>; path=/; secure; HttpOnly`

Validation: `webvpn_cstp_parse_webvpn_cookie` (0x38B2EF0)
- `sub_385D2F0` extracts session index from `@<index>@` in cookie
- Looks up session by index via `sub_38A00C0`
- Full string comparison against stored cookie at session+136
- Checks max login time and idle timeout
- Validates geo-fencing rules
- Source file: `webvpn_cstp.c:1342`

**Portal cookie**: `webvpn_portal=<value>`
- `webvpn_portal=start-anyconnect` → triggers AnyConnect auto-launch
- Cleared on logout: `webvpn_portal=; expires=Thu, 01 Jan 1970 22:00:00 GMT`
- HttpOnly flag set based on configuration

**SAML cookie**: `acSamlv2Token=<token>` (§4.11)

**Tunnel group**: `CSCO_WEBVPN_CONNECTION_PROFILE=<ROT13HEX(group)>`
- Obfuscated via `ROT13STR2HEX(tunnel_group)`
- Used in URL path: `/CSCO_WEBVPN_CONNECTION_PROFILE=<encoded>/...`

Other cookies: `csc_next`, `acsamlcap`

### 3.5 User Auth Methods (from SDK)

| Method | Description |
|--------|-------------|
| USER_AUTH_UNKNOWN | Unknown |
| USER_AUTH_SSL_MACHINE_STORE_CERT | Machine certificate |
| USER_AUTH_IKE_PSK | IKE pre-shared key (reconnect only) |
| USER_AUTH_IKE_RSA | IKE RSA |
| USER_AUTH_IKE_ECDSA | IKE ECDSA |
| USER_AUTH_IKE_EAP_MD5 | IKE EAP-MD5 |
| USER_AUTH_IKE_EAP_MSCHAPv2 | IKE EAP-MSCHAPv2 |
| USER_AUTH_IKE_EAP_GTC | IKE EAP-GTC |
| USER_AUTH_IKE_EAP_ANYCONNECT | IKE EAP-AnyConnect (default) |

---

## 4. Tunnel Parameters

### 4.1 Protocol Versions (from SDK)

| Enum | Version |
|------|---------|
| PROTO_VERSION_TLS10 | TLS 1.0 |
| PROTO_VERSION_SSL30 | SSL 3.0 |
| PROTO_VERSION_DTLS10 | DTLS 1.0 |
| PROTO_VERSION_IPSEC | IPsec |
| PROTO_VERSION_IPSEC_NAT_T | IPsec NAT-T |
| PROTO_VERSION_TLS11 | TLS 1.1 |
| PROTO_VERSION_TLS12 | TLS 1.2 |
| PROTO_VERSION_DTLS12 | DTLS 1.2 |
| PROTO_VERSION_TLS13 | TLS 1.3 |

### 4.2 Compression (from SDK + decompilation + lina strings)

| Enum | Algorithm | Transport |
|------|-----------|-----------|
| COMPR_NONE | No compression | CSTP + DTLS |
| COMPR_DEFLATE | Deflate (zlib) | CSTP only |
| COMPR_LZS | Stac LZS (RFC 1974) | CSTP + DTLS |

Quality-based negotiation: `X-CSTP-Accept-Encoding: deflate;q=1.0,lzs;q=0.8` (parsed at 0x38B25F0).

Offset +1076 in session struct: SSL compression mode.
Offset +1080: DTLS compression mode.
Values: 1=deflate, 2=LZS.

Server-side implementation:
- **Deflate**: zlib 1.2.3, `zl_deflate_init`/`zl_deflate_free`, COMP_ZLIB_DEFLATE_ERROR/INFLATE_ERROR
- **LZS**: Hardware-accelerated via CTM (`ctm_init_session() failed for SSL LZS`, `ctm_lzs_cb_func`), source: `lzsc.c`/`lzsd.c`, LZS_C_WINDOW_SIZE+4 scrap buffer, LZS_C_INTERNAL_ENGINE_THRESHOLD
- **IPcomp**: Separate from SVC compression — IPCOMP_DEFLATE, IPCOMP_LZS for IPsec tunnel compression
- **GZIP**: Used only for web portal content-encoding, NOT for tunnel data
- Config: `anyconnect ssl compression {deflate | none}`, `LZS compression algorithm enable`
- Confirmed: **No LZ4 in client or server** (zero references across all binaries)

### 4.3 Cipher Suite (66 values in SDK)

Key modern ciphers:
| ID | Cipher |
|----|--------|
| 42 | AES-128-GCM |
| 44 | AES-256-GCM |
| 49 | ECDHE-ECDSA-AES256-GCM-SHA384 |
| 50 | ECDHE-RSA-AES256-GCM-SHA384 |
| 55 | ECDHE-ECDSA-AES128-GCM-SHA256 |
| 56 | ECDHE-RSA-AES128-GCM-SHA256 |
| 63 | AES-128-GCM-SHA256 (TLS 1.3) |
| 64 | AES-256-GCM-SHA384 (TLS 1.3) |
| 65 | CHACHA20-POLY1305-SHA256 (TLS 1.3) |
| 66 | AES-128-CCM-SHA256 (TLS 1.3) |

**Post-Quantum (oqsprovider.so in CSC 5.1.17)**:
Kyber512/768/1024, Dilithium2/3/5, Falcon512/1024, BIKE, HQC, FrodoKEM, Classic-McEliece.
Hybrid/composite key exchange modes available.

### 4.4 VPN States (from SDK)

| State | Description |
|-------|-------------|
| CONNECTING | Establishing tunnel |
| CONNECTED | Tunnel active |
| RECONNECTING | Re-establishing after interruption |
| DISCONNECTING | Tearing down |
| DISCONNECTED | Inactive |
| PAUSING | Suspending tunnel |
| PAUSED | Tunnel suspended |
| AUTHENTICATING | Auth in progress |
| SSOPOLLING | SSO auth-poll |

### 4.5 Tunneling Modes (from SDK)

- "Tunnel All Traffic"
- "Split Include"
- "Split Exclude"
- "Application Tunnel"
- "Drop All Traffic"
- "Bypass All Traffic"

Dynamic split tunneling: `DYN_SPLIT_TUN_EXC` (exclusion), `DYN_SPLIT_TUN_INC` (inclusion).

Split tunnel route headers (client-side, NOT in lina as literals — generated dynamically):
```
X-CSTP-Split-Include: <IP>/<netmask>       (e.g. 10.0.0.0/255.0.0.0)
X-CSTP-Split-Exclude: <IP>/<netmask>
X-CSTP-Split-Include-IP6: <prefix>/<len>    (e.g. fd00::/64)
X-CSTP-Split-Exclude-IP6: <prefix>/<len>
```
Validation: `Invalid %s split-include route: %s/%s` / `Invalid %s split-exclude route: %s/%s`
Format: IP/mask (subnet mask notation, NOT CIDR prefix length for IPv4).

Split DNS: `X-CSTP-Split-DNS: <domain>` (multiple headers, one per domain).
Tunnel All DNS: `X-CSTP-Tunnel-All-DNS: true|false` (config: `split-tunnel-all-dns <disable|enable>`).

### 4.6 Rekey

Method: `X-CSTP-Rekey-Method` → "new-tunnel" (default) or "none"
Time: `X-CSTP-Rekey-Time` → seconds until rekey

### 4.7 MTU Calculation (from lina format strings)

Server computes TLS-MTU and DTLS-MTU from base-mtu through a multi-stage pipeline:

```
Step 1: path-mtu = base-mtu - ip - tcp
  path-mtu = %d(base-mtu) - %d(ip) - %d(tcp) = %d
  (or: path-mtu = %d(mss) if MSS-based)

Step 2: mtu (raw transport MTU)
  TLS:  mtu = path-mtu - opts - ssl - cstp
       (or: mtu = path-mtu - opts - ssl - iv)
       (or: mtu = path-mtu - opts - ssl)
  DTLS: mtu = base-mtu - ip - udp - dtlshdr - dtlsiv

Step 3: mod-mtu (cipher block alignment)
  mod-mtu = mtu & complement   (round down to block size)

Step 4: final MTU (subtract frame + MAC overhead)
  tls-mtu  = mod-mtu - cstp - mac - 1(pad)
  dtls-mtu = mod-mtu - cdtp - mac - 1(pad)
  (or: tls-mtu = mtu - mac for stream ciphers)

Step 5: override check
  if conf-mtu < computed: use conf-mtu
  "overide computed tls-mtu=%d with conf-mtu=%d"
  "overide computed dtls-mtu=%d with conf-mtu=%d"
```

Key variables:
- `base-mtu` = X-CSTP-Base-MTU from client (or default 1500)
- `ip` = 20 (IPv4) or 40 (IPv6), from `Iphdr=%d`
- `tcp` = 20 (TCP header)
- `udp` = 8 (UDP header)
- `opts` = TCP options length
- `ssl` = TLS record header (5 bytes)
- `cstp` = CSTP frame header (8 bytes)
- `cdtp` = DTLS type prefix (1 byte = "Compressed DTLS Transport Protocol" overhead)
- `dtlshdr` = DTLS record header
- `dtlsiv` = DTLS explicit IV
- `mac` = MAC tag length (varies by cipher)
- `1(pad)` = minimum padding for block ciphers
- `complement` = ~(blocksize-1) for block alignment

Default values: `Default cstp_mtu=%d`, `Default svc_mtu=%d`
Legacy: `Computing the legacy svc_mtu, configured=%d, client requested=%d`

### 4.8 STRAP Protocol (Secure Trusted Registration And Provisioning)

STRAP provides device identity binding — EC public key pinning to prevent session hijacking.

Headers:
- `X-AnyConnect-STRAP-DH-Pubkey` — Diffie-Hellman public key (EC)
- `X-AnyConnect-STRAP-Pubkey` — Device identity public key (EC)
- `X-AnyConnect-STRAP-Verify` — Client signature for verification

Server flow (from 90+ lina strings):
1. Client sends STRAP-Pubkey on first connect → stored in session
2. On reconnect, client sends STRAP-Verify (signature over SSL server data)
3. Server generates "SSL server data" and verifies signature via CTM
4. If public key changes, old key replaced after verification of new key
5. STRAP verification failure → tunnel dropped (`Drop tunnel due to STRAP verification failure`)
6. Public key synced to failover peer (`WebVPN Failover: Sending a STRAP public key update message`)

IKEv2 integration:
- IKEv2 sessions use STRAP VID (Vendor ID) for capability negotiation
- `AnyConnect STRAP DH VID received from peer`
- `IKEv2 Number of STRAP reconnect = %d`

SCEP Proxy integration:
- STRAP verification during certificate enrollment
- `SCEP PROXY: Anyconnect STRAP client signature verification successful`

Crypto details:
- EC curve validation: `Anyconnect STRAP: EC curve (nid = %d) not supported`
- DER-encoded public keys, base64-encoded signatures
- CTM (Crypto Task Manager) session for verification
- Key size limits: `STRAP DH Key size %d is bigger than the MAX key length %d`

Failure counters:
- STRAP parsing failure
- STRAP server data generation failure
- STRAP supported publik key failure / unsupported publik key failure
- STRAP no client signature found failure
- STRAP verification failure

### 4.9 DPD (Dead Peer Detection)

Functions: `svc_dpd_request`, `svc_dpd_response`, `svc_udp_dpd_request`, `svc_udp_dpd_response`
Config: `anyconnect dpd-interval {client | gateway} {none | <seconds>}`
- Client DPD: client sends DPD request, server responds
- Gateway DPD: server sends DPD request, client responds
- DPD timeout → session cleanup
Separate intervals for CSTP (TLS) and DTLS channels.

### 4.10 Firewall Rules (X-CSTP-FW-RULE)

Format: `X-CSTP-FW-RULE: {permit|deny} ip <src> <mask> <dst> <dmask> [proto] [port]`
IPv6 variant: `X-CSTP-FW-RULE-IP6`

Generation:
- ACL-based: `webvpn_svc_parse_acl` (0x3857C70) converts ACL → FW-RULE strings
- `Sending X-CSTP-FW-RULE msgs: Start` ... `Done` log markers
- Debug: `X-CSTP-FW-RULE for ACL - %s (type - %s)`
- Config: `Configure AnyConnect firewall rule` / `firewall-rule`
- CVC FW Rules stored in session (Custom VPN Configuration)
- `X-CSTP-FW-RULE msgs: No rules configured` when empty

### 4.11 SAML Authentication (Server-Side)

Cookie: `acSamlv2Token` — SAML assertion token
- Set-Cookie: `acSamlv2Token=%s; path=/; secure; HttpOnly`
- Logout: `acSamlv2Token=; expires=Thu, 01 Jan 1970 22:00:00 GMT`
- Replay protection: `SAML assertion replay detected` / `SAML_ASSERTION_NOT_REPLAY_SAFE`
- Expiry check: `SAML assertion expired upon receipt`
- Token reuse: `SAML Token Reuse` / `SAML_TOKEN_REUSE`
- Relay validation: `SAML Relay hash validation failure`
- STRAP integration: `STRAP key mismatch during SAML token validation`
- Tunnel group binding: `SAML token received on wrong tunnel group`
- XML parsing: `lasso_saml2_assertion_get_type`, `lasso_saml2_assertion_validate_audience` (liblasso2)

### 4.12 Geolocation Filtering

- GeoIP database loaded at boot, maintained in hash table
- Entries synced in HA: `[HA-GEO] STANDBY : Updated %d geolocation entries`
- Session-level check in cookie parser (`sub_384C0B0`)
- Drop counter: `Geolocation Filter Drop: %17d`

---

## 5. ASAc vs FTDv Diff

### 5.1 Protocol Layer: IDENTICAL

All 72 X-CSTP/X-DTLS/X-AnyConnect headers, CSTP frame format, AggAuth, SAML, session cookie — 100% shared between ASAc 9.24.1 and FTDv 10.0.

### 5.2 Binary Size Diff

| Metric | ASAc 9.24.1 | FTDv 10.0 | Delta |
|--------|-------------|-----------|-------|
| lina size | 113 MB | 166 MB | +53 MB |
| .text | 55.3 MB | 56.1 MB | +0.8 MB |
| .data | 17.1 MB | 31.6 MB | +14.5 MB |
| .bss | 54.6 MB | 116.7 MB | +62.1 MB |

### 5.3 FTD-Only Components

| Component | Description |
|-----------|-------------|
| Muster gRPC | Protobuf telemetry (ravpn/events, user_sessions) for FMC/CDO |
| RAVPN BEE | Bidirectional Event Engine for session streaming |
| eNIC + KC FPGA | Firepower chassis hardware drivers |
| Per-core IPSec | 256-entry block/frag lists for multi-core |
| offload_app | DPDK flow offload for Firepower chassis |
| ftw_monitor | FPGA health watchdog |
| asa_log_client | Image signature verification + log registration |

### 5.4 ASAc-Only Components

| Component | Description |
|-----------|-------------|
| VPP (fd.io) | 25 `vapi_*` symbols for dataplane offload |
| NVIDIA DOCA | 13 DOCA libs for DPU-accelerated IPsec |
| Redis IPC | hiredis for inter-process state |
| memif PMD | Container-to-container networking |

---

## 6. Key Decompiled Functions

### 6.1 CSTP Tunnel State Machine (32 events)

Entry: `sub_38D1DF0` sets up request descriptor (method=CONNECT, URI=/CSCOSSLC/tunnel).
URI parser: `cstp_util_request_determine` (0x38D5010) — method table at `off_63B5160`:
- GET=1, PUT=2, POST=3, HEAD=4, OPTIONS=5, TRACE=6, DELETE=7, **CONNECT=8** + WebDAV 9-24
- URI match: `CSCOSSLC/tunnel` → 1, `CSCOSSLC/cvcconfig` → 2

State machine: `CSTPtunnelTable` at `off_63B5300`, 32 events:

| Event | Name | Purpose |
|-------|------|---------|
| 0-3 | EV_OPTIONS/ADDRESS_REQUEST/RECEIVE/ACCEPT | Option + IP address negotiation |
| 8-10 | EV_IP_MASK_CHECK/CALCULATE/NORMALIZE | Subnet mask processing |
| 11-13 | EV_MUS_CHECK/REQUEST/RESPONSE | Umbrella MUS |
| 14 | EV_TUNNEL_SETUP | Create CSTP tunnel |
| 15 | EV_INSTALL_UAUTH | User auth installation |
| 16-17 | EV_FO_CHECK/ADDRESS | Failover handling |
| 20-21 | EV_DAP_CHECK/RUN | Dynamic Access Policy |
| 22 | EV_SESSION_SETUP | Session initialization |
| **24** | **EV_RESPONSE_BUILD** | **Build all X-CSTP/X-DTLS headers** → `sub_38B7BE0` |
| 25 | EV_CONNECTED | Tunnel active |
| 26 | EV_DATA_RECEIVED | Data transfer |
| 29 | EV_SEND_RECONNECT | Reconnect signal |

Pre-CONNECT auth: `cstp_connect_authenticate` (0x38D2230, 2411 bytes):
- 401: no user auth
- 503: no SVC image, AnyConnect not permitted, invalid session type, no license, CSTP not enabled
- 406: bad CSTP version
- License rejection: `X-CSTP-License: reject`

### 6.2 CSTP FSM Handlers (source: tunnel_fsm_act.c)

| Address | Name | Size | Purpose |
|---------|------|------|---------|
| 0x38D3460 | CSTP_fsm_compression_option | 274 | SSL/DTLS compression negotiation |
| 0x38D36F0 | CSTP_fsm_address_request | 1363 | IP address allocation (IPv4+IPv6) |
| 0x38D4B70 | CSTP_fsm_message_process | 253 | Frame type dispatch (5→DPD, 0xFF→disconnect) |
| 0x38D4C70 | CSTP_fsm_conn_close | 457 | Session teardown, cleanup |
| 0x38D68C0 | CSTP_fsm_util_message_verify | 932 | Frame magic/version/length/type validation |
| 0x38D6C70 | address_renew_request | 216 | IP address renewal |
| 0x38D6D50 | (DPD handler) | 410 | DPD response processing |
| 0x38DE000 | cstp_send_external_session_r | 829 | External session notification |

### 6.2 CSTP Parser (source: webvpn_cstp.c)

| Address | Name | Size | Purpose |
|---------|------|------|---------|
| 0x38B4C00 | webvpn_cstp_parse_request_header | 584 | Main header parser loop |
| 0x38B4760 | http_parse_cstp_method | 1169 | HTTP method parser (CONNECT) |
| 0x38B3910 | webvpn_cstp_parse_request_field | 217 | Individual header field parser |
| 0x38B2EF0 | webvpn_cstp_parse_webvpn_cookie | 871 | Session cookie validation + geo-fence |
| 0x38B25F0 | webvpn_cstp_request_accept_encoding | 762 | Compression negotiation parser |
| 0x38B7460 | webvpn_cstp_generate_content_encoding | 257 | Response compression header |
| 0x38B39F0 | (legacy SVC MTU) | 365 | Legacy MTU computation |

### 6.3 WebVPN SVC (source: webvpn_svc.c)

| Address | Name | Size | Purpose |
|---------|------|------|---------|
| 0x3857C70 | webvpn_svc_parse_acl | 676 | ACL parsing for split tunnel |
| 0x38ACDF0 | (SVC handler 1) | 391 | SVC processing |
| 0x38AD4B0 | cache_stc_profiles | 309 | Profile caching (/CACHE/stc/profiles/) |
| 0x38ADA40 | (SVC handler 3) | 131 | SVC processing |

### 6.4 Auth

| Address | Name | Size | Purpose |
|---------|------|------|---------|
| 0x3B5EBD0 | aggregate_auth_process_client_r | 111 | AggAuth Lua callback registrar |
| 0x3BBD450 | URL router (aware_webvpn_content.c) | large | Routes `/CSCOSSLC/config-auth` → Lua template |
| 0x3BBD070 | AGGREGATE_AUTH_PROCESS_CLIENT_REQUEST | — | Lua→C callback, calls sub_115AC50 |
| 0x115AC50 | aggauth_process_request | — | Init context + dispatch by message type |
| 0x115A9D0 | aggauth_dispatch_request | — | Type 1-6 dispatcher (INIT/AUTH-REPLY/CONFIG/TOKEN/POLL) |
| 0x1159B10 | aggauth_init_handler | — | Type 1: initial auth + cert processing |
| 0x1159530 | aggauth_auth_reply_handler | — | Type 2: tunnel group + multi-cert |
| 0x11521D0 | aggauth_config_request_handler | — | Type 3: AnyConnect identity + DAP attrs |
| 0x1150BA0 | aggauth_session_token_handler | — | Type 4: session validation |
| 0x11534C0 | aggauth_create_xml_response | — | XML response generator |
| 0x115DDE0 | aggauth_xml_parser | — | XML request parser |
| 0x385D2F0 | webvpn_index_from_cookie | 525 | Parse cookie, extract session index, lookup |
| 0x3861440 | http_webvpn_auth_accept | — | Cookie creation + session init |
| 0x38A3580 | cookie_token_generator | — | Generate CSPRNG cookie token |
| 0x3B6EAE0 | session_saver | — | Save session to /admin/sessions/ |

### 6.5 CSTP Response Generator (source: webvpn_cstp.c)

Main function: `webvpn_cstp_generate_headers` (0x38B7BE0, 7435 bytes).
Call chain: `EV_RESPONSE_BUILD` → `sub_38D48F0` → `sub_38D6810` → `0x38B7BE0`.
Generates 60+ response headers via 27 sub-functions:

#### Sub-function Map

| Address | Function | Headers Generated |
|---------|----------|-------------------|
| 0x38B52A0 | cstp_append_ipv4_address | X-CSTP-Address |
| 0x38B53A0 | cstp_append_address_ip6 | X-CSTP-Address-IP6 |
| 0x38B5590 | cstp_append_netmask | X-CSTP-Netmask |
| 0x38B5690 | cstp_append_remote_local_address | X-CSTP-Remote/Local-Address-IP4/IP6 |
| 0x38B5970 | cstp_append_dns | X-CSTP-DNS, X-CSTP-DNS-IP6 |
| 0x38B5D40 | cstp_append_nbns | X-CSTP-NBNS |
| 0x38B5E30 | cstp_append_lease_duration | X-CSTP-Lease-Duration |
| 0x38B5EE0 | cstp_append_session_timeout | X-CSTP-Session-Timeout/-Alert-Interval/-Remaining |
| 0x38B6180 | cstp_append_hostname | X-CSTP-Hostname |
| 0x38B61E0 | cstp_append_split_routes | X-CSTP-Split-Include/Exclude[-IP6] |
| 0x38B6B00 | cstp_append_split_dns | X-CSTP-Split-DNS |
| 0x38B6BF0 | cstp_append_keep | X-CSTP-Keep: true/false |
| 0x38B6C20 | cstp_append_tunnel_all_dns | X-CSTP-Tunnel-All-DNS: true/false |
| 0x38B6C50 | cstp_append_rekey_time | X-CSTP-Rekey-Time |
| 0x38B6E10 | cstp_append_cstp_dpd | X-CSTP-DPD |
| 0x38B6EC0 | cstp_append_dtls_dpd | X-DTLS-DPD |
| 0x38B6F90 | cstp_append_keepalive | X-CSTP-Keepalive |
| 0x38B70B0 | cstp_append_banner | X-CSTP-Banner |
| 0x38B7170 | cstp_append_msie_proxy | X-CSTP-MSIE-Proxy: none/auto/bypass-local |
| 0x38B72A0 | cstp_append_msie_proxy_server | X-CSTP-MSIE-Proxy-Server |
| 0x38B72E0 | cstp_append_msie_proxy_pac | X-CSTP-MSIE-Proxy-PAC-URL |
| 0x38B7330 | cstp_append_msie_proxy_exception | X-CSTP-MSIE-Proxy-Exception |
| 0x38B7460 | cstp_append_content_encoding | X-CSTP-Content-Encoding |
| 0x38B7570 | cstp_append_dtls_content_enc | X-DTLS-Content-Encoding |
| 0x38B77F0 | cstp_append_mtu | X-CSTP-MTU, X-DTLS-MTU |
| 0x38B7B80 | cstp_append_smartcard_disconnect | X-CSTP-Smartcard-Removal-Disconnect |
| 0x38B1D40 | cstp_append_fw_rules | X-CSTP-FW-RULE, X-CSTP-FW-RULE-IP6 |
| 0x38B7680 | cstp_append_dtls_session_id | X-DTLS-Session-ID (32 bytes → 64 hex) |

#### Complete Header Order (60 headers)

1. `HTTP/1.1 200 OK`
2. `Server: ASA (%v)`
3. `X-CSTP-Version:` / `X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.`
4. `X-CSTP-Address:` / `X-CSTP-Netmask:`
5. `X-CSTP-Address-IP6:` (if configured)
6. `X-CSTP-Remote-Address-IP4/IP6:` / `X-CSTP-Local-Address-IP4/IP6:`
7. `X-CSTP-Default-Domain:`
8. `X-CSTP-Hostname:`
9. `X-CSTP-DNS:` / `X-CSTP-DNS-IP6:` (repeated per server)
10. `X-CSTP-NBNS:` (repeated per server)
11. `X-CSTP-Lease-Duration:`
12. `X-CSTP-Session-Timeout:` / `-Alert-Interval:` / `-Remaining:`
13. `X-CSTP-Idle-Timeout:` / `X-CSTP-Disconnected-Timeout:`
14. `X-CSTP-Split-Include:` / `X-CSTP-Split-Exclude:` (per ACL entry, subnet mask notation)
15. `X-CSTP-Split-Include-IP6:` / `X-CSTP-Split-Exclude-IP6:`
16. `X-CSTP-Split-DNS:` (per domain)
17. `X-CSTP-Keep: true|false`
18. `X-CSTP-Tunnel-All-DNS: true|false`
19. `X-CSTP-Rekey-Time:` / `X-CSTP-Rekey-Method: new-tunnel`
20. `X-CSTP-DPD:` / `X-CSTP-Keepalive:`
21. `X-CSTP-Banner:`
22. `X-CSTP-Homepage:`
23. `X-CSTP-MSIE-Proxy: none|auto|bypass-local` + Server/PAC-URL/Exception/Lockdown
24. `X-CSTP-Smartcard-Removal-Disconnect: true|false`
25. `X-CSTP-Content-Encoding: deflate|lzs`
26. `X-CSTP-FW-RULE:` / `X-CSTP-FW-RULE-IP6:` (per ACL rule)
27. `X-CSTP-MTU:`
28. `X-DTLS-Session-ID:` (64 hex uppercase)
29. `X-DTLS-Port:` / `X-DTLS-Keepalive:`
30. `X-DTLS-Rekey-Time:`
31. `X-DTLS-CipherSuite:` / `X-DTLS12-CipherSuite:`
32. `X-DTLS-DPD:`
33. `X-DTLS-Content-Encoding:`
34. `X-DTLS-MTU:`
35. `X-CSTP-Routing-Filtering-Ignore: true|false`
36. `X-CSTP-MUS-HOST:`
37. `X-CSTP-License: accept`
38. `X-CSTP-Quarantine:`
39. `X-CSTP-DAP-User-Message:`
40. `X-CSTP-Disable-Always-On-VPN:`
41. `X-CSTP-Client-Bypass-Protocol:`
42. `X-CSTP-TCP-Keepalive:`
43. `X-CSTP-Post-Auth-XML:`
44. `\r\n` (blank line terminator)

### 6.6 DTLS Session Setup

| Address | Name | Purpose |
|---------|------|---------|
| 0x38B7680 | webvpn_dtls_generate_session_id | 32 random bytes → 64 uppercase hex |
| 0x38B1A40 | dtls_master_secret_handler | Parse 96 hex → 48 bytes at session+0x50 |
| 0x38B1BA0 | dtls_ciphersuite_handler | Select DTLSv1 cipher |
| 0x38BA220 | dtls12_ciphersuite_handler | Select DTLSv1.2 cipher |
| 0x4017880 | hex_encoder | Binary to uppercase hex ("0123456789ABCDEF") |
| 0x12C4CA0 | csprng | Per-CPU random data generator |

### 6.7 Session Structure Key Offsets

| Offset | Type | Field |
|--------|------|-------|
| +0x18 | DWORD | CSTP version |
| +0x4C | BYTE | DTLS master secret received flag |
| +0x50 | 48B | DTLS master secret (48 bytes) |
| +0x80 | 32B | DTLS session ID (32 random bytes) |
| +0x88 | — | Session cookie string |
| +0xD5 | BYTE | DTLS capability flags (bit 7 = enabled) |
| +0x400 | PTR | Route ACL for split tunnel |
| +0x424 | DWORD | Rekey time (minutes) |
| +0x428 | DWORD | Rekey method (1=new-tunnel, 0=none) |
| +0x480 | PTR | FW-RULE ACL string |
| +0x43C | DWORD | SSL compression mode (1=deflate, 2=LZS) |
| +0x440 | DWORD | DTLS compression mode |

Session struct size: 0x8B0 bytes (allocated by `sub_1D48CF0`).

### 6.8 Headend / Client Download (WebDeploy) — 56 functions decompiled

Source files: `webvpn_svc.c`, `webvpn_custom.c`, `cache_file.c`

#### Package Registry Architecture

Package linked list at portal config offset +384. Each package entry (struct, >112 bytes):
- +40: platform ID (DWORD)
- +80: User-Agent regex string (PTR)
- +104: flags (DWORD)
- +236: capability flags (masked with 0x64)

#### Key Functions

| Address | Name | Size | Purpose |
|---------|------|------|---------|
| 0x38AE590 | stc_url_handler | 1578 | Main `/CACHE/stc/` request handler |
| 0x38787E0 | anyconnect_image_loader | 2842 | `anyconnect image` CLI — loads .pkg into cache |
| 0x38ADD50 | headinfo_txt_parser | 2102 | Parse `headinfo.txt` from .pkg ZIP |
| 0x38AEC20 | platform_detect_from_ua | 190 | User-Agent → platform ID via regex match |
| 0x38AEBC0 | platform_pkg_lookup | 83 | Find package by platform ID |
| 0x3B6CB30 | stc_url_builder | 1767 | Build `/CACHE/stc/N/` URL for redirect |
| 0x38AD4B0 | cache_stc_profiles | 309 | Create profile cache entry (`cache:/stc/profiles/%s.xml`) |
| 0x38ADAD0 | headinfo_xml_builder | 631 | Build XML from parsed headinfo |
| 0x38ABC40 | pkg_extract_to_cache | 1858 | Extract .pkg contents to `/CACHE/stc/N/` |
| 0x38AD230 | pkg_archive_create | 300 | Create package archive entry |
| 0x38AD1B0 | pkg_regex_add | 123 | Register `regex=` from headinfo.txt |
| 0x38AD060 | pkg_config_reset | 165 | Reset package config |
| 0x38AD420 | pkg_entry_free | 129 | Free package entry |
| 0x38ACDF0 | pkg_list_init | 391 | Initialize package list |
| 0x38AD7E0 | find_archive_by_device_id | 128 | Lookup archive by `device-id=` |
| 0x38AD650 | profile_manifest_lookup | 89 | Profile manifest lookup |
| 0x38B04C0 | profile_list_split | 698 | Split profile list entries |
| 0x38AAA00 | headinfo_readline | 121 | Read line from headinfo.txt |
| 0x3878730 | pkg_filename_validate | 163 | Validate .pkg filename |
| 0x3FE55B0 | user_agent_regex_match | 208 | Regex match engine for UA detection |
| 0x115FBE0 | svc_download_handler | 8260 | Main SVC download orchestrator |
| 0x3B5E330 | svc_ask_type_handler | 2124 | SESSION_* Lua callback registration (40+ callbacks) |
| 0x1731A20 | stc_page_generator | large | STC HTML page generator |
| 0x3A01DE0 | webvpn_content_handler | — | WebVPN content dispatch |

#### Platform Detection Algorithm (from `platform_detect_from_ua`)

```
for pkg in package_linked_list:
    if pkg.regex and regex_match(pkg.regex, user_agent):
        if pkg.platform_id != 0:
            return pkg.platform_id
for pkg in package_linked_list:
    return first_package.platform_id   # fallback: first registered
default: return 1
```

#### `/CACHE/stc/` URL Routing (from `stc_url_handler`)

| URL | Action |
|-----|--------|
| `/CACHE/stc/logout` | → `/+webvpn+/webvpn_logout.html` |
| `/CACHE/stc/auto` | Iterate packages, match UA, redirect to `/CACHE/stc/N/` |
| `/CACHE/stc/N/...` | Serve content from package N cache |
| `/CACHE/stc/profiles/X.xml` | Serve VPN profile |
| (no AnyConnect config) | → `/+CSCOE+/no_svc.html?s=2` |
| (caps 0x64 not set) | → `/+CSCOE+/no_svc.html?s=3` |

#### HostScan / Posture Functions

| Address | Name | Size | Purpose |
|---------|------|------|---------|
| 0x3B69370 | sdesktop_handler | 1995 | Main `/+CSCOE+/sdesktop/` handler |
| 0x174CEE0 | sdesktop_redirect | 1559 | HostScan redirect logic |
| 0x174D550 | sdesktop_cache_check | 246 | Check HostScan cache |
| 0x174DE10 | sdesktop_secret_xml | 1782 | Generate `secret.xml` |
| 0x11C5FE0 | hostscan_sdesktop_config | 936 | HostScan config |
| 0x387D830 | hostscan_image_install | 1193 | Install HostScan image |
| 0x38ACB40 | hostscan_cachefs_cleanup | 212 | Cache cleanup |
| 0x38970A0 | csd_enabled_check | 109 | CSD enabled flag check |
| 0x3879300 | hostscan_install_check | 688 | Check if HostScan installed |
| 0x387DCE0 | hostscan_enable_disable | 1098 | Enable/disable HostScan |
| 0x3876A20 | hostscan_version_check | 678 | HostScan version comparison |

#### Cache Filesystem Functions

| Address | Name | Size | Purpose |
|---------|------|------|---------|
| 0x11C57D0 | cache_dir_remove | 604 | Remove cache directory |
| 0x11C4920 | cache_file_open | 242 | Open cached file |
| 0x11C4790 | cache_file_path_get | 130 | Get cache file path |
| 0x11C5A30 | cache_file_install | 745 | Install file to cache |
| 0x11C2F00 | cache_filesystem_create | 56 | Create cache FS |
| 0x11C50E0 | cache_get_default_path | 591 | Default cache path |

#### SESSION_* Lua Callbacks (from `svc_ask_type_handler`, 40+ registered)

```
SESSION_USERNAME, SESSION_PRIMARY_USERNAME, SESSION_SECONDARY_USERNAME
SESSION_PASSWORD, SESSION_PRIMARY_PASSWORD, SESSION_SECONDARY_PASSWORD
SESSION_INTERNAL_PASSWORD, SESSION_GROUP, SESSION_TGROUP
SESSION_FILE_FEATURE_ENABLED, SESSION_FEATURE_ENABLED
SESSION_INDEX, SESSION_BANNER, SESSION_CLEAR_BANNER
SESSION_CUSTOM_PROFILE, SESSION_GET_SMART_TUNNELED_APPS
SESSION_GET_SMART_TUNNEL_APPLIST, SESSION_GET_SMART_TUNNEL_ASOSITES
SESSION_GET_SMART_TUNNEL_SPLITPOLICY, SESSION_GET_SMART_TUNNEL_STARTKEY
SESSION_GET_SMART_TUNNEL_LOCALIZATION, SESSION_GET_SMART_TUNNEL_LOGOFFMODE
SESSION_GET_USER_STORAGE, SESSION_URL_LISTS, SESSION_CHECK_URL
SESSION_IS_SSOASO_ALLOWED, SESSION_MAX_IDLE_TIME
SESSION_IDLE_ALERT_INTERVAL, SESSION_MAX_CONNECT_TIME
SESSION_END_ALERT_INTERVAL, SESSION_VALIDATE
SESSION_USER_ALERT, SESSION_TIME, SESSION_IDLE_TIME
SESSION_LOGIN_TIME, SESSION_MAGIC_STRING
SESSION_SMART_TUNNEL_STATUS, SESSION_ANYCONNECT_ENABLED
SESSION_ANYCONNECT_CONFIGURED, ...
```

---

## 7. VPNAPI SDK Structure (CSC 5.1.17.3394)

### 7.1 Class Hierarchy

```
ClientIfcBase (abstract)
  └── ClientIfc (main API)
        ├── attach(ClientType, fullCapabilities, suppressAutoConnect)
        ├── detach()
        ├── connect(host) / disconnect()
        ├── cancel()  — SSO cancellation
        ├── setNewTunnelGroup(group)
        ├── getHostNames() / getDefaultHostName()
        ├── isConnected() / isAvailable()
        ├── getState() / getStats()
        ├── getPreferences() / savePreferences()
        ├── setBannerResponse(accepted)
        ├── setCertWarningResponse(connect, import)
        ├── UserSubmit()
        └── Callbacks (pure virtual):
              StatsCB, StateCB, BannerCB, NoticeCB
              CertBannerCB, ServiceReadyCB, UserPromptCB
              CertBlockedCB, CertWarningCB
              ClientCertificateCB, ServiceStatusCB
              PreConnectReminderCB, ExitNoticeCB
              WMHintCB, EventAvailable
              ImportPKCS12ResultCB, AgentDetachedCB

VPNStats
  ├── getSecureRoutes() → list<RouteInfo*>
  ├── getNonsecureRoutes() → list<RouteInfo*>
  ├── getProtocolInfo() → list<ProtocolInfo*>
  ├── getFirewallInfo() → list<FirewallInfo*>
  └── 40+ stat fields (BytesSent, PacketsReceived, ...)

ConnectPromptInfo
  ├── getConnectPromptType()
  ├── getListPromptEntry() → list<PromptEntry*>
  ├── setTunnelGroup(group)
  └── hasEnrollmentCA()

ProtocolInfo { State, Protocol, Cipher, Compression, isActive }
RouteInfo { network, subnet, hostNames }
FirewallInfo { interface, permission, protocol, ports, dstAddress }
```

### 7.2 Header Files

```
include/
├── api.h                    — Master enums (VPNState, VPNError, PreferenceId, etc.)
├── GlobalEnums.h            — Protocol enums (ProtocolVersion, ProtocolCipher, COMPR_*)
├── ClientIfc.h              — Main client interface class
├── ClientIfcBase.h          — Abstract base
├── ClientIfcCommon.h        — Common definitions
├── ConnectPromptInfo.h      — Auth prompt container
├── ConnectPromptInfoBase.h  — Auth prompt base
├── PromptEntry.h            — Individual auth field
├── PromptEntryBase.h        — Auth field base
├── Preference.h             — User preference
├── PreferenceBase.h         — Preference base
├── PreferenceInfo.h         — Preference container
├── PreferenceInfoBase.h     — Preference container base
├── ProtocolInfo.h           — Protocol details (TLS/DTLS/IPsec)
├── RouteInfo.h              — Split tunnel route
├── FirewallInfo.h           — Firewall rule
├── VPNStats.h               — Statistics container
├── VPNStatsBase.h           — Statistics base
├── ApprovalStatus.h         — Approval status
├── GenDefs.h                — General definitions
├── config.h                 — Build config
```

### 7.3 VPNAPI SDK Libraries (CSC 5.1.17)

```
lib/Linux/Intel_64/
├── libvpnapi.a            5.6MB   Public VPN API (374K symbols)
├── libvpncommon.a         15MB    Common lib (797K symbols)
├── libvpncommoncrypt.a    1.6MB   Crypto (132K symbols)
├── libacciscossl.so       19MB    CiscoSSL (OpenSSL fork)
├── libacciscocrypto.so    6.9MB   CiscoSSL crypto
├── fips.so                6.9MB   FIPS module
├── oqsprovider.so         2.5MB   Post-Quantum OQS provider
├── legacy.so              522KB   Legacy OpenSSL provider
├── libboost_regex.so      396KB   Boost regex
├── libaccurl.a            818KB   URL library
├── openssl.cnf            577B    OpenSSL config
```

**Post-Quantum support (oqsprovider.so, ciscossl-3.3.5.8.3.63):**
- KEM: ML-KEM-512/768/1024, Kyber512/768/1024, BIKE-L1/L3/L5, HQC-128/192/256, FrodoKEM
- Hybrid KEM: SecP256r1+ML-KEM-768, X25519+ML-KEM-768
- Signatures: ML-DSA-44/65/87, Falcon-512/1024, SPHINCS+

### 7.4 CSC 5.1.17 Package Inventory

| Package Type | Files | Size Range | Purpose |
|-------------|-------|------------|---------|
| webdeploy-k9.pkg | 5 platform variants | 112-188MB | VPN client + modules |
| predeploy-k9 | .zip (win), .dmg (mac), .tgz (linux) | 72-190MB | Pre-install packages |
| vpnapi | .zip (win), .tgz (linux/mac) | 18-129MB | SDK for 3rd-party clients |
| external-sso | 1 cross-platform | 5.7KB | SAML browser SSO relay |
| profileeditor-k9 | MSI (win) | 14MB | VPN Profile XML editor |
| transforms | .zip (win) | 79KB | 9 MST install customization |

**External SSO pkg** contents: `headinfo.txt` + `index.html` (JS app).
**Profile Editor MSI** contains XSD schemas for VPN Profile XML.
**Transforms**: disable-feedback, enable-fips, desktop-shortcut, reset-mtu, strict-cert, reboot-suppress, hide-addremove, lockdown.

### 7.5 CLI Example (from VPNAPI SDK)

`examples/cli/CLIClientMain.cpp` — minimal VPN client flow:
1. `ClientIfc::attach()` → connect to vpnagentd
2. `ClientIfc::connect(host)` → initiate AggAuth
3. `UserPromptCB` callback → handle auth prompts
4. `UserSubmit()` → send credentials
5. `StateCB` → monitor vpnState transitions
6. `ClientIfc::disconnect()` → graceful teardown

Build: Clang 18 (Linux), Apple Clang 15 (macOS), MSVC v142 (Windows).
Defines: `_WIN32 UNICODE _UNICODE _NOEXPORTDLL` (Windows only).

---

## 8. Feature Parity: ASA vs FTD vs ioguard Target

| Feature | ASA | FTD | ioguard Target |
|---------|-----|-----|----------------|
| CSTP/TLS tunnel | Yes | Yes | S3 (done) |
| DTLS tunnel | Yes | Yes | S4 (done) |
| TLS 1.3 | 9.19+ | 7.2+ | wolfSSL (done) |
| DTLS 1.2 | 9.10+ | 6.2.3+ | wolfSSL (done) |
| Split tunneling | Yes | Yes | S5 (done) |
| Dynamic split tunnel | 9.12+ | 6.6+ | Planned |
| Compression (deflate/LZS) | Yes | Yes | Planned |
| DPD | Yes | Yes | S3 (done) |
| Keepalive | Yes | Yes | S3 (done) |
| Rekey (new-tunnel) | Yes | Yes | Planned |
| AggAuth v2 | Yes | Yes | Planned |
| SAML/SSO | 9.7+ | 6.7+ | S7 planned |
| Certificate auth | Yes | Yes | S7 planned |
| RADIUS | Yes | Yes | S7 in progress |
| LDAP | Yes | Yes | S7 planned |
| DAP | Full | Limited | Not planned |
| Firewall rules (X-CSTP-FW-RULE) | Yes | Yes | Planned |
| WebVPN/clientless | Yes | No | Not planned |
| VPN load balancing | Yes | No | Planned |
| STRAP device binding | 9.12+ | 7.2+ | Planned (§4.8) |
| Geo-fencing | 9.x+ | 7.7+ | Not planned (§4.12) |
| ZTNA | No | 7.4+ | Not applicable |
| RAVPN telemetry (protobuf) | No | Yes | Not applicable |
| IKEv2 | Yes | Yes | Not planned (TLS-only) |
| Post-quantum | Planned | Planned | wolfSSL ready |
| On-Demand/Always-On | Profile push | Profile push | Profile push (S7) |
| TND (Trusted Network) | Profile | Profile | Client-side |
| Per-App VPN | eBPF (acsockd) | eBPF (acsockd) | cgroup/eBPF (future) |
| External SSO/SAML | 9.7+ | 6.7+ | S7 planned |
| Multi-cert auth | 9.14+ | 7.1+ | S7 planned |
| SCEP enrollment | Yes | Yes | Not planned |
| VPNAPI SDK compat | Official | Official | API-compatible (future) |
| PQ TLS (ML-KEM) | CSC 5.1+ | CSC 5.1+ | wolfSSL + liboqs (future) |

---

## 9. Decompilation Artifacts

All outputs on oel-lab-gui:

```
/share/asac/9.24.1/workspace/vpn_decompile/
├── vpn_strings.jsonl          — 151 string matches (CSTP/DTLS/AggAuth/webvpn_svc)
├── vpn_decomp.jsonl           — 72 decompiled functions (189 KB)
├── aggauth_connect.jsonl      — 51 decompiled functions (CONNECT + AggAuth + headers)
├── connect_handler.jsonl      — /CSCOSSLC/tunnel string xrefs (depth=3)
├── cstp_response_gen.jsonl    — X-CSTP-Address string xrefs (depth=3)
├── aggauth_callgraph.jsonl    — AggAuth process_request callgraph (depth=1)
├── P0_AGGAUTH_CONNECT.md      — AggAuth + CONNECT + Response Generator (427 lines)
├── P0_DTLS_COOKIE_REKEY.md    — DTLS + Cookie + Rekey + Split + FW-RULE (332 lines)
├── P1_HEADEND_DOWNLOADER.md   — Headend/WebDeploy protocol (24.8KB, 56 functions)
├── headend_downloader.jsonl   — Consolidated headend decompilation (204KB, 56 functions)
├── p2a_aggauth_deep.jsonl     — AggAuth deep dive: 159 functions (2.8MB)
├── p2a_state_handlers.jsonl   — AggAuth state handlers: 81 functions (210KB)
└── P2A_AGGAUTH_DEEP.md        — AggAuth analysis report (615 lines, 240 functions total)

/share/asac/9.24.1/workspace/ida_dbs/
├── lina.i64               — ASAc 9.24.1 IDB (rebuilt, also at /tmp/lina_ida/lina on oel-lab-gui)
├── smart_agent.i64         — smart_agent IDB (intact)
└── lina.asm                — Full disassembly listing (905 MB)

/share/secure-firewall-ftd/workspace/ftdv-10.0.0/
├── SERVER_TRIAGE.md        — ASAc vs FTDv diff report (302 lines)
├── extracted/lina-ftdv10   — FTDv 10.0 lina (166 MB)
├── extracted/smart_agent-ftdv10
├── extracted/offload_app-ftdv10
├── extracted/ftw_monitor-ftdv10
└── extracted/asa_log_client-ftdv10

/share/secure-firewall-asa/workspace/extracted/vpnapi/
├── include/                — 22 C++ header files (full VPNAPI SDK)
├── doc/                    — Doxygen HTML documentation
├── examples/cli/           — CLI client example
└── Readme

/share/secure-firewall-asa/workspace/CSC_CLIENT_TRIAGE.md — full client binary triage (556 lines)
/opt/projects/repositories/cisco-asac-re/data/csc_triage_report.md — local copy
```

---

## 10. Client Architecture (CSC 5.1.17.3394)

### 10.1 Binary Ownership

| Binary | Size | Role |
|--------|------|------|
| vpnagentd | 1.09 MB | CSTP/DTLS tunnel FSM, TUN/TAP, DPD, reconnect |
| libvpnagentutilities.so | 1.13 MB | X-CSTP/X-DTLS header parsing (CCvcConfig), LZS, HTTP auth |
| libvpnapi.so | 2.00 MB | AggAuth XML, SSO, ConnectIfc, SCEP, profile mgmt |
| libvpncommon.so | 4.25 MB | IPC, HTTP, DNS, TLS, session TLV, DBus, SSO/SAML |
| libvpncommoncrypt.so | 671 KB | X.509, PKCS12, SCEP, OCSP, FIPS |
| libvpnipsec.so | 1.19 MB | IKEv2 (758 IKE strings), ESP, IPsec tunnel |
| libacciscossl.so | 987 KB | OpenSSL 3.0 libssl (TLS 1.3, DTLS 1.2) |
| libacciscocrypto.so | 4.89 MB | OpenSSL 3.0 libcrypto (FIPS) |
| oqsprovider.so | 2.06 MB | Post-quantum: Kyber, Dilithium, Falcon, BIKE, HQC |
| acextwebhelper | 1.45 MB | External browser SSO (localhost:29786 relay) |
| acsockd | 9.47 MB | eBPF socket filter (10 BPF programs), per-app VPN |

### 10.2 Critical Discoveries

**CDTP Clarified**: CDTP = "Compressed DTLS Transport Protocol" — NOT a separate protocol. It appears in lina MTU calculation: `dtls-mtu = %d(mod-mtu) - %d(cdtp) - %d(mac) - 1(pad)`. The `cdtp` overhead is the 1-byte DTLS frame type prefix. `CdtpProtocol.cpp` in vpnagentd is likely the client-side compressed DTLS transport handler.

**No LZ4 on client or server**: Zero LZ4 references across all CSC binaries and lina. Only LZS + deflate.

**X-DTLS12-CipherSuite**: Client supports DTLS 1.2 cipher negotiation via separate header (not just X-DTLS-CipherSuite for DTLS 1.0).

**X-DTLS-Header-Pad-Length**: Found in client but not server strings — padding for DTLS header alignment.

**Lua Portal Engine**: lina embeds a full Lua engine for portal page generation. 90+ `SESSION_*` API functions. AggAuth XML, DAP evaluation, SSO flow, and portal customization all via Lua templates.

**DAP via Lua**: Dynamic Access Policy uses embedded Lua: `dap_create_Lua_instance`, `dap_install_endpoint_data_to_lua`, `dap_select_records`. DAP evaluates endpoint posture data in Lua and generates per-session policy.

**WebSocket Proxy**: lina includes `websocket_utils.c` for proxying WebSocket through clientless VPN portal (NOT for VPN tunnel transport).

**Service Worker**: Portal supports offline caching via `/+CSCOL+/sw.js` with `Service-Worker-Allowed: /` header.

**MTU Formula**: Six-step computation pipeline with TLS/DTLS variants, cipher block alignment, and config override. Full formula extracted from format strings (§4.7).

**STRAP Protocol**: 90+ strings documenting full EC-DH key exchange, signature verification, failover sync, SCEP proxy integration, IKEv2 VID negotiation. EC curves validated server-side (§4.8).

**ROT13 Obfuscation**: Tunnel group name obfuscated via `ROT13STR2HEX()` in portal URLs. Not security — anti-caching.

**External SSO Flow**:
1. Browser opens `/+CSCOE+/saml/sp/login?tgname=<group>`
2. SAML IdP authenticates → redirect to external-sso/index.html with token
3. JS reads token from `{{AC_SAML_TOKEN}}` or `acSamlv2Token` cookie
4. JS posts to `http://localhost:29786/api/sso/{token}`
5. acextwebhelper receives token, passes to vpnagentd via IPC

**Reconnect codes**: `CFailureInfo::LogReconnectReason` with `RECONNECT_REASON_CODE` enum — 47 reconnect-related strings.

**MTU caching**: `CMtuAdjustmentCache` persists MTU across sessions.

### 10.3 Header Discrepancy: Server 52 vs Client 56

Server lina: 52 X-CSTP headers.
Client libvpnagentutilities.so: 56 X-CSTP headers.

Client-only headers (4 extra — parsed but not generated by ASA 9.24):
- X-CSTP-Split-Include (with IP6 variant)
- X-CSTP-Split-Exclude (with IP6 variant)

These are present as separate data strings in the client but generated dynamically (not as fixed header strings) in lina.

---

## 11. Remaining Decompilation Targets

### P0 — COMPLETE (123 functions decompiled, 2 agent reports)
- [x] AggAuth callgraph + 5 message type handlers (INIT/AUTH-REPLY/CONFIG/TOKEN/POLL)
- [x] AggAuth Lua integration (3 C callbacks registered via sub_3B5EBD0)
- [x] AggAuth XML elements (30+ elements from sub_115FBE0)
- [x] AggAuth DAP endpoint attributes (11 `endpoint.anyconnect.*` attrs)
- [x] CONNECT /CSCOSSLC/tunnel handler → sub_38D1DF0 init, sub_38D5010 parser
- [x] CSTP state machine → 32 events (CSTPtunnelTable at off_63B5300)
- [x] Pre-connect auth → cstp_connect_authenticate (0x38D2230, 8 error conditions)
- [x] DTLS session ID generation → sub_38B7680 (DONE)
- [x] DTLS master secret parsing → sub_38B1A40 (DONE)
- [x] Cookie creation flow → sub_38A3580 + sub_3861440 (DONE)
- [x] Response header generator → 27 sub-functions, 60+ headers (DONE)
- [x] Rekey mechanism → sub_38B6C50/sub_38B6CE0, offsets +0x424/+0x428 (DONE)
- [x] Split-Include/Exclude → sub_38B61E0, max 1200 entries (DONE)
- [x] FW-RULE format → sub_38B1D40, ACL-based (DONE)
- [x] Header dispatch table → 24 handlers at off_63B4840 (DONE)
- [x] URL router → sub_3BBD450 (aware_webvpn_content.c), Lua template mapping (DONE)

### P1 — Headend / WebDeploy (56 functions decompiled, phase1-3 JSONL)

Decompilation data:
```
/share/asac/9.24.1/workspace/vpn_decompile/
├── phase1_string_xrefs.jsonl       — 1239 string matches (CACHE/stc/sdesktop/Lua)
├── phase2_stc_decomp.jsonl         — 20 decompiled functions (STC/HostScan handlers)
├── phase3_platform_decomp.jsonl    — 36 decompiled functions (platform/cache/pkg)
├── headend_downloader.jsonl        — 56 functions consolidated (204KB)
├── P1_HEADEND_DOWNLOADER.md        — Full report (24.8KB)
```

Key findings:
- [x] `/CACHE/stc/` URL routing — stc_url_handler (0x38AE590): logout/auto/N/error dispatch
- [x] Platform detection — platform_detect_from_ua (0x38AEC20): UA regex → RB-tree ordered scan
- [x] Package registry — RB-tree + hash(17 buckets), pkg_id % 17. Struct ~128 bytes + filename.
- [x] Package loading — anyconnect_image_loader (0x38787E0): .pkg extract, headinfo parse, ZIP comment = "CISCO STC"
- [x] headinfo.txt — vpn-public/private-config-import, device-id, regex fields
- [x] Profile manifest — `"Name#ServiceType"` format, split by commas, SHA-1 hash per profile
- [x] Profile caching — cache_stc_profiles (0x38AD4B0): `cache:/stc/profiles/%s.xml`
- [x] XML generation — svc_download_handler (0x115FBE0): `<base-package-uri>` or `<nopkg/>`, device-id matching
- [x] SVC Ask — svc_ask_type_handler (0x3B5E330): 50+ SESSION_* Lua callbacks, ask types 0-5
- [x] DAP merge — dap_svc_ask_fcn (0x15E2F50): state machine for ask type merging
- [x] HostScan/CSD — 8 functions: install, version check, data limits, token cleanup
- [x] Cache filesystem — 6 functions: create, open, install, path_get, dir_remove
- [x] Lua templates — svc.lua, svc_ask.lua, svc_no.lua, svc_noaccess.lua, aggregate_auth_page.lua
- [x] Source files — webvpn_svc.c, webvpn_chain.c:3273-3459, webvpn_unjar.c, rbtree.c, dap_api.c
- [x] Error pages — 7 error codes: ?s=1 through ?s=6 + incomplete_uri/didnt_get_a_number
- [ ] STC page generator — stc_page_generator (0x1731A20, 27KB): too large for single decompile
- [ ] webvpn_content_router — aware_webvpn_content_router (0x3BBD450, 102KB): master URL router
- [ ] webvpn_content_handler — 0x3A01DE0 (64KB): includes scan.xml HostScan processing

### P2-A — AggAuth Deep Dive — COMPLETE (240 functions, 2 JSONL files)

Artifacts: `p2a_aggauth_deep.jsonl` (159 fn, 2.8MB), `p2a_state_handlers.jsonl` (81 fn, 210KB)

Key findings:
- [x] AggAuth is a 13-state FSM, next-state pointer at context+512
- [x] INIT handler (sub_1159B10, 596B): rate limiting → session sync check → cert/no-cert dispatch
- [x] AUTH-REPLY (sub_1159530, 1493B): handle validation → config version → TG lookup → auth mode dispatch
- [x] Tunnel group resolution (sub_1161C50, 853B): cert→name→URL→alias→iterate→"DefaultWEBVPNGroup"
- [x] TG auth mode bitmask at tg+4168: bit0=cert, bit1=cert_required, bit2=SAML, bit3=multi_cert
- [x] User lockout: 600s auto-expire (non-NGFW), permanent in NGFW mode, threshold configurable
- [x] Session: hash table with 3-min expiry, session token at auth_result+136, session ID = int→decimal
- [x] Error table: 116 entries at off_63B4080, codes 91/96/99/107 identified
- [x] SAML: login URL `%s/+CSCOE+/saml/sp/login?ctx=%s&acsamlcap=v2`, embedded browser fallback
- [x] AAA vtable at qword_6F6A448, service ID 0x33002 (208898)
- [x] Source: aggregate_auth_api.c, aggregate_auth_xml_generator.c + 28 other files

### P2 — Next Targets
- [ ] STRAP DH key exchange (sub_38B0870, sub_38B0780)
- [ ] LZS compress/decompress engine (lzsc.c/lzsd.c via CTM)
- [ ] Dynamic split tunnel (domain-based DNS routing, DYN_SPLIT_TUN_*)
- [ ] DAP Lua engine (dap_create_Lua_instance, dap_select_records)
- [ ] Session timeout FSM (idle, session, disconnect timeout handlers)
- [ ] MTU calculation full pipeline (sub_38B39F0 + formula chain)
- [ ] Certificate-group-map engine (webvpn__certificate_group_map_cb)
- [ ] Profile push mechanism (/CACHE/stc/profiles/) — VPN Profile XML schema

### P2 — Future
- [ ] SAML assertion validation (lasso_saml2_assertion_validate_audience)
- [ ] Geo-fencing check (sub_384C0B0)
- [ ] Post-Auth-XML content generation (sub_38B6F90)
- [ ] Profile push mechanism (/CACHE/stc/profiles/)
- [ ] Admin session management (/admin/sessions/ path)
- [ ] Connection profile selector (ROT13STR2HEX obfuscation)
- [ ] Portal Lua template engine (90+ SESSION_* API functions)
