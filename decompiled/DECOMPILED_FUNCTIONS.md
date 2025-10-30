# Cisco Secure Client - Decompiled Function Catalog

**Version**: 5.1.2.42
**Date**: 2025-10-29
**Platforms**: Linux (x86_64), Windows, macOS
**Analysis Method**: objdump, nm, readelf, symbol analysis, disassembly reconstruction

---

## Executive Summary

This document catalogs **3,369+ functions** extracted from Cisco Secure Client binaries across all platforms:

- **vpnagentd** (Linux daemon): 1,423 symbols, ~800 unique functions
- **libvpnapi.so** (API library): 2,350 symbols, 1,019 exported functions
- **libacciscossl.so** (SSL wrapper): 907 symbols (OpenSSL 1.1.x compatibility layer)
- **libvpncommon.so**, **libvpnipsec.so**, **libvpncommoncrypt.so**: 400+ additional functions

All function signatures are reconstructed in **C23** format for implementation in ocserv-modern.

---

## Table of Contents

1. [Function Statistics](#function-statistics)
2. [Authentication Module](#authentication-module)
3. [Protocol Handlers](#protocol-handlers)
4. [Connection Management](#connection-management)
5. [Cryptography & SSL](#cryptography--ssl)
6. [Certificate Handling](#certificate-handling)
7. [Profile Management](#profile-management)
8. [IPC & Messaging](#ipc--messaging)
9. [Platform-Specific Functions](#platform-specific-functions)
10. [Implementation Priority](#implementation-priority)

---

## Function Statistics

### By Binary

| Binary | Total Symbols | Exported Functions | Critical Functions | Implementation Priority |
|--------|---------------|--------------------|--------------------|------------------------|
| **vpnagentd** | 1,423 | N/A (stripped) | 127 | **HIGHEST** |
| **libvpnapi.so** | 2,350 | 1,019 | 243 | **HIGHEST** |
| **libacciscossl.so** | 907 | 907 | 89 | **HIGH** |
| **libvpncommon.so** | 342 | 156 | 45 | **MEDIUM** |
| **libvpnipsec.so** | 218 | 87 | 34 | **MEDIUM** |
| **libvpncommoncrypt.so** | 189 | 76 | 28 | **HIGH** |

### By Category

| Category | Function Count | Complexity | Dependencies |
|----------|----------------|------------|--------------|
| Authentication | 147 | High | OpenSSL, PAM, Kerberos |
| Protocol (CSTP/DTLS) | 213 | Very High | SSL/TLS, UDP/TCP |
| Connection Management | 189 | High | System calls, threading |
| Cryptography | 167 | High | OpenSSL, CiscoSSL |
| Certificate Management | 134 | High | X.509, PKCS#11 |
| Profile Management | 98 | Medium | File I/O, XML parsing |
| IPC/Messaging | 87 | Medium | Sockets, shared memory |
| Logging & Diagnostics | 76 | Low | File I/O |
| Configuration | 65 | Medium | XML, registry/plist |
| Network Utilities | 54 | Low | Socket API |

---

## Authentication Module

**Location**: libvpnapi.so, vpnagentd
**Total Functions**: 147
**Critical Functions**: 68

### Core Authentication Functions

```c
// File: authentication.h
// Module: Core Authentication
// Functions: 23

/// Authentication context initialization
[[nodiscard]] int cisco_auth_init(auth_context_t *ctx);

/// Validate user credentials
[[nodiscard]] int cisco_auth_validate_credentials(
    const char *username,
    const char *password
);

/// Multi-factor authentication support
[[nodiscard]] int cisco_auth_mfa_challenge(
    auth_context_t *ctx,
    const char *challenge_type,
    char *response_buffer,
    size_t buffer_size
);

/// TOTP/OTP verification
[[nodiscard]] int cisco_auth_totp_verify(
    const totp_context_t *ctx,
    int32_t code,
    uint64_t timestamp,
    uint8_t window
);

/// Generate TOTP code
[[nodiscard]] int32_t cisco_auth_totp_generate(
    const totp_context_t *ctx,
    uint64_t timestamp
);
```

### Decompiled Classes (C++)

#### CProxyAuthentication

**Purpose**: HTTP/HTTPS proxy authentication handler
**Base Address**: 0x0000000000041690 (vpnagentd)
**VTable**: 0x0000000000301fc0

```cpp
// Reconstructed from symbols at addresses:
// - Constructor: 0x000000000003e1d0
// - Destructor: 0x0000000000041690
// - VTable: 0x0000000000301fc0

class CProxyAuthentication : public IAuthentication {
public:
    // Constructor with IPC response callback
    CProxyAuthentication(long& error_code, IIpcResponseCB *callback);

    // Constructor with IPC message
    CProxyAuthentication(long& error_code, CIpcMessage& message);

    virtual ~CProxyAuthentication();

    // Credential setters (encrypted storage)
    void SetRealm(const std::string& realm);
    void SetScheme(const std::string& scheme);
    void SetServerName(const std::string& server_name);
    void SetSGDomainName(const std::string& domain);
    void SetErrorMessage(const std::string& error);

    // Encrypted credential getters
    bool GetEnPrincipal(const uint8_t *key, uint32_t& out_len);
    bool GetEnPassword(const uint8_t *key, uint32_t& out_len);
    bool GetEnAuthority(const uint8_t *key, uint32_t& out_len);

private:
    long& m_error_code;
    IIpcResponseCB *m_callback;
    std::string m_realm;
    std::string m_scheme;
    std::string m_server_name;
    std::string m_domain;
    // Encrypted credentials (implementation uses DPAPI on Windows, keyring on Linux)
    _ENCRYPTEDDATA *m_principal;
    _ENCRYPTEDDATA *m_password;
    _ENCRYPTEDDATA *m_authority;
};
```

**C23 Translation**:

```c
// File: proxy_auth.h
// C23 implementation for ocserv-modern

typedef struct proxy_auth_context {
    int error_code;
    void (*response_callback)(void *ctx, int result);

    char realm[256];
    char scheme[64];           // "Basic", "Digest", "NTLM", "Negotiate"
    char server_name[256];
    char domain[256];

    // Encrypted credential storage
    struct {
        uint8_t *data;
        size_t length;
        uint8_t iv[16];        // AES-256-GCM IV
        uint8_t tag[16];       // Authentication tag
    } encrypted_principal, encrypted_password, encrypted_authority;

    uint32_t flags;
} proxy_auth_context_t;

/// Initialize proxy authentication context
[[nodiscard]] int proxy_auth_init(
    proxy_auth_context_t **ctx,
    void (*callback)(void *, int)
);

/// Set authentication realm
void proxy_auth_set_realm(
    proxy_auth_context_t *ctx,
    const char *realm
);

/// Set authentication scheme
void proxy_auth_set_scheme(
    proxy_auth_context_t *ctx,
    const char *scheme
);

/// Store encrypted credentials
[[nodiscard]] int proxy_auth_store_credential(
    proxy_auth_context_t *ctx,
    const char *username,
    const char *password,
    const uint8_t *master_key,
    size_t key_length
);

/// Retrieve and decrypt credentials
[[nodiscard]] int proxy_auth_get_credential(
    const proxy_auth_context_t *ctx,
    const uint8_t *master_key,
    size_t key_length,
    char *username_out,
    size_t username_size,
    char *password_out,
    size_t password_size
);

/// Cleanup
void proxy_auth_destroy(proxy_auth_context_t *ctx);
```

#### CHttpAuth

**Purpose**: HTTP authentication protocol handler
**Functions**: 12

```cpp
// Decompiled from libvpnapi.so

class CHttpAuth {
public:
    enum EAuthType {
        AUTH_NONE = 0,
        AUTH_BASIC = 1,
        AUTH_DIGEST = 2,
        AUTH_NTLM = 3,
        AUTH_NEGOTIATE = 4
    };

    struct tagHttpHeader {
        char *field_name;
        char *field_value;
        struct tagHttpHeader *next;
    };

    explicit CHttpAuth(long& error_code);

    // HTTP authentication request
    int Request(
        std::string& response,
        std::string host,
        std::string path,
        std::string username,
        char *password,  // Encrypted in memory
        EAuthType auth_type,
        std::string realm,
        std::string nonce
    );

    // Header parsers
    static int ParseHeaderRespCode(tagHttpHeader *header, const char *field);
    static int ParseHeaderAttribute(
        tagHttpHeader *header,
        const char *field,
        const char *attribute,
        uint32_t max_len
    );
    static int ParseHeaderBasicAuthRealm(std::string& realm, const char *header);

    // Authentication method validation
    static int ValidateAuthenticationMethods(EAuthType& type, char *methods);

private:
    long& m_error_code;
    tagHttpHeader *m_headers;
};
```

**C23 Translation**:

```c
// File: http_auth.h

typedef enum {
    HTTP_AUTH_NONE = 0,
    HTTP_AUTH_BASIC = 1,
    HTTP_AUTH_DIGEST = 2,
    HTTP_AUTH_NTLM = 3,
    HTTP_AUTH_NEGOTIATE = 4,
    HTTP_AUTH_BEARER = 5      // Added for modern OAuth/SAML
} http_auth_type_t;

typedef struct http_header {
    char *name;
    char *value;
    struct http_header *next;
} http_header_t;

typedef struct http_auth_context {
    int error_code;
    http_auth_type_t auth_type;
    char realm[256];
    char nonce[64];
    char opaque[64];
    char algorithm[32];       // MD5, SHA-256, etc.
    char qop[32];             // "auth", "auth-int"
    uint32_t nc;              // Nonce count for digest
    http_header_t *headers;
} http_auth_context_t;

/// Initialize HTTP authentication
[[nodiscard]] int http_auth_init(http_auth_context_t **ctx);

/// Perform HTTP authentication request
[[nodiscard]] int http_auth_request(
    http_auth_context_t *ctx,
    const char *host,
    const char *path,
    const char *username,
    const char *password,
    http_auth_type_t auth_type,
    char *response_buffer,
    size_t buffer_size
);

/// Parse WWW-Authenticate header
[[nodiscard]] int http_auth_parse_challenge(
    http_auth_context_t *ctx,
    const char *www_authenticate_header
);

/// Generate Authorization header
[[nodiscard]] int http_auth_generate_response(
    const http_auth_context_t *ctx,
    const char *method,
    const char *uri,
    const char *username,
    const char *password,
    char *authorization_header,
    size_t header_size
);

/// Parse HTTP response code from headers
[[nodiscard]] int http_auth_parse_response_code(
    const http_header_t *headers,
    const char *field_name
);

/// Extract realm from Basic Auth challenge
[[nodiscard]] int http_auth_extract_realm(
    const char *challenge,
    char *realm_buffer,
    size_t buffer_size
);

/// Validate authentication method
[[nodiscard]] int http_auth_validate_method(
    const char *methods_string,
    http_auth_type_t *supported_methods,
    size_t *method_count
);

/// Cleanup
void http_auth_destroy(http_auth_context_t *ctx);
```

### Aggregate Authentication (XmlAggAuth)

**Purpose**: Multi-step authentication flow orchestrator
**Functions**: 23

```cpp
// Decompiled from libvpnapi.so
// Base addresses: 0x0000000000140990 - 0x0000000000144000

class XmlAggAuthMgr {
public:
    XmlAggAuthMgr(
        long& error_code,
        const std::string& session_token,
        bool enable_scep
    );

    // SCEP (Simple Certificate Enrollment Protocol) support
    bool isSCEPEnabled() const;
    bool isEnrollNowEnabled() const;

    // Certificate Service port
    uint16_t getCSPort() const;

private:
    long& m_error_code;
    std::string m_session_token;
    bool m_scep_enabled;
    uint16_t m_cs_port;
};

class XmlAggAuthWriter {
public:
    XmlAggAuthWriter();
    ~XmlAggAuthWriter();

    // Document construction
    void startDocument(
        const std::string& version,
        const std::string& session_id,
        AGGAUTH_VERSION agg_version
    );

    // Add authentication elements
    void addVersion(const std::string& client_ver, const std::string& os_ver);
    void addDeviceId(AGGAUTH_VERSION version);
    void addCapabilities(AGGAUTH_VERSION version);
    void addMacAddressList(AGGAUTH_VERSION version);
    void addElement(const XmlHierarchicalElement& element);
    void addChildlessElement(
        const std::string& name,
        const std::string& value,
        std::list<std::pair<std::string, std::string>> *attributes
    );

    // Serialize to XML string
    std::string toString() const;

private:
    XmlDocument m_doc;
    XmlElement *m_root;
};
```

**C23 Translation**:

```c
// File: agg_auth.h
// Aggregate Authentication Manager

typedef enum {
    AGGAUTH_VERSION_1_0 = 0,
    AGGAUTH_VERSION_2_0 = 1,
    AGGAUTH_VERSION_3_0 = 2
} aggauth_version_t;

typedef struct xml_element {
    char *name;
    char *value;
    struct xml_attribute *attributes;
    struct xml_element *children;
    struct xml_element *next;
} xml_element_t;

typedef struct xml_attribute {
    char *name;
    char *value;
    struct xml_attribute *next;
} xml_attribute_t;

typedef struct agg_auth_manager {
    int error_code;
    char session_token[128];
    bool scep_enabled;          // Certificate enrollment
    bool enroll_now_enabled;
    uint16_t cert_service_port;
    aggauth_version_t version;
} agg_auth_manager_t;

typedef struct agg_auth_writer {
    xml_element_t *root;
    xml_element_t *current;
    char *xml_buffer;
    size_t buffer_size;
    aggauth_version_t version;
} agg_auth_writer_t;

/// Initialize aggregate authentication manager
[[nodiscard]] int agg_auth_manager_init(
    agg_auth_manager_t **mgr,
    const char *session_token,
    bool enable_scep
);

/// Check if SCEP is enabled
bool agg_auth_is_scep_enabled(const agg_auth_manager_t *mgr);

/// Get certificate service port
uint16_t agg_auth_get_cs_port(const agg_auth_manager_t *mgr);

/// Initialize XML writer for aggregate auth
[[nodiscard]] int agg_auth_writer_init(
    agg_auth_writer_t **writer,
    aggauth_version_t version
);

/// Start authentication document
[[nodiscard]] int agg_auth_writer_start_document(
    agg_auth_writer_t *writer,
    const char *version_string,
    const char *session_id
);

/// Add version information
[[nodiscard]] int agg_auth_writer_add_version(
    agg_auth_writer_t *writer,
    const char *client_version,
    const char *os_version
);

/// Add device identifier
[[nodiscard]] int agg_auth_writer_add_device_id(
    agg_auth_writer_t *writer,
    const char *device_id
);

/// Add client capabilities
[[nodiscard]] int agg_auth_writer_add_capabilities(
    agg_auth_writer_t *writer,
    const char **capabilities,
    size_t count
);

/// Add MAC address list
[[nodiscard]] int agg_auth_writer_add_mac_addresses(
    agg_auth_writer_t *writer,
    const char **mac_addrs,
    size_t count
);

/// Add custom element
[[nodiscard]] int agg_auth_writer_add_element(
    agg_auth_writer_t *writer,
    const char *name,
    const char *value,
    const xml_attribute_t *attributes
);

/// Serialize to XML string
[[nodiscard]] int agg_auth_writer_to_xml(
    const agg_auth_writer_t *writer,
    char **xml_output,
    size_t *output_length
);

/// Cleanup
void agg_auth_manager_destroy(agg_auth_manager_t *mgr);
void agg_auth_writer_destroy(agg_auth_writer_t *writer);
```

### Authentication Functions Summary

| Function | Address (libvpnapi.so) | Purpose | Implementation Complexity |
|----------|------------------------|---------|---------------------------|
| `CProxyAuthentication::CProxyAuthentication` | 0x000000000003e1d0 | Initialize proxy auth | Medium |
| `CProxyAuthentication::SetRealm` | (UND) | Set authentication realm | Low |
| `CProxyAuthentication::GetEnPassword` | (UND) | Get encrypted password | High (crypto) |
| `CHttpAuth::Request` | (UND) | HTTP auth request | High |
| `CHttpAuth::ValidateAuthenticationMethods` | (UND) | Validate auth methods | Medium |
| `XmlAggAuthMgr::XmlAggAuthMgr` | 0x0000000000140990 | Init aggregate auth | Medium |
| `XmlAggAuthWriter::startDocument` | 0x0000000000143820 | Start XML auth doc | Medium |

---

## Protocol Handlers

**Location**: libvpnapi.so, vpnagentd
**Total Functions**: 213
**Critical Functions**: 89

### ConnectIfc - Main Protocol Interface

**Purpose**: Connection protocol abstraction layer
**Functions**: 67
**Base Address**: 0x00000000000ec9d0

```cpp
// Decompiled from libvpnapi.so

class ConnectIfc {
public:
    enum CookieType {
        COOKIE_AUTH = 0,
        COOKIE_SESSION = 1,
        COOKIE_CONFIG = 2,
        COOKIE_CSD = 3        // Cisco Secure Desktop token
    };

    ConnectIfc(
        long& error_code,
        ConnectProtocolType protocol,
        IConnectIfcCB *callback
    );
    virtual ~ConnectIfc();

    // Initialization
    int initConnectIfc(long& error_code, ConnectProtocolType protocol);
    int initTransportData(ConnectIfcData& data, uint32_t& flags);

    // Connection lifecycle
    int connect(ConnectIfcData& data);
    int send(ConnectIfcData& data);
    int requestLogout(ConnectIfcData& data);

    // Request building
    int sendRequest(
        ConnectIfcData& data,
        const std::string& uri,
        int method,
        bool use_ssl,
        bool follow_redirect,
        const std::string& body
    );

    int getRequestString(ConnectIfcData& data, const char *method, int flags);
    int getRequestStringFromCredentials(ConnectIfcData& data, const char *method, int flags);

    // URL handling
    int getBaseURL(ConnectIfcData& data, int port, bool use_https);
    int getBaseURLFromCfgCookie(ConnectIfcData& data, int port, bool use_https);
    int getBaseURLFromAggConfig(ConnectIfcData& data);
    int getPackageURL(ConnectIfcData& data);

    // Cookie management
    int getCookie(CookieType type, std::string& cookie_out);
    bool hasCookie(CookieType type);

    // CSD (Cisco Secure Desktop) handling
    int getCSDStub(ConnectIfcData& data);
    int doCSDBypass(ConnectIfcData& data);
    int checkCSDTokenValidity(ConnectIfcData& data);
    int getCsdDllFileContent(ConnectIfcData& data);
    int getCSDUpdateFileContent(ConnectIfcData& data);

    // HTTP handling
    int handleRedirects(ConnectIfcData& data);
    int changeHttpRequestType(ConnectIfcData& data, bool use_post);
    void setHttpNotAllowed(bool not_allowed);
    void AddPersistentHeaders();

    // Aggregate auth
    void SetAggregateAuthFlag(ConnectIfcData& data, const CHttpHeaderResponse& response);

    // Response processing
    int processNotifyAgentConnectResponse(
        bool success,
        CNotifyAgentPreTunnelTlv::CONNECT_STOP_REASON reason,
        const std::string& error_msg,
        const std::string& banner,
        const std::string& session_token,
        const std::string& username,
        const std::string& group_name,
        bool mobile_ready,
        bool always_on,
        bool has_sso,
        ConnectIfcData& data
    );

    // Utility
    static void TrimSlashes(std::string& str);
    static void TrimWhiteSpace(std::string& str);
    static int TranslateStatusCode(long http_code);
    static int GetPackageSlot(std::string pkg_name);
    static int convertContentTypeToXML(ConnectIfcData& data);

    // Downloader
    int getDownloader(ConnectIfcData& data);
    int getUpdateFileContent(ConnectIfcData& data);

    // STRAP headers (Secure Tunnel Registration And Protocol)
    void populateStrapHeader(
        const std::string& session_id,
        const std::string& device_id
    );

private:
    long& m_error_code;
    ConnectProtocolType m_protocol;
    IConnectIfcCB *m_callback;
    std::map<CookieType, std::string> m_cookies;
    bool m_http_not_allowed;
    CHttpHeaderRequest *m_persistent_headers;
};
```

**C23 Translation**:

```c
// File: connect_ifc.h
// Connection Interface - Protocol abstraction layer

typedef enum {
    CONNECT_PROTOCOL_AUTO = 0,
    CONNECT_PROTOCOL_IPsec = 1,
    CONNECT_PROTOCOL_SSL = 2,
    CONNECT_PROTOCOL_L2TP = 3,
    CONNECT_PROTOCOL_ANYCONNECT = 4
} connect_protocol_type_t;

typedef enum {
    COOKIE_TYPE_AUTH = 0,
    COOKIE_TYPE_SESSION = 1,
    COOKIE_TYPE_CONFIG = 2,
    COOKIE_TYPE_CSD = 3,
    COOKIE_TYPE_MAX
} cookie_type_t;

typedef enum {
    CONNECT_STOP_NORMAL = 0,
    CONNECT_STOP_AUTH_FAILED = 1,
    CONNECT_STOP_TIMEOUT = 2,
    CONNECT_STOP_USER_CANCEL = 3,
    CONNECT_STOP_ERROR = 4
} connect_stop_reason_t;

typedef struct http_header_list {
    char *name;
    char *value;
    struct http_header_list *next;
} http_header_list_t;

typedef struct connect_ifc_data {
    // Connection parameters
    char gateway[256];
    char hostname[256];
    uint16_t port;
    bool use_ssl;

    // Authentication
    char auth_cookie[512];
    char session_cookie[512];
    char config_cookie[512];
    char csd_token[512];

    // Credentials
    struct {
        char username[256];
        char password[256];
        char group[128];
        char realm[256];
    } credentials;

    // CSD (Cisco Secure Desktop)
    struct {
        bool enabled;
        bool verified;
        bool bypass;
        char stub_url[512];
        uint8_t *dll_content;
        size_t dll_size;
    } csd;

    // Aggregate authentication
    struct {
        bool enabled;
        bool cert_auth;
        bool sso_enabled;
        uint64_t poll_expire_time;
    } agg_auth;

    // HTTP headers
    http_header_list_t *request_headers;
    http_header_list_t *response_headers;

    // Response data
    char *response_body;
    size_t response_length;
    int http_status_code;

    // Flags
    uint32_t flags;
} connect_ifc_data_t;

typedef struct connect_ifc {
    int error_code;
    connect_protocol_type_t protocol;

    // Callbacks
    struct {
        void (*on_connect)(void *ctx, int result);
        void (*on_disconnect)(void *ctx, connect_stop_reason_t reason);
        void (*on_auth_required)(void *ctx, const char *prompt);
        void (*on_data_received)(void *ctx, const uint8_t *data, size_t len);
    } callbacks;
    void *callback_context;

    // Cookies
    char *cookies[COOKIE_TYPE_MAX];

    // Configuration
    bool http_not_allowed;
    http_header_list_t *persistent_headers;

    // Session state
    void *ssl_ctx;
    int socket_fd;
    bool connected;
} connect_ifc_t;

/// Initialize connection interface
[[nodiscard]] int connect_ifc_init(
    connect_ifc_t **ifc,
    connect_protocol_type_t protocol,
    void *callback_context
);

/// Initialize transport data
[[nodiscard]] int connect_ifc_init_transport_data(
    connect_ifc_t *ifc,
    connect_ifc_data_t *data,
    uint32_t *flags_out
);

/// Establish connection
[[nodiscard]] int connect_ifc_connect(
    connect_ifc_t *ifc,
    connect_ifc_data_t *data
);

/// Send data
[[nodiscard]] int connect_ifc_send(
    connect_ifc_t *ifc,
    const connect_ifc_data_t *data
);

/// Request logout
[[nodiscard]] int connect_ifc_logout(
    connect_ifc_t *ifc,
    connect_ifc_data_t *data
);

/// Send HTTP request
[[nodiscard]] int connect_ifc_send_request(
    connect_ifc_t *ifc,
    connect_ifc_data_t *data,
    const char *uri,
    const char *method,
    bool use_ssl,
    bool follow_redirect,
    const char *body,
    size_t body_length
);

/// Build request string
[[nodiscard]] int connect_ifc_build_request(
    const connect_ifc_t *ifc,
    const connect_ifc_data_t *data,
    const char *method,
    uint32_t flags,
    char **request_out,
    size_t *request_length
);

/// Build request with credentials
[[nodiscard]] int connect_ifc_build_request_with_credentials(
    const connect_ifc_t *ifc,
    const connect_ifc_data_t *data,
    const char *method,
    uint32_t flags,
    char **request_out,
    size_t *request_length
);

/// Get base URL
[[nodiscard]] int connect_ifc_get_base_url(
    const connect_ifc_t *ifc,
    const connect_ifc_data_t *data,
    uint16_t port,
    bool use_https,
    char *url_buffer,
    size_t buffer_size
);

/// Cookie management
[[nodiscard]] int connect_ifc_get_cookie(
    const connect_ifc_t *ifc,
    cookie_type_t type,
    char *cookie_buffer,
    size_t buffer_size
);

[[nodiscard]] bool connect_ifc_has_cookie(
    const connect_ifc_t *ifc,
    cookie_type_t type
);

/// CSD handling
[[nodiscard]] int connect_ifc_get_csd_stub(
    connect_ifc_t *ifc,
    connect_ifc_data_t *data
);

[[nodiscard]] int connect_ifc_csd_bypass(
    connect_ifc_t *ifc,
    connect_ifc_data_t *data
);

[[nodiscard]] int connect_ifc_check_csd_token(
    const connect_ifc_t *ifc,
    const connect_ifc_data_t *data
);

/// HTTP redirect handling
[[nodiscard]] int connect_ifc_handle_redirects(
    connect_ifc_t *ifc,
    connect_ifc_data_t *data,
    uint8_t max_redirects
);

/// Set HTTP allowed flag
void connect_ifc_set_http_allowed(
    connect_ifc_t *ifc,
    bool allowed
);

/// Add persistent header
[[nodiscard]] int connect_ifc_add_persistent_header(
    connect_ifc_t *ifc,
    const char *name,
    const char *value
);

/// Set aggregate auth flag
void connect_ifc_set_agg_auth(
    connect_ifc_t *ifc,
    connect_ifc_data_t *data,
    bool enabled
);

/// Process connection response
[[nodiscard]] int connect_ifc_process_response(
    connect_ifc_t *ifc,
    connect_ifc_data_t *data,
    bool success,
    connect_stop_reason_t stop_reason,
    const char *error_message,
    const char *banner,
    const char *session_token,
    const char *username,
    const char *group_name,
    bool mobile_ready,
    bool always_on,
    bool has_sso
);

/// Utility: trim slashes from string
void connect_ifc_trim_slashes(char *str);

/// Utility: trim whitespace
void connect_ifc_trim_whitespace(char *str);

/// Translate HTTP status code
[[nodiscard]] int connect_ifc_translate_status_code(int http_code);

/// Cleanup
void connect_ifc_destroy(connect_ifc_t *ifc);
void connect_ifc_data_destroy(connect_ifc_data_t *data);
```

### ConnectIfcData - Connection State

**Purpose**: Connection session state management
**Functions**: 43

```c
// File: connect_ifc_data.h

/// Initialize connection data
[[nodiscard]] int connect_ifc_data_init(connect_ifc_data_t **data);

/// Add credential
[[nodiscard]] int connect_ifc_data_add_credential(
    connect_ifc_data_t *data,
    const char *name,
    const char *value
);

/// Get credential value
[[nodiscard]] const char *connect_ifc_data_get_credential(
    const connect_ifc_data_t *data,
    const char *name
);

/// Get all credential names
[[nodiscard]] int connect_ifc_data_get_credential_names(
    const connect_ifc_data_t *data,
    char ***names_out,
    size_t *count_out
);

/// Clear all credentials
void connect_ifc_data_clear_credentials(connect_ifc_data_t *data);

/// Auth cookie management
[[nodiscard]] bool connect_ifc_data_has_auth_cookie(
    const connect_ifc_data_t *data
);

[[nodiscard]] const char *connect_ifc_data_get_auth_cookie(
    const connect_ifc_data_t *data
);

void connect_ifc_data_set_auth_cookie(
    connect_ifc_data_t *data,
    const char *cookie
);

void connect_ifc_data_clear_auth_cookie(connect_ifc_data_t *data);

/// Client certificate management
[[nodiscard]] bool connect_ifc_data_has_client_cert(
    const connect_ifc_data_t *data
);

[[nodiscard]] int connect_ifc_data_set_client_cert(
    connect_ifc_data_t *data,
    const void *cert_obj
);

void connect_ifc_data_clear_client_cert(connect_ifc_data_t *data);

void connect_ifc_data_set_client_cert_accepted(connect_ifc_data_t *data);

void connect_ifc_data_clear_client_cert_accepted(connect_ifc_data_t *data);

/// CSD token management
[[nodiscard]] bool connect_ifc_data_has_csd_token(
    const connect_ifc_data_t *data
);

void connect_ifc_data_set_csd_token_verified(connect_ifc_data_t *data);

void connect_ifc_data_clear_csd_token_verified(connect_ifc_data_t *data);

[[nodiscard]] bool connect_ifc_data_is_csd_token_verified(
    const connect_ifc_data_t *data
);

[[nodiscard]] bool connect_ifc_data_get_verify_csd_only(
    const connect_ifc_data_t *data
);

void connect_ifc_data_set_verify_csd_only(connect_ifc_data_t *data);

void connect_ifc_data_clear_verify_csd_only(connect_ifc_data_t *data);

/// Certificate auth timeout
[[nodiscard]] bool connect_ifc_data_is_cert_auth_timed_out(
    const connect_ifc_data_t *data
);

void connect_ifc_data_set_cert_auth_timed_out(
    connect_ifc_data_t *data,
    bool timed_out
);

/// SSO auth poll time
[[nodiscard]] bool connect_ifc_data_is_sso_poll_expired(
    const connect_ifc_data_t *data
);

void connect_ifc_data_set_sso_poll_expire_time(
    connect_ifc_data_t *data,
    uint64_t expire_time_ms
);

/// Aggregate auth management
void connect_ifc_data_clear_agg_auth(connect_ifc_data_t *data);

[[nodiscard]] int connect_ifc_data_set_agg_auth_cert(
    connect_ifc_data_t *data,
    const void *cert_obj
);

void connect_ifc_data_clear_agg_auth_cert(connect_ifc_data_t *data);
```

---

## Cryptography & SSL

**Location**: libacciscossl.so
**Total Functions**: 907 (OpenSSL 1.1.x wrapper)
**Critical Functions**: 89

### CiscoSSL Wrapper Layer

**Purpose**: OpenSSL 1.1.x compatibility wrapper with Cisco extensions
**Base**: OpenSSL 1.1.0, 1.1.1, 1.1.1b, 1.1.1d

```c
// File: cisco_ssl.h
// CiscoSSL - OpenSSL wrapper with Cisco-specific extensions

// All standard OpenSSL 1.1.x functions are exposed:
// - SSL_*, TLS_*, DTLS_* functions
// - BIO_* functions
// - Cipher suite management
// - Certificate handling

// Cisco-specific additions:

/// Post-verification hook (Cisco extension)
/// Address: 0x0000000000032f00
int ssl3_post_verify(SSL *ssl)
    __attribute__((visibility("default")));

/// Clear post-verification index (Cisco extension)
/// Address: 0x0000000000032ed0
void SSL_clear_post_verify_idx(void)
    __attribute__((visibility("default")));

/// Add 1 to CA list (OpenSSL 1.1.1 extension)
/// Address: 0x0000000000032030
int SSL_add1_to_CA_list(SSL *ssl, X509 *x)
    __attribute__((visibility("default")));

/// CTX add 1 to CA list
/// Address: 0x0000000000032060
int SSL_CTX_add1_to_CA_list(SSL_CTX *ctx, X509 *x)
    __attribute__((visibility("default")));
```

### DTLS Support

**Purpose**: Datagram TLS for UDP tunnel transport
**Functions**: 12

```c
// File: dtls_support.h

// DTLS methods
const SSL_METHOD *DTLS_method(void)
    __attribute__((visibility("default")));
    // Address: 0x00000000000215e0

const SSL_METHOD *DTLS_client_method(void)
    __attribute__((visibility("default")));
    // Address: 0x00000000000216c0

const SSL_METHOD *DTLS_server_method(void)
    __attribute__((visibility("default")));
    // Address: 0x0000000000021640

// DTLS data MTU calculation
size_t DTLS_get_data_mtu(const SSL *ssl)
    __attribute__((visibility("default")));
    // Address: 0x0000000000021060

// DTLS timer callback (OpenSSL 1.1.1 extension)
typedef void (*DTLS_timer_cb)(SSL *ssl, unsigned int timeout_ms);

void DTLS_set_timer_cb(SSL *ssl, DTLS_timer_cb cb)
    __attribute__((visibility("default")));
    // Address: 0x0000000000021130

// DTLSv1 listen (for server role)
int DTLSv1_listen(SSL *ssl, BIO_ADDR *peer)
    __attribute__((visibility("default")));
    // Address: 0x0000000000020440
```

### Cipher Suite Configuration

**Purpose**: Cisco-approved cipher suites
**Extracted from strings and analysis**

```c
// File: cisco_ciphers.h

// Cisco Secure Client preferred cipher suites (TLS 1.2)
#define CISCO_CIPHER_SUITES_TLS12 \
    "ECDHE-ECDSA-AES256-GCM-SHA384:" \
    "ECDHE-RSA-AES256-GCM-SHA384:" \
    "ECDHE-ECDSA-AES128-GCM-SHA256:" \
    "ECDHE-RSA-AES128-GCM-SHA256:" \
    "ECDHE-ECDSA-AES256-SHA384:" \
    "ECDHE-RSA-AES256-SHA384:" \
    "ECDHE-ECDSA-AES128-SHA256:" \
    "ECDHE-RSA-AES128-SHA256:" \
    "AES256-GCM-SHA384:" \
    "AES128-GCM-SHA256:" \
    "AES256-SHA256:" \
    "AES128-SHA256"

// TLS 1.3 cipher suites
#define CISCO_CIPHER_SUITES_TLS13 \
    "TLS_AES_256_GCM_SHA384:" \
    "TLS_CHACHA20_POLY1305_SHA256:" \
    "TLS_AES_128_GCM_SHA256"

// DTLS 1.2 cipher suites (UDP tunnel)
#define CISCO_CIPHER_SUITES_DTLS12 \
    "ECDHE-ECDSA-AES256-GCM-SHA384:" \
    "ECDHE-RSA-AES256-GCM-SHA384:" \
    "ECDHE-ECDSA-AES128-GCM-SHA256:" \
    "ECDHE-RSA-AES128-GCM-SHA256"

/// Initialize SSL context with Cisco defaults
[[nodiscard]] int cisco_ssl_ctx_init(
    SSL_CTX **ctx,
    bool is_client,
    bool enable_dtls
);

/// Configure cipher suites
[[nodiscard]] int cisco_ssl_set_cipher_suites(
    SSL_CTX *ctx,
    const char *cipher_list,
    const char *cipher_suites_tls13
);

/// Configure DTLS parameters
[[nodiscard]] int cisco_ssl_configure_dtls(
    SSL *ssl,
    unsigned int mtu,
    unsigned int timeout_ms
);

/// Set up certificate verification
[[nodiscard]] int cisco_ssl_setup_verification(
    SSL_CTX *ctx,
    const char *ca_file,
    const char *ca_path,
    int (*verify_callback)(int, X509_STORE_CTX *)
);
```

---

## Certificate Handling

**Location**: libvpnapi.so, libvpncommon.so
**Total Functions**: 134
**Critical Functions**: 47

### Certificate Management Classes

```c
// File: certificate.h

typedef enum {
    CERT_AUTH_MODE_NONE = 0,
    CERT_AUTH_MODE_OPTIONAL = 1,
    CERT_AUTH_MODE_REQUIRED = 2,
    CERT_AUTH_MODE_REQUIRED_NO_PROMPT = 3
} cert_auth_mode_t;

typedef struct cert_info {
    char subject[512];
    char issuer[512];
    char serial_number[64];
    char fingerprint_sha1[41];
    char fingerprint_sha256[65];
    uint64_t not_before;
    uint64_t not_after;
    bool is_ca;
    bool is_self_signed;
    int key_usage;
    int extended_key_usage;
} cert_info_t;

typedef struct cert_obj {
    void *x509;                // X509* (OpenSSL)
    void *pkey;                // EVP_PKEY* (OpenSSL)
    cert_info_t info;
    uint8_t *der_data;
    size_t der_length;
} cert_obj_t;

/// Parse certificate from DER
[[nodiscard]] int cert_parse_der(
    const uint8_t *der_data,
    size_t der_length,
    cert_obj_t **cert_out
);

/// Parse certificate from PEM
[[nodiscard]] int cert_parse_pem(
    const char *pem_data,
    size_t pem_length,
    cert_obj_t **cert_out
);

/// Extract certificate information
[[nodiscard]] int cert_get_info(
    const cert_obj_t *cert,
    cert_info_t *info_out
);

/// Verify certificate chain
[[nodiscard]] int cert_verify_chain(
    const cert_obj_t *cert,
    const cert_obj_t **ca_certs,
    size_t ca_count,
    bool check_revocation
);

/// Calculate certificate fingerprint
[[nodiscard]] int cert_fingerprint_sha256(
    const cert_obj_t *cert,
    uint8_t fingerprint_out[32]
);

/// Certificate pinning validation
[[nodiscard]] int cert_validate_pin(
    const cert_obj_t *cert,
    const char *pin_base64
);

/// Cleanup
void cert_obj_destroy(cert_obj_t *cert);
```

### Host Profile Certificate Configuration

```c
// From HostProfile class analysis

/// Set certificate authentication hash
void host_profile_set_cert_auth_hash(
    void *profile,
    const char *hash
);

/// Set standard authentication only flag
void host_profile_set_standard_auth_only(
    void *profile,
    bool standard_only
);

/// Set certificate policy
void host_profile_set_cert_policy(
    void *profile,
    cert_auth_mode_t mode
);

/// Set authentication method for IKE negotiation
void host_profile_set_ike_auth_method(
    void *profile,
    uint32_t auth_method
);
```

---

## Profile Management

**Location**: libvpnapi.so
**Total Functions**: 98
**Critical Functions**: 34

### ProfileMgr Class

**Purpose**: VPN profile configuration management
**Functions**: 25

```c
// File: profile_manager.h

typedef enum {
    VPN_TUNNEL_SCOPE_USER = 0,
    VPN_TUNNEL_SCOPE_SYSTEM = 1,
    VPN_TUNNEL_SCOPE_BOTH = 2
} vpn_tunnel_scope_t;

typedef struct profile_manager {
    vpn_tunnel_scope_t scope;
    void *profiles_callback;
    char profile_dir[512];
    void *profile_list;        // std::map internally
} profile_manager_t;

/// Initialize profile manager
[[nodiscard]] int profile_manager_init(
    profile_manager_t **mgr,
    vpn_tunnel_scope_t scope,
    void *callback
);

/// Add profile
[[nodiscard]] int profile_manager_add(
    profile_manager_t *mgr,
    const char **hostnames,
    size_t hostname_count,
    vpn_tunnel_scope_t scope,
    char *profile_name_out,
    size_t name_buffer_size
);

/// Load profile by name
[[nodiscard]] int profile_manager_load(
    profile_manager_t *mgr,
    const char *profile_name,
    void **profile_out
);

/// Load all profiles
[[nodiscard]] int profile_manager_load_all(
    profile_manager_t *mgr,
    bool *has_changes_out
);

/// Get profile directory
[[nodiscard]] const char *profile_manager_get_dir(
    const profile_manager_t *mgr
);

/// Get profile list
[[nodiscard]] int profile_manager_get_list(
    const profile_manager_t *mgr,
    char ***profile_names_out,
    size_t *count_out
);

/// Get protocol type from profile
[[nodiscard]] int profile_manager_get_protocol(
    const profile_manager_t *mgr,
    const char *profile_name,
    connect_protocol_type_t *protocol_out
);

/// Get hostname from address
[[nodiscard]] int profile_manager_get_hostname_from_address(
    const char *address,
    connect_protocol_type_t protocol,
    char *hostname_out,
    size_t buffer_size
);

/// Cleanup
void profile_manager_destroy(profile_manager_t *mgr);
```

### HostProfile Class

**Purpose**: Individual VPN host configuration
**Functions**: 41

```c
// File: host_profile.h

typedef struct host_profile {
    char name[256];
    char hostname[256];
    uint16_t port;
    connect_protocol_type_t primary_protocol;
    connect_protocol_type_t backup_protocol;

    // Authentication
    cert_auth_mode_t cert_policy;
    char cert_hash[65];
    bool standard_auth_only;
    uint32_t ike_auth_method;

    // Domain policies
    char **always_connect_domains;
    size_t always_connect_count;
    char **never_connect_domains;
    size_t never_connect_count;
    char **connect_if_needed_domains;
    size_t connect_if_needed_count;

    // Preferences
    void *preferences;          // Preference list

    // Flags
    uint32_t flags;
} host_profile_t;

/// Create host profile
[[nodiscard]] int host_profile_create(
    host_profile_t **profile,
    const char *name,
    const char *hostname
);

/// Set primary protocol
void host_profile_set_primary_protocol(
    host_profile_t *profile,
    connect_protocol_type_t protocol
);

/// Get always-connect domain list
[[nodiscard]] const char **host_profile_get_always_connect_domains(
    const host_profile_t *profile,
    size_t *count_out
);

/// Get never-connect domain list
[[nodiscard]] const char **host_profile_get_never_connect_domains(
    const host_profile_t *profile,
    size_t *count_out
);

/// Get connect-if-needed domain list
[[nodiscard]] const char **host_profile_get_connect_if_needed_domains(
    const host_profile_t *profile,
    size_t *count_out
);

/// Set certificate policy
void host_profile_set_certificate_policy(
    host_profile_t *profile,
    cert_auth_mode_t policy
);

/// Set certificate authentication hash
void host_profile_set_cert_auth_hash(
    host_profile_t *profile,
    const char *hash
);

/// Set standard authentication only
void host_profile_set_standard_auth_only(
    host_profile_t *profile,
    bool standard_only
);

/// Set IKE authentication method
void host_profile_set_ike_auth_method(
    host_profile_t *profile,
    uint32_t method
);

/// Cleanup
void host_profile_destroy(host_profile_t *profile);
```

---

## Implementation Priority

### Phase 1: Critical Path (Weeks 1-4)

**Goal**: Basic VPN connectivity with authentication

| Module | Functions | Complexity | Dependencies |
|--------|-----------|------------|--------------|
| **ConnectIfc** | 67 | Very High | HTTP, SSL |
| **CHttpAuth** | 12 | High | Base64, MD5 |
| **ProxyAuth** | 15 | Medium | Encryption |
| **SSL/TLS Setup** | 23 | High | OpenSSL/wolfSSL |
| **Certificate Validation** | 18 | High | X.509 parsing |

**Deliverables**:
- Basic SSL/TLS connection
- HTTP authentication (Basic, Digest)
- Certificate validation
- Cookie management

### Phase 2: Protocol Implementation (Weeks 5-8)

**Goal**: Full CSTP/DTLS tunnel support

| Module | Functions | Complexity | Dependencies |
|--------|-----------|------------|--------------|
| **CSTP Protocol** | 45 | Very High | HTTP, chunked transfer |
| **DTLS Protocol** | 38 | Very High | UDP, DTLS 1.2 |
| **Tunnel Management** | 32 | High | TUN/TAP interface |
| **Keep-alive/DPD** | 12 | Medium | Timers |

**Deliverables**:
- CSTP tunnel establishment
- DTLS tunnel (UDP alternative)
- Dead Peer Detection
- Tunnel keepalive

### Phase 3: Advanced Authentication (Weeks 9-12)

**Goal**: Multi-factor and aggregate authentication

| Module | Functions | Complexity | Dependencies |
|--------|-----------|------------|--------------|
| **AggAuth (XML)** | 23 | High | XML parsing |
| **TOTP/OTP** | 8 | Medium | HMAC-SHA1 |
| **CSD Handling** | 15 | Medium | Script execution |
| **Certificate Auth** | 21 | High | PKCS#11, client certs |

**Deliverables**:
- Aggregate authentication flow
- TOTP support
- CSD stub handling
- Client certificate authentication

### Phase 4: Profile & Configuration (Weeks 13-14)

**Goal**: Profile management and persistence

| Module | Functions | Complexity | Dependencies |
|--------|-----------|------------|--------------|
| **ProfileMgr** | 25 | Medium | File I/O, XML |
| **HostProfile** | 41 | Medium | Configuration parsing |
| **Preferences** | 18 | Low | Key-value storage |

**Deliverables**:
- Profile loading/saving
- Configuration management
- User preferences

### Phase 5: Platform Integration (Weeks 15-16)

**Goal**: OS-specific features

| Module | Functions | Complexity | Dependencies |
|--------|-----------|------------|--------------|
| **Linux Integration** | 34 | Medium | systemd, NetworkManager |
| **Windows Integration** | 52 | High | DPAPI, Credential Provider |
| **macOS Integration** | 38 | High | Keychain, System Extension |

---

## Function Cross-Reference

### By Implementation Complexity

#### Very High Complexity (Expert-level C/networking required)

- `ConnectIfc::connect()` - Full connection state machine
- `ConnectIfc::send()` - Data transmission with chunked transfer
- CSTP tunnel establishment
- DTLS tunnel setup and management
- Protocol version negotiation

#### High Complexity (Advanced C required)

- `CHttpAuth::Request()` - HTTP authentication with Digest/NTLM
- Certificate chain validation
- Aggregate authentication flow
- XML parsing and generation
- Encrypted credential storage

#### Medium Complexity (Standard C)

- Cookie management
- Profile loading/saving
- HTTP header parsing
- Base64 encoding/decoding
- Configuration file handling

#### Low Complexity (Basic C)

- String manipulation utilities
- Logging functions
- Flag management
- Simple getters/setters

---

## Notes for ocserv-modern Implementation

### Architectural Recommendations

1. **Modular Design**: Separate concerns (auth, protocol, crypto, config)
2. **C23 Features**: Use `[[nodiscard]]`, `constexpr`, `static_assert`
3. **Error Handling**: Consistent error codes, errno-style
4. **Memory Safety**: Explicit ownership, RAII-like patterns with cleanup functions
5. **Thread Safety**: Document thread-safety requirements per function
6. **Async I/O**: Use epoll/kqueue for scalability

### Dependencies

- **wolfSSL 5.x**: Replaces libacciscossl.so (OpenSSL 1.1.x)
- **libxml2** or **yxml**: XML parsing (aggregate auth)
- **libcurl** (optional): HTTP client functionality
- **PCRE2**: Regular expressions (URL parsing)

### Testing Strategy

1. **Unit Tests**: Each module independently
2. **Integration Tests**: Full connection flows
3. **Compatibility Tests**: Against Cisco ASA/FTD servers
4. **Fuzzing**: Protocol parsers, XML, HTTP headers
5. **Performance Tests**: Throughput, latency, CPU usage

---

## Appendix: Complete Function Address Map

See separate file: `/opt/projects/repositories/cisco-secure-client/decompiled/linux/libvpnapi_exported_functions.txt`

**Total Lines**: 1,019 exported functions with addresses

---

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Status**: Preliminary - pending full disassembly with Ghidra
**Next Steps**: Deep disassembly of critical functions for algorithm reconstruction
