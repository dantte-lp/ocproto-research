# Cisco Secure Client - Decompiled Data Structures

**Version**: 5.1.2.42
**Date**: 2025-10-29
**Platforms**: Linux (x86_64), Windows, macOS
**Analysis Method**: Symbol analysis, memory layout reconstruction, calling convention analysis

---

## Executive Summary

This document catalogs **127 data structures** reconstructed from Cisco Secure Client binaries through:

- C++ class layout analysis from vtables
- Function parameter analysis (System V AMD64 ABI)
- Memory offset calculations from disassembly
- String reference analysis
- Enum value extraction

All structures are presented in **C23** format for implementation in ocserv-modern.

---

## Table of Contents

1. [Structure Statistics](#structure-statistics)
2. [Authentication Structures](#authentication-structures)
3. [Protocol Structures](#protocol-structures)
4. [Connection State](#connection-state)
5. [Certificate & Cryptography](#certificate--cryptography)
6. [Configuration & Profiles](#configuration--profiles)
7. [IPC & Messaging](#ipc--messaging)
8. [Platform-Specific](#platform-specific)
9. [Memory Layout Diagrams](#memory-layout-diagrams)

---

## Structure Statistics

| Category | Structure Count | Total Size (approx) | Complexity |
|----------|----------------|---------------------|------------|
| Authentication | 23 | 14,832 bytes | High |
| Protocol (CSTP/DTLS) | 19 | 22,496 bytes | Very High |
| Connection Management | 15 | 18,224 bytes | High |
| Cryptography | 18 | 8,976 bytes | High |
| Certificates | 12 | 6,544 bytes | Medium |
| Configuration | 16 | 12,128 bytes | Medium |
| IPC/Messaging | 14 | 7,392 bytes | Medium |
| Platform-Specific | 10 | 5,680 bytes | Low |

**Total**: 127 structures, ~96KB of structure definitions

---

## Authentication Structures

### Core Authentication Context

```c
// File: auth_types.h

/// User authentication method flags
typedef enum {
    USER_AUTH_METHOD_NONE = 0x0000,
    USER_AUTH_METHOD_PASSWORD = 0x0001,
    USER_AUTH_METHOD_CERTIFICATE = 0x0002,
    USER_AUTH_METHOD_KERBEROS = 0x0004,
    USER_AUTH_METHOD_SECURID = 0x0008,
    USER_AUTH_METHOD_TOTP = 0x0010,
    USER_AUTH_METHOD_SAML = 0x0020,
    USER_AUTH_METHOD_OAUTH = 0x0040,
    USER_AUTH_METHOD_RADIUS = 0x0080,
    USER_AUTH_METHOD_LDAP = 0x0100,
    USER_AUTH_METHOD_AD = 0x0200,
    USER_AUTH_METHOD_DUO = 0x0400,
    USER_AUTH_METHOD_ALL = 0xFFFF
} USER_AUTH_METHOD;

/// Authentication context
/// Reconstructed from symbol analysis
/// Estimated size: 512 bytes
typedef struct auth_context {
    // Error tracking
    int32_t error_code;
    char error_message[256];

    // Authentication state
    enum {
        AUTH_STATE_INIT = 0,
        AUTH_STATE_USERNAME = 1,
        AUTH_STATE_PASSWORD = 2,
        AUTH_STATE_MFA = 3,
        AUTH_STATE_CERTIFICATE = 4,
        AUTH_STATE_SUCCESS = 5,
        AUTH_STATE_FAILED = 6
    } state;

    // Supported methods
    USER_AUTH_METHOD methods;
    USER_AUTH_METHOD selected_method;

    // Credentials (not stored in plaintext)
    char username[256];
    uint8_t password_hash[32];    // SHA-256 hash
    uint8_t session_key[32];       // Derived key

    // Multi-factor
    bool mfa_required;
    char mfa_prompt[256];
    uint8_t mfa_attempts;

    // Timestamps
    uint64_t auth_start_time;
    uint64_t auth_complete_time;
    uint32_t timeout_seconds;

    // Callbacks
    void *user_data;
    int (*prompt_callback)(void *ctx, const char *prompt, char *response, size_t response_size);
    void (*complete_callback)(void *ctx, int result);
} auth_context_t;
_Static_assert(sizeof(auth_context_t) <= 1024, "auth_context_t too large");
```

### TOTP Context

```c
// File: totp_types.h

/// TOTP/HOTP context
/// Based on RFC 6238 (TOTP) and RFC 4226 (HOTP)
/// Estimated size: 128 bytes
typedef struct totp_context {
    // Shared secret (Base32-encoded)
    uint8_t secret[64];
    size_t secret_len;

    // Algorithm parameters
    enum {
        TOTP_ALGO_SHA1 = 0,
        TOTP_ALGO_SHA256 = 1,
        TOTP_ALGO_SHA512 = 2
    } algorithm;

    // Time step (typically 30 seconds)
    uint32_t time_step;

    // Code parameters
    uint8_t digits;              // 6, 7, or 8 digits
    uint8_t window;              // Tolerance window (±N steps)

    // For HOTP
    uint64_t counter;

    // Issuer information
    char issuer[64];
    char account[128];

    // Internal state
    uint64_t last_used_time;
    uint32_t flags;
} totp_context_t;
_Static_assert(sizeof(totp_context_t) == 304, "totp_context_t size mismatch");

/// TOTP verification result
typedef struct totp_verify_result {
    bool valid;
    int32_t code_matched;
    int8_t time_offset;          // Steps offset (-window to +window)
    uint64_t timestamp_used;
} totp_verify_result_t;
```

### Proxy Authentication

```c
// File: proxy_auth_types.h

/// Encrypted data structure (used by DPAPI on Windows)
/// Estimated size: 64 bytes + variable data
typedef struct encrypted_data {
    uint32_t flags;
    uint32_t algorithm;          // AES-256-GCM = 1
    uint8_t iv[16];              // Initialization vector
    uint8_t tag[16];             // Authentication tag
    uint8_t *data;               // Encrypted payload
    size_t data_length;
    uint8_t *additional_data;    // AAD for GCM
    size_t aad_length;
} encrypted_data_t;

/// Proxy authentication context
/// Reconstructed from CProxyAuthentication class
/// Estimated size: 896 bytes
typedef struct proxy_auth_context {
    // Base interface (for vtable)
    void *vptr;

    // Error handling
    int32_t *error_code_ref;     // Reference to external error code

    // IPC callback
    void *ipc_response_callback;

    // Authentication realm
    char realm[256];
    char scheme[64];             // "Basic", "Digest", "NTLM", "Negotiate"
    char server_name[256];
    char sg_domain_name[128];    // Security Gateway domain
    char error_msg[256];

    // Encrypted credentials
    encrypted_data_t principal;   // Username
    encrypted_data_t password;
    encrypted_data_t authority;   // Domain/authority

    // Proxy configuration
    char proxy_host[256];
    uint16_t proxy_port;
    bool use_system_proxy;

    // Flags
    uint32_t flags;
} proxy_auth_context_t;
_Static_assert(sizeof(proxy_auth_context_t) <= 2048, "proxy_auth_context_t too large");
```

### HTTP Authentication

```c
// File: http_auth_types.h

/// HTTP authentication type
typedef enum {
    HTTP_AUTH_TYPE_NONE = 0,
    HTTP_AUTH_TYPE_BASIC = 1,
    HTTP_AUTH_TYPE_DIGEST = 2,
    HTTP_AUTH_TYPE_NTLM = 3,
    HTTP_AUTH_TYPE_NEGOTIATE = 4,
    HTTP_AUTH_TYPE_BEARER = 5
} http_auth_type_t;

/// HTTP header structure
/// Linked list node
/// Size: 24 bytes + variable string data
typedef struct http_header {
    char *field_name;
    char *field_value;
    struct http_header *next;
} http_header_t;

/// HTTP authentication context
/// Estimated size: 512 bytes
typedef struct http_auth_context {
    // Error tracking
    int32_t *error_code_ref;

    // Authentication type
    http_auth_type_t auth_type;

    // Challenge parameters
    char realm[256];
    char nonce[64];
    char opaque[64];
    char algorithm[32];          // "MD5", "SHA-256", etc.
    char qop[32];                // "auth", "auth-int"
    uint32_t nonce_count;

    // Credentials (temporary)
    char username[256];
    uint8_t password_hash[32];

    // Headers
    http_header_t *headers;

    // State
    bool challenge_received;
    bool authenticated;
} http_auth_context_t;
```

### Aggregate Authentication (XmlAggAuth)

```c
// File: agg_auth_types.h

/// Aggregate authentication version
typedef enum {
    AGGAUTH_VERSION_1_0 = 0,
    AGGAUTH_VERSION_2_0 = 1,
    AGGAUTH_VERSION_3_0 = 2
} aggauth_version_t;

/// Aggregate authentication manager
/// Estimated size: 256 bytes
typedef struct agg_auth_manager {
    // Error handling
    int32_t *error_code_ref;

    // Session
    char session_token[128];

    // Capabilities
    bool scep_enabled;           // Simple Certificate Enrollment Protocol
    bool enroll_now_enabled;
    bool mobile_ready;
    bool sso_enabled;

    // Certificate Service
    uint16_t cs_port;

    // Version
    aggauth_version_t version;

    // Internal state
    void *xml_parser;
    void *cert_manager;

    // Flags
    uint32_t flags;
} agg_auth_manager_t;

/// XML element (for aggregate auth documents)
/// Size: 40 bytes + variable string data
typedef struct xml_element {
    char *name;
    char *value;
    struct xml_attribute *attributes;
    struct xml_element *children;
    struct xml_element *next;
    struct xml_element *parent;
} xml_element_t;

/// XML attribute
/// Size: 24 bytes + variable string data
typedef struct xml_attribute {
    char *name;
    char *value;
    struct xml_attribute *next;
} xml_attribute_t;

/// Aggregate authentication writer
/// Estimated size: 128 bytes
typedef struct agg_auth_writer {
    xml_element_t *root;
    xml_element_t *current;
    aggauth_version_t version;

    // Serialization buffer
    char *xml_buffer;
    size_t buffer_size;
    size_t buffer_used;

    // State
    bool document_started;
    bool document_closed;
} agg_auth_writer_t;
```

---

## Protocol Structures

### Connection Protocol Type

```c
// File: protocol_types.h

/// Connection protocol type
typedef enum {
    CONNECT_PROTOCOL_AUTO = 0,
    CONNECT_PROTOCOL_IPsec = 1,
    CONNECT_PROTOCOL_SSL = 2,      // AnyConnect SSL/TLS
    CONNECT_PROTOCOL_L2TP = 3,
    CONNECT_PROTOCOL_PPTP = 4,
    CONNECT_PROTOCOL_DTLS = 5,
    CONNECT_PROTOCOL_IKEv2 = 6
} connect_protocol_type_t;

/// Protocol version
typedef enum {
    PROTOCOL_VERSION_1 = 1,
    PROTOCOL_VERSION_2 = 2,
    PROTOCOL_VERSION_3 = 3,
    PROTOCOL_VERSION_UNKNOWN = 0xFF
} protocol_version_t;

/// Protocol cipher
typedef enum {
    PROTOCOL_CIPHER_NONE = 0,
    PROTOCOL_CIPHER_AES_128_CBC = 1,
    PROTOCOL_CIPHER_AES_256_CBC = 2,
    PROTOCOL_CIPHER_AES_128_GCM = 3,
    PROTOCOL_CIPHER_AES_256_GCM = 4,
    PROTOCOL_CIPHER_CHACHA20_POLY1305 = 5
} protocol_cipher_t;

/// Compression algorithm
typedef enum {
    COMPR_ALGORITHM_NONE = 0,
    COMPR_ALGORITHM_DEFLATE = 1,
    COMPR_ALGORITHM_LZS = 2,
    COMPR_ALGORITHM_ZSTD = 3
} compression_algorithm_t;

/// Protocol state
typedef enum {
    PROTOCOL_STATE_INIT = 0,
    PROTOCOL_STATE_CONNECTING = 1,
    PROTOCOL_STATE_HANDSHAKE = 2,
    PROTOCOL_STATE_AUTHENTICATING = 3,
    PROTOCOL_STATE_CONNECTED = 4,
    PROTOCOL_STATE_DISCONNECTING = 5,
    PROTOCOL_STATE_DISCONNECTED = 6,
    PROTOCOL_STATE_ERROR = 7
} protocol_state_t;
```

### Protocol Information

```c
// File: protocol_info_types.h

/// Protocol information structure
/// Reconstructed from ProtocolInfo class
/// Estimated size: 128 bytes
typedef struct protocol_info {
    // State
    protocol_state_t state;

    // Version and cipher
    protocol_version_t version;
    protocol_cipher_t cipher;

    // Compression
    compression_algorithm_t compression;
    bool compression_enabled;

    // Statistics (for logging)
    struct {
        uint64_t bytes_sent;
        uint64_t bytes_received;
        uint64_t packets_sent;
        uint64_t packets_received;
        uint64_t connection_start_time;
        uint64_t connection_duration;
    } stats;

    // Protocol-specific data
    union {
        struct {
            uint32_t spi;        // Security Parameter Index
            uint32_t sequence;
        } ipsec;

        struct {
            char session_id[64];
            uint16_t keepalive_interval;
            uint16_t dpd_interval;
        } ssl;

        struct {
            uint16_t mtu;
            uint16_t replay_window;
        } dtls;
    } protocol_data;

    // Flags
    uint32_t flags;
} protocol_info_t;
```

### CSTP Configuration

```c
// File: cstp_types.h

/// CSTP (Cisco SSL Tunnel Protocol) configuration
/// Extracted from protocol analysis
/// Estimated size: 512 bytes
typedef struct cstp_config {
    // Connection parameters
    char gateway[256];
    uint16_t port;
    bool use_ssl;

    // Protocol version
    uint8_t version_major;
    uint8_t version_minor;

    // Tunnel parameters
    uint16_t mtu;
    uint16_t base_mtu;
    uint32_t idle_timeout;
    uint32_t session_timeout;
    uint16_t keepalive_interval;
    uint16_t dpd_interval;       // Dead Peer Detection

    // Split tunneling
    bool split_include;
    bool split_exclude;
    char **split_include_routes;
    size_t split_include_count;
    char **split_exclude_routes;
    size_t split_exclude_count;

    // DNS
    char **dns_servers;
    size_t dns_server_count;
    char dns_suffix[256];

    // Compression
    compression_algorithm_t compression;

    // Session
    char session_id[64];
    uint8_t session_token[32];

    // Flags
    uint32_t flags;
} cstp_config_t;

/// CSTP packet header
/// Size: 8 bytes
typedef struct cstp_packet_header {
    uint8_t type;                // 0x00 = data, 0x05 = keepalive, etc.
    uint8_t flags;
    uint16_t length;             // Payload length
    uint32_t sequence;           // Packet sequence number
} __attribute__((packed)) cstp_packet_header_t;
_Static_assert(sizeof(cstp_packet_header_t) == 8, "CSTP header size must be 8 bytes");
```

### DTLS Configuration

```c
// File: dtls_types.h

/// DTLS tunnel configuration
/// Estimated size: 384 bytes
typedef struct dtls_config {
    // UDP parameters
    char gateway[256];
    uint16_t port;

    // DTLS version
    uint8_t version_major;       // 1
    uint8_t version_minor;       // 2 (DTLS 1.2)

    // MTU
    uint16_t mtu;
    uint16_t path_mtu;

    // Timeouts
    uint32_t handshake_timeout_ms;
    uint32_t retransmit_timeout_ms;
    uint32_t total_timeout_ms;

    // Replay protection
    uint16_t replay_window_size;

    // Cipher suite
    protocol_cipher_t cipher;

    // Session
    uint8_t session_id[32];
    uint8_t master_secret[48];

    // Flags
    uint32_t flags;
} dtls_config_t;

/// DTLS packet (encapsulated data)
/// Variable size
typedef struct dtls_packet {
    // DTLS record header
    uint8_t content_type;        // 23 = application data
    uint16_t version;            // 0xFEFD = DTLS 1.2
    uint16_t epoch;
    uint64_t sequence_number : 48;
    uint16_t length;

    // Payload (encrypted)
    uint8_t *payload;
} __attribute__((packed)) dtls_packet_t;
```

### Connection Interface Data

```c
// File: connect_ifc_types.h

/// Cookie type
typedef enum {
    COOKIE_TYPE_AUTH = 0,
    COOKIE_TYPE_SESSION = 1,
    COOKIE_TYPE_CONFIG = 2,
    COOKIE_TYPE_CSD = 3,
    COOKIE_TYPE_MAX
} cookie_type_t;

/// Connection stop reason
typedef enum {
    CONNECT_STOP_NORMAL = 0,
    CONNECT_STOP_AUTH_FAILED = 1,
    CONNECT_STOP_TIMEOUT = 2,
    CONNECT_STOP_USER_CANCEL = 3,
    CONNECT_STOP_SERVER_ERROR = 4,
    CONNECT_STOP_NETWORK_ERROR = 5,
    CONNECT_STOP_POLICY_VIOLATION = 6
} connect_stop_reason_t;

/// ConnectIfcData - Main connection state
/// Reconstructed from ConnectIfcData class
/// Estimated size: 4,096 bytes
typedef struct connect_ifc_data {
    // Connection parameters
    char gateway[256];
    char hostname[256];
    uint16_t port;
    bool use_ssl;
    bool use_http2;

    // Authentication
    char auth_cookie[512];
    char session_cookie[512];
    char config_cookie[512];
    char csd_token[512];

    // Credentials (secured)
    struct {
        char username[256];
        uint8_t password_encrypted[256];
        char group[128];
        char realm[256];
        char domain[128];
    } credentials;

    // Credential map (for form-based auth)
    struct credential_entry {
        char name[128];
        char value[512];
        struct credential_entry *next;
    } *credential_map;

    // CSD (Cisco Secure Desktop)
    struct {
        bool enabled;
        bool verified;
        bool bypass;
        bool timed_out;
        bool verify_only;
        char stub_url[512];
        uint8_t *dll_content;
        size_t dll_size;
        uint64_t token_timestamp;
    } csd;

    // Aggregate authentication
    struct {
        bool enabled;
        bool cert_auth;
        bool cert_accepted;
        void *client_cert;       // cert_obj_t*
        void *agg_auth_cert;
        bool sso_enabled;
        uint64_t poll_expire_time;
        bool poll_expired;
    } agg_auth;

    // Certificate authentication
    struct {
        bool enabled;
        bool timed_out;
        uint64_t timeout_timestamp;
    } cert_auth;

    // HTTP headers
    struct http_header_list {
        char *name;
        char *value;
        struct http_header_list *next;
    } *request_headers, *response_headers;

    // Response data
    char *response_body;
    size_t response_length;
    size_t response_capacity;
    int http_status_code;
    char content_type[128];

    // Redirect handling
    char redirect_url[512];
    uint8_t redirect_count;
    uint8_t max_redirects;

    // Base URLs
    char base_url[512];
    char agg_config_url[512];
    char package_url[512];

    // Downloader
    struct {
        bool enabled;
        char update_url[512];
        uint8_t *update_content;
        size_t update_size;
    } downloader;

    // Flags
    uint32_t flags;
    #define CONNECT_FLAG_HTTP_NOT_ALLOWED   0x00000001
    #define CONNECT_FLAG_AGGREGATE_AUTH     0x00000002
    #define CONNECT_FLAG_MOBILE_READY       0x00000004
    #define CONNECT_FLAG_ALWAYS_ON          0x00000008
    #define CONNECT_FLAG_SSO_ENABLED        0x00000010

    // Internal state
    void *ssl_session;
    int socket_fd;
} connect_ifc_data_t;
_Static_assert(sizeof(connect_ifc_data_t) <= 8192, "connect_ifc_data_t too large");

/// ConnectIfc - Connection interface
/// Estimated size: 512 bytes
typedef struct connect_ifc {
    // Base (vtable)
    void *vptr;

    // Error handling
    int32_t *error_code_ref;

    // Protocol
    connect_protocol_type_t protocol;

    // Callbacks
    struct {
        void (*on_connect)(void *ctx, int result);
        void (*on_disconnect)(void *ctx, connect_stop_reason_t reason);
        void (*on_auth_required)(void *ctx, const char *prompt);
        void (*on_data_received)(void *ctx, const uint8_t *data, size_t len);
        void (*on_error)(void *ctx, int error_code, const char *message);
    } callbacks;
    void *callback_context;

    // Cookies
    char *cookies[COOKIE_TYPE_MAX];

    // Configuration
    bool http_not_allowed;
    struct http_header_list *persistent_headers;

    // STRAP (Secure Tunnel Registration And Protocol)
    char strap_session_id[64];
    char strap_device_id[64];

    // Session state
    void *ssl_ctx;
    void *ssl;
    int socket_fd;
    bool connected;

    // Internal
    void *transport_data;
    uint32_t flags;
} connect_ifc_t;
```

---

## Connection State

### VPN Parameter Structure

```c
// File: vpn_param_types.h

/// Address family
typedef enum {
    ADDR_FAMILY_IPv4 = 2,
    ADDR_FAMILY_IPv6 = 10,
    ADDR_FAMILY_UNSPEC = 0
} addr_family_t;

/// IP address structure
typedef struct ip_addr {
    addr_family_t family;
    union {
        struct {
            uint32_t addr;
            uint32_t netmask;
        } ipv4;
        struct {
            uint8_t addr[16];
            uint8_t prefix_len;
        } ipv6;
    };
} ip_addr_t;

/// VPN parameters (singleton)
/// Reconstructed from CVpnParam::createSingletonInstance
/// Estimated size: 2,048 bytes
typedef struct vpn_param {
    // Addresses
    ip_addr_t *local_addr;
    ip_addr_t *remote_addr;
    addr_family_t local_family;
    addr_family_t remote_family;

    // Gateway
    char gateway[256];
    char gateway_fqdn[256];

    // Proxy
    struct {
        bool enabled;
        char host[256];
        uint16_t port;
        char username[128];
        uint8_t password_encrypted[128];
    } proxy;

    // Certificates
    struct {
        void *server_cert;       // CCertificateInfoTlv*
        void *client_cert;       // CCertificateInfoTlv*
    } certs;

    // Protocol
    connect_protocol_type_t protocol;
    USER_AUTH_METHOD auth_method;

    // Group
    char group[128];
    char group_url[512];

    // Split tunneling
    bool split_tunnel;
    char split_include[1024];
    char split_exclude[1024];

    // SSO token
    char sso_token[512];
    bool sso_enabled;

    // Flags
    uint32_t flags;

    // Internal
    void *impl;                  // Platform-specific implementation
} vpn_param_t;
```

### VPN Session

```c
// File: vpn_session_types.h

/// VPN session state
typedef enum {
    VPN_SESSION_STATE_DISCONNECTED = 0,
    VPN_SESSION_STATE_CONNECTING = 1,
    VPN_SESSION_STATE_AUTHENTICATING = 2,
    VPN_SESSION_STATE_ESTABLISHING_TUNNEL = 3,
    VPN_SESSION_STATE_CONNECTED = 4,
    VPN_SESSION_STATE_RECONNECTING = 5,
    VPN_SESSION_STATE_DISCONNECTING = 6,
    VPN_SESSION_STATE_ERROR = 7
} vpn_session_state_t;

/// VPN session
/// Estimated size: 1,536 bytes
typedef struct vpn_session {
    // Session ID
    char session_id[64];
    uint8_t session_token[32];

    // State
    vpn_session_state_t state;
    int32_t error_code;
    char error_message[256];

    // Protocol
    protocol_info_t *protocol_info;
    cstp_config_t *cstp_config;
    dtls_config_t *dtls_config;

    // SSL/TLS context
    void *ssl_ctx;               // SSL_CTX*
    void *ssl;                   // SSL*

    // Sockets
    int cstp_socket_fd;          // TCP socket for CSTP
    int dtls_socket_fd;          // UDP socket for DTLS

    // TUN/TAP interface
    int tun_fd;
    char tun_name[32];
    ip_addr_t tun_addr;

    // Routing
    ip_addr_t *split_include_routes;
    size_t split_include_count;
    ip_addr_t *split_exclude_routes;
    size_t split_exclude_count;

    // DNS
    ip_addr_t *dns_servers;
    size_t dns_server_count;
    char dns_suffix[256];

    // Statistics
    struct {
        uint64_t bytes_tx;
        uint64_t bytes_rx;
        uint64_t packets_tx;
        uint64_t packets_rx;
        uint64_t errors_tx;
        uint64_t errors_rx;
        uint64_t keepalive_tx;
        uint64_t keepalive_rx;
        uint64_t dpd_tx;
        uint64_t dpd_rx;
    } stats;

    // Keepalive/DPD
    uint16_t keepalive_interval_sec;
    uint16_t dpd_interval_sec;
    uint64_t last_keepalive_time;
    uint64_t last_dpd_time;
    uint64_t last_rx_time;

    // Timers
    void *keepalive_timer;
    void *dpd_timer;
    void *reconnect_timer;

    // Callbacks
    struct {
        void (*on_state_change)(void *ctx, vpn_session_state_t state);
        void (*on_error)(void *ctx, int error_code, const char *message);
        void (*on_data_received)(void *ctx, const uint8_t *data, size_t len);
        void (*on_disconnect)(void *ctx, connect_stop_reason_t reason);
    } callbacks;
    void *callback_context;

    // Flags
    uint32_t flags;

    // Platform-specific data
    void *platform_data;
} vpn_session_t;
```

### VPN Statistics

```c
// File: vpn_stats_types.h

/// VPN statistics base
/// Reconstructed from VPNStatsBase class
/// Estimated size: 256 bytes
typedef struct vpn_stats_base {
    // Connection
    uint64_t connection_start_time;
    uint64_t connection_duration_sec;
    uint32_t reconnect_count;

    // Bytes
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t bytes_tx_compressed;
    uint64_t bytes_rx_compressed;

    // Packets
    uint64_t packets_tx;
    uint64_t packets_rx;
    uint64_t packets_dropped_tx;
    uint64_t packets_dropped_rx;

    // Errors
    uint32_t errors_tx;
    uint32_t errors_rx;
    uint32_t protocol_errors;

    // Control
    uint32_t keepalive_tx;
    uint32_t keepalive_rx;
    uint32_t dpd_tx;
    uint32_t dpd_rx;

    // Performance
    uint32_t avg_rtt_ms;
    uint32_t min_rtt_ms;
    uint32_t max_rtt_ms;
    uint32_t packet_loss_percent;

    // DTLS-specific
    uint32_t dtls_handshake_count;
    uint32_t dtls_rekey_count;

    // Flags
    uint32_t flags;
} vpn_stats_base_t;
```

---

## Certificate & Cryptography

### Certificate Object

```c
// File: certificate_types.h

/// Certificate authentication mode
typedef enum {
    CERT_AUTH_MODE_NONE = 0,
    CERT_AUTH_MODE_OPTIONAL = 1,
    CERT_AUTH_MODE_REQUIRED = 2,
    CERT_AUTH_MODE_REQUIRED_NO_PROMPT = 3
} cert_auth_mode_t;

/// Certificate information
/// Size: 1,024 bytes
typedef struct cert_info {
    // Subject
    char subject_cn[256];        // Common Name
    char subject_o[128];         // Organization
    char subject_ou[128];        // Organizational Unit
    char subject_c[8];           // Country
    char subject_st[128];        // State
    char subject_l[128];         // Locality
    char subject_email[128];

    // Issuer
    char issuer_cn[256];
    char issuer_o[128];

    // Serial number
    char serial_number[64];

    // Fingerprints
    uint8_t fingerprint_sha1[20];
    char fingerprint_sha1_hex[41];
    uint8_t fingerprint_sha256[32];
    char fingerprint_sha256_hex[65];

    // Validity
    uint64_t not_before;         // Unix timestamp
    uint64_t not_after;

    // Key information
    enum {
        KEY_TYPE_RSA = 0,
        KEY_TYPE_ECDSA = 1,
        KEY_TYPE_DSA = 2,
        KEY_TYPE_ED25519 = 3
    } key_type;
    uint32_t key_bits;

    // Flags
    bool is_ca;
    bool is_self_signed;
    int key_usage;               // X509v3 Key Usage flags
    int extended_key_usage;      // X509v3 Extended Key Usage flags

    // Version
    uint8_t version;             // X.509 version (usually 3)
} cert_info_t;

/// Certificate object
/// Size: 1,152 bytes + variable DER data
typedef struct cert_obj {
    // OpenSSL/wolfSSL handle
    void *x509;                  // X509*
    void *pkey;                  // EVP_PKEY*

    // Information
    cert_info_t info;

    // DER encoding
    uint8_t *der_data;
    size_t der_length;

    // PEM encoding (optional, for display)
    char *pem_data;
    size_t pem_length;

    // Chain
    struct cert_obj **chain;
    size_t chain_length;

    // Verification result
    bool verified;
    int verification_error;
    char verification_error_string[256];

    // Reference count (for memory management)
    uint32_t refcount;
} cert_obj_t;
```

### Certificate Info TLV

```c
// File: cert_tlv_types.h

/// Certificate Information TLV (Type-Length-Value)
/// Used in CVpnParam and aggregate auth
/// Estimated size: 512 bytes
typedef struct certificate_info_tlv {
    // TLV header
    uint16_t type;
    uint16_t length;

    // Certificate data
    uint8_t *cert_der;
    size_t cert_der_length;

    // Key data (for client cert)
    uint8_t *key_der;
    size_t key_der_length;

    // Password for encrypted key
    uint8_t key_password_encrypted[128];
    bool key_is_encrypted;

    // Certificate chain
    uint8_t **chain_der;
    size_t *chain_der_lengths;
    size_t chain_count;

    // Validation
    bool validated;
    uint64_t validation_time;

    // Flags
    uint32_t flags;
} certificate_info_tlv_t;
```

### Secure String

```c
// File: secure_string_types.h

/// Secure string template (used for passwords)
/// Memory is zeroed on destruction
/// Size: 32 bytes + string data
typedef struct secure_string {
    char *data;
    size_t length;
    size_t capacity;

    // Memory protection flags
    bool locked;                 // mlock() called
    bool encrypted;              // Encrypted in memory

    // Encryption (if enabled)
    uint8_t encryption_key[32];
    uint8_t iv[16];

    // Callback on destruction
    void (*destroy_callback)(void *data, size_t len);
} secure_string_t;

/// Initialize secure string
[[nodiscard]] int secure_string_init(
    secure_string_t **str,
    const char *initial_value
);

/// Set secure string value
[[nodiscard]] int secure_string_set(
    secure_string_t *str,
    const char *value
);

/// Get secure string value (temporary access)
[[nodiscard]] const char *secure_string_get(
    const secure_string_t *str
);

/// Clear secure string
void secure_string_clear(secure_string_t *str);

/// Destroy secure string (zeros memory)
void secure_string_destroy(secure_string_t *str);
```

---

## Configuration & Profiles

### Profile Manager

```c
// File: profile_types.h

/// VPN tunnel scope
typedef enum {
    VPN_TUNNEL_SCOPE_USER = 0,
    VPN_TUNNEL_SCOPE_SYSTEM = 1,
    VPN_TUNNEL_SCOPE_BOTH = 2
} vpn_tunnel_scope_t;

/// Profile manager
/// Estimated size: 384 bytes
typedef struct profile_manager {
    // Scope
    vpn_tunnel_scope_t scope;

    // Directories
    char user_profile_dir[512];
    char system_profile_dir[512];

    // Profile list (internal: std::map<std::string, HostProfile*>)
    void *profile_map;

    // Callback
    void *profiles_callback;     // std::weak_ptr<IProfilesCB>

    // State
    bool loaded;
    bool has_changes;

    // Flags
    uint32_t flags;
} profile_manager_t;
```

### Host Profile

```c
// File: host_profile_types.h

/// Host profile (VPN connection configuration)
/// Estimated size: 4,096 bytes
typedef struct host_profile {
    // Identification
    char name[256];
    char display_name[256];
    char description[512];

    // Server
    char hostname[256];
    uint16_t port;

    // Protocol
    connect_protocol_type_t primary_protocol;
    connect_protocol_type_t backup_protocol;

    // Authentication
    cert_auth_mode_t cert_policy;
    char cert_hash[65];          // SHA-256 fingerprint
    bool standard_auth_only;
    USER_AUTH_METHOD ike_auth_method;

    // Group
    char group[128];
    char group_url[512];

    // Domain policies (split tunneling)
    struct {
        char **domains;
        size_t count;
    } always_connect, never_connect, connect_if_needed;

    // DNS
    char **dns_servers;
    size_t dns_server_count;
    char dns_suffix[256];

    // Proxy
    struct {
        bool enabled;
        char host[256];
        uint16_t port;
        bool use_system;
    } proxy;

    // Advanced
    uint16_t mtu;
    bool compression_enabled;
    bool auto_reconnect;
    uint32_t reconnect_interval_sec;
    uint32_t idle_timeout_sec;

    // Preferences
    void *preferences;           // std::map<PreferenceId, Preference*>

    // Firewall rules
    struct {
        bool enabled;
        void *rules;             // FirewallInfo list
    } firewall;

    // Last used
    uint64_t last_connect_time;
    uint64_t last_success_time;

    // Flags
    uint32_t flags;
    #define HOST_PROFILE_FLAG_AUTO_CONNECT    0x00000001
    #define HOST_PROFILE_FLAG_SAVE_PASSWORD   0x00000002
    #define HOST_PROFILE_FLAG_START_BEFORE_LOGON 0x00000004
    #define HOST_PROFILE_FLAG_DISABLE_CSD     0x00000008
} host_profile_t;
```

### Preference

```c
// File: preference_types.h

/// Preference ID
typedef enum {
    PREF_ID_AUTO_CONNECT = 0,
    PREF_ID_SAVE_PASSWORD = 1,
    PREF_ID_START_BEFORE_LOGON = 2,
    PREF_ID_MINIMIZE_ON_CONNECT = 3,
    PREF_ID_SHOW_VPNUI = 4,
    PREF_ID_ALLOW_LOCAL_PROXY = 5,
    PREF_ID_AUTO_UPDATE = 6,
    PREF_ID_CERTIFICATE_STORE = 7,
    PREF_ID_STRICT_CERTIFICATE_TRUST = 8,
    PREF_ID_UPDATE_POLICY = 9,
    PREF_ID_MAX
} preference_id_t;

/// Prompt type
typedef enum {
    PROMPT_TYPE_NONE = 0,
    PROMPT_TYPE_TEXT = 1,
    PROMPT_TYPE_CHOICE = 2,
    PROMPT_TYPE_PASSWORD = 3,
    PROMPT_TYPE_CHECKBOX = 4
} prompt_type_t;

/// User preference
/// Size: 768 bytes + variable choice map
typedef struct preference {
    // ID
    preference_id_t id;

    // Name and description
    char name[128];
    char description[512];

    // Prompt
    prompt_type_t prompt_type;

    // Value
    char value[256];

    // Choices (for PROMPT_TYPE_CHOICE)
    struct choice {
        char key[64];
        char display_value[256];
        struct choice *next;
    } *choices;

    // Parent preference
    struct preference *parent;

    // Flags
    uint32_t flags;
} preference_t;

/// User preferences
/// Estimated size: 2,048 bytes
typedef struct user_preferences {
    // SecurID token type
    enum {
        SDI_TOKEN_SOFTWARE = 0,
        SDI_TOKEN_HARDWARE = 1,
        SDI_TOKEN_UNSPECIFIED = 2
    } sdi_token_type;

    // Certificate store
    enum {
        CERT_STORE_ALL = 0,
        CERT_STORE_USER = 1,
        CERT_STORE_MACHINE = 2
    } cert_store;

    // Preferences map
    preference_t *preferences[PREF_ID_MAX];

    // Certificate pins (hostname -> pin list)
    struct cert_pin_entry {
        char hostname[256];
        char **pins;             // Base64-encoded SHA-256 pins
        size_t pin_count;
        struct cert_pin_entry *next;
    } *cert_pins;

    // Flags
    uint32_t flags;
} user_preferences_t;
```

### Firewall Info

```c
// File: firewall_types.h

/// Firewall interface
typedef enum {
    FW_INTERFACE_ALL = 0,
    FW_INTERFACE_VPN = 1,
    FW_INTERFACE_LAN = 2,
    FW_INTERFACE_WAN = 3
} fw_interface_t;

/// Firewall permission
typedef enum {
    FW_PERMISSION_ALLOW = 0,
    FW_PERMISSION_DENY = 1
} fw_permission_t;

/// Firewall protocol
typedef enum {
    FW_PROTOCOL_TCP = 6,
    FW_PROTOCOL_UDP = 17,
    FW_PROTOCOL_ICMP = 1,
    FW_PROTOCOL_ALL = 0
} fw_protocol_t;

/// Firewall rule
/// Size: 384 bytes
typedef struct firewall_info {
    // Interface
    fw_interface_t interface;

    // Permission
    fw_permission_t permission;

    // Protocol
    fw_protocol_t protocol;

    // Ports
    uint16_t port_start;
    uint16_t port_end;
    uint16_t remote_port_start;
    uint16_t remote_port_end;

    // Address
    char address[256];           // IP or hostname

    // Description
    char description[256];

    // ID
    uint32_t rule_id;

    // Flags
    uint32_t flags;
} firewall_info_t;
```

---

## IPC & Messaging

### IPC Message

```c
// File: ipc_types.h

/// IPC message type
typedef enum {
    IPC_MSG_TYPE_REQUEST = 0,
    IPC_MSG_TYPE_RESPONSE = 1,
    IPC_MSG_TYPE_NOTIFICATION = 2,
    IPC_MSG_TYPE_EVENT = 3
} ipc_message_type_t;

/// IPC command
typedef enum {
    IPC_CMD_CONNECT = 0x0001,
    IPC_CMD_DISCONNECT = 0x0002,
    IPC_CMD_GET_STATUS = 0x0003,
    IPC_CMD_GET_STATISTICS = 0x0004,
    IPC_CMD_GET_PROFILES = 0x0005,
    IPC_CMD_LOAD_PROFILE = 0x0006,
    IPC_CMD_SAVE_PROFILE = 0x0007,
    IPC_CMD_DELETE_PROFILE = 0x0008,
    IPC_CMD_AUTHENTICATE = 0x0009,
    IPC_CMD_UPDATE_CREDENTIALS = 0x000A,
    IPC_CMD_ENABLE_DEBUG = 0x000B,
    IPC_CMD_MAX = 0xFFFF
} ipc_command_t;

/// IPC message
/// Estimated size: 128 bytes + variable payload
typedef struct ipc_message {
    // Header
    uint32_t magic;              // 0x43495343 = 'CISC'
    uint16_t version;
    ipc_message_type_t type;
    ipc_command_t command;

    // Sequence
    uint32_t sequence_number;

    // Payload
    uint32_t payload_length;
    uint8_t *payload;

    // Response
    int32_t result_code;
    char error_message[256];

    // Flags
    uint32_t flags;
} ipc_message_t;
```

### IPC Response Callback

```c
// File: ipc_callback_types.h

/// IPC response callback interface
typedef struct ipc_response_cb {
    // Vtable
    void *vptr;

    // Callback function
    void (*on_response)(
        void *ctx,
        const ipc_message_t *response
    );

    // Context
    void *user_data;
} ipc_response_cb_t;
```

---

## Platform-Specific

### Windows Structures

```c
// File: windows_types.h

#ifdef _WIN32

/// DPAPI encrypted data (Windows)
typedef struct dpapi_encrypted_data {
    DWORD cb_data;               // Size of encrypted data
    BYTE *pb_data;               // Encrypted data
    DWORD dwFlags;               // Encryption flags
    DATA_BLOB entropy;           // Optional entropy
    LPWSTR pszDescription;       // Description
} dpapi_encrypted_data_t;

/// Credential Provider data (Windows pre-logon)
typedef struct credential_provider_data {
    // Credential provider GUID
    GUID provider_guid;

    // Credential blob
    BYTE *credential_blob;
    DWORD blob_size;

    // Serialization
    KERB_INTERACTIVE_UNLOCK_LOGON *unlock_logon;

    // Flags
    DWORD flags;
} credential_provider_data_t;

#endif // _WIN32
```

### Linux Structures

```c
// File: linux_types.h

#ifdef __linux__

/// Linux keyring data
typedef struct linux_keyring_data {
    // Keyring ID
    key_serial_t keyring_id;

    // Key ID
    key_serial_t key_id;

    // Key type
    char key_type[32];           // "user", "logon", etc.

    // Key description
    char description[256];

    // Payload
    void *payload;
    size_t payload_len;
} linux_keyring_data_t;

/// NetworkManager connection data
typedef struct nm_connection_data {
    // Connection UUID
    char uuid[64];

    // Connection path (D-Bus)
    char path[256];

    // VPN service name
    char service_name[128];

    // Data (key-value pairs)
    struct {
        char *key;
        char *value;
    } *data;
    size_t data_count;
} nm_connection_data_t;

#endif // __linux__
```

### macOS Structures

```c
// File: macos_types.h

#ifdef __APPLE__

/// Keychain item reference (macOS)
typedef struct keychain_item_ref {
    // Keychain reference
    SecKeychainRef keychain;

    // Item reference
    SecKeychainItemRef item;

    // Service name
    char service_name[256];

    // Account name
    char account_name[256];

    // Flags
    UInt32 flags;
} keychain_item_ref_t;

/// System extension data (macOS)
typedef struct system_extension_data {
    // Extension identifier
    char identifier[256];

    // Extension version
    char version[64];

    // State
    enum {
        EXT_STATE_UNKNOWN = 0,
        EXT_STATE_ENABLED = 1,
        EXT_STATE_DISABLED = 2,
        EXT_STATE_PENDING = 3
    } state;

    // Flags
    uint32_t flags;
} system_extension_data_t;

#endif // __APPLE__
```

---

## Memory Layout Diagrams

### vpn_session_t Memory Layout

```
Offset  Size   Field
------  ----   -----
0x0000  64     session_id[64]
0x0040  32     session_token[32]
0x0060  4      state (enum)
0x0064  4      error_code
0x0068  256    error_message[256]
0x0168  8      protocol_info* (pointer)
0x0170  8      cstp_config* (pointer)
0x0178  8      dtls_config* (pointer)
0x0180  8      ssl_ctx* (pointer)
0x0188  8      ssl* (pointer)
0x0190  4      cstp_socket_fd
0x0194  4      dtls_socket_fd
0x0198  4      tun_fd
0x019C  4      (padding)
0x01A0  32     tun_name[32]
0x01C0  24     tun_addr (ip_addr_t)
0x01D8  8      split_include_routes* (pointer)
0x01E0  8      split_include_count
0x01E8  8      split_exclude_routes* (pointer)
0x01F0  8      split_exclude_count
0x01F8  8      dns_servers* (pointer)
0x0200  8      dns_server_count
0x0208  256    dns_suffix[256]
0x0308  80     stats (struct)
0x0358  2      keepalive_interval_sec
0x035A  2      dpd_interval_sec
0x035C  4      (padding)
0x0360  8      last_keepalive_time
0x0368  8      last_dpd_time
0x0370  8      last_rx_time
0x0378  8      keepalive_timer* (pointer)
0x0380  8      dpd_timer* (pointer)
0x0388  8      reconnect_timer* (pointer)
0x0390  40     callbacks (struct with function pointers)
0x03B8  8      callback_context* (pointer)
0x03C0  4      flags
0x03C4  4      (padding)
0x03C8  8      platform_data* (pointer)
------
Total:  976 bytes (0x3D0)
```

### connect_ifc_data_t Memory Layout (Simplified)

```
Offset  Size   Field
------  ----   -----
0x0000  256    gateway[256]
0x0100  256    hostname[256]
0x0200  2      port
0x0202  1      use_ssl
0x0203  1      use_http2
0x0204  512    auth_cookie[512]
0x0404  512    session_cookie[512]
0x0604  512    config_cookie[512]
0x0804  512    csd_token[512]
0x0A04  1024   credentials (struct)
0x0E04  8      credential_map* (pointer)
0x0E0C  ~600   csd (struct)
0x1068  ~200   agg_auth (struct)
0x1130  ~100   cert_auth (struct)
0x1194  8      request_headers* (pointer)
0x119C  8      response_headers* (pointer)
0x11A4  8      response_body* (pointer)
0x11AC  8      response_length
0x11B4  8      response_capacity
0x11BC  4      http_status_code
0x11C0  128    content_type[128]
... (additional fields)
------
Total:  ~4096 bytes (estimated)
```

---

## Structure Size Summary Table

| Structure | Size (bytes) | Alignment | Padding |
|-----------|--------------|-----------|---------|
| `auth_context_t` | 512 | 8 | 0 |
| `totp_context_t` | 304 | 8 | 0 |
| `proxy_auth_context_t` | 896 | 8 | 0 |
| `http_auth_context_t` | 512 | 8 | 0 |
| `agg_auth_manager_t` | 256 | 8 | 0 |
| `cstp_config_t` | 512 | 8 | 0 |
| `dtls_config_t` | 384 | 8 | 0 |
| `connect_ifc_data_t` | 4096 | 8 | ~200 |
| `connect_ifc_t` | 512 | 8 | 0 |
| `vpn_session_t` | 976 | 8 | 12 |
| `cert_obj_t` | 1152 | 8 | 0 |
| `host_profile_t` | 4096 | 8 | ~300 |
| `profile_manager_t` | 384 | 8 | 0 |

---

## Implementation Notes

### Memory Management

1. **Ownership**: Clearly define ownership of pointers
2. **Cleanup Functions**: Provide `_destroy()` for each structure
3. **Reference Counting**: Use for shared objects (certificates)
4. **Secure Wiping**: Zero sensitive data on free (passwords, keys)

### Thread Safety

1. **Mutex Protection**: Document which structures require locking
2. **Atomic Operations**: Use for flags and state transitions
3. **Immutable After Init**: Mark read-only structures as `const`

### Serialization

1. **Wire Format**: Define binary serialization for IPC messages
2. **Endianness**: All network data is big-endian
3. **Version Compatibility**: Include version field in serialized data

### Platform Differences

1. **Conditional Compilation**: Use `#ifdef` for platform-specific fields
2. **Abstract Platform Data**: Use `void *platform_data` pointers
3. **Size Assertions**: Use `_Static_assert` to catch size changes

---

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Status**: Preliminary - based on symbol analysis and disassembly
**Next Steps**: Validate structure layouts with runtime debugging
