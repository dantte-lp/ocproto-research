# RADIUS Integration - Complete Implementation Guide

**Analysis Date:** 2025-10-29
**Purpose:** RADIUS authentication and static IP assignment for ocserv (C23)

## RADIUS Attributes for IP Assignment

### Standard Attributes

| Attribute | Number | Type | Purpose |
|-----------|--------|------|---------|
| **Framed-IP-Address** | 8 | IPv4 | Assign static IPv4 to client |
| **Framed-IP-Netmask** | 9 | IPv4 | Netmask for assigned IP |
| **Framed-IPv6-Address** | 168 | IPv6 | Assign static IPv6 (RFC 6911) |
| **Framed-IPv6-Prefix** | 97 | IPv6 | IPv6 prefix delegation |

### Cisco VSAs

| VSA | Attribute ID | Purpose |
|-----|--------------|---------|
| **profile-name** | 26:9:1 | Group policy profile name |
| **Class** | 25 | Session identifier from ISE |

## Assignment Flow

```
1. Client → FTD: SSL handshake + credentials
2. FTD → RADIUS: Access-Request with username/password
3. RADIUS → FTD: Access-Accept with attribute 8 (Framed-IP-Address)
4. FTD: Extract IP from attribute 8
5. FTD → Client: Assign IP during IPAA (IP Address Assignment)
6. Client: Configure virtual adapter with assigned IP
```

## C23 Implementation

```c
// ocserv-modern/src/auth/radius.c

#include <freeradius-client.h>

#define RADIUS_FRAMED_IP_ADDRESS    8
#define RADIUS_FRAMED_IP_NETMASK    9
#define RADIUS_CLASS                25
#define RADIUS_VENDOR_CISCO         9

typedef struct {
    char server[256];        // RADIUS server IP/FQDN
    uint16_t auth_port;      // Auth port (default 1812)
    uint16_t acct_port;      // Accounting port (default 1813)
    char secret[64];         // Shared secret
} radius_config_t;

// C23: Authenticate user and get static IP
[[nodiscard]] int radius_authenticate_and_assign_ip(
    radius_config_t *config,
    const char *username,
    const char *password,
    uint32_t *assigned_ip,
    uint32_t *netmask
) {
    if (config == nullptr || username == nullptr || password == nullptr) {
        return -EINVAL;
    }

    rc_handle *rh = rc_read_config(nullptr);
    if (rh == nullptr) {
        return -ENOMEM;
    }

    // Build RADIUS request
    VALUE_PAIR *send = nullptr;
    rc_avpair_add(rh, &send, PW_USER_NAME, username, -1, 0);
    rc_avpair_add(rh, &send, PW_USER_PASSWORD, password, -1, 0);
    rc_avpair_add(rh, &send, PW_NAS_IDENTIFIER, "ocserv", -1, 0);
    rc_avpair_add(rh, &send, PW_NAS_PORT_TYPE, &(uint32_t){5}, -1, 0);  // Virtual

    // Send authentication request
    VALUE_PAIR *received = nullptr;
    int result = rc_auth(rh, 0, send, &received, nullptr);

    if (result == OK_RC) {
        // Extract Framed-IP-Address (attribute 8)
        VALUE_PAIR *vp = rc_avpair_get(received, RADIUS_FRAMED_IP_ADDRESS, 0);
        if (vp != nullptr && assigned_ip != nullptr) {
            *assigned_ip = ntohl(vp->lvalue);
        }

        // Extract Framed-IP-Netmask (attribute 9)
        vp = rc_avpair_get(received, RADIUS_FRAMED_IP_NETMASK, 0);
        if (vp != nullptr && netmask != nullptr) {
            *netmask = ntohl(vp->lvalue);
        }
    }

    // Cleanup
    rc_avpair_free(send);
    rc_avpair_free(received);
    rc_destroy(rh);

    return (result == OK_RC) ? 0 : -EACCES;
}
```

## Attribute Priority

**Priority Order**:
1. RADIUS Framed-IP-Address (highest priority)
2. Local IP pool on ASA/FTD

**Conflict Prevention**:
- Use **different IP ranges** for RADIUS assignments vs local pool
- Example: RADIUS assigns 10.0.50.100-200, local pool 10.0.50.1-99

## FreeRADIUS Server Configuration

```
# /etc/freeradius/users
user1   Cleartext-Password := "password1"
        Framed-IP-Address = 10.0.50.101,
        Framed-IP-Netmask = 255.255.255.0

user2   Cleartext-Password := "password2"
        Framed-IP-Address = 10.0.50.102,
        Framed-IP-Netmask = 255.255.255.0
```

---

**End of Document**
