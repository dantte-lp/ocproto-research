# DNS Resolution and Split DNS - Implementation Guide

**Analysis Date:** 2025-10-29
**Purpose:** Complete DNS resolution logic for ocserv (C23)

## Split DNS Decision Algorithm

### Three DNS Modes

1. **Split DNS** (AnyConnect 3.0+): Domain-based routing
   - Matching domains → tunnel DNS
   - Non-matching domains → local DNS or blocked

2. **Tunnel-All-DNS**: All DNS → tunnel DNS servers only

3. **Standard DNS**: All DNS → tunnel DNS servers (legacy)

### True Split DNS Logic (CSCtn14578)

```
For each DNS query:
  IF domain matches split-DNS list:
    Route to tunnel DNS servers
  ELSE:
    Route to local DNS servers (or refuse if tunnel-all)
```

## Platform-Specific Implementations

### Windows (7+)

**NRPT (Name Resolution Policy Table)**:
- Windows 8+ uses NRPT for split DNS
- Registers domains with NRPT API
- DNS client automatically routes based on NRPT rules

```c
// C23: NRPT rule registration
#include <netlistmgr.h>

typedef struct {
    wchar_t domain[256];     // Domain to match (e.g., L".example.com")
    wchar_t dns_server[64];  // DNS server IP
    uint32_t priority;       // Rule priority
} nrpt_rule_t;

int windows_register_nrpt_rule(const nrpt_rule_t *rule) {
    // Use SetInterfaceDnsSettings() or PowerShell:
    // Add-DnsClientNrptRule -Namespace ".example.com" -NameServers "10.0.0.1"
    return 0;
}
```

**Pre-Windows 8** (Windows 7):
- Driver responds with "no such name" (NXDOMAIN) to prevent leaks
- Forces application to retry with tunnel DNS

### macOS

**Global DNS Settings**:
- Does NOT modify /etc/resolv.conf
- Uses SCDynamicStore API (System Configuration framework)
- View with: `scutil --dns`

```bash
# macOS DNS configuration
sudo scutil
> d.init
> d.add ServerAddresses * 10.0.0.1 10.0.0.2
> d.add SearchDomains * example.com corp.local
> d.add DomainName example.com
> set State:/Network/Service/VPN/DNS
> quit
```

**Split DNS Requirement**:
- Requires dual-protocol support (IPv4+IPv6) OR
- Protocol bypass for non-split protocol

**Limitation**:
- ".local" domains not supported on iPhone

### Linux

**Method 1: /etc/resolv.conf manipulation**:
```bash
# Backup original
cp /etc/resolv.conf /etc/resolv.conf.backup

# Modify for split DNS
nameserver 10.0.0.1  # Tunnel DNS (preferred)
nameserver 8.8.8.8   # Public DNS (fallback)
search example.com corp.local
```

**Method 2: NetworkManager integration**:
```bash
# Use nmcli to configure DNS
nmcli connection modify vpn ipv4.dns "10.0.0.1"
nmcli connection modify vpn ipv4.dns-search "example.com"
nmcli connection modify vpn ipv4.ignore-auto-dns yes
```

**Split DNS Implementation**:
- Tunnel DNS servers configured as preferred
- DNS fallback: Client replies with "refused" to force public DNS

## C23 Implementation

```c
// ocserv-modern/src/dns/split_dns.c

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
    char domain[256];         // Domain to match
    bool is_suffix;           // Match as suffix (.example.com)
    uint32_t priority;        // Match priority
} split_dns_domain_t;

typedef struct {
    split_dns_domain_t *domains;
    size_t count;
    char tunnel_dns[4][64];   // Up to 4 tunnel DNS servers
    size_t tunnel_dns_count;
    bool tunnel_all;          // Tunnel all DNS (no split)
} split_dns_config_t;

// Match domain against split DNS list
[[nodiscard]] static bool domain_matches_split_dns(
    const char *query_domain,
    const split_dns_config_t *config
) {
    if (query_domain == nullptr || config == nullptr) {
        return false;
    }

    for (size_t i = 0; i < config->count; i++) {
        const split_dns_domain_t *rule = &config->domains[i];

        if (rule->is_suffix) {
            // Suffix match: query.example.com matches .example.com
            size_t query_len = strlen(query_domain);
            size_t rule_len = strlen(rule->domain);

            if (query_len >= rule_len) {
                const char *suffix = query_domain + (query_len - rule_len);
                if (strcasecmp(suffix, rule->domain) == 0) {
                    return true;
                }
            }
        } else {
            // Exact match
            if (strcasecmp(query_domain, rule->domain) == 0) {
                return true;
            }
        }
    }

    return false;
}

// Determine if DNS query should go through tunnel
[[nodiscard]] bool dns_should_tunnel(
    const char *query_domain,
    const split_dns_config_t *config
) {
    if (config == nullptr || query_domain == nullptr) {
        return false;
    }

    // Tunnel-all mode: everything goes through tunnel
    if (config->tunnel_all) {
        return true;
    }

    // Split DNS: check domain list
    return domain_matches_split_dns(query_domain, config);
}

// DNS interception handler
int dns_intercept_query(
    struct worker_st *ws,
    const uint8_t *dns_packet,
    size_t packet_len,
    bool *should_tunnel
) {
    // Parse DNS query to extract domain name
    char query_domain[256] = {0};
    if (parse_dns_query(dns_packet, packet_len, query_domain, sizeof(query_domain)) < 0) {
        return -EINVAL;
    }

    // Check split DNS configuration
    *should_tunnel = dns_should_tunnel(query_domain, ws->split_dns_config);

    if (*should_tunnel) {
        mslog(ws, nullptr, LOG_DEBUG,
              "DNS query for '%s' routed to tunnel DNS", query_domain);
    } else {
        mslog(ws, nullptr, LOG_DEBUG,
              "DNS query for '%s' routed to local DNS", query_domain);
    }

    return 0;
}
```

## DNS Leak Prevention

**Method 1: Intercept at driver level** (Windows/macOS):
- Capture DNS packets before routing decision
- Route based on split DNS rules
- Respond with NXDOMAIN if leak detected

**Method 2: Firewall rules** (Linux):
```bash
# Block all DNS except through tunnel
iptables -A OUTPUT -p udp --dport 53 -o eth0 -j DROP
iptables -A OUTPUT -p tcp --dport 53 -o eth0 -j DROP
# Allow DNS through tunnel interface
iptables -A OUTPUT -p udp --dport 53 -o tun0 -j ACCEPT
```

**Method 3: NRPT** (Windows 8+):
- Register split DNS domains with NRPT
- Windows DNS client automatically routes correctly
- No manual interception needed

## Troubleshooting

**Issue**: DNS leaks to public DNS servers

**Solution**:
- Verify split DNS configuration
- Check firewall rules (Linux)
- Verify NRPT rules (Windows): `Get-DnsClientNrptRule`
- Check DNS settings (macOS): `scutil --dns`

**Issue**: Internal domains not resolving

**Solution**:
- Verify domain in split DNS list
- Check tunnel DNS server reachability
- Test with: `nslookup internal.example.com <tunnel-dns-ip>`

---

**End of Document**
