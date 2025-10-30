# Optimal Gateway Selection (OGS) - Implementation Guide

**Analysis Date:** 2025-10-29
**Purpose:** Complete OGS algorithm for ocserv (C23)

## OGS Algorithm

**Selection Criteria**: Lowest Round Trip Time (RTT)

**Probe Mechanism**: HTTP/443 requests (not ICMP pings)

**Measurement**: TCP SYN to FIN/ACK delay

```
Client sends 3 HTTP/443 requests per gateway
Measures: SYN → FIN/ACK interval for each probe
Selects: Gateway with lowest RTT among 3 probes
```

## Probe Implementation

```c
// ocserv-modern/src/gateway/ogs.c

#include <time.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#define OGS_PROBES_PER_GATEWAY  3
#define OGS_TIMEOUT_SEC         7
#define OGS_CACHE_VALIDITY_DAYS 14

typedef struct {
    char fqdn[256];           // Gateway FQDN
    char ip[64];              // Gateway IP
    uint32_t rtt_ms[3];       // RTT for 3 probes
    uint32_t best_rtt_ms;     // Lowest RTT
    time_t last_probed;       // Last probe timestamp
} gateway_probe_result_t;

// C23: Probe single gateway
[[nodiscard]] int ogs_probe_gateway(
    const char *gateway_fqdn,
    uint16_t port,
    gateway_probe_result_t *result
) {
    if (gateway_fqdn == nullptr || result == nullptr) {
        return -EINVAL;
    }

    strncpy(result->fqdn, gateway_fqdn, sizeof(result->fqdn) - 1);
    result->best_rtt_ms = UINT32_MAX;

    for (int i = 0; i < OGS_PROBES_PER_GATEWAY; i++) {
        struct timespec start, end;
        int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (sock < 0) {
            continue;
        }

        // Start timer
        clock_gettime(CLOCK_MONOTONIC, &start);

        // Connect (non-blocking)
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, result->ip, &addr.sin_addr);

        connect(sock, (struct sockaddr *)&addr, sizeof(addr));

        // Wait for connection or timeout
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval timeout = {.tv_sec = OGS_TIMEOUT_SEC, .tv_usec = 0};

        int ret = select(sock + 1, nullptr, &wfds, nullptr, &timeout);
        if (ret > 0) {
            // Connection established, measure time
            clock_gettime(CLOCK_MONOTONIC, &end);

            uint64_t elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000ULL +
                                  (end.tv_nsec - start.tv_nsec);
            result->rtt_ms[i] = elapsed_ns / 1000000;  // Convert to ms

            if (result->rtt_ms[i] < result->best_rtt_ms) {
                result->best_rtt_ms = result->rtt_ms[i];
            }
        } else {
            result->rtt_ms[i] = UINT32_MAX;  // Timeout or error
        }

        close(sock);
        usleep(100000);  // 100ms between probes
    }

    result->last_probed = time(nullptr);
    return 0;
}

// Select optimal gateway from results
[[nodiscard]] const gateway_probe_result_t *ogs_select_optimal(
    gateway_probe_result_t *results,
    size_t count
) {
    const gateway_probe_result_t *best = nullptr;
    uint32_t best_rtt = UINT32_MAX;

    for (size_t i = 0; i < count; i++) {
        if (results[i].best_rtt_ms < best_rtt) {
            best_rtt = results[i].best_rtt_ms;
            best = &results[i];
        }
    }

    return best;
}
```

## Caching

**Cache Location**: `preferences_global.xml`

**Cache Format**:
```xml
<OGSCache>
  <Location dns="example.com" ip="192.168.1.1">
    <Gateway fqdn="vpn1.example.com" rtt="45" timestamp="1730217600"/>
    <Gateway fqdn="vpn2.example.com" rtt="120" timestamp="1730217600"/>
  </Location>
</OGSCache>
```

**Cache Key**: `DNS_domain|server_ip`

**Cache Validity**: 14 days

**Re-evaluation Triggers**:
- 14 days elapsed
- Reconnection after 4+ hours disconnect
- Location change detected

## Failover Logic

```
1. Attempt optimal server (lowest RTT)
2. If fails, try that server's backup list
3. If fails, try remaining OGS servers by ranking
4. If all fail, manual gateway selection required
```

---

**End of Document**
