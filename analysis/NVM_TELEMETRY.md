# Cisco Secure Client - Network Visibility Module (NVM) Telemetry Analysis

**Document Version:** 1.0
**Analysis Date:** 2025-10-29
**Cisco Secure Client Version Analyzed:** 5.1.2.42
**Component:** Network Visibility Module (NVM)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Protocol Specification](#3-protocol-specification)
4. [Flow Record Structure](#4-flow-record-structure)
5. [Integration Architecture](#5-integration-architecture)
6. [Data Collection Mechanisms](#6-data-collection-mechanisms)
7. [Configuration Schema](#7-configuration-schema)
8. [C23 Implementation Guide](#8-c23-implementation-guide)
9. [Example C23 Code](#9-example-c23-code)
10. [Testing & Validation](#10-testing--validation)
11. [Performance Considerations](#11-performance-considerations)
12. [Security Implementation](#12-security-implementation)

---

## 1. Executive Summary

### 1.1 What is NVM?

The **Network Visibility Module (NVM)** is Cisco's endpoint telemetry system that provides comprehensive network flow monitoring, application visibility, and security intelligence capabilities. NVM operates as a client-side agent that collects, processes, and exports network flow data to centralized collectors for analysis.

### 1.2 Key Capabilities

- **Network Flow Telemetry**: Capture TCP/UDP flows with source/destination IPs, ports, protocols, byte counts
- **Application Visibility**: Track process names, paths, command-line arguments, parent processes
- **User Context**: Associate network flows with logged-in users and account types
- **Interface Monitoring**: Detect network changes, interface states, VPN/trusted network status
- **DNS Resolution**: Capture hostname information for network destinations
- **Process Intelligence**: Track process hashes, integrity levels, WoW64 status on Windows
- **Compliance Monitoring**: Filter flows based on policy rules (block/allow lists)
- **Performance Metrics**: Measure bandwidth usage, connection durations, packet counts

### 1.3 Use Cases

1. **Security Monitoring**: Detect unauthorized applications, suspicious network connections, data exfiltration
2. **Compliance Enforcement**: Ensure only approved applications access network resources
3. **Bandwidth Management**: Identify high-bandwidth applications and optimize usage
4. **Incident Response**: Provide detailed forensic data for security investigations
5. **Application Discovery**: Map application dependencies and communication patterns
6. **User Behavior Analytics**: Correlate network activity with user identities

### 1.4 Deployment Models

- **On-Premise Collector**: IPFIX-based UDP export to customer-managed collector (default port 2055)
- **Cloud Collector**: gRPC-based HTTPS export to Cisco-managed cloud service
- **Hybrid Mode**: Support both on-prem and cloud simultaneously based on network conditions

---

## 2. Architecture Overview

### 2.1 Component Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                    Cisco Secure Client                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              VPN Agent (vpnagentd)                    │  │
│  │  ┌─────────────────────────────────────────────────┐ │  │
│  │  │         NVM Agent (acnvmagent)                  │ │  │
│  │  │                                                  │ │  │
│  │  │  ┌──────────────────────────────────────────┐   │ │  │
│  │  │  │    User-Space Flow Collector             │   │ │  │
│  │  │  │  - Process tracking                      │   │ │  │
│  │  │  │  - Flow aggregation                      │   │ │  │
│  │  │  │  - DNS cache                             │   │ │  │
│  │  │  │  - Policy enforcement                    │   │ │  │
│  │  │  └──────────────────────────────────────────┘   │ │  │
│  │  │                      ↕                           │ │  │
│  │  │           Netlink Socket (AF_NETLINK)           │ │  │
│  │  │                      ↕                           │ │  │
│  │  │  ┌──────────────────────────────────────────┐   │ │  │
│  │  │  │    Kernel Driver (anyconnect_kdf.ko)     │   │ │  │
│  │  │  │  - Netfilter hooks                       │   │ │  │
│  │  │  │  - TCP/UDP packet inspection             │   │ │  │
│  │  │  │  - Per-process socket tracking           │   │ │  │
│  │  │  │  - Flow state machines                   │   │ │  │
│  │  │  └──────────────────────────────────────────┘   │ │  │
│  │  └─────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            ↓
        ┌───────────────────┴────────────────────┐
        │                                         │
   ┌────▼──────┐                          ┌──────▼──────┐
   │  On-Prem  │                          │    Cloud    │
   │ Collector │                          │  Collector  │
   │  (IPFIX)  │                          │   (gRPC)    │
   │ UDP:2055  │                          │ HTTPS:443   │
   └───────────┘                          └─────────────┘
```

### 2.2 Binary Components

| Component | Binary Name | Description | Platform |
|-----------|-------------|-------------|----------|
| NVM Agent | `acnvmagent` | User-space telemetry agent | Linux/Windows/macOS |
| Kernel Driver | `anyconnect_kdf.ko` (Linux)<br>`anyconnect_kdf.sys` (Windows) | Kernel packet inspector | Linux/Windows |
| Control Plugin | `libacnvmctrl.so` | VPN agent integration plugin | Linux/macOS |
| Socket Filter API | `libsock_fltr_api.so` | Kernel↔User communication library | Linux |

### 2.3 Data Flow

```
1. Kernel Driver (anyconnect_kdf.ko)
   ├─ Netfilter hook captures TCP/UDP packets
   ├─ Extracts L3 (IP) and L4 (TCP/UDP) headers
   ├─ Associates packets with PIDs via /proc filesystem
   └─ Sends struct app_flow via netlink to user-space

2. User-Space Agent (acnvmagent)
   ├─ Receives flow data from kernel via netlink socket
   ├─ Enriches with process metadata (name, path, hash, parent)
   ├─ Enriches with user context (username, account type)
   ├─ Enriches with DNS resolution (destination hostname)
   ├─ Applies policy filters (drop unauthorized flows)
   ├─ Aggregates flows (start/periodic/end reports)
   ├─ Serializes to IPFIX format (on-prem) or Protobuf (cloud)
   └─ Exports to collector

3. Collector
   ├─ On-Prem: Receives IPFIX via UDP:2055 (DTLS optional)
   ├─ Cloud: Receives Protobuf via gRPC/HTTPS:443
   ├─ Stores in database (time-series optimized)
   └─ Provides analytics/visualization APIs
```

### 2.4 Threading Model

The NVM agent uses a multi-threaded architecture:

```c
// Main thread: Profile management, network state detection
main_thread() {
    - Monitor VPN connection state
    - Detect trusted/untrusted network transitions
    - Load/reload XML profiles
    - Coordinate shutdown
}

// Exporter thread: Send data to collector
exporter_thread() {
    - Maintain UDP/DTLS socket to collector (on-prem)
    - Maintain gRPC channel to cloud (cloud mode)
    - Send IPFIX templates every 1440 minutes (default)
    - Send flow/interface records as queued
    - Handle network errors and retries
}

// KDF thread: Receive flows from kernel
kdf_thread() {
    - Read netlink socket (blocking)
    - Parse struct app_flow messages
    - Enrich with process metadata
    - Queue for processing
}

// Processor threads (ACKDF*): Aggregate and serialize
processor_thread() {
    - Dequeue raw flow data
    - Aggregate flows by 5-tuple
    - Apply flow report interval logic
    - Serialize to IPFIX/Protobuf
    - Cache to SQLite if collector unreachable
}
```

---

## 3. Protocol Specification

### 3.1 On-Premise Mode: IPFIX over UDP/DTLS

Cisco NVM implements the **nvzFlow** protocol, based on IETF RFC 7011 (IPFIX).

#### 3.1.1 Transport Layer

- **Protocol**: UDP (unsecured) or DTLS 1.2+ (secured)
- **Default Port**: 2055/UDP
- **Packet Size**: Variable, typically 1024-1400 bytes (MTU-constrained)
- **Reliability**: Best-effort (UDP), no acknowledgments at transport layer

#### 3.1.2 Security Modes

| Mode | Description | Authentication | Encryption |
|------|-------------|----------------|------------|
| **Unsecured** | Plain UDP | None | None |
| **DTLS** | Server authentication | Server certificate validated by client | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 |
| **mDTLS** | Mutual authentication | Client + Server certificates | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 |

**Certificate Requirements:**
- Format: PEM (Base64-encoded X.509)
- Key Size: RSA 2048+ or ECDSA P-256+
- Password-protected keys: **Not supported**
- Validation: Standard X.509 chain of trust

#### 3.1.3 IPFIX Packet Structure

```
┌────────────────────────────────────────────────┐
│         IPFIX Message Header (16 bytes)        │
├────────────────────────────────────────────────┤
│  Version Number (uint16)        │ 0x000A (10) │
│  Length (uint16)                │ Total bytes │
│  Export Time (uint32)           │ Unix epoch  │
│  Sequence Number (uint32)       │ Incremental │
│  Observation Domain ID (uint32) │ 0x00000000  │
├────────────────────────────────────────────────┤
│             Set 1 (Template Set)               │
│  Set ID (uint16)    = 0x0002 (Template)       │
│  Set Length (uint16)                           │
│  ┌──────────────────────────────────────────┐  │
│  │ Template Record                          │  │
│  │  Template ID (uint16) = 256-65535       │  │
│  │  Field Count (uint16)                   │  │
│  │  ┌────────────────────────────────────┐ │  │
│  │  │ Field Specifier 1                  │ │  │
│  │  │  Information Element ID (uint16)   │ │  │
│  │  │  Field Length (uint16)             │ │  │
│  │  │  [Enterprise Number (uint32)]      │ │  │
│  │  └────────────────────────────────────┘ │  │
│  │  ... (repeat for each field)            │  │
│  └──────────────────────────────────────────┘  │
├────────────────────────────────────────────────┤
│             Set 2 (Data Set)                   │
│  Set ID (uint16)    = Template ID             │
│  Set Length (uint16)                           │
│  ┌──────────────────────────────────────────┐  │
│  │ Data Record 1                            │  │
│  │  Field 1 Value                           │  │
│  │  Field 2 Value                           │  │
│  │  ...                                     │  │
│  └──────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────┐  │
│  │ Data Record 2                            │  │
│  │  ...                                     │  │
│  └──────────────────────────────────────────┘  │
└────────────────────────────────────────────────┘
```

#### 3.1.4 Template Transmission

- **Frequency**: Every 1440 minutes (24 hours) by default (configurable)
- **Trigger**: Session initialization, profile change, collector restart
- **Templates**: 6 types (Endpoint Identity, Interface Info, Flow IPv4, Flow IPv6, Process Info, OSquery Data)

### 3.2 Cloud Mode: gRPC over HTTPS

For cloud deployments, NVM uses **Protocol Buffers** over gRPC (HTTP/2).

#### 3.2.1 Transport Layer

- **Protocol**: gRPC (HTTP/2 over TLS 1.2+)
- **Port**: 443/TCP (standard HTTPS)
- **Compression**: gzip (automatic)
- **Authentication**: Bearer token or mTLS

#### 3.2.2 gRPC Service Definition

```protobuf
syntax = "proto3";
package nvmgrpc;

service NVMCloudService {
  // Health check / keep-alive
  rpc Ping(NVMPingRequest) returns (NVMPingResponse);

  // Submit endpoint identity (once per agent start)
  rpc PostEndpointInfo(NVMEndpointInfoRequest) returns (NVMResponse);

  // Submit network interface changes
  rpc PostInterfaceInfo(NVMInterfaceInfoRequestList) returns (NVMResponse);

  // Submit network flow records (batched)
  rpc PostNetworkFlowInfo(NVMFlowInfoRequestList) returns (NVMResponse);
}

message NVMFlowInfoRequest {
  // Flow identifiers
  uint32 flow_id = 1;
  uint64 flow_start_millisecond = 2;
  uint64 flow_end_millisecond = 3;

  // Network 5-tuple
  string source_ip = 4;          // IPv4 or IPv6
  uint32 source_port = 5;
  string destination_ip = 6;
  uint32 destination_port = 7;
  uint32 protocol = 8;           // IPPROTO_TCP=6, IPPROTO_UDP=17

  // Traffic counters
  uint64 bytes_sent = 9;
  uint64 bytes_received = 10;
  uint64 packets_sent = 11;
  uint64 packets_received = 12;

  // Process information
  uint32 process_id = 13;
  string process_name = 14;
  string process_path = 15;
  string process_args = 16;
  string process_account = 17;    // username
  string process_hash = 18;       // SHA256

  // Parent process
  uint32 parent_process_id = 19;
  string parent_process_name = 20;
  string parent_process_path = 21;
  string parent_process_args = 22;
  string parent_process_account = 23;

  // Network context
  string destination_hostname = 24;
  string dns_suffix = 25;
  string http_host = 26;
  repeated string module_name_list = 27;

  // User context
  string loggedin_user = 28;
  repeated string additional_loggedin_user = 29;

  // Flow metadata
  uint32 flow_direction = 30;    // 0=unknown, 1=inbound, 2=outbound
  uint32 flow_report_stage = 31; // 0=end, 1=start, 2=periodic
}

message NVMResponse {
  int32 status_code = 1;
  string message = 2;
}
```

#### 3.2.3 Batching Strategy

- **Batch Size**: 50-100 flows per gRPC call (configurable)
- **Time Window**: 60 seconds maximum (flush if batch incomplete)
- **Backpressure**: SQLite cache if cloud unreachable, up to 10K records
- **Retry Logic**: Exponential backoff (1s, 2s, 4s, 8s, max 60s)

### 3.3 Trusted Network Detection (TND) Integration

NVM respects Cisco's **Trusted Network Detection** state:

- **Trusted Network**: Disable telemetry OR send to on-prem collector only
- **Untrusted Network**: Enable full telemetry to cloud collector
- **Transition Handling**: Stop flows, flush cache, re-initialize exporter

---

## 4. Flow Record Structure

### 4.1 Kernel Data Structure (app_flow)

```c
// From: kdf/lkm/src/nvm_user_kernel_types.h

#define APPFLOW_FILE_NAME_LEN  260
#define APPFLOW_FILE_PATH_LEN  2048

struct app_flow {
    struct nvm_message_header header;  // length, version, type

    // Network 5-tuple
    struct ac_sockaddr_inet local;     // Local IP:port (sockaddr_in/in6)
    struct ac_sockaddr_inet peer;      // Peer IP:port
    int family;                         // AF_INET or AF_INET6
    int proto;                          // IPPROTO_TCP=6, IPPROTO_UDP=17

    // Traffic counters
    uint64_t in_bytes;                  // Bytes received
    uint64_t out_bytes;                 // Bytes sent

    // Process context
    uint32_t pid;                       // Process ID
    uint32_t parent_pid;                // Parent process ID

    // Timestamps (Unix epoch)
    uint32_t start_time;                // Socket creation time
    uint32_t end_time;                  // Socket close time

    // Process information
    uint16_t file_name_len;
    uint16_t file_path_len;
    char file_name[APPFLOW_FILE_NAME_LEN];   // e.g., "firefox"
    char file_path[APPFLOW_FILE_PATH_LEN];   // e.g., "/usr/bin/firefox"

    // Parent process information
    uint16_t parent_file_name_len;
    uint16_t parent_file_path_len;
    char parent_file_name[APPFLOW_FILE_NAME_LEN];
    char parent_file_path[APPFLOW_FILE_PATH_LEN];

    // Flow metadata
    uint8_t direction;                  // 0=unknown, 1=inbound, 2=outbound
    enum flow_report_stage stage;      // START, PERIODIC, END
};

enum flow_report_stage {
    e_FLOW_REPORT_STAGE_END = 0,       // Final report (socket closed)
    e_FLOW_REPORT_STAGE_START = 1,     // Initial report (connection established)
    e_FLOW_REPORT_STAGE_PERIODIC = 2   // Intermediate report (timer-based)
};
```

### 4.2 IPFIX Information Elements

Cisco uses a mix of **IETF standard** and **Cisco enterprise** Information Elements (IEs):

#### 4.2.1 Standard IPFIX IEs (PEN=0)

| IE ID | Name | Type | Length | Description |
|-------|------|------|--------|-------------|
| 1 | octetDeltaCount | unsigned64 | 8 | Bytes transferred |
| 2 | packetDeltaCount | unsigned64 | 8 | Packets transferred |
| 4 | protocolIdentifier | unsigned8 | 1 | IP protocol (6=TCP, 17=UDP) |
| 7 | sourceTransportPort | unsigned16 | 2 | Source TCP/UDP port |
| 8 | sourceIPv4Address | ipv4Address | 4 | Source IPv4 address |
| 11 | destinationTransportPort | unsigned16 | 2 | Destination TCP/UDP port |
| 12 | destinationIPv4Address | ipv4Address | 4 | Destination IPv4 address |
| 27 | sourceIPv6Address | ipv6Address | 16 | Source IPv6 address |
| 28 | destinationIPv6Address | ipv6Address | 16 | Destination IPv6 address |
| 136 | flowEndReason | unsigned8 | 1 | 1=idle timeout, 2=active timeout, 3=end of flow |
| 150 | flowStartSeconds | dateTimeSeconds | 4 | Flow start (Unix epoch) |
| 151 | flowEndSeconds | dateTimeSeconds | 4 | Flow end (Unix epoch) |
| 152 | flowStartMilliseconds | dateTimeMilliseconds | 8 | Flow start (high precision) |
| 153 | flowEndMilliseconds | dateTimeMilliseconds | 8 | Flow end (high precision) |
| 176 | flowDirection | unsigned8 | 1 | 0=ingress, 1=egress |

#### 4.2.2 Cisco Enterprise IEs (PEN=9)

| IE ID | Name | Type | Length | Description |
|-------|------|------|--------|-------------|
| 12232 | nvmProcessID | unsigned32 | 4 | Process ID (PID) |
| 12233 | nvmProcessName | string | variable | Process executable name |
| 12234 | nvmProcessPath | string | variable | Full path to executable |
| 12235 | nvmProcessHash | string | 64 | SHA256 hash of executable |
| 12236 | nvmProcessArgs | string | variable | Command-line arguments |
| 12237 | nvmProcessAccount | string | variable | Username running process |
| 12238 | nvmParentProcessID | unsigned32 | 4 | Parent PID |
| 12239 | nvmParentProcessName | string | variable | Parent process name |
| 12240 | nvmParentProcessPath | string | variable | Parent process path |
| 12241 | nvmDestinationHostname | string | variable | Resolved DNS name |
| 12242 | nvmInterfaceName | string | variable | Network interface (e.g., "eth0") |
| 12243 | nvmInterfaceType | unsigned8 | 1 | 0=unknown, 1=ethernet, 2=wifi, 3=vpn |
| 12244 | nvmLoggedInUser | string | variable | Currently logged-in user |
| 12245 | nvmEndpointUDID | string | variable | Unique Device ID |
| 12246 | nvmEndpointHostname | string | variable | Device hostname |
| 12247 | nvmEndpointOS | string | variable | OS name and version |

*Note: IE IDs are illustrative. Actual Cisco IDs obtained via template analysis.*

### 4.3 Flow Aggregation Logic

The NVM agent aggregates flows to reduce collector load:

```
Key: (src_ip, src_port, dst_ip, dst_port, protocol, pid)

Flow States:
1. NEW: SYN packet seen (TCP) or first UDP packet
   → Send START report immediately (if report_interval >= 0)

2. ESTABLISHED: SYN-ACK received (TCP) or 2+ UDP packets
   → Send PERIODIC report every report_interval seconds

3. FINISHED: FIN/RST packet (TCP) or timeout (UDP)
   → Send END report with final counters
   → Remove from tracking hash table
```

#### Flow Report Intervals

- **report_interval = -1**: Only send END report (minimal telemetry)
- **report_interval = 0**: Send START + END reports
- **report_interval > 0**: Send START + PERIODIC (every N seconds) + END

**Timeout Values:**
- TCP: 120 seconds of inactivity
- UDP: 120 seconds of inactivity
- Configurable via `SetFlowReportInterval` API

### 4.4 Example Flow Records

#### Example 1: HTTPS Connection (TCP)

```json
{
  "flow_id": 1234567,
  "flow_start_millisecond": 1730246400000,
  "flow_end_millisecond": 1730246420000,
  "source_ip": "192.168.1.100",
  "source_port": 54321,
  "destination_ip": "93.184.216.34",
  "destination_port": 443,
  "protocol": 6,
  "bytes_sent": 1024,
  "bytes_received": 8192,
  "packets_sent": 12,
  "packets_received": 18,
  "process_id": 5678,
  "process_name": "firefox",
  "process_path": "/usr/bin/firefox",
  "process_args": "-profile /home/user/.mozilla",
  "process_account": "user",
  "process_hash": "a3f7b8c9d1e2f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
  "parent_process_id": 1234,
  "parent_process_name": "bash",
  "destination_hostname": "example.com",
  "flow_direction": 2,
  "flow_report_stage": 0
}
```

#### Example 2: DNS Query (UDP)

```json
{
  "flow_id": 2345678,
  "flow_start_millisecond": 1730246400000,
  "flow_end_millisecond": 1730246400250,
  "source_ip": "192.168.1.100",
  "source_port": 48392,
  "destination_ip": "8.8.8.8",
  "destination_port": 53,
  "protocol": 17,
  "bytes_sent": 45,
  "bytes_received": 128,
  "packets_sent": 1,
  "packets_received": 1,
  "process_id": 5678,
  "process_name": "firefox",
  "flow_direction": 2,
  "flow_report_stage": 0
}
```

---

## 5. Integration Architecture

### 5.1 Kernel Module (anyconnect_kdf.ko)

The kernel driver hooks into the **Netfilter** framework to intercept packets:

```c
// Netfilter hook registration (from nvm_plugin.c)

static struct nf_hook_ops nf_hooks[] = {
    {
        .hook = nvm_netfilter_hook_v4,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,   // Outbound packets
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = nvm_netfilter_hook_v4,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,    // Inbound packets
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = nvm_netfilter_hook_v6,
        .pf = NFPROTO_IPV6,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = nvm_netfilter_hook_v6,
        .pf = NFPROTO_IPV6,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
    },
};

// Packet processing flow:
unsigned int nvm_netfilter_hook_v4(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct nwk_packet_info pkt_info;

    // 1. Extract IP header
    ip_header = ip_hdr(skb);

    // 2. Skip loopback traffic
    if (ip_header->saddr == htonl(INADDR_LOOPBACK) ||
        ip_header->daddr == htonl(INADDR_LOOPBACK)) {
        return NF_ACCEPT;
    }

    // 3. Parse L4 header (TCP/UDP only)
    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)((u8 *)ip_header + (ip_header->ihl * 4));
        pkt_info.l4.sport = tcp_header->source;
        pkt_info.l4.dport = tcp_header->dest;
        pkt_info.l4.flags = tcp_flags;
    } else if (ip_header->protocol == IPPROTO_UDP) {
        udp_header = (struct udphdr *)((u8 *)ip_header + (ip_header->ihl * 4));
        pkt_info.l4.sport = udp_header->source;
        pkt_info.l4.dport = udp_header->dest;
    } else {
        return NF_ACCEPT;  // Ignore non-TCP/UDP
    }

    // 4. Get process context (PID from socket)
    pkt_info.pid = get_pid_from_socket(skb->sk);
    pkt_info.start_time = get_unix_systime();

    // 5. Add to untracked queue (lock-protected)
    spin_lock(&g_nvm_plugin.spin_untrack_lock);
    list_insert_tail(g_nvm_plugin.untracked_pkt_list, &pkt_info);
    spin_unlock(&g_nvm_plugin.spin_untrack_lock);

    // 6. Schedule processor workqueue
    queue_work(processor_wq, &g_nvm_plugin.track_work);

    return NF_ACCEPT;  // Allow packet to continue
}
```

#### Hash Table Flow Tracking

```c
// TCP flow tracking (from nvm_plugin.h)
DECLARE_HASHTABLE(tcp_flows, TCP_HASH_BUCKET_SIZE_BITS);  // 32 buckets

struct TrackAppFlow {
    struct app_flow *flow;          // Flow data structure
    uint8_t sent_flags;             // TCP flags seen (outbound)
    uint8_t recv_flags;             // TCP flags seen (inbound)
    bool finished;                  // Ready for deletion
    bool connected;                 // TCP handshake complete
    uint32_t last_timestamp;        // Last packet time
    struct hlist_node hash_node;    // Hash table linkage
};

// Flow lookup/insert
static struct TrackAppFlow* find_flow(
    struct ac_addr *src_ip,
    uint16_t src_port,
    struct ac_addr *dst_ip,
    uint16_t dst_port,
    uint8_t protocol
) {
    uint32_t hash = jhash_3words(
        src_ip->ipv4.s_addr,
        dst_ip->ipv4.s_addr,
        (src_port << 16) | dst_port,
        protocol
    );

    struct TrackAppFlow *flow;
    hash_for_each_possible(tcp_flows, flow, hash_node, hash) {
        if (flow_matches(flow, src_ip, src_port, dst_ip, dst_port, protocol)) {
            return flow;
        }
    }
    return NULL;
}
```

### 5.2 Netlink Communication

The kernel and user-space communicate via **AF_NETLINK** sockets:

```c
// Kernel-side: Send flow to user-space
static void send_flow_to_userspace(struct app_flow *flow) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;

    skb = nlmsg_new(sizeof(struct app_flow), GFP_ATOMIC);
    if (!skb) return;

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, sizeof(struct app_flow), 0);
    memcpy(nlmsg_data(nlh), flow, sizeof(struct app_flow));

    nlmsg_unicast(nl_sock, skb, user_pid);
}

// User-space: Receive flow from kernel
int receive_flow_from_kernel(int netlink_fd, struct app_flow *flow) {
    struct sockaddr_nl src_addr;
    struct nlmsghdr *nlh;
    struct iovec iov;
    struct msghdr msg;
    char buffer[4096];

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = &src_addr;
    msg.msg_namelen = sizeof(src_addr);

    ssize_t len = recvmsg(netlink_fd, &msg, 0);
    if (len < 0) return -1;

    nlh = (struct nlmsghdr *)buffer;
    memcpy(flow, NLMSG_DATA(nlh), sizeof(struct app_flow));

    return 0;
}
```

### 5.3 Process Enrichment

The user-space agent enriches flows with process metadata:

```c
// Read process information from /proc
int enrich_flow_with_process_info(struct app_flow *flow) {
    char proc_path[256];
    char exe_path[APPFLOW_FILE_PATH_LEN];
    FILE *fp;

    // 1. Read executable path from /proc/<pid>/exe
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/exe", flow->pid);
    ssize_t len = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        strncpy(flow->file_path, exe_path, APPFLOW_FILE_PATH_LEN);

        // Extract basename
        char *basename = strrchr(exe_path, '/');
        if (basename) {
            strncpy(flow->file_name, basename + 1, APPFLOW_FILE_NAME_LEN);
        }
    }

    // 2. Read command-line arguments from /proc/<pid>/cmdline
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/cmdline", flow->pid);
    fp = fopen(proc_path, "r");
    if (fp) {
        // cmdline uses null separators, convert to spaces
        char cmdline[2048];
        size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
        for (size_t i = 0; i < n; i++) {
            if (cmdline[i] == '\0') cmdline[i] = ' ';
        }
        cmdline[n] = '\0';
        // Store in custom field (not in kernel struct)
        fclose(fp);
    }

    // 3. Get username from /proc/<pid>/status
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/status", flow->pid);
    fp = fopen(proc_path, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                uid_t uid;
                sscanf(line, "Uid:\t%u", &uid);
                struct passwd *pw = getpwuid(uid);
                if (pw) {
                    // Store username (in extended metadata)
                }
                break;
            }
        }
        fclose(fp);
    }

    // 4. Calculate SHA256 hash of executable
    unsigned char hash[32];
    if (sha256_file(flow->file_path, hash) == 0) {
        // Store as hex string
        for (int i = 0; i < 32; i++) {
            sprintf(&flow->process_hash[i*2], "%02x", hash[i]);
        }
    }

    return 0;
}
```

### 5.4 DNS Resolution Cache

NVM maintains a local DNS cache to associate IPs with hostnames:

```c
struct dns_cache_entry {
    struct in6_addr ip_address;
    char hostname[256];
    time_t timestamp;
    struct hlist_node hash_node;
};

// DNS query interception (from DNS plugin)
static void capture_dns_response(
    const struct dns_packet *pkt,
    const char *query_name,
    const struct in6_addr *resolved_ip
) {
    struct dns_cache_entry *entry = malloc(sizeof(*entry));
    entry->ip_address = *resolved_ip;
    strncpy(entry->hostname, query_name, sizeof(entry->hostname));
    entry->timestamp = time(NULL);

    // Insert into hash table
    uint32_t hash = hash_ipv6(resolved_ip);
    hash_add(dns_cache, &entry->hash_node, hash);
}

// Lookup hostname for flow
const char* lookup_hostname(const struct in6_addr *ip) {
    struct dns_cache_entry *entry;
    uint32_t hash = hash_ipv6(ip);

    hash_for_each_possible(dns_cache, entry, hash_node, hash) {
        if (memcmp(&entry->ip_address, ip, sizeof(*ip)) == 0) {
            // Check if entry is stale (older than 5 minutes)
            if (time(NULL) - entry->timestamp < 300) {
                return entry->hostname;
            }
        }
    }
    return NULL;
}
```

### 5.5 SQLite Caching

When the collector is unreachable, flows are cached to SQLite:

```sql
-- Database schema (from acnvmagent strings)
CREATE TABLE FLOW_DATA (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    TIMESTAMP INTEGER NOT NULL,
    INFO BLOB NOT NULL
);

CREATE TABLE INTERFACE_DATA (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    TIMESTAMP INTEGER NOT NULL,
    INFO BLOB NOT NULL
);

CREATE TABLE PROCESS_DATA (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    TIMESTAMP INTEGER NOT NULL,
    INFO BLOB NOT NULL
);

-- Cache management
-- Max records: 10,000 (configurable)
-- Max duration: 7 days (purge older)
-- On collector reconnect: Drain cache FIFO
```

---

## 6. Data Collection Mechanisms

### 6.1 Flow Collection Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Always On** | Collect flows continuously | Enterprise monitoring |
| **Trusted Network Only** | Collect only on corporate networks | Privacy-compliant telemetry |
| **Untrusted Network Only** | Collect only on public networks | Threat detection |
| **On-Demand** | Enable via API/profile push | Incident investigation |

### 6.2 Policy-Based Filtering

Flows can be filtered based on XML-defined rules:

```xml
<!-- Flow Filter Rules (from acnvmagent strings) -->
<FlowFilterRules>
  <Rule action="allow">
    <ProcessName>firefox</ProcessName>
    <DestinationPort>443</DestinationPort>
  </Rule>
  <Rule action="deny">
    <ProcessPath>/usr/bin/torrent-client</ProcessPath>
  </Rule>
  <Rule action="deny">
    <DestinationHostname>*.torrent</DestinationHostname>
  </Rule>
</FlowFilterRules>
```

**Logging:**
```
NVM-TRACE-FLOWS: Dropping flow with id: 12345, PID: 6789, process name - torrent-client,
as per policy because it contained - *.torrent
```

### 6.3 Interface Monitoring

NVM detects network interface changes:

```c
struct InterfaceInfo {
    char name[64];                  // e.g., "eth0", "wlan0"
    uint8_t type;                   // 0=unknown, 1=ethernet, 2=wifi, 3=vpn
    uint8_t state;                  // 0=down, 1=up
    char ssid[256];                 // WiFi SSID (if applicable)
    struct in6_addr ip_address;
    struct in6_addr gateway;
    struct in6_addr dns_servers[4];
    bool is_vpn;
    bool is_trusted;
};

// Interface change events trigger:
// 1. Send InterfaceInfo record to collector
// 2. Re-evaluate trusted network state
// 3. Flush flow cache (if transitioning trusted↔untrusted)
```

### 6.4 Endpoint Identity

At startup, the agent sends endpoint identity:

```json
{
  "endpoint_udid": "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
  "hostname": "employee-laptop",
  "os_name": "Ubuntu",
  "os_version": "22.04 LTS",
  "os_architecture": "x86_64",
  "kernel_version": "5.15.0-56-generic",
  "client_version": "5.1.2.42",
  "mac_addresses": ["00:1A:2B:3C:4D:5E"],
  "logged_in_users": ["jsmith", "root"],
  "domain": "corp.example.com"
}
```

---

## 7. Configuration Schema

### 7.1 XML Profile Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<NVMServiceProfile>
  <!-- Collector Configuration -->
  <CollectorConfiguration>
    <!-- Export Mode: "Collector" (on-prem) or "Cloud" -->
    <ExportTo>Collector</ExportTo>

    <!-- On-Premise Collector Settings -->
    <Collector>
      <Address>nvm-collector.example.com</Address>
      <Port>2055</Port>
      <Protocol>DTLS</Protocol>  <!-- UDP, DTLS, mDTLS -->

      <!-- DTLS Certificate Validation -->
      <CertificateValidation>
        <Enabled>true</Enabled>
        <PinnedHash algorithm="SHA256">
          A3F7B8C9D1E2F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9
        </PinnedHash>
      </CertificateValidation>

      <!-- Client Certificate (for mDTLS) -->
      <ClientCertificate>
        <CertificateFile>/opt/cisco/secureclient/NVM/client.pem</CertificateFile>
        <!-- Note: Password-protected keys NOT supported -->
      </ClientCertificate>
    </Collector>

    <!-- Proxy Settings (if collector behind proxy) -->
    <Proxy>
      <Enabled>false</Enabled>
      <Address>proxy.example.com</Address>
      <Port>8080</Port>
      <Authentication>
        <Username>proxyuser</Username>
        <Password>proxypass</Password>
      </Authentication>
    </Proxy>

    <!-- Cloud Collector Settings -->
    <CloudCollector>
      <ServerURL>https://nvm-cloud.cisco.com</ServerURL>
      <Port>443</Port>
      <Authentication>
        <BearerToken>eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...</BearerToken>
      </Authentication>
    </CloudCollector>
  </CollectorConfiguration>

  <!-- Data Collection Policy -->
  <DataCollectionPolicy>
    <!-- Enable/Disable NVM globally -->
    <Enabled>true</Enabled>

    <!-- Flow Report Interval
         -1: Only report on flow end (minimal telemetry)
          0: Report on start and end
         >0: Report every N seconds (e.g., 60 for 1-minute updates)
    -->
    <FlowReportInterval unit="seconds">60</FlowReportInterval>

    <!-- Template Report Interval (IPFIX templates retransmission) -->
    <TemplateReportInterval unit="minutes">1440</TemplateReportInterval>

    <!-- Cache Control (when collector unreachable) -->
    <CacheConfig>
      <MaxRecords>10000</MaxRecords>
      <MaxDuration unit="days">7</MaxDuration>
      <DatabasePath>/opt/cisco/secureclient/NVM/PersistedData.dat</DatabasePath>
    </CacheConfig>

    <!-- Throttle Rate (max flows per second) -->
    <ThrottleRate>1000</ThrottleRate>

    <!-- Ping Interval (cloud keep-alive) -->
    <PingInterval unit="seconds">300</PingInterval>
  </DataCollectionPolicy>

  <!-- Trusted Network Detection -->
  <TrustedNetworkDetection>
    <Enabled>true</Enabled>

    <!-- List of trusted servers (DNS suffix matching) -->
    <TrustedServer>
      <DomainSuffix>corp.example.com</DomainSuffix>
      <IPAddress>10.1.2.3</IPAddress>
      <Port>443</Port>
      <CertificateHash algorithm="SHA256">
        B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5
      </CertificateHash>
    </TrustedServer>

    <!-- Action on trusted network -->
    <OnTrustedNetwork>
      <DisableTelemetry>false</DisableTelemetry>
      <UseOnPremCollectorOnly>true</UseOnPremCollectorOnly>
    </OnTrustedNetwork>
  </TrustedNetworkDetection>

  <!-- Flow Filtering Rules -->
  <FlowFilterRules>
    <!-- Inclusion rules (whitelist) -->
    <InclusionRules>
      <Rule>
        <ProcessName>firefox</ProcessName>
        <DestinationPort>443</DestinationPort>
      </Rule>
    </InclusionRules>

    <!-- Exclusion rules (blacklist) -->
    <ExclusionRules>
      <Rule>
        <ProcessPath>/usr/bin/torrent</ProcessPath>
      </Rule>
      <Rule>
        <DestinationHostname>*.local</DestinationHostname>
      </Rule>
      <Rule>
        <DestinationIPRange>224.0.0.0/4</DestinationIPRange>  <!-- Multicast -->
      </Rule>
    </ExclusionRules>

    <!-- Hybrid mode: Exclude first, then include -->
    <Mode>hybrid</Mode>
  </FlowFilterRules>

  <!-- Privacy Settings -->
  <PrivacySettings>
    <!-- Scrub sensitive data -->
    <AnonymizeUsernames>false</AnonymizeUsernames>
    <AnonymizePrivateIPs>false</AnonymizePrivateIPs>
    <TruncateCommandLineArgs>false</TruncateCommandLineArgs>

    <!-- PII filtering regex -->
    <PIIFilterPatterns>
      <Pattern type="regex">\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b</Pattern>
      <Pattern type="regex">\\b\\d{3}-\\d{2}-\\d{4}\\b</Pattern>  <!-- SSN -->
    </PIIFilterPatterns>
  </PrivacySettings>

  <!-- Debug Settings -->
  <DebugSettings>
    <EnableFlowTracing>false</EnableFlowTracing>  <!-- NVM-TRACE-FLOWS -->
    <LogLevel>INFO</LogLevel>  <!-- ERROR, WARN, INFO, DEBUG -->
    <LogFile>/var/log/acnvmagent.log</LogFile>
  </DebugSettings>
</NVMServiceProfile>
```

### 7.2 Configuration File Paths

| Platform | Service Profile | Bootstrap Profile | KConfig |
|----------|----------------|-------------------|---------|
| **Linux** | `/opt/cisco/secureclient/NVM/NVM_ServiceProfile.xml` | `/opt/cisco/secureclient/NVM/NVM_BootstrapProfile.xml` | `/opt/cisco/secureclient/NVM/KConfig.dat` |
| **Windows** | `%ProgramData%\Cisco\Cisco Secure Client\NVM\NVM_ServiceProfile.xml` | `%ProgramData%\Cisco\Cisco Secure Client\NVM\NVM_BootstrapProfile.xml` | `%ProgramData%\Cisco\Cisco Secure Client\NVM\KConfig.dat` |
| **macOS** | `/opt/cisco/secureclient/NVM/NVM_ServiceProfile.xml` | `/opt/cisco/secureclient/NVM/NVM_BootstrapProfile.xml` | `/opt/cisco/secureclient/NVM/KConfig.dat` |

**KConfig.dat**: Binary configuration file for kernel driver (collector address, ports).

### 7.3 Profile Validation

The agent validates profiles with these checks:

- Port numbers: 1-65535
- IP addresses: Valid IPv4/IPv6 format
- IPFIX timer: 60-86400 seconds
- Throttle rate: 100-10000 flows/sec
- Template interval: 1-10080 minutes (7 days max)
- Cache size: 100-100000 records
- Certificate hashes: Valid SHA256 (64 hex chars)

**Default Values:**
- FlowReportInterval: 60 seconds
- TemplateReportInterval: 1440 minutes (24 hours)
- CacheMaxRecords: 10,000
- ThrottleRate: 1000 flows/sec

---

## 8. C23 Implementation Guide

### 8.1 Overview

To implement NVM telemetry in **ocserv**, we need:

1. **Kernel Module**: eBPF program (or netfilter hook) to capture packets
2. **User-Space Daemon**: Process flow data, enrich, serialize, export
3. **IPFIX Exporter**: Implement IPFIX packet builder
4. **Configuration Parser**: Read XML profiles
5. **SQLite Cache**: Persistent storage for offline mode

### 8.2 Recommended Architecture for ocserv

```
ocserv (C23)
├─ src/nvm/
│  ├─ nvm_kernel.c/.h       # eBPF loader and netlink interface
│  ├─ nvm_flow.c/.h          # Flow aggregation and state machine
│  ├─ nvm_process.c/.h       # Process metadata enrichment
│  ├─ nvm_dns.c/.h           # DNS cache
│  ├─ nvm_ipfix.c/.h         # IPFIX encoder
│  ├─ nvm_exporter.c/.h      # UDP/DTLS transport
│  ├─ nvm_cache.c/.h         # SQLite persistent cache
│  ├─ nvm_config.c/.h        # XML profile parser
│  └─ nvm_main.c             # NVM thread entry point
├─ ebpf/
│  └─ nvm_flow_tracker.bpf.c # eBPF packet capture program
└─ tests/
   └─ nvm_test.c             # Unit tests
```

### 8.3 eBPF vs. Netfilter

**Recommendation: Use eBPF** for modern Linux kernels (5.10+)

| Feature | eBPF | Netfilter |
|---------|------|-----------|
| **Performance** | Very high (JIT compiled) | Good |
| **Overhead** | ~5% CPU | ~10-15% CPU |
| **Kernel Version** | 5.10+ | All |
| **Complexity** | High (requires BPF CO-RE) | Medium |
| **Portability** | Modern kernels only | All Linux |

**Fallback Strategy:**
- Try eBPF first
- If kernel < 5.10 or eBPF unavailable, use netfilter
- If both fail, log warning and disable NVM

### 8.4 Data Flow in ocserv

```
1. eBPF Program (nvm_flow_tracker.bpf.c)
   ├─ Attach to TC egress/ingress hooks OR
   ├─ Attach to sock_ops/sockmap OR
   ├─ Attach to kprobe on tcp_sendmsg/tcp_recvmsg
   └─ Output: struct nvm_event → ring buffer

2. User-Space Daemon (nvm_kernel.c)
   ├─ Read ring buffer in event loop
   ├─ Parse nvm_event → struct nvm_flow_record
   └─ Queue for processing

3. Flow Aggregator (nvm_flow.c)
   ├─ Hash table lookup by 5-tuple + PID
   ├─ Update counters (bytes, packets, timestamps)
   ├─ State machine (NEW → ESTABLISHED → FINISHED)
   └─ Emit flow reports based on interval

4. Enrichment (nvm_process.c, nvm_dns.c)
   ├─ Read /proc/<pid>/{exe,cmdline,status}
   ├─ Calculate SHA256 of executable
   ├─ Lookup DNS cache for destination hostname
   └─ Add to flow record

5. Serialization (nvm_ipfix.c)
   ├─ Build IPFIX message header
   ├─ Encode template (if needed)
   ├─ Encode data records
   └─ Return serialized buffer

6. Export (nvm_exporter.c)
   ├─ Send via UDP socket OR
   ├─ Send via DTLS socket (OpenSSL)
   └─ Handle errors → cache to SQLite

7. Cache (nvm_cache.c)
   ├─ On export failure, INSERT INTO FLOW_DATA
   ├─ On collector reconnect, SELECT and drain cache
   └─ Purge old records (> 7 days)
```

### 8.5 Threading Model for ocserv

```c
// Main thread: Configuration and coordination
main_thread() {
    nvm_config_load("nvm_profile.xml");
    nvm_start();

    // Integrate with ocserv event loop
    while (running) {
        handle_ocserv_events();
        nvm_poll();  // Non-blocking
    }

    nvm_stop();
}

// NVM thread 1: eBPF event reader
nvm_kernel_thread() {
    while (running) {
        struct nvm_event events[64];
        int n = ring_buffer__poll(rb, 100 /* timeout_ms */);

        for (int i = 0; i < n; i++) {
            nvm_flow_process_event(&events[i]);
        }
    }
}

// NVM thread 2: Exporter (timer-based)
nvm_exporter_thread() {
    while (running) {
        sleep(1);  // 1-second tick

        // Check if flows are ready to export
        struct nvm_flow_record *flows;
        size_t count = nvm_flow_get_ready(&flows);

        if (count > 0) {
            uint8_t ipfix_buf[65536];
            size_t ipfix_len = nvm_ipfix_encode(flows, count, ipfix_buf);

            if (nvm_exporter_send(ipfix_buf, ipfix_len) < 0) {
                nvm_cache_store(flows, count);
            }

            free(flows);
        }

        // Send IPFIX templates every 24 hours
        static time_t last_template = 0;
        if (time(NULL) - last_template > 86400) {
            nvm_exporter_send_templates();
            last_template = time(NULL);
        }
    }
}
```

### 8.6 Memory Management

```c
// Use reference counting for flow records
struct nvm_flow_record {
    atomic_int refcount;

    // Flow data...
    uint32_t flow_id;
    uint64_t start_time_ms;
    // ...
};

// Increment reference
static inline void nvm_flow_ref(struct nvm_flow_record *flow) {
    atomic_fetch_add(&flow->refcount, 1);
}

// Decrement reference, free if zero
static inline void nvm_flow_unref(struct nvm_flow_record *flow) {
    if (atomic_fetch_sub(&flow->refcount, 1) == 1) {
        free(flow);
    }
}

// Memory pools for high-frequency allocations
struct nvm_mempool {
    void *blocks[1024];
    size_t block_size;
    size_t free_count;
    pthread_mutex_t lock;
};

void* nvm_mempool_alloc(struct nvm_mempool *pool);
void nvm_mempool_free(struct nvm_mempool *pool, void *ptr);
```

---

## 9. Example C23 Code

### 9.1 Core Data Structures

```c
// nvm_flow.h - Core flow record structure

#pragma once

#include <stdint.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include <time.h>

#define NVM_PROCESS_NAME_MAX  256
#define NVM_PROCESS_PATH_MAX  2048
#define NVM_HOSTNAME_MAX      256
#define NVM_HASH_SIZE         64

// Flow direction
enum nvm_flow_direction {
    NVM_FLOW_DIR_UNKNOWN = 0,
    NVM_FLOW_DIR_INBOUND = 1,
    NVM_FLOW_DIR_OUTBOUND = 2
};

// Flow report stage
enum nvm_flow_stage {
    NVM_FLOW_STAGE_END = 0,
    NVM_FLOW_STAGE_START = 1,
    NVM_FLOW_STAGE_PERIODIC = 2
};

// Flow state (internal)
enum nvm_flow_state {
    NVM_FLOW_STATE_NEW = 0,
    NVM_FLOW_STATE_ESTABLISHED = 1,
    NVM_FLOW_STATE_FINISHED = 2
};

// IP address (IPv4 or IPv6)
struct nvm_ipaddr {
    uint8_t family;  // AF_INET or AF_INET6
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    };
};

// Flow 5-tuple
struct nvm_flow_tuple {
    struct nvm_ipaddr src_ip;
    struct nvm_ipaddr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;  // IPPROTO_TCP or IPPROTO_UDP
};

// Process information
struct nvm_process_info {
    uint32_t pid;
    uint32_t parent_pid;
    char name[NVM_PROCESS_NAME_MAX];
    char path[NVM_PROCESS_PATH_MAX];
    char args[NVM_PROCESS_PATH_MAX];
    char username[256];
    char parent_name[NVM_PROCESS_NAME_MAX];
    char parent_path[NVM_PROCESS_PATH_MAX];
    uint8_t hash[32];  // SHA256
};

// Network flow record
struct nvm_flow_record {
    // Reference counting for memory management
    atomic_int refcount;

    // Flow identification
    uint32_t flow_id;
    struct nvm_flow_tuple tuple;

    // Timestamps (milliseconds since epoch)
    uint64_t start_time_ms;
    uint64_t end_time_ms;
    uint64_t last_update_ms;

    // Traffic counters
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;

    // Process information
    struct nvm_process_info process;

    // Network context
    char destination_hostname[NVM_HOSTNAME_MAX];
    char dns_suffix[256];

    // Flow metadata
    enum nvm_flow_direction direction;
    enum nvm_flow_stage stage;
    enum nvm_flow_state state;  // Internal state

    // TCP-specific
    uint8_t tcp_flags_sent;
    uint8_t tcp_flags_received;

    // Hash table linkage
    struct nvm_flow_record *ht_next;
};

// Flow hash table
#define NVM_FLOW_HT_SIZE  1024  // Power of 2

struct nvm_flow_table {
    struct nvm_flow_record *buckets[NVM_FLOW_HT_SIZE];
    pthread_rwlock_t locks[NVM_FLOW_HT_SIZE];
    atomic_uint_least32_t next_flow_id;
    uint32_t flow_count;
};

// API functions
[[nodiscard]] int nvm_flow_table_init(struct nvm_flow_table *table);
void nvm_flow_table_destroy(struct nvm_flow_table *table);

[[nodiscard]] struct nvm_flow_record* nvm_flow_find_or_create(
    struct nvm_flow_table *table,
    const struct nvm_flow_tuple *tuple,
    uint32_t pid,
    bool *created
);

void nvm_flow_update(
    struct nvm_flow_record *flow,
    uint64_t bytes_delta,
    uint64_t packets_delta,
    uint8_t tcp_flags,
    bool is_outbound
);

[[nodiscard]] int nvm_flow_get_ready(
    struct nvm_flow_table *table,
    struct nvm_flow_record ***flows_out,
    size_t *count_out,
    int report_interval
);

void nvm_flow_ref(struct nvm_flow_record *flow);
void nvm_flow_unref(struct nvm_flow_record *flow);
```

### 9.2 Flow Management Implementation

```c
// nvm_flow.c - Flow aggregation and state management

#include "nvm_flow.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

// Hash function (FNV-1a)
static uint32_t hash_flow_tuple(const struct nvm_flow_tuple *tuple, uint32_t pid) {
    uint32_t hash = 2166136261u;

    // Hash IP addresses
    const uint8_t *data = (const uint8_t *)&tuple->src_ip;
    size_t len = tuple->src_ip.family == AF_INET ? 4 : 16;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }

    data = (const uint8_t *)&tuple->dst_ip;
    len = tuple->dst_ip.family == AF_INET ? 4 : 16;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }

    // Hash ports and protocol
    hash ^= tuple->src_port;
    hash *= 16777619u;
    hash ^= tuple->dst_port;
    hash *= 16777619u;
    hash ^= tuple->protocol;
    hash *= 16777619u;

    // Hash PID
    hash ^= pid;
    hash *= 16777619u;

    return hash;
}

// Get current time in milliseconds
static uint64_t get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Initialize flow table
[[nodiscard]] int nvm_flow_table_init(struct nvm_flow_table *table) {
    memset(table, 0, sizeof(*table));

    for (size_t i = 0; i < NVM_FLOW_HT_SIZE; i++) {
        if (pthread_rwlock_init(&table->locks[i], nullptr) != 0) {
            // Cleanup on error
            for (size_t j = 0; j < i; j++) {
                pthread_rwlock_destroy(&table->locks[j]);
            }
            return -1;
        }
    }

    atomic_init(&table->next_flow_id, 1);
    return 0;
}

// Destroy flow table
void nvm_flow_table_destroy(struct nvm_flow_table *table) {
    for (size_t i = 0; i < NVM_FLOW_HT_SIZE; i++) {
        pthread_rwlock_wrlock(&table->locks[i]);

        struct nvm_flow_record *flow = table->buckets[i];
        while (flow) {
            struct nvm_flow_record *next = flow->ht_next;
            nvm_flow_unref(flow);
            flow = next;
        }

        pthread_rwlock_unlock(&table->locks[i]);
        pthread_rwlock_destroy(&table->locks[i]);
    }
}

// Find or create flow
[[nodiscard]] struct nvm_flow_record* nvm_flow_find_or_create(
    struct nvm_flow_table *table,
    const struct nvm_flow_tuple *tuple,
    uint32_t pid,
    bool *created
) {
    uint32_t hash = hash_flow_tuple(tuple, pid);
    size_t bucket = hash % NVM_FLOW_HT_SIZE;

    pthread_rwlock_wrlock(&table->locks[bucket]);

    // Search for existing flow
    struct nvm_flow_record *flow = table->buckets[bucket];
    while (flow) {
        if (memcmp(&flow->tuple, tuple, sizeof(*tuple)) == 0 &&
            flow->process.pid == pid) {
            nvm_flow_ref(flow);
            pthread_rwlock_unlock(&table->locks[bucket]);
            *created = false;
            return flow;
        }
        flow = flow->ht_next;
    }

    // Create new flow
    flow = calloc(1, sizeof(*flow));
    if (!flow) {
        pthread_rwlock_unlock(&table->locks[bucket]);
        *created = false;
        return nullptr;
    }

    atomic_init(&flow->refcount, 2);  // 1 for hash table, 1 for caller
    flow->flow_id = atomic_fetch_add(&table->next_flow_id, 1);
    flow->tuple = *tuple;
    flow->start_time_ms = get_time_ms();
    flow->last_update_ms = flow->start_time_ms;
    flow->process.pid = pid;
    flow->state = NVM_FLOW_STATE_NEW;

    // Insert into hash table
    flow->ht_next = table->buckets[bucket];
    table->buckets[bucket] = flow;
    __atomic_add_fetch(&table->flow_count, 1, __ATOMIC_RELAXED);

    pthread_rwlock_unlock(&table->locks[bucket]);

    *created = true;
    return flow;
}

// Update flow counters
void nvm_flow_update(
    struct nvm_flow_record *flow,
    uint64_t bytes_delta,
    uint64_t packets_delta,
    uint8_t tcp_flags,
    bool is_outbound
) {
    flow->last_update_ms = get_time_ms();

    if (is_outbound) {
        __atomic_add_fetch(&flow->bytes_sent, bytes_delta, __ATOMIC_RELAXED);
        __atomic_add_fetch(&flow->packets_sent, packets_delta, __ATOMIC_RELAXED);
        flow->tcp_flags_sent |= tcp_flags;
        flow->direction = NVM_FLOW_DIR_OUTBOUND;
    } else {
        __atomic_add_fetch(&flow->bytes_received, bytes_delta, __ATOMIC_RELAXED);
        __atomic_add_fetch(&flow->packets_received, packets_delta, __ATOMIC_RELAXED);
        flow->tcp_flags_received |= tcp_flags;
        flow->direction = NVM_FLOW_DIR_INBOUND;
    }

    // State transitions for TCP
    if (flow->tuple.protocol == IPPROTO_TCP) {
        if (flow->state == NVM_FLOW_STATE_NEW) {
            // Check for SYN-ACK (connection established)
            if ((flow->tcp_flags_sent & 0x02) &&    // SYN sent
                (flow->tcp_flags_received & 0x12)) { // SYN-ACK received
                flow->state = NVM_FLOW_STATE_ESTABLISHED;
            }
        } else if (flow->state == NVM_FLOW_STATE_ESTABLISHED) {
            // Check for FIN or RST (connection closing)
            if ((tcp_flags & 0x01) || (tcp_flags & 0x04)) {  // FIN or RST
                flow->state = NVM_FLOW_STATE_FINISHED;
                flow->end_time_ms = flow->last_update_ms;
            }
        }
    }
}

// Get flows ready for export
[[nodiscard]] int nvm_flow_get_ready(
    struct nvm_flow_table *table,
    struct nvm_flow_record ***flows_out,
    size_t *count_out,
    int report_interval
) {
    uint64_t now = get_time_ms();
    size_t capacity = 128;
    size_t count = 0;
    struct nvm_flow_record **flows = malloc(capacity * sizeof(*flows));

    if (!flows) return -1;

    for (size_t i = 0; i < NVM_FLOW_HT_SIZE; i++) {
        pthread_rwlock_rdlock(&table->locks[i]);

        struct nvm_flow_record *flow = table->buckets[i];
        while (flow) {
            bool ready = false;

            // Determine if flow is ready to export
            if (flow->state == NVM_FLOW_STATE_FINISHED) {
                // Always export finished flows
                flow->stage = NVM_FLOW_STAGE_END;
                ready = true;
            } else if (report_interval == 0 && flow->state == NVM_FLOW_STATE_NEW) {
                // Export on start if interval == 0
                flow->stage = NVM_FLOW_STAGE_START;
                ready = true;
            } else if (report_interval > 0) {
                // Export periodically
                uint64_t age_ms = now - flow->last_update_ms;
                if (age_ms >= (uint64_t)report_interval * 1000) {
                    flow->stage = (flow->stage == NVM_FLOW_STAGE_START) ?
                        NVM_FLOW_STAGE_PERIODIC : NVM_FLOW_STAGE_START;
                    ready = true;
                }
            }

            if (ready) {
                // Resize array if needed
                if (count >= capacity) {
                    capacity *= 2;
                    struct nvm_flow_record **new_flows =
                        realloc(flows, capacity * sizeof(*flows));
                    if (!new_flows) {
                        pthread_rwlock_unlock(&table->locks[i]);
                        free(flows);
                        return -1;
                    }
                    flows = new_flows;
                }

                nvm_flow_ref(flow);
                flows[count++] = flow;
            }

            flow = flow->ht_next;
        }

        pthread_rwlock_unlock(&table->locks[i]);
    }

    *flows_out = flows;
    *count_out = count;
    return 0;
}

// Reference counting
void nvm_flow_ref(struct nvm_flow_record *flow) {
    atomic_fetch_add(&flow->refcount, 1);
}

void nvm_flow_unref(struct nvm_flow_record *flow) {
    if (atomic_fetch_sub(&flow->refcount, 1) == 1) {
        free(flow);
    }
}
```

### 9.3 Process Enrichment

```c
// nvm_process.c - Process metadata enrichment

#include "nvm_flow.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <openssl/evp.h>

// Read process executable path
static int read_process_exe(uint32_t pid, char *path, size_t path_len) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/exe", pid);

    ssize_t len = readlink(proc_path, path, path_len - 1);
    if (len < 0) return -1;

    path[len] = '\0';
    return 0;
}

// Read process command line
static int read_process_cmdline(uint32_t pid, char *cmdline, size_t cmdline_len) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/cmdline", pid);

    FILE *fp = fopen(proc_path, "r");
    if (!fp) return -1;

    size_t n = fread(cmdline, 1, cmdline_len - 1, fp);
    fclose(fp);

    // Replace null bytes with spaces
    for (size_t i = 0; i < n; i++) {
        if (cmdline[i] == '\0') cmdline[i] = ' ';
    }
    cmdline[n] = '\0';

    return 0;
}

// Get process owner username
static int read_process_username(uint32_t pid, char *username, size_t username_len) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/status", pid);

    FILE *fp = fopen(proc_path, "r");
    if (!fp) return -1;

    char line[256];
    uid_t uid = (uid_t)-1;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "Uid:\t%u", &uid) == 1) {
            break;
        }
    }
    fclose(fp);

    if (uid == (uid_t)-1) return -1;

    struct passwd *pw = getpwuid(uid);
    if (!pw) return -1;

    snprintf(username, username_len, "%s", pw->pw_name);
    return 0;
}

// Calculate SHA256 hash of file
static int sha256_file(const char *path, uint8_t *hash) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(fp);
        return -1;
    }

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    uint8_t buffer[4096];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        EVP_DigestUpdate(ctx, buffer, n);
    }

    unsigned int hash_len;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);

    EVP_MD_CTX_free(ctx);
    fclose(fp);

    return (hash_len == 32) ? 0 : -1;
}

// Enrich flow with process information
[[nodiscard]] int nvm_flow_enrich_process(struct nvm_flow_record *flow) {
    struct nvm_process_info *proc = &flow->process;

    // Read executable path
    if (read_process_exe(proc->pid, proc->path, sizeof(proc->path)) == 0) {
        // Extract basename
        char *basename = strrchr(proc->path, '/');
        if (basename) {
            snprintf(proc->name, sizeof(proc->name), "%s", basename + 1);
        }
    }

    // Read command line
    read_process_cmdline(proc->pid, proc->args, sizeof(proc->args));

    // Read username
    read_process_username(proc->pid, proc->username, sizeof(proc->username));

    // Calculate hash
    if (proc->path[0]) {
        sha256_file(proc->path, proc->hash);
    }

    // Read parent process info
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/status", proc->pid);

    FILE *fp = fopen(proc_path, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (sscanf(line, "PPid:\t%u", &proc->parent_pid) == 1) {
                break;
            }
        }
        fclose(fp);

        // Read parent executable
        if (proc->parent_pid > 0) {
            read_process_exe(proc->parent_pid, proc->parent_path,
                           sizeof(proc->parent_path));
            char *basename = strrchr(proc->parent_path, '/');
            if (basename) {
                snprintf(proc->parent_name, sizeof(proc->parent_name),
                        "%s", basename + 1);
            }
        }
    }

    return 0;
}
```

### 9.4 IPFIX Encoder

```c
// nvm_ipfix.c - IPFIX message encoder

#include "nvm_flow.h"
#include <arpa/inet.h>
#include <string.h>

#define IPFIX_VERSION  10
#define IPFIX_SET_ID_TEMPLATE  2
#define IPFIX_SET_ID_DATA      256

// IPFIX message header
struct ipfix_header {
    uint16_t version;
    uint16_t length;
    uint32_t export_time;
    uint32_t sequence_number;
    uint32_t observation_domain_id;
} __attribute__((packed));

// IPFIX set header
struct ipfix_set_header {
    uint16_t set_id;
    uint16_t length;
} __attribute__((packed));

// IPFIX template field
struct ipfix_template_field {
    uint16_t ie_id;
    uint16_t field_length;
    uint32_t enterprise_number;  // Optional (if ie_id & 0x8000)
} __attribute__((packed));

// Template definition for IPv4 flows
static const struct ipfix_template_field flow_template_ipv4[] = {
    {150, 4, 0},     // flowStartSeconds
    {151, 4, 0},     // flowEndSeconds
    {8, 4, 0},       // sourceIPv4Address
    {7, 2, 0},       // sourceTransportPort
    {12, 4, 0},      // destinationIPv4Address
    {11, 2, 0},      // destinationTransportPort
    {4, 1, 0},       // protocolIdentifier
    {1, 8, 0},       // octetDeltaCount (bytes sent)
    {2, 8, 0},       // packetDeltaCount (packets sent)
    {176, 1, 0},     // flowDirection
    {12232, 4, 9},   // nvmProcessID (Cisco PEN=9)
    {12233, 0xffff, 9},  // nvmProcessName (variable length)
    {12234, 0xffff, 9},  // nvmProcessPath (variable length)
    {12241, 0xffff, 9},  // nvmDestinationHostname (variable length)
};

#define TEMPLATE_ID_IPV4  256
#define TEMPLATE_FIELD_COUNT_IPV4  (sizeof(flow_template_ipv4) / sizeof(flow_template_ipv4[0]))

// Global sequence number
static uint32_t g_sequence_number = 0;

// Encode IPFIX template set
static size_t encode_template_set(uint8_t *buf, size_t buf_len) {
    size_t offset = 0;

    // Set header
    struct ipfix_set_header *set_hdr = (struct ipfix_set_header *)(buf + offset);
    set_hdr->set_id = htons(IPFIX_SET_ID_TEMPLATE);
    offset += sizeof(*set_hdr);

    // Template header
    uint16_t *template_id = (uint16_t *)(buf + offset);
    *template_id = htons(TEMPLATE_ID_IPV4);
    offset += sizeof(uint16_t);

    uint16_t *field_count = (uint16_t *)(buf + offset);
    *field_count = htons(TEMPLATE_FIELD_COUNT_IPV4);
    offset += sizeof(uint16_t);

    // Template fields
    for (size_t i = 0; i < TEMPLATE_FIELD_COUNT_IPV4; i++) {
        const struct ipfix_template_field *field = &flow_template_ipv4[i];

        uint16_t ie_id = field->ie_id;
        if (field->enterprise_number != 0) {
            ie_id |= 0x8000;  // Set enterprise bit
        }

        uint16_t *ie_id_ptr = (uint16_t *)(buf + offset);
        *ie_id_ptr = htons(ie_id);
        offset += sizeof(uint16_t);

        uint16_t *field_len_ptr = (uint16_t *)(buf + offset);
        *field_len_ptr = htons(field->field_length);
        offset += sizeof(uint16_t);

        if (field->enterprise_number != 0) {
            uint32_t *pen_ptr = (uint32_t *)(buf + offset);
            *pen_ptr = htonl(field->enterprise_number);
            offset += sizeof(uint32_t);
        }
    }

    // Update set length
    set_hdr->length = htons(offset);

    return offset;
}

// Encode variable-length string
static size_t encode_string(uint8_t *buf, const char *str) {
    size_t len = strlen(str);
    size_t offset = 0;

    if (len < 255) {
        buf[offset++] = (uint8_t)len;
    } else if (len < 65535) {
        buf[offset++] = 255;
        uint16_t *len_ptr = (uint16_t *)(buf + offset);
        *len_ptr = htons((uint16_t)len);
        offset += 2;
    }

    memcpy(buf + offset, str, len);
    offset += len;

    return offset;
}

// Encode single flow data record
static size_t encode_flow_record(uint8_t *buf, const struct nvm_flow_record *flow) {
    size_t offset = 0;

    // flowStartSeconds (4 bytes)
    uint32_t *start_sec = (uint32_t *)(buf + offset);
    *start_sec = htonl((uint32_t)(flow->start_time_ms / 1000));
    offset += 4;

    // flowEndSeconds (4 bytes)
    uint32_t *end_sec = (uint32_t *)(buf + offset);
    *end_sec = htonl((uint32_t)(flow->end_time_ms / 1000));
    offset += 4;

    // sourceIPv4Address (4 bytes)
    memcpy(buf + offset, &flow->tuple.src_ip.ipv4.s_addr, 4);
    offset += 4;

    // sourceTransportPort (2 bytes)
    uint16_t *src_port = (uint16_t *)(buf + offset);
    *src_port = htons(flow->tuple.src_port);
    offset += 2;

    // destinationIPv4Address (4 bytes)
    memcpy(buf + offset, &flow->tuple.dst_ip.ipv4.s_addr, 4);
    offset += 4;

    // destinationTransportPort (2 bytes)
    uint16_t *dst_port = (uint16_t *)(buf + offset);
    *dst_port = htons(flow->tuple.dst_port);
    offset += 2;

    // protocolIdentifier (1 byte)
    buf[offset++] = flow->tuple.protocol;

    // octetDeltaCount (8 bytes)
    uint64_t *bytes = (uint64_t *)(buf + offset);
    *bytes = htobe64(flow->bytes_sent);
    offset += 8;

    // packetDeltaCount (8 bytes)
    uint64_t *packets = (uint64_t *)(buf + offset);
    *packets = htobe64(flow->packets_sent);
    offset += 8;

    // flowDirection (1 byte)
    buf[offset++] = flow->direction;

    // nvmProcessID (4 bytes)
    uint32_t *pid = (uint32_t *)(buf + offset);
    *pid = htonl(flow->process.pid);
    offset += 4;

    // nvmProcessName (variable)
    offset += encode_string(buf + offset, flow->process.name);

    // nvmProcessPath (variable)
    offset += encode_string(buf + offset, flow->process.path);

    // nvmDestinationHostname (variable)
    offset += encode_string(buf + offset, flow->destination_hostname);

    return offset;
}

// Encode IPFIX message with flow records
[[nodiscard]] ssize_t nvm_ipfix_encode(
    const struct nvm_flow_record **flows,
    size_t flow_count,
    uint8_t *buf,
    size_t buf_len
) {
    size_t offset = 0;

    // Reserve space for IPFIX header
    offset += sizeof(struct ipfix_header);

    // Encode data set
    struct ipfix_set_header *set_hdr = (struct ipfix_set_header *)(buf + offset);
    set_hdr->set_id = htons(TEMPLATE_ID_IPV4);
    offset += sizeof(*set_hdr);

    size_t data_set_start = offset;

    for (size_t i = 0; i < flow_count; i++) {
        if (offset + 1024 > buf_len) break;  // Ensure space

        // Only encode IPv4 flows (IPv6 requires different template)
        if (flows[i]->tuple.src_ip.family == AF_INET) {
            offset += encode_flow_record(buf + offset, flows[i]);
        }
    }

    // Update data set length
    size_t data_set_len = offset - data_set_start + sizeof(*set_hdr);
    set_hdr->length = htons((uint16_t)data_set_len);

    // Fill in IPFIX header
    struct ipfix_header *hdr = (struct ipfix_header *)buf;
    hdr->version = htons(IPFIX_VERSION);
    hdr->length = htons((uint16_t)offset);
    hdr->export_time = htonl((uint32_t)time(nullptr));
    hdr->sequence_number = htonl(__atomic_fetch_add(&g_sequence_number, 1, __ATOMIC_RELAXED));
    hdr->observation_domain_id = 0;

    return offset;
}

// Send IPFIX templates
[[nodiscard]] ssize_t nvm_ipfix_encode_templates(uint8_t *buf, size_t buf_len) {
    size_t offset = 0;

    // Reserve space for IPFIX header
    offset += sizeof(struct ipfix_header);

    // Encode template set
    offset += encode_template_set(buf + offset, buf_len - offset);

    // Fill in IPFIX header
    struct ipfix_header *hdr = (struct ipfix_header *)buf;
    hdr->version = htons(IPFIX_VERSION);
    hdr->length = htons((uint16_t)offset);
    hdr->export_time = htonl((uint32_t)time(nullptr));
    hdr->sequence_number = htonl(__atomic_fetch_add(&g_sequence_number, 1, __ATOMIC_RELAXED));
    hdr->observation_domain_id = 0;

    return offset;
}
```

### 9.5 UDP/DTLS Exporter

```c
// nvm_exporter.c - Transport layer (UDP/DTLS)

#include "nvm_flow.h"
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct nvm_exporter {
    int sockfd;
    struct sockaddr_storage collector_addr;
    socklen_t collector_addr_len;

    // DTLS context
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    BIO *bio;

    bool use_dtls;
    atomic_bool connected;
};

// Initialize UDP exporter
[[nodiscard]] int nvm_exporter_init_udp(
    struct nvm_exporter *exporter,
    const char *collector_host,
    uint16_t collector_port
) {
    // Resolve collector address
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP,
    };

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", collector_port);

    struct addrinfo *result;
    int err = getaddrinfo(collector_host, port_str, &hints, &result);
    if (err != 0) {
        return -1;
    }

    // Create UDP socket
    exporter->sockfd = socket(result->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (exporter->sockfd < 0) {
        freeaddrinfo(result);
        return -1;
    }

    // Store collector address
    memcpy(&exporter->collector_addr, result->ai_addr, result->ai_addrlen);
    exporter->collector_addr_len = result->ai_addrlen;

    freeaddrinfo(result);

    exporter->use_dtls = false;
    atomic_store(&exporter->connected, true);

    return 0;
}

// Initialize DTLS exporter
[[nodiscard]] int nvm_exporter_init_dtls(
    struct nvm_exporter *exporter,
    const char *collector_host,
    uint16_t collector_port,
    const char *ca_cert_path,
    const char *client_cert_path,
    const char *client_key_path
) {
    // First initialize UDP socket
    if (nvm_exporter_init_udp(exporter, collector_host, collector_port) < 0) {
        return -1;
    }

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // Create DTLS context
    exporter->ssl_ctx = SSL_CTX_new(DTLS_client_method());
    if (!exporter->ssl_ctx) {
        close(exporter->sockfd);
        return -1;
    }

    // Load CA certificate
    if (SSL_CTX_load_verify_locations(exporter->ssl_ctx, ca_cert_path, nullptr) != 1) {
        SSL_CTX_free(exporter->ssl_ctx);
        close(exporter->sockfd);
        return -1;
    }

    // Load client certificate (mDTLS)
    if (client_cert_path && client_key_path) {
        if (SSL_CTX_use_certificate_file(exporter->ssl_ctx, client_cert_path,
                                         SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(exporter->ssl_ctx);
            close(exporter->sockfd);
            return -1;
        }

        if (SSL_CTX_use_PrivateKey_file(exporter->ssl_ctx, client_key_path,
                                       SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(exporter->ssl_ctx);
            close(exporter->sockfd);
            return -1;
        }
    }

    // Create SSL object
    exporter->ssl = SSL_new(exporter->ssl_ctx);
    if (!exporter->ssl) {
        SSL_CTX_free(exporter->ssl_ctx);
        close(exporter->sockfd);
        return -1;
    }

    // Create BIO and connect
    exporter->bio = BIO_new_dgram(exporter->sockfd, BIO_NOCLOSE);
    BIO_ctrl(exporter->bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0,
             &exporter->collector_addr);
    SSL_set_bio(exporter->ssl, exporter->bio, exporter->bio);

    // Perform DTLS handshake
    if (SSL_connect(exporter->ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(exporter->ssl);
        SSL_CTX_free(exporter->ssl_ctx);
        close(exporter->sockfd);
        return -1;
    }

    exporter->use_dtls = true;
    atomic_store(&exporter->connected, true);

    return 0;
}

// Send IPFIX data
[[nodiscard]] ssize_t nvm_exporter_send(
    struct nvm_exporter *exporter,
    const uint8_t *data,
    size_t len
) {
    if (!atomic_load(&exporter->connected)) {
        return -1;
    }

    ssize_t sent;

    if (exporter->use_dtls) {
        sent = SSL_write(exporter->ssl, data, len);
        if (sent <= 0) {
            int err = SSL_get_error(exporter->ssl, sent);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                return 0;  // Retry
            }
            atomic_store(&exporter->connected, false);
            return -1;
        }
    } else {
        sent = sendto(exporter->sockfd, data, len, 0,
                     (struct sockaddr *)&exporter->collector_addr,
                     exporter->collector_addr_len);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;  // Retry
            }
            return -1;
        }
    }

    return sent;
}

// Cleanup
void nvm_exporter_destroy(struct nvm_exporter *exporter) {
    if (exporter->use_dtls) {
        if (exporter->ssl) {
            SSL_shutdown(exporter->ssl);
            SSL_free(exporter->ssl);
        }
        if (exporter->ssl_ctx) {
            SSL_CTX_free(exporter->ssl_ctx);
        }
    }

    if (exporter->sockfd >= 0) {
        close(exporter->sockfd);
    }
}
```

---

## 10. Testing & Validation

### 10.1 Test Flow Generation

```c
// Create synthetic flows for testing
void generate_test_flow(struct nvm_flow_record *flow) {
    flow->flow_id = 1;

    // Source: 192.168.1.100:54321
    flow->tuple.src_ip.family = AF_INET;
    inet_pton(AF_INET, "192.168.1.100", &flow->tuple.src_ip.ipv4);
    flow->tuple.src_port = 54321;

    // Destination: 93.184.216.34:443 (example.com)
    flow->tuple.dst_ip.family = AF_INET;
    inet_pton(AF_INET, "93.184.216.34", &flow->tuple.dst_ip.ipv4);
    flow->tuple.dst_port = 443;
    flow->tuple.protocol = IPPROTO_TCP;

    // Timestamps
    flow->start_time_ms = 1730246400000;
    flow->end_time_ms = 1730246420000;

    // Traffic
    flow->bytes_sent = 1024;
    flow->bytes_received = 8192;
    flow->packets_sent = 12;
    flow->packets_received = 18;

    // Process
    flow->process.pid = 5678;
    strcpy(flow->process.name, "firefox");
    strcpy(flow->process.path, "/usr/bin/firefox");
    strcpy(flow->process.username, "testuser");

    // Network
    strcpy(flow->destination_hostname, "example.com");

    // Metadata
    flow->direction = NVM_FLOW_DIR_OUTBOUND;
    flow->stage = NVM_FLOW_STAGE_END;
}
```

### 10.2 Mock Collector Server

```python
#!/usr/bin/env python3
# mock_collector.py - Simple IPFIX collector for testing

import socket
import struct
import sys

IPFIX_VERSION = 10
PORT = 2055

def parse_ipfix_header(data):
    version, length, export_time, seq_num, obs_domain = struct.unpack('!HHIII', data[:16])
    return {
        'version': version,
        'length': length,
        'export_time': export_time,
        'sequence_number': seq_num,
        'observation_domain_id': obs_domain
    }

def parse_set_header(data):
    set_id, length = struct.unpack('!HH', data[:4])
    return {'set_id': set_id, 'length': length}

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', PORT))
    print(f"[*] Listening on 0.0.0.0:{PORT}")

    while True:
        data, addr = sock.recvfrom(65536)
        print(f"\n[+] Received {len(data)} bytes from {addr[0]}:{addr[1]}")

        # Parse IPFIX header
        header = parse_ipfix_header(data)
        print(f"    Version: {header['version']}")
        print(f"    Length: {header['length']}")
        print(f"    Sequence: {header['sequence_number']}")

        if header['version'] != IPFIX_VERSION:
            print(f"    [!] Invalid IPFIX version: {header['version']}")
            continue

        # Parse sets
        offset = 16
        while offset < len(data):
            set_hdr = parse_set_header(data[offset:])
            print(f"    Set ID: {set_hdr['set_id']}, Length: {set_hdr['length']}")

            if set_hdr['set_id'] == 2:
                print(f"        [Template Set]")
            elif set_hdr['set_id'] >= 256:
                print(f"        [Data Set]")

            offset += set_hdr['length']

if __name__ == '__main__':
    main()
```

### 10.3 Validation Checklist

**Protocol Compliance:**
- [ ] IPFIX version field = 10
- [ ] Sequence numbers increment monotonically
- [ ] Set lengths are correct (including padding to 4-byte boundary)
- [ ] Template IDs >= 256
- [ ] Enterprise IEs have bit 15 set (0x8000)

**Data Accuracy:**
- [ ] Flow 5-tuples match captured packets
- [ ] Byte/packet counts are accurate
- [ ] Timestamps in milliseconds since epoch
- [ ] Process names match running processes
- [ ] DNS resolutions are correct

**Performance:**
- [ ] CPU overhead < 5% under normal load
- [ ] Memory usage < 100 MB for 10K active flows
- [ ] No packet drops at 1000 flows/sec
- [ ] Latency < 100ms from packet capture to export

**Reliability:**
- [ ] Graceful handling of collector unavailability
- [ ] SQLite cache persists across restarts
- [ ] No memory leaks over 24-hour run
- [ ] No crashes under stress test (100K flows)

---

## 11. Performance Considerations

### 11.1 CPU Overhead

**Target:** < 5% CPU on typical workstation (Intel Core i5, 2.5 GHz)

**Optimization Strategies:**

1. **eBPF Filtering**: Only capture TCP/UDP ports of interest (e.g., 80, 443, 8080)
2. **Flow Sampling**: Sample 1 in N flows for high-throughput servers
3. **Batching**: Send IPFIX messages with 50-100 records per packet
4. **Lock-Free Data Structures**: Use atomic operations for counters
5. **Worker Threads**: Process flows in parallel across CPU cores

### 11.2 Memory Usage

**Target:** < 100 MB for 10,000 active flows

**Memory Breakdown:**
- Flow hash table: 10K flows × 500 bytes = 5 MB
- DNS cache: 1K entries × 300 bytes = 300 KB
- SQLite cache: 10K records × 2 KB = 20 MB (on disk)
- eBPF maps: 10K entries × 200 bytes = 2 MB
- **Total:** ~27 MB

**Memory Management:**
- Use memory pools for flow allocations (reduce malloc overhead)
- Periodic cleanup of stale flows (> 120 seconds idle)
- LRU eviction for DNS cache
- Compress SQLite cache with ZSTD

### 11.3 Network Bandwidth

**Estimate for 1000 flows/second:**
- Average IPFIX record size: 200 bytes
- IPFIX header overhead: 16 bytes
- Total per second: 1000 × 200 + 16 = 200 KB/s
- With 50% compression: 100 KB/s
- **Daily:** 100 KB/s × 86400 = 8.6 GB/day

**Bandwidth Optimization:**
- Enable compression (DTLS supports gzip)
- Filter out low-value flows (DNS, ICMP)
- Aggregate short-lived flows (< 1 second)
- Reduce report frequency for long-lived flows

### 11.4 Scalability Limits

| Configuration | Max Flows/sec | Max Active Flows | CPU Usage | Memory |
|---------------|---------------|------------------|-----------|--------|
| Embedded (RPi 4) | 100 | 1,000 | 10% | 50 MB |
| Desktop (i5) | 1,000 | 10,000 | 5% | 100 MB |
| Server (Xeon) | 10,000 | 100,000 | 20% | 1 GB |
| High-End Server | 100,000 | 1,000,000 | 50% | 10 GB |

---

## 12. Security Implementation

### 12.1 Certificate Pinning

```c
// Verify collector certificate hash
bool verify_cert_pinning(SSL *ssl, const char *expected_hash) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) return false;

    // Calculate SHA256 of certificate DER encoding
    unsigned char hash[32];
    unsigned int hash_len;

    unsigned char *der = nullptr;
    int der_len = i2d_X509(cert, &der);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, der, der_len);
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    OPENSSL_free(der);
    X509_free(cert);

    // Convert to hex string
    char hash_str[65];
    for (unsigned int i = 0; i < 32; i++) {
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    }
    hash_str[64] = '\0';

    return (strcasecmp(hash_str, expected_hash) == 0);
}
```

### 12.2 PII Filtering

```c
// Scrub sensitive data from command-line arguments
void sanitize_cmdline_args(char *args) {
    // Example: Remove --password=XXX patterns
    char *p = args;
    while ((p = strstr(p, "--password=")) != nullptr) {
        char *end = strchr(p, ' ');
        size_t len = end ? (end - p) : strlen(p);
        memset(p + 11, '*', len - 11);
    }

    // Add more patterns as needed (API keys, tokens, etc.)
}
```

### 12.3 Rate Limiting

```c
// Token bucket rate limiter
struct rate_limiter {
    double tokens;
    double max_tokens;
    double refill_rate;  // tokens per second
    struct timespec last_refill;
};

bool rate_limiter_allow(struct rate_limiter *limiter) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    double elapsed = (now.tv_sec - limiter->last_refill.tv_sec) +
                     (now.tv_nsec - limiter->last_refill.tv_nsec) / 1e9;

    limiter->tokens += elapsed * limiter->refill_rate;
    if (limiter->tokens > limiter->max_tokens) {
        limiter->tokens = limiter->max_tokens;
    }

    limiter->last_refill = now;

    if (limiter->tokens >= 1.0) {
        limiter->tokens -= 1.0;
        return true;
    }

    return false;
}
```

### 12.4 Secure Storage

```c
// Encrypt SQLite cache at rest
int encrypt_cache_file(const char *plaintext_path, const char *encrypted_path) {
    // Use AES-256-GCM with key derived from device UUID
    unsigned char key[32];
    derive_key_from_device_id(key, sizeof(key));

    // Encrypt file (implementation using OpenSSL EVP API)
    // ... (omitted for brevity)

    return 0;
}
```

---

## Appendices

### Appendix A: IPFIX Information Element Registry

See: https://www.iana.org/assignments/ipfix/ipfix.xhtml

### Appendix B: Cisco Enterprise Number (PEN)

Cisco Systems: **9**

### Appendix C: Kernel Module Build Instructions

```bash
cd /opt/projects/repositories/cisco-secure-client/cisco-secure-client-linux64-5.1.2.42/nvm
tar -xzf ac_kdf_src.tar.gz
cd kdf/lkm
make
sudo insmod anyconnect_kdf.ko
```

### Appendix D: References

1. **RFC 7011**: IPFIX Protocol Specification
2. **RFC 7012**: IPFIX Information Elements
3. **RFC 3954**: Cisco NetFlow v9
4. **RFC 6347**: DTLS 1.2
5. **Cisco NVM Admin Guide**: https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/nvm-collector-5-1-1-admin-guide.html
6. **eBPF Documentation**: https://ebpf.io/
7. **OpenSSL DTLS**: https://www.openssl.org/docs/man3.0/man7/ossl-guide-tls-introduction.html

---

**End of Document**
