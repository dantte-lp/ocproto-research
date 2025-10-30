# Cisco Secure Client Reverse Engineering Tools

**Version**: 2.0
**Date**: 2025-10-30
**Status**: Production Ready

Modern container-based reverse engineering environment using **Buildah**, **Podman**, and **Skopeo** for multi-version Cisco Secure Client analysis.

---

## Overview

This containerized environment provides a comprehensive toolkit for analyzing Cisco Secure Client binaries across multiple versions (4.9, 4.10, 5.0, 5.1).

> **Note**: Proprietary tools (IDA Pro) are NOT included in this repository. Install separately and mount from `/opt/software/IDA_Pro_9.2.250908/` as documented below.

### Tools Included

| Tool | Version | Purpose |
|------|---------|---------|
| **IDA Pro** | 9.2.250908 | Deep decompilation (mounted from host) |
| **Ghidra** | 11.3 | Open-source decompilation & batch processing |
| **radare2** | 5.9.4 | Binary diffing, quick disassembly |
| **angr** | 9.2.142 | Symbolic execution, security validation |
| **GNU Binutils** | System | objdump, nm, readelf, strings |
| **GDB** | System | Dynamic debugging |
| **strace/ltrace** | System | System call tracing |

### Modern Container Stack

- **Containerfile**: OCI-compliant container definition (not Dockerfile)
- **compose.yaml**: Compose Specification v3 (not docker-compose.yml)
- **Buildah**: Builds OCI containers
- **Podman**: Daemonless container runtime
- **Skopeo**: Container image operations (push, inspect, copy)

---

## Quick Start

### Prerequisites

```bash
# Check versions
buildah --version  # 1.27+
podman --version   # 4.0+
podman-compose --version  # 1.0+
skopeo --version   # 1.9+
```

If missing, install on Oracle Linux/RHEL:
```bash
sudo dnf install -y buildah podman podman-compose skopeo
```

### 1. Build Container

```bash
cd /opt/projects/repositories/ocproto-research/reverse-engineering-tools
make build
```

This uses **Buildah** to build the container image.

### 2. Start Workspace

```bash
make run
```

This uses **podman-compose** to start the environment with all volume mounts configured.

### 3. Access Shell

```bash
make shell
```

You're now in the container with access to all analysis tools and binaries.

### 4. Stop Workspace

```bash
make stop
```

---

## Makefile Commands

### Build & Distribution
```bash
make build          # Build container image with Buildah
make push           # Push to registry with Skopeo
make save           # Export to tarball
make load           # Import from tarball
```

### Runtime Management
```bash
make run            # Start workspace
make stop           # Stop workspace
make shell          # Interactive shell
make logs           # View container logs
```

### Testing & Inspection
```bash
make test           # Test all tools
make inspect        # Inspect image metadata
make info           # Show system and image info
```

### Analysis Workflows
```bash
make recon          # Run reconnaissance on all binaries
make ghidra         # Start Ghidra GUI
make ida            # Start IDA Pro GUI
```

### Maintenance
```bash
make clean          # Remove containers and images
make purge          # Clean + delete output data
make rebuild        # Clean rebuild from scratch
```

---

## Volume Mounts

The following directories are mounted in the container:

| Host Path | Container Path | Access | Purpose |
|-----------|---------------|--------|---------|
| `../binaries` | `/workspace/binaries` | **Read-only** | Cisco binaries (all versions) |
| `../analysis` | `/workspace/analysis` | Read-write | Analysis workspace |
| `/opt/software/IDA_Pro_9.2.250908` | `/opt/ida` | **Read-only** | IDA Pro installation |
| `./scripts` | `/workspace/scripts` | **Read-only** | Analysis scripts |
| `./output` | `/workspace/output` | Read-write | Analysis results |
| `./ghidra-projects` | `/workspace/ghidra-projects` | Read-write | Ghidra project files |

---

## Usage Examples

### Reconnaissance Phase

Extract strings and keywords from all binaries:

```bash
make recon
```

Or manually:

```bash
podman exec cisco-re-workspace bash -c '
  for binary in $(find /workspace/binaries -type f -executable); do
    echo "Analyzing: $binary"
    file $binary
    strings -n 8 $binary | grep -E "(CSTP|DTLS|X-CSTP|X-DTLS)"
  done
'
```

### Ghidra Batch Analysis

```bash
podman exec cisco-re-workspace bash -c '
  /tools/ghidra/support/analyzeHeadless \
    /workspace/ghidra-projects \
    CiscoMultiVersion \
    -import /workspace/binaries/5.1/predeploy/linux-x64/vpnagentd \
    -postScript ExportFunctions.py
'
```

### Binary Comparison (radare2)

Compare vpnagentd across versions:

```bash
podman exec cisco-re-workspace radiff2 \
  /workspace/binaries/4.9/predeploy/linux-x64/vpnagentd \
  /workspace/binaries/5.1/predeploy/linux-x64/vpnagentd
```

### IDA Pro Batch Analysis

```bash
podman exec cisco-re-workspace /opt/ida/idat64 \
  -A \
  -S/workspace/scripts/export_functions.py \
  /workspace/binaries/5.1/predeploy/linux-x64/vpnagentd
```

### angr Symbolic Execution

```bash
podman exec -it cisco-re-workspace python3 << 'EOF'
import angr
import sys

binary = '/workspace/binaries/5.1/predeploy/linux-x64/vpnagentd'
project = angr.Project(binary, auto_load_libs=False)

# Analysis here
print(f"Loaded: {project.filename}")
print(f"Architecture: {project.arch}")
print(f"Entry point: {hex(project.entry)}")
EOF
```

---

## Architecture

### Multi-Version Binary Structure

```
binaries/
├── 4.9/
│   ├── predeploy/
│   ├── webdeploy/
│   └── utils/
├── 4.10/
│   ├── predeploy/
│   ├── webdeploy/
│   └── utils/
├── 5.0/
│   ├── predeploy/
│   ├── webdeploy/
│   └── utils/
└── 5.1/
    ├── predeploy/
    ├── webdeploy/
    └── utils/
```

### Container Workflow

```
┌──────────────┐
│   Buildah    │  Build OCI image
│ (build time) │
└──────┬───────┘
       │
       v
┌──────────────┐
│   Podman     │  Run container
│  (runtime)   │
└──────┬───────┘
       │
       v
┌──────────────┐
│  Analysis    │  Ghidra, radare2, angr
│   Workspace  │  /workspace/*
└──────┬───────┘
       │
       v
┌──────────────┐
│    Output    │  Results, reports
│  /workspace/ │  Persistent volumes
│    output/   │
└──────────────┘
```

---

## Advanced Usage

### Custom Registry Push

```bash
# Set registry in environment
export REGISTRY=registry.wolfguard.internal

# Push with Skopeo
make push
```

### Export for Offline Use

```bash
# Export to tarball
make save

# Transfer cisco-re-tools.tar to offline system

# Import on offline system
make load
```

### X11 Forwarding for GUI Tools

```bash
# Allow X11 connections
xhost +local:

# Start Ghidra GUI
make ghidra

# Or IDA Pro GUI
make ida
```

### Persistent Ghidra Projects

Ghidra projects are stored in `./ghidra-projects` (persistent volume):

```bash
ls -la ghidra-projects/
# CiscoMultiVersion.gpr
# CiscoMultiVersion.rep/
```

---

## Troubleshooting

### Ghidra Out of Memory

Increase Java heap:

```bash
export _JAVA_OPTIONS="-Xmx8g"
make run
```

### IDA Pro Not Found

Ensure IDA Pro is installed at:
```
/opt/software/IDA_Pro_9.2.250908/
```

Or update `compose.yaml` to point to your installation.

### Permission Denied on Volumes

Check SELinux contexts:

```bash
# Disable SELinux labels temporarily
sudo setenforce 0

# Or add :Z to volumes in compose.yaml
# - ../binaries:/workspace/binaries:ro,Z
```

### Container Won't Start

Check logs:

```bash
make logs
```

Test individual tools:

```bash
make test
```

---

## Development

### Testing Changes

```bash
# Rebuild after modifying Containerfile
make rebuild

# Run tests
make test
```

### Adding Analysis Scripts

Place scripts in `./scripts/`:

```bash
mkdir -p scripts
cat > scripts/my_analysis.py << 'EOF'
#!/usr/bin/env python3
import sys
# Your analysis code
EOF
chmod +x scripts/my_analysis.py
```

Access in container:

```bash
podman exec cisco-re-workspace /workspace/scripts/my_analysis.py
```

---

## Security Notes

### Container Security

- **Non-root user**: Container runs as `analyst` (UID 1000)
- **Read-only binaries**: Source binaries mounted read-only
- **Capability dropping**: All capabilities dropped except SYS_PTRACE
- **Network isolation**: Isolated bridge network
- **Resource limits**: CPU and memory constrained

### Analysis Safety

- **Always mount binaries read-only** (`ro` flag)
- **Run in isolated VM** if analyzing untrusted binaries
- **Review extracted data** before copying to host
- **Use separate analysis and implementation teams** (clean room)

---

## Legal Compliance

This reverse engineering environment is used exclusively for **interoperability purposes** under:

- **DMCA §1201(f)** - Reverse Engineering for Interoperability
- **Clean Room Methodology** - Separation of analysis and implementation
- **Fair Use** - Educational and research purposes

**Purpose**: Creating compatible open-source VPN server implementation (WolfGuard).

**Restrictions**:
- ❌ Do not distribute proprietary binaries
- ❌ Do not circumvent license protection
- ❌ Do not copy Cisco code verbatim
- ✅ Document protocols and behaviors only

---

## References

- **Buildah**: https://buildah.io/
- **Podman**: https://podman.io/
- **Skopeo**: https://github.com/containers/skopeo
- **Compose Specification**: https://github.com/compose-spec/compose-spec
- **Ghidra**: https://github.com/NationalSecurityAgency/ghidra
- **radare2**: https://rada.re/
- **angr**: https://angr.io/

---

## Changelog

### Version 2.0 (2025-10-30)
- Migrated to Buildah/Podman/Skopeo stack
- Renamed Dockerfile → Containerfile (OCI standard)
- Renamed docker-compose.yml → compose.yaml (Compose Spec)
- Added comprehensive Makefile
- Added multi-version binary support
- Removed Binary Ninja (not acquired)
- Added IDA Pro mount support

### Version 1.0 (2025-10-29)
- Initial release with Docker
- Ghidra, Reko, angr, radare2
- Single version analysis (5.1.12.146)

---

**Maintained by**: WolfGuard Reverse Engineering Team
**Last Updated**: 2025-10-30
**Status**: Production Ready
