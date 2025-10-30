# OpenConnect Protocol Research (ocproto-research)

Reverse engineering and analysis of VPN client implementations for achieving interoperability with the OpenConnect protocol.

[![License](https://img.shields.io/badge/License-CC--BY--SA--4.0-blue.svg)](LICENSE)
[![DMCA](https://img.shields.io/badge/DMCA-§1201(f)-green.svg)](https://www.law.cornell.edu/uscode/text/17/1201)

## ⚖️ Legal Notice

This research is conducted under **17 U.S.C. § 1201(f) - Reverse Engineering** for interoperability purposes.

**Purpose**: Creating compatible, interoperable VPN server implementations (WolfGuard project).

**Scope**: Analysis of publicly available software for protocol documentation only.

**NOT Included**: Proprietary binaries are not distributed in this repository.

## 🎯 Project Goals

1. **Document OpenConnect Protocol**: Complete specification of CSTP, DTLS, authentication
2. **Multi-Version Analysis**: Compare protocol evolution across client versions 4.9 → 5.1
3. **Interoperability Guide**: Enable open-source servers to support standard VPN clients
4. **WolfGuard Integration**: Apply findings to [wolfguard-docs](https://docs.wolfguard.io) project

## 📊 Analysis Scope

### Versions Analyzed

| Version | Release | Status | Progress | Documentation |
|---------|---------|--------|----------|---------------|
| **5.1.12.146** | 2023 | Latest | ✅ 85% | [Analysis](analysis/5.1/) |
| **5.0.05040** | 2022 | Current | 🔄 15% | [Analysis](analysis/5.0/) |
| **4.10.08029** | 2021 | Stable | 🔄 10% | [Analysis](analysis/4.10/) |
| **4.9.06037** | 2020 | Legacy | 📋 5% | [Analysis](analysis/4.9/) |

### Platforms Analyzed

- ✅ **Windows** (x64, ARM64) - Predeploy, Webdeploy, Utils
- ✅ **Linux** (x86_64, ARM64) - Predeploy, Webdeploy, Utils
- ✅ **macOS** (Intel, ARM) - Predeploy, Utils

### Package Types

- **Predeploy**: Standalone installers for direct deployment
- **Webdeploy**: Server-side deployment packages (Cisco ASA-style)
- **Utils**: Profile Editor, VPN API, Transforms

## 🛠️ Methodology

See [Reverse Engineering Guidelines](https://docs.wolfguard.io/docs/cisco-secure-client/reverse-engineering-guidelines) for complete methodology (Russian).

### Tools Used

- **IDA Pro 9.2** - Deep decompilation and C++ analysis
- **Ghidra 11.3** - Batch processing and open-source analysis
- **radare2** - Binary diffing and quick reconnaissance
- **GNU Binutils** - Symbol extraction (`nm`, `readelf`, `strings`)
- **angr** - Symbolic execution for security validation
- **Wireshark** - Protocol capture and analysis

### Container Environment

```bash
# Build RE tools container
cd reverse-engineering-tools
make build

# Start workspace
make run

# Access shell
make shell
```

See [reverse-engineering-tools/README.md](reverse-engineering-tools/README.md) for details.

## 📁 Repository Structure

```
ocproto-research/
├── .github/
│   ├── ISSUE_TEMPLATE/       # Issue templates
│   └── workflows/            # CI/CD (validation only)
├── analysis/
│   ├── BINARY_INVENTORY.md   # 72 files cataloged
│   ├── 4.9/, 4.10/, 5.0/, 5.1/
│   └── version-comparison/
├── docs/
│   ├── methodology.md        # RE methodology
│   ├── tools.md              # Tool usage guide
│   └── legal-compliance.md   # DMCA §1201(f)
├── reverse-engineering-tools/
│   ├── Containerfile         # OCI container
│   ├── compose.yaml          # Podman Compose
│   └── Makefile              # Build automation
├── scripts/
│   ├── binary-catalog.py     # Catalog automation
│   └── string-extractor.sh   # Protocol string extraction
├── .gitignore
├── LICENSE
└── README.md
```

**Note**: Proprietary binaries NOT included. Obtain from [official Cisco sources](https://software.cisco.com/).

## 🚀 Quick Start

### Prerequisites

- **Podman 4.0+** or Docker 20.0+
- **Python 3.12+**
- **IDA Pro 9.2** (optional, for deep analysis)
- **Binaries** (obtain separately, not distributed)

### Setup

```bash
# Clone repository
git clone https://github.com/YOUR-ORG/ocproto-research.git
cd ocproto-research

# Place your binaries (not tracked by git)
mkdir -p binaries/5.1/predeploy/linux-x64
# ... extract your packages here

# Build analysis container
cd reverse-engineering-tools
make build && make run

# Catalog binaries
make shell
python3 /workspace/scripts/binary-catalog.py /workspace/binaries/
```

## 📖 Documentation

> **Comprehensive Guides**: Visit [docs.wolfguard.io/docs/cisco-secure-client/](https://docs.wolfguard.io/docs/cisco-secure-client/) for detailed documentation including:
> - [Reverse Engineering Guidelines](https://docs.wolfguard.io/docs/cisco-secure-client/reverse-engineering-guidelines) (Russian)
> - [Version Comparison Analysis](https://docs.wolfguard.io/docs/cisco-secure-client/version-comparison) (TLS 1.3, DTLS 1.2, Post-Quantum Crypto)
> - Platform-specific analysis (Windows, Linux, macOS)

### Analysis Documentation

- **[Binary Inventory](analysis/BINARY_INVENTORY.md)** - 72 files across 4 versions
- **[5.1 Analysis](analysis/5.1/)** - Latest version (85% complete)

### Analysis Plans

- **[Predeploy Analysis Plan](analysis/ANALYSIS_PLAN_PREDEPLOY.md)** - Standalone installers (6 weeks, 240 hours)
- **[Webdeploy Analysis Plan](analysis/ANALYSIS_PLAN_WEBDEPLOY.md)** - Server-side deployment (4 weeks, 160 hours)
- **[Utils Analysis Plan](analysis/ANALYSIS_PLAN_UTILS.md)** - Profile Editor, VPN API (7 weeks, 280 hours)

## 📊 Progress Tracking

Track analysis progress via:
- **[GitHub Issues](https://github.com/YOUR-ORG/ocproto-research/issues)** - Individual analysis tasks
- **[Milestones](https://github.com/YOUR-ORG/ocproto-research/milestones)** - Major phases
- **[Project Board](https://github.com/YOUR-ORG/ocproto-research/projects/1)** - Kanban view

### Current Milestones

1. **[Multi-Version Binary Cataloging](../../milestone/1)** - ✅ Complete
2. **[Predeploy Analysis](../../milestone/2)** - 🔄 20% (Due: Week 6)
3. **[Webdeploy Analysis](../../milestone/3)** - 📋 Planned (Due: Week 9)
4. **[Utils Analysis](../../milestone/4)** - 📋 Planned (Due: Week 13)

## 🤝 Contributing

This is a research project. Contributions welcome following these guidelines:

### DO:
✅ Share analysis findings and documentation
✅ Improve RE methodology
✅ Add tool automation scripts
✅ Document protocol specifications
✅ Report issues or suggest improvements

### DO NOT:
❌ Commit proprietary binaries
❌ Share copyrighted Cisco code
❌ Violate software licenses
❌ Use for non-interoperability purposes

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 🔗 Related Projects

- **[WolfGuard](https://github.com/YOUR-ORG/wolfguard)** - Open-source VPN server (implementation)
- **[WolfGuard Docs](https://docs.wolfguard.io)** - Documentation site
- **[OpenConnect](https://www.infradead.org/openconnect/)** - Open-source VPN client
- **[ocserv](https://gitlab.com/ocserv/ocserv)** - OpenConnect server (original)

## 📊 Key Findings

### Version 5.1 Highlights

- ✅ **TLS 1.3 Support**: Confirmed with cipher suite analysis
- ✅ **Protocol Compatibility**: 100% backward compatible with 4.x
- ✅ **Binary Analysis**: 197 binaries cataloged (Linux x64, ARM64, Windows)
- ✅ **Function Catalog**: 3,369+ functions documented

See [analysis/5.1/](analysis/5.1/) for detailed findings.

## 📜 License

- **Analysis Documentation**: [Creative Commons BY-SA 4.0](LICENSE)
- **Automation Scripts**: [MIT License](LICENSE)
- **Research Exemption**: DMCA §1201(f) interoperability

## ⚠️ Disclaimer

This research is conducted exclusively for interoperability purposes under 17 U.S.C. § 1201(f). The software being analyzed is copyrighted by Cisco Systems, Inc. This project does not distribute proprietary software or violate copyright protections.

**For Educational and Interoperability Research Only**

---

**Maintained by**: WolfGuard Project Team
**Documentation**: https://docs.wolfguard.io
**Contact**: [Create an issue](https://github.com/YOUR-ORG/ocproto-research/issues/new)
