#!/usr/bin/env bash
#
# github-setup.sh - Automate GitHub repository setup for ocproto-research
#
# Usage: ./scripts/github-setup.sh YOUR-ORG
#
# Prerequisites:
#   - gh CLI installed and authenticated (gh auth login)
#   - Repository name: ocproto-research
#

set -euo pipefail

# Configuration
ORG="${1:-YOUR-ORG}"
REPO_NAME="ocproto-research"
REPO_FULL="${ORG}/${REPO_NAME}"
REPO_DESC="OpenConnect Protocol Research - Reverse engineering for VPN interoperability (DMCA §1201(f))"
REPO_HOMEPAGE="https://docs.wolfguard.io"

echo "=========================================="
echo "GitHub Repository Setup"
echo "=========================================="
echo "Organization: ${ORG}"
echo "Repository: ${REPO_NAME}"
echo "Full name: ${REPO_FULL}"
echo "=========================================="
echo ""

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "ERROR: GitHub CLI (gh) not found"
    echo "Install: sudo dnf install gh"
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo "ERROR: Not authenticated with GitHub"
    echo "Run: gh auth login"
    exit 1
fi

echo "Step 1: Creating GitHub repository..."
if gh repo view "${REPO_FULL}" &> /dev/null; then
    echo "  ✅ Repository already exists: ${REPO_FULL}"
else
    gh repo create "${REPO_FULL}" \
        --public \
        --description "${REPO_DESC}" \
        --homepage "${REPO_HOMEPAGE}"
    echo "  ✅ Repository created: ${REPO_FULL}"
fi
echo ""

echo "Step 2: Creating milestones..."

# Milestone 1: Multi-Version Binary Cataloging (COMPLETED)
echo "  Creating Milestone 1: Multi-Version Binary Cataloging..."
gh api "repos/${REPO_FULL}/milestones" \
    -f title="1. Multi-Version Binary Cataloging" \
    -f description="Extract and catalog all binaries from versions 4.9, 4.10, 5.0, 5.1 across Windows, Linux, macOS platforms. Package types: Predeploy, Webdeploy, Utils. Target: 72+ binaries cataloged with metadata." \
    -f due_on="2025-11-13T23:59:59Z" \
    -f state="closed" || echo "  ⚠️  Milestone 1 may already exist"

# Milestone 2: Predeploy Analysis (IN PROGRESS)
echo "  Creating Milestone 2: Predeploy Analysis..."
gh api "repos/${REPO_FULL}/milestones" \
    -f title="2. Predeploy Analysis" \
    -f description="Static and dynamic analysis of predeploy packages (standalone installers). Focus: vpnagentd, libvpnapi.so, libacciscossl.so, protocol handlers, authentication flows. Tools: IDA Pro, Ghidra, radare2. Target: 20% complete." \
    -f due_on="2025-12-11T23:59:59Z" \
    -f state="open" || echo "  ⚠️  Milestone 2 may already exist"

# Milestone 3: Webdeploy Analysis (PLANNED)
echo "  Creating Milestone 3: Webdeploy Analysis..."
gh api "repos/${REPO_FULL}/milestones" \
    -f title="3. Webdeploy Analysis" \
    -f description="Analysis of web deployment protocol and implementation. Server-side deployment packages (Cisco ASA-style). Focus: HTTPS delivery, manifest parsing, package installation logic. Target: Complete webdeploy specification." \
    -f due_on="2026-01-01T23:59:59Z" \
    -f state="open" || echo "  ⚠️  Milestone 3 may already exist"

# Milestone 4: Utils Analysis (PLANNED)
echo "  Creating Milestone 4: Utils Analysis..."
gh api "repos/${REPO_FULL}/milestones" \
    -f title="4. Utils Analysis" \
    -f description="Analysis of Profile Editor, VPN API, and Transforms utilities. Focus: XML profile schema, VPN API bindings, configuration transforms. Target: Complete utilities documentation." \
    -f due_on="2026-01-22T23:59:59Z" \
    -f state="open" || echo "  ⚠️  Milestone 4 may already exist"

# Milestone 5: Protocol Specification (FINAL)
echo "  Creating Milestone 5: Protocol Specification Complete..."
gh api "repos/${REPO_FULL}/milestones" \
    -f title="5. Protocol Specification Complete" \
    -f description="Complete OpenConnect protocol specification for WolfGuard implementation. Deliverable: Full CSTP, DTLS, authentication specification with multi-version compatibility matrix." \
    -f due_on="2026-02-12T23:59:59Z" \
    -f state="open" || echo "  ⚠️  Milestone 5 may already exist"

echo "  ✅ Milestones created"
echo ""

echo "Step 3: Creating initial issues..."

# Issue #1: Version 5.1 Linux predeploy analysis
echo "  Creating Issue #1: Linux predeploy analysis..."
gh issue create \
    --repo "${REPO_FULL}" \
    --title "[5.1] Analyze Linux x86_64 predeploy binaries" \
    --label "analysis,version-5.1,linux,high-priority" \
    --milestone "2" \
    --body "## Objective

Extract and analyze Linux x86_64 predeploy package for version 5.1.12.146.

## Binaries to Analyze

- vpnagentd (main daemon)
- libvpnapi.so (client API)
- libacciscossl.so (TLS/DTLS)
- libacciscocrypto.so (cryptography)
- vpnui (user interface)

## Tasks

- [ ] Extract predeploy package
- [ ] Catalog binaries with metadata (size, hash, symbols)
- [ ] Symbol extraction (nm -D, readelf -s)
- [ ] String analysis (protocol strings, error messages)
- [ ] Identify TLS 1.3 implementation
- [ ] Document authentication flow
- [ ] Create analysis/5.1/linux-predeploy-x64.md

## Tools

- GNU Binutils (nm, readelf, strings, objdump)
- IDA Pro 9.2 (deep decompilation)
- RE container environment

## Expected Deliverables

1. Binary metadata catalog
2. Symbol extraction output
3. Protocol string analysis
4. Detailed analysis document

## Milestone

Predeploy Analysis (Week 6)

## Priority

High

## Estimated Effort

8-12 hours" || echo "  ⚠️  Issue #1 may already exist"

# Issue #2: Cross-version vpnagentd comparison
echo "  Creating Issue #2: Cross-version comparison..."
gh issue create \
    --repo "${REPO_FULL}" \
    --title "[ALL] Cross-version vpnagentd evolution analysis" \
    --label "analysis,comparison,high-priority" \
    --milestone "2" \
    --body "## Objective

Perform binary diff analysis of vpnagentd across versions 4.9, 4.10, 5.0, 5.1 to track protocol evolution.

## Goal

Understand how OpenConnect protocol evolved over 4 major versions.

## Tools

- radare2 (binary diffing)
- IDA Pro BinDiff (function comparison)
- Python (automation)

## Tasks

- [ ] Extract vpnagentd from all 4 versions
- [ ] Run radare2 binary diff (4.9 vs 4.10, 4.10 vs 5.0, 5.0 vs 5.1)
- [ ] Identify new functions added in each version
- [ ] Identify removed/deprecated functions
- [ ] Track TLS version support evolution
- [ ] Document protocol changes by version
- [ ] Create protocol evolution timeline
- [ ] Map changes to WolfGuard requirements

## Expected Deliverables

1. analysis/version-comparison/vpnagentd-evolution.md
2. Function diff tables (added/removed/modified)
3. Protocol change timeline
4. WolfGuard compatibility matrix

## Milestone

Predeploy Analysis (Week 6)

## Priority

High

## Estimated Effort

16-20 hours" || echo "  ⚠️  Issue #2 may already exist"

# Issue #3: TLS 1.3 implementation analysis
echo "  Creating Issue #3: TLS 1.3 analysis..."
gh issue create \
    --repo "${REPO_FULL}" \
    --title "[5.1] Deep dive: TLS 1.3 handshake implementation" \
    --label "analysis,version-5.1,crypto,critical" \
    --milestone "2" \
    --body "## Objective

Decompile and document TLS 1.3 handshake implementation in libacciscossl.so (version 5.1).

## Goal

Understand TLS 1.3 implementation for accurate wolfSSL mapping in WolfGuard.

## Binary

- libacciscossl.so (version 5.1.12.146)
- Platform: Linux x86_64

## Tool

IDA Pro 9.2 (advanced decompilation required)

## Tasks

- [ ] Load libacciscossl.so in IDA Pro
- [ ] Locate TLS 1.3 handshake function
- [ ] Decompile to C pseudocode
- [ ] Identify cipher suite selection logic
- [ ] Document certificate validation flow
- [ ] Identify key exchange mechanism (ECDHE, DHE)
- [ ] Document session resumption (PSK)
- [ ] Map to wolfSSL API equivalents
- [ ] Create sequence diagram
- [ ] Document WolfGuard implementation requirements

## Expected Deliverables

1. analysis/5.1/tls-1.3-implementation.md
2. Decompiled pseudocode
3. TLS 1.3 sequence diagram
4. wolfSSL mapping table
5. WolfGuard implementation notes

## Milestone

Predeploy Analysis (Week 6)

## Priority

Critical

## Estimated Effort

20-24 hours" || echo "  ⚠️  Issue #3 may already exist"

echo "  ✅ Initial issues created"
echo ""

echo "=========================================="
echo "GitHub Setup Complete!"
echo "=========================================="
echo ""
echo "Repository URL: https://github.com/${REPO_FULL}"
echo "Issues URL: https://github.com/${REPO_FULL}/issues"
echo "Milestones URL: https://github.com/${REPO_FULL}/milestones"
echo ""
echo "Next steps:"
echo "1. Push local repository to GitHub:"
echo "   cd /opt/projects/repositories/cisco-secure-client"
echo "   git remote add origin https://github.com/${REPO_FULL}.git"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "2. Configure repository settings:"
echo "   - Enable Discussions"
echo "   - Set up branch protection"
echo "   - Create project board"
echo ""
echo "3. Create additional issues as needed"
echo ""
