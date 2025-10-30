# Contributing to OpenConnect Protocol Research

Thank you for your interest in contributing! This project is conducted under DMCA §1201(f) for interoperability research.

## ⚖️ Legal Requirements

**Before contributing, you MUST**:
1. Ensure your contribution complies with DMCA §1201(f)
2. Not include proprietary binaries or copyrighted code
3. Document interoperability purpose
4. Respect all applicable laws and licenses

## 🤝 How to Contribute

### 1. Analysis Contributions

**Share your findings**:
- Protocol specifications discovered
- Binary analysis results
- Cross-version comparisons
- Cipher suite documentation

**Format**: Create markdown documentation following existing structure.

**Example**:
```markdown
## TLS 1.3 Cipher Suite Analysis (Version 5.1)

**Discovery Method**: String analysis in libacciscossl.so

**Findings**:
- TLS_AES_256_GCM_SHA384 (supported)
- TLS_CHACHA20_POLY1305_SHA256 (supported)

**Evidence**:
\`\`\`
strings libacciscossl.so | grep TLS13
\`\`\`

**WolfGuard Impact**: Must support these cipher suites for TLS 1.3
```

### 2. Tool Contributions

**Automation scripts welcome**:
- Binary cataloging improvements
- String extraction tools
- Protocol parsers
- Analysis automation

**Requirements**:
- Python 3.12+ or Bash
- Well-documented
- Include usage examples
- MIT licensed

### 3. Documentation Improvements

**Help improve**:
- Methodology documentation
- Tool usage guides
- Analysis templates
- README clarity

### 4. Issue Reports

**Report**:
- Errors in analysis
- Missing documentation
- Tool issues
- Methodology improvements

## 📝 Contribution Process

### Step 1: Check Existing Work

1. Search [existing issues](https://github.com/YOUR-ORG/ocproto-research/issues)
2. Review [project board](https://github.com/YOUR-ORG/ocproto-research/projects/1)
3. Read analysis plans in `analysis/`

### Step 2: Create an Issue

**Before submitting pull request**, create an issue:

```markdown
**Title**: [VERSION] Brief description

**Type**: Analysis / Tool / Documentation / Bug

**Description**:
- What you're contributing
- Interoperability purpose
- Legal compliance confirmation

**Checklist**:
- [ ] No proprietary binaries included
- [ ] Analysis methodology documented
- [ ] Interoperability purpose clear
- [ ] Follows project structure
```

### Step 3: Fork and Branch

```bash
# Fork repository (GitHub UI)

# Clone your fork
git clone https://github.com/YOUR-USERNAME/ocproto-research.git
cd ocproto-research

# Create feature branch
git checkout -b feature/version-5.1-tls-analysis
```

### Step 4: Make Changes

**Follow structure**:
```
analysis/
└── 5.1/
    └── tls-1.3-analysis.md  # Your new analysis
```

**Documentation standards**:
- Use markdown
- Include evidence (strings, symbols, etc.)
- Document methodology
- Reference source binaries (without including them)

### Step 5: Commit

```bash
git add analysis/5.1/tls-1.3-analysis.md
git commit -m "[5.1] Add TLS 1.3 cipher suite analysis

- Document supported cipher suites
- Extract from libacciscossl.so strings
- Map to wolfSSL equivalents

Purpose: Interoperability (DMCA §1201(f))"
```

### Step 6: Submit Pull Request

**PR Template**:
```markdown
## Description
[What this PR adds]

## Interoperability Purpose
[How this contributes to WolfGuard compatibility]

## Legal Compliance
- [ ] No proprietary binaries included
- [ ] Analysis under DMCA §1201(f)
- [ ] Original work or properly attributed

## Testing
[How analysis was verified]

## Related Issues
Closes #123
```

## ❌ What NOT to Contribute

**DO NOT submit**:
- Proprietary binaries (.exe, .dll, .so, .tar.gz, .msi, .pkg)
- Decompiled source code from Cisco
- Copyrighted documentation
- IDA Pro / Ghidra project files with binaries
- Credentials or secrets
- Circumvention tools (non-interoperability)

**These will be rejected immediately**

## ✅ Contribution Checklist

Before submitting:

- [ ] No binaries committed (`git status | grep -E "\.(exe|dll|so|tar\.gz)"` returns nothing)
- [ ] Documentation follows markdown standards
- [ ] Analysis methodology clear
- [ ] Interoperability purpose documented
- [ ] LICENSE compliance confirmed
- [ ] Tests pass (if applicable)
- [ ] PR description complete

## 🔍 Review Process

1. **Automated checks**: CI validates no binaries, proper formatting
2. **Legal review**: Ensure DMCA §1201(f) compliance
3. **Technical review**: Analysis accuracy, methodology soundness
4. **Approval**: 1+ maintainer approval required
5. **Merge**: Squash and merge to main

## 📊 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in relevant documentation
- Acknowledged in release notes

## 🤔 Questions?

- **Legal questions**: See [docs/legal-compliance.md](docs/legal-compliance.md)
- **Technical questions**: Open a [discussion](https://github.com/YOUR-ORG/ocproto-research/discussions)
- **Security issues**: Email security@wolfguard.io (private disclosure)

## 📜 Code of Conduct

Be respectful, professional, and focused on interoperability research. This is an educational and technical project.

---

Thank you for contributing to open VPN interoperability!
