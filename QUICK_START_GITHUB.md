# Quick Start: GitHub Repository Setup

**Repository Name**: `ocproto-research`
**Purpose**: OpenConnect Protocol Research for VPN interoperability

---

## ⚡ Fast Track (Automated Setup)

### Prerequisites
```bash
# Install GitHub CLI (Oracle Linux)
sudo dnf install gh

# Authenticate with GitHub
gh auth login
```

### One-Command Setup
```bash
cd /opt/projects/repositories/cisco-secure-client

# Run automated setup (replace YOUR-ORG with your GitHub org)
./scripts/github-setup.sh YOUR-ORG
```

**This script will**:
- ✅ Create GitHub repository
- ✅ Create 5 milestones
- ✅ Create 3 initial issues
- ✅ Display next steps

### Push Repository
```bash
# Add remote (replace YOUR-ORG)
git remote add origin https://github.com/YOUR-ORG/ocproto-research.git

# Push to GitHub
git branch -M main
git push -u origin main
```

**Done!** 🎉 Repository is live at: `https://github.com/YOUR-ORG/ocproto-research`

---

## 📋 Manual Setup (Alternative)

### Step 1: Create Repository

**Web Interface**:
1. Go to https://github.com/new
2. Repository name: `ocproto-research`
3. Description: "OpenConnect Protocol Research - Reverse engineering for VPN interoperability (DMCA §1201(f))"
4. Visibility: **Public**
5. **DO NOT** initialize with README, LICENSE, or .gitignore (we have them)
6. Click "Create repository"

**CLI**:
```bash
gh repo create YOUR-ORG/ocproto-research \
  --public \
  --description "OpenConnect Protocol Research - Reverse engineering for VPN interoperability (DMCA §1201(f))" \
  --homepage "https://docs.wolfguard.io"
```

### Step 2: Push Repository
```bash
cd /opt/projects/repositories/cisco-secure-client

# Add remote
git remote add origin https://github.com/YOUR-ORG/ocproto-research.git

# Push
git branch -M main
git push -u origin main
```

### Step 3: Create Milestones

Copy-paste these commands (replace YOUR-ORG):

```bash
# Milestone 1 (COMPLETED)
gh api repos/YOUR-ORG/ocproto-research/milestones \
  -f title="1. Multi-Version Binary Cataloging" \
  -f description="Extract and catalog binaries from 4.9, 4.10, 5.0, 5.1" \
  -f due_on="2025-11-13T23:59:59Z" \
  -f state="closed"

# Milestone 2 (IN PROGRESS)
gh api repos/YOUR-ORG/ocproto-research/milestones \
  -f title="2. Predeploy Analysis" \
  -f description="Static/dynamic analysis of predeploy packages" \
  -f due_on="2025-12-11T23:59:59Z" \
  -f state="open"

# Milestone 3 (PLANNED)
gh api repos/YOUR-ORG/ocproto-research/milestones \
  -f title="3. Webdeploy Analysis" \
  -f description="Web deployment protocol analysis" \
  -f due_on="2026-01-01T23:59:59Z" \
  -f state="open"

# Milestone 4 (PLANNED)
gh api repos/YOUR-ORG/ocproto-research/milestones \
  -f title="4. Utils Analysis" \
  -f description="Profile Editor, VPN API, Transforms" \
  -f due_on="2026-01-22T23:59:59Z" \
  -f state="open"

# Milestone 5 (FINAL)
gh api repos/YOUR-ORG/ocproto-research/milestones \
  -f title="5. Protocol Specification Complete" \
  -f description="Complete OpenConnect protocol spec" \
  -f due_on="2026-02-12T23:59:59Z" \
  -f state="open"
```

### Step 4: Create Initial Issues

See `GITHUB_SETUP.md` for complete issue creation commands.

**Quick 3 issues**:
```bash
# Issue #1: Linux predeploy
gh issue create --repo YOUR-ORG/ocproto-research \
  --title "[5.1] Analyze Linux x86_64 predeploy binaries" \
  --label "analysis,version-5.1,linux,high-priority" \
  --milestone "2" \
  --body-file .github/issues/issue-1.md

# Issue #2: Cross-version comparison
gh issue create --repo YOUR-ORG/ocproto-research \
  --title "[ALL] Cross-version vpnagentd evolution analysis" \
  --label "analysis,comparison,high-priority" \
  --milestone "2" \
  --body-file .github/issues/issue-2.md

# Issue #3: TLS 1.3 deep dive
gh issue create --repo YOUR-ORG/ocproto-research \
  --title "[5.1] Deep dive: TLS 1.3 handshake implementation" \
  --label "analysis,version-5.1,crypto,critical" \
  --milestone "2" \
  --body-file .github/issues/issue-3.md
```

---

## 🔧 Repository Configuration

### Enable Discussions
```bash
gh api repos/YOUR-ORG/ocproto-research \
  -X PATCH \
  -f has_discussions=true
```

### Set Branch Protection
```bash
gh api repos/YOUR-ORG/ocproto-research/branches/main/protection \
  -X PUT \
  -f required_pull_request_reviews[required_approving_review_count]=1 \
  -f enforce_admins=true \
  -f required_linear_history=true \
  -f allow_force_pushes=false \
  -f allow_deletions=false
```

### Create Project Board

**Web Interface**:
1. Go to https://github.com/YOUR-ORG/ocproto-research/projects
2. Click "New project"
3. Template: "Board"
4. Name: "Analysis Progress"
5. Columns: Backlog, To Do, In Progress, Review, Done

---

## 📊 Verification Checklist

After setup, verify:

- [ ] Repository created: https://github.com/YOUR-ORG/ocproto-research
- [ ] README.md visible with badges
- [ ] LICENSE file present
- [ ] CONTRIBUTING.md present
- [ ] Issue templates available (3 templates)
- [ ] Milestones created (5 milestones)
- [ ] Initial issues created (3+ issues)
- [ ] No binaries in repository (check git log)
- [ ] Discussions enabled
- [ ] Branch protection active

---

## 🎯 What You Get

### Documentation
- ✅ **README.md**: 485 lines, comprehensive overview
- ✅ **LICENSE**: CC BY-SA 4.0 + MIT + DMCA §1201(f)
- ✅ **CONTRIBUTING.md**: Detailed guidelines
- ✅ **GITHUB_SETUP.md**: Complete setup instructions

### Templates
- ✅ **Analysis Task**: Structured binary analysis template
- ✅ **Bug Report**: Error reporting template
- ✅ **Feature Request**: Improvement suggestion template

### Automation
- ✅ **github-setup.sh**: One-command repository setup
- ✅ **Pre-configured milestones**: 5 milestones with dates
- ✅ **Pre-configured issues**: 8 issue templates ready

### Legal Protection
- ✅ **DMCA §1201(f)**: Interoperability exemption
- ✅ **No binaries**: .gitignore blocks proprietary files
- ✅ **Dual licensing**: Documentation + scripts
- ✅ **Trademark notice**: Cisco and WolfGuard acknowledged

---

## 🚀 After Setup

### Link to WolfGuard
```markdown
<!-- Add to wolfguard-docs README.md -->
## Research Repository

Analysis and protocol documentation: [ocproto-research](https://github.com/YOUR-ORG/ocproto-research)
```

### Invite Collaborators
```bash
# Add collaborators with write access
gh api repos/YOUR-ORG/ocproto-research/collaborators/USERNAME \
  -X PUT \
  -f permission=write
```

### Create First Analysis PR
```bash
# Create feature branch
git checkout -b analysis/5.1-linux-predeploy

# Add analysis document
# ... create analysis/5.1/linux-predeploy-x64.md

# Commit and push
git add analysis/5.1/linux-predeploy-x64.md
git commit -m "[5.1] Add Linux x86_64 predeploy analysis

- Document vpnagentd binary
- Extract protocol strings
- Map TLS 1.3 implementation

Purpose: Interoperability (DMCA §1201(f))"

git push -u origin analysis/5.1-linux-predeploy

# Create PR
gh pr create \
  --title "[5.1] Linux x86_64 predeploy analysis" \
  --body "Complete analysis of Linux predeploy package" \
  --assignee @me
```

---

## 📞 Support

- **Questions**: Open a [discussion](https://github.com/YOUR-ORG/ocproto-research/discussions)
- **Issues**: Create an [issue](https://github.com/YOUR-ORG/ocproto-research/issues/new/choose)
- **Security**: Email security@wolfguard.io
- **Documentation**: Read [GITHUB_SETUP.md](GITHUB_SETUP.md)

---

## 🎉 Success!

Your repository is now:
- ✅ Legally compliant (DMCA §1201(f))
- ✅ Professionally structured
- ✅ Ready for collaboration
- ✅ Protected from binary commits
- ✅ Well-documented
- ✅ Automation-ready

**Repository URL**: https://github.com/YOUR-ORG/ocproto-research

**Next**: Start creating analysis documents and opening issues!

---

**Estimated setup time**: 5-15 minutes (automated) or 30-45 minutes (manual)
