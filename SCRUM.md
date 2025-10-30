# Scrum Methodology for ocproto-research

**Version**: 1.0
**Date**: 2025-10-30
**Framework**: Scrum for Research & Reverse Engineering

---

## Overview

This document describes how Scrum methodology is applied to the OpenConnect Protocol Research project. While Scrum is traditionally used for software development, we've adapted it for reverse engineering research with specific ceremonies, artifacts, and roles tailored to RE work.

## Sprint Structure

### Sprint Duration
- **Length**: 2 weeks (10 working days)
- **Rationale**: RE work requires focused analysis periods with regular checkpoints

### Sprint Cadence

| Sprint | Dates | Focus Area | Milestone |
|--------|-------|------------|-----------|
| **Sprint 1** | Nov 4 - Nov 15 | Binary cataloging complete, predeploy reconnaissance | Milestone #1 |
| **Sprint 2** | Nov 18 - Nov 29 | vpnagentd analysis (CSTP protocol) | Milestone #2 |
| **Sprint 3** | Dec 2 - Dec 13 | libacciscossl.so (TLS 1.3, DTLS 1.2) | Milestone #2 |
| **Sprint 4** | Dec 16 - Dec 27 | Predeploy module integration & testing | Milestone #2 |
| **Sprint 5** | Dec 30 - Jan 10 | vpndownloader analysis (updates) | Milestone #3 |
| **Sprint 6** | Jan 13 - Jan 24 | acwebhelper (SAML/OAuth) | Milestone #3 |
| **Sprint 7** | Jan 27 - Feb 7 | Profile Editor XML schema | Milestone #4 |
| **Sprint 8** | Feb 10 - Feb 21 | libvpnapi SDK analysis | Milestone #4 |
| **Sprint 9** | Feb 24 - Mar 7 | Cross-platform comparison & diffing | Milestone #4 |
| **Sprint 10** | Mar 10 - Mar 21 | WolfGuard specification & roadmap | Milestone #5 |

---

## Scrum Roles

### Product Owner
**Role**: Defines priorities based on WolfGuard project needs

**Responsibilities**:
- Maintain Product Backlog prioritization
- Define acceptance criteria for analysis tasks
- Make decisions on scope (which binaries/versions to analyze)
- Represent stakeholder needs (WolfGuard team, ocserv community)

### Scrum Master
**Role**: Facilitates Scrum ceremonies and removes blockers

**Responsibilities**:
- Organize sprint planning, review, retrospective
- Track velocity and burndown
- Remove impediments (tooling issues, missing binaries, licensing questions)
- Maintain GitHub Project board

### Development Team
**Role**: Conducts reverse engineering analysis

**Responsibilities**:
- Perform static/dynamic analysis
- Document findings in markdown
- Create analysis scripts (Python, Bash)
- Review and validate findings with peers

**Note**: For solo research, one person may wear multiple hats while maintaining role separation.

---

## Scrum Artifacts

### Product Backlog

The Product Backlog consists of:
1. **GitHub Issues** tagged with `analysis`
2. **Milestones** representing major deliverables
3. **Analysis Plans** (ANALYSIS_PLAN_PREDEPLOY.md, etc.)

**Prioritization Criteria**:
- **P0 (Critical)**: TLS 1.3 handshake, CSTP protocol, DTLS implementation
- **P1 (High)**: Authentication mechanisms, session management
- **P2 (Medium)**: Configuration profiles, diagnostic tools
- **P3 (Low)**: GUI analysis, legacy version comparison

**Story Point Scale** (Fibonacci):
- **1 point**: String extraction, basic reconnaissance (1-2 hours)
- **2 points**: Function identification, symbol mapping (2-4 hours)
- **3 points**: Protocol flow analysis, crypto identification (4-8 hours)
- **5 points**: Deep decompilation, C++ class reconstruction (1-2 days)
- **8 points**: Cross-version binary diffing, protocol spec writing (2-3 days)
- **13 points**: Complex module analysis (e.g., libacciscossl.so) (3-5 days)

### Sprint Backlog

Selected items from Product Backlog for the current sprint.

**Tracked via**:
- GitHub Project board: "Sprint Backlog" column
- `sprint-N` label on issues

**Capacity Planning**:
- Assume 6 hours/day of focused RE work (30 hours/week)
- Velocity: 20-30 story points per 2-week sprint (based on complexity)

### Increment

Each sprint produces a **potentially shippable increment**:
- Updated analysis documentation (.md files)
- Extracted protocol specifications
- Binary analysis scripts
- Updated WolfGuard roadmap

**Acceptance Criteria** (generic):
- [ ] Analysis findings documented in markdown
- [ ] Code examples extracted (if applicable)
- [ ] Protocol flow diagrams created (if applicable)
- [ ] Findings reviewed by peer or validated against OpenConnect
- [ ] Committed to GitHub with proper issue references

---

## Sprint Ceremonies

### Sprint Planning
**Duration**: 2 hours (at sprint start)

**Agenda**:
1. Review previous sprint (what was accomplished)
2. Select issues from Product Backlog for new sprint
3. Break down issues into tasks (if needed)
4. Assign story points
5. Commit to sprint goal

**Sprint Goal Examples**:
- Sprint 1: "Complete multi-version binary catalog and reconnaissance"
- Sprint 2: "Document CSTP protocol flow in vpnagentd"
- Sprint 3: "Extract TLS 1.3 implementation from libacciscossl.so"

### Daily Standup
**Duration**: 15 minutes (daily or every 2 days for solo work)

**Three Questions**:
1. What did I analyze yesterday?
2. What will I analyze today?
3. Are there any blockers? (tools, binaries, understanding)

**Note**: For solo work, use this as a written journal entry in issue comments.

### Sprint Review
**Duration**: 1 hour (at sprint end)

**Agenda**:
1. Demo findings (show decompiled code, protocol flows, diagrams)
2. Update WolfGuard team on interoperability implications
3. Review acceptance criteria completion
4. Update Product Backlog based on new findings

### Sprint Retrospective
**Duration**: 45 minutes (after Sprint Review)

**Questions**:
1. What went well? (e.g., Ghidra scripts worked great)
2. What didn't go well? (e.g., IDA Pro crashed repeatedly)
3. What should we improve? (e.g., automate symbol extraction)

**Action Items**: Create issues for process improvements (labeled `process`).

---

## Definition of Done

An analysis task is **Done** when:

### For Binary Analysis Tasks:
- [ ] Binary loaded in IDA Pro/Ghidra with auto-analysis complete
- [ ] Key functions identified and documented (minimum 10 functions)
- [ ] Function signatures extracted (parameters, return types)
- [ ] Strings extracted and categorized (protocol keywords, error messages)
- [ ] Markdown documentation created in `analysis/` directory
- [ ] Code committed to Git with issue reference (`Fixes #N`)
- [ ] Peer review completed (or self-review checklist)

### For Protocol Analysis Tasks:
- [ ] Protocol flow diagram created (PlantUML or Mermaid)
- [ ] Message format documented (headers, fields, encoding)
- [ ] Authentication mechanism identified
- [ ] Encryption/hashing algorithms identified
- [ ] Comparison with OpenConnect implementation documented
- [ ] Test case scenarios documented
- [ ] Findings added to WolfGuard spec

### For Cross-Version Comparison Tasks:
- [ ] Binary diff completed (radiff2 or BinDiff)
- [ ] Changed functions documented with before/after
- [ ] New features identified (e.g., TLS 1.3 in 5.0+)
- [ ] Deprecated features identified
- [ ] Migration notes created
- [ ] Version comparison table updated

---

## GitHub Integration

### Project Board

**URL**: https://github.com/dantte-lp/ocproto-research/projects/1

**Columns**:
1. **Backlog**: All Product Backlog Items (prioritized)
2. **Sprint Backlog**: Items selected for current sprint
3. **In Progress**: Currently being analyzed
4. **Review**: Analysis complete, awaiting peer review
5. **Done**: Accepted and merged

**Automation**:
- Moving issue to "In Progress" → auto-assigns to sprint
- Moving issue to "Done" → closes issue and updates milestone

### Labels

| Label | Color | Purpose |
|-------|-------|---------|
| `analysis` | Blue (#0366d6) | Analysis tasks |
| `critical` | Red (#d73a4a) | P0 priority (TLS 1.3, CSTP) |
| `predeploy` | Dark Blue (#1d76db) | Predeploy package analysis |
| `webdeploy` | Purple (#5319e7) | Webdeploy package analysis |
| `utils` | Yellow (#fbca04) | Utils package analysis |
| `protocol` | Green (#28a745) | Protocol specification |
| `sprint-N` | Orange (#d93f0b) | Current sprint number |
| `blocked` | Black (#000000) | Blocked (missing tools/binaries) |
| `process` | Grey (#7057ff) | Process improvement |

### Milestones

Milestones map to major project phases (see Sprint Cadence table above).

---

## Metrics & Reporting

### Velocity Tracking

Track completed story points per sprint to estimate future capacity.

**Example**:
```
Sprint 1: 25 points completed
Sprint 2: 28 points completed
Sprint 3: 22 points completed
→ Average velocity: 25 points/sprint
```

### Burndown Chart

GitHub Projects supports burndown tracking. Review weekly:
- Are we on track to complete sprint goal?
- Do we need to descope or add items?

### Analysis Coverage

Track percentage of binaries analyzed per milestone:
```
Milestone #2 (Predeploy): 15/45 binaries analyzed (33%)
Milestone #3 (Webdeploy): 2/18 binaries analyzed (11%)
```

---

## Adaptations for Reverse Engineering

### Differences from Traditional Scrum

1. **Research Spikes**: RE often requires exploratory work (story points = ?)
   - **Solution**: Time-box spikes to 4 hours, then reassess

2. **Uncertainty**: Can't always predict analysis complexity
   - **Solution**: Use higher story points (8, 13) for unknown binaries

3. **Technical Debt**: RE doesn't accumulate code debt (read-only analysis)
   - **Solution**: Track "analysis debt" (incomplete documentation)

4. **Definition of Done**: Hard to define "done" for open-ended analysis
   - **Solution**: Use acceptance criteria per task type (see above)

### RE-Specific Best Practices

1. **Pair Analysis**: When possible, have two analysts review critical binaries
2. **Time-Boxing**: Limit deep-dive analysis to 2 days max, then document and move on
3. **Iterative Deepening**: First pass = reconnaissance, second pass = detailed analysis
4. **Cross-Reference**: Always compare findings with OpenConnect source code

---

## Example Sprint Plan

### Sprint 2: CSTP Protocol Analysis (Nov 18 - Nov 29)

**Sprint Goal**: Document CSTP (Cisco SSL Tunnel Protocol) implementation in vpnagentd

**Selected Issues**:
1. **#1**: Version 5.1 Linux x86_64 Analysis (13 points) - focus on vpnagentd
2. **#2**: TLS 1.3 Handshake Implementation (CRITICAL) (8 points)

**Tasks**:
- [ ] Load vpnagentd (5.1.12.146) in IDA Pro
- [ ] Identify main() and connection establishment functions
- [ ] Extract CSTP header format (X-CSTP-* headers)
- [ ] Document TLS 1.3 cipher suite selection
- [ ] Compare with OpenConnect client implementation
- [ ] Create protocol flow diagram (CSTP handshake)
- [ ] Write analysis report in `analysis/5.1/predeploy/vpnagentd.md`

**Acceptance Criteria**:
- CSTP protocol flow documented with diagram
- TLS 1.3 handshake sequence verified
- Minimum 20 key functions documented
- Findings validated against OpenConnect v9.x behavior

**Estimated Capacity**: 30 hours (3 hours/day × 10 days)
**Committed Points**: 21 points

---

## References

- **Scrum Guide**: https://scrumguides.org/scrum-guide.html
- **GitHub Projects**: https://docs.github.com/en/issues/planning-and-tracking-with-projects
- **Story Point Estimation**: https://www.mountaingoatsoftware.com/blog/what-are-story-points

---

**Last Updated**: 2025-10-30
**Sprint**: Sprint 1 (Nov 4 - Nov 15)
**Current Velocity**: TBD (first sprint)
