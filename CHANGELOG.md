# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- P2-B DAP Lua + LZS compression results integrated into `SERVER_PROTOCOL_MAP.md`:
  3904 functions (1016 DAP/Lua + 2888 LZS/CTM). DAP Lua VM (6 libs + LuaExpat +
  LuaLDAP), 18 Lua C API mapped, endpoint attrs (12 fields), DAP merge (5-state),
  LZS per-record (2048B window, 1751B max), deflate (zlib 1.2.3, CRC32), CTM pipeline.
- P2-A AggAuth deep dive results integrated into `SERVER_PROTOCOL_MAP.md` §3.3:
  13-state FSM architecture, tunnel group resolution chain (cert→name→URL→alias→
  DefaultWEBVPNGroup), auth mode bitmask (tg+4168), user lockout (600s auto-expire),
  session management (3-min hash table), error table (116 entries), SAML login URL.
- External SSO client-side protocol fully reversed: JS token relay via
  `anyconnectsso://` (mobile) or `localhost:29786/api/sso/` (desktop), cookie
  `acSamlv2Token`, template substitution `{{AC_SAML_TOKEN}}`.
- CSC 5.1.17 package inventory in `FULL_PROTOCOL_DECOMPILATION_PLAN.md` §4.1:
  external-sso.pkg, Profile Editor MSI, MST transforms (9 files), VPNAPI SDK.
- VPNAPI SDK library inventory in `SERVER_PROTOCOL_MAP.md` §7.3-7.5: lib sizes,
  Post-Quantum algorithms (ML-KEM, ML-DSA, Kyber, BIKE, Falcon via oqsprovider.so),
  CLI example flow.
- 8 new gap items (G14-G21): External SSO, On-Demand/TND, Per-App VPN, Cert Auth,
  VPN Profile XML, VPNAPI SDK, PQ Crypto, MST Transforms.
- 6 new decompilation phases (Ф10-Ф15) in `FULL_PROTOCOL_DECOMPILATION_PLAN.md` §4.2.
- Feature parity table expanded with 9 new rows (On-Demand, TND, Per-App, SSO,
  Multi-cert, SCEP, VPNAPI, PQ TLS).

### Changed
- `FULL_PROTOCOL_DECOMPILATION_PLAN.md` — expanded from 574 to 781 lines:
  timeline extended to 358 hours / 18 weeks, added Batches 3-6, 4 new risks.
- `SERVER_PROTOCOL_MAP.md` — expanded from 1343 to 1461 lines: P2-A checklist
  (11 items done), decompilation artifacts updated with P2-A files.

## [0.3.0] — 2026-06-28

### Added
- `SERVER_PROTOCOL_MAP.md` — central protocol document (1343 lines), covering
  CSTP frame format, 52 X-CSTP headers, AggAuth XML protocol, DTLS setup,
  headend/WebDeploy (§6.8, 56 functions), VPNAPI SDK structure, feature parity.
- `FULL_PROTOCOL_DECOMPILATION_PLAN.md` — 9-phase, 12-week, ~230-hour plan
  covering gaps G1-G13, phases F0-F9, test scenarios T1-T10, ioguard mapping.

## [0.2.0] — 2026-06-15

### Added
- Stage 1 batch reconnaissance script for automated IDA string + xref extraction.

## [0.1.0] — 2026-06-01

### Added
- Initial project infrastructure: Sprint 1 reconnaissance.
- CSTP protocol confirmed, TLS 1.3 support verified.
- Documentation links and references.
