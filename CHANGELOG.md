# Changelog

## v1.0.0 — 2026-11-18 (FebusAI)
- Initial public release.
- `Base64Trigger`: minimal local PoC (62-byte OOB write reproduction).
- `Base64Service3` + `Java4Shell3`: demonstrated end-to-end RCE chain on
  Temurin 21.0.12+8 (Ice Lake, AVX-512 VBMI); mitigation negative-check included.
- `RemoteProbe`: dependency-free HTTP applicability probe with JVM fingerprinting
  from disclosed stack traces; JSONL output + stable exit codes for agent automation.
- `SKILL.md`: agent-oriented decision tree and engagement rules.
