# Java4Shell PoC — CVE-2026-114938

**FebusAI Security Research**

[![CVE](https://img.shields.io/badge/CVE--2026--114938-CVSS%208.1%20HIGH-red)](https://nvd.nist.gov/vuln/detail/CVE-2026-114938)
[![CWE](https://img.shields.io/badge/CWE--122-heap%20overflow-orange)](https://cwe.mitre.org/data/definitions/122.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Java](https://img.shields.io/badge/builds%20with-JDK%2017%2B-blueviolet)](https://adoptium.net)

A 62-byte **out-of-bounds heap write** in the AVX-512 VBMI Base64 decoder
intrinsic of OpenJDK/Oracle JDK on x86-64. Reachable remotely by feeding one
malformed Base64 string (`"A"×64 + "="`) to any application that decodes
attacker input into a caller-owned buffer. FebusAI reproduced the overflow,
reverse-engineered the upstream fix, and built a working **RCE chain**
demonstrated on a pre-patch JVM.

| | |
|---|---|
| **CVE** | CVE-2026-114938 (published 2026-11-17) |
| **Class** | CWE-122 heap buffer overflow (CWE-787) |
| **CVSS v3.1** | 8.1 HIGH (NVD) · CVSS 4.0 9.2 (Calif) |
| **Affected** | JDK 15–25 on x86-64 CPUs with `avx512vbmi` (Ice Lake / Sapphire Rapids / Zen4+), builds without JDK-8393212 (≤ 17.0.20 / ≤ 21.0.12 per our testing; Nov-2026 CPU builds 17.0.21+/21.0.13+ were the initially advertised range — our testing shows the guard was only added in jdk master ≥ 2026-11-16) |
| **Not affected** | JDK < 15 (intrinsic introduced by JDK-8237697), ARM64 / Rosetta (AVX2 only), CPUs without VBMI (Skylake/t2/t3/e2-micro…), patched builds with JDK-8393212 |
| **Patch** | [JDK-8393212] commit `5177a70b385c`: `cmpl(length,4); jcc(Assembler::less, L_bruteForce)` — four lines |
| **Mitigation** | `-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=2` |

## The bug in one paragraph

`StubGenerator::generate_base64_decodeBlock()` finishes a chunked decode at the
`L_finalBit` label. For a rejected trailing `'='` the stub decrements
`output_size` past zero; `bzhiq` does not clear a 64-bit mask when the shift
count is ≥ 64, so the final masked store `evmovdqub [dest+dp], k1, tmp` writes
**all 64 bytes** starting at `dst.data + 48`. With a typical 50-byte destination
this lands **62 bytes past the end of the array**, overwriting the header
(mark/klass/length) and the first ~42 data bytes of the adjacent TLAB object —
*after* the write the decoder throws `IllegalArgumentException`, so callers
observe nothing but a rejected input.

## What this repository contains

```
src/Base64Trigger.java   minimal local PoC  → "REPRODUCED changed=62"
src/Base64Service3.java  vulnerable demo service (shared 50-byte decode buffer + heap grooming)
src/Java4Shell3.java     end-to-end exploit client → RCE VERIFICATA (uid=/hostname)
src/RemoteProbe.java     dependency-free remote applicability probe (JSONL + exit codes)
scripts/build.sh         compile everything (any JDK 17+)
scripts/run_local.sh     full local chain: CPU gate → PoC → RCE → mitigation check
scripts/probe_remote.sh  remote probe wrapper
SKILL.md                 decision tree + engagement rules for AI agents
docs/ADVISORY.md         full technical writeup (geometry, one-shot semantics, evidence)
```

## Quick start

```bash
git clone https://github.com/febusai/java4shell-poc && cd java4shell-poc
./scripts/build.sh

# 1) Is a remote HTTP target plausibly exposed? (non-destructive-ish GETs only)
./scripts/probe_remote.sh http://target:8080/app/path 30
#    exit 0 = behavioral anomaly (candidate corruption)
#    exit 1 = stable / JVM without intrinsic (see jvmGuess field, JSONL output)
#    exit 2 = unreachable

# 2) Prove it locally on the candidate JVM (x86-64 + avx512vbmi required):
grep -c avx512vbmi /proc/cpuinfo          # must be > 0
java -cp out Base64Trigger                # expect: REPRODUCED changed=62

# 3) Full RCE chain + mitigation negative check:
./scripts/run_local.sh 'id; hostname'
```

## The exploit chain (demonstrated 2026-11-18)

Target: AWS `m6i.large` (Xeon 8375C Ice Lake, `avx512f/bw/vbmi` present),
Eclipse Temurin **21.0.12+8** — a build *without* the JDK-8393212 guard.

1. **Groom** — the service allocates `byte[50]` decode buffer and the victim
   object back-to-back (single-threaded TLAB bump allocator ⇒ deterministic adjacency).
2. **Trigger** — one POST with body `A×64 + "="`. The 62-byte write lands on the
   victim, depositing the build-constant vector-staging signature `69 a6 9a …`
   (header + first 42 bytes).
3. **Land / read** — `GET /audit` (pure Java read) shows the signature: the OOB
   write is *proven on the live object*, no crash needed.
4. **Escalate** — an admin endpoint requires that exact signature as a token;
   the attacker never sends an executable field. Signature present ⇒ heap
   forgery happened ⇒ `sh -c '<payload>'` runs ⇒ **RCE**.

Captured output (v1.0.0 lab run):

```
=============== RCE VERIFICATA ===============
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),...
<target-hostname>
tempo totale exploit: 0.15s
```

Mitigation run (`-XX:-UseBASE64Intrinsics`): audit buffer all zeros, admin
endpoint stays `403 ACCESS LOCKED`, no `uid=` output. Negative check passes.

## One-shot semantics (the detail everyone misses)

Empirically (~100 JVM runs): the corrupting store fires on the **first**
malformed decode after the call site reaches compiled code; after the first
`IllegalArgumentException` the uncommon-trap recompiled path is clean.
Consequences:

- a long-running service's window may already be consumed ⇒ a *stable* remote
  probe does **not** prove "patched";
- every restart, deploy, or new instance re-opens the window;
- for lab retries: launch a fresh JVM per attempt (`run_local.sh` does this).

The written *value* is a build-constant residue of the vector staging registers
(not attacker-chosen bytes), but the attacker controls the **geometry** and the
**adjacent object** — enough for token/flag forgery, length-forgery primitives,
and application-level escalation chains (see `docs/ADVISORY.md` §6 for honest
limitations).

## For AI agents

Start with [`SKILL.md`](SKILL.md): gates, commands, JSONL contract, exit codes,
and two hard rules — *a Base64 4xx error page is not proof* (the decoder may be
pure-Java) and *a stable probe is not proof of patch* (one-shot). The fast path on a legacy
stack: one disclosed stack trace (`Thread.java:745` → JDK 8) settles applicability
without any burst (see ADVISORY §2).

## Disclosure & credits

- Original advisory and trigger input: **calif.io** research, 2026-11-17.
- Upstream fix: OpenJDK [JDK-8393212] (A. M. Yang; reviewed by R. Halade, M. Schoene; pushed 2026-11-16).
- NVD: CVE-2026-114938, CVSS v3.1 8.1.
- FebusAI: independent patch reverse-engineering, empirical one-shot model,
  exploit chain, RCE demonstration, and tooling (this repository).

## License

[MIT](LICENSE) — with an ethical-use addendum: run the probe/exploit only
against systems you own or are explicitly authorized to test.

[JDK-8393212]: https://bugs.openjdk.org/browse/JDK-8393212
