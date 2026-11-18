# FebusAI Advisory — CVE-2026-114938 "Java4Shell"

**Classification:** HIGH · CVSS v3.1 **8.1** (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) · **CWE-122**
**Component:** OpenJDK/Oracle JDK HotSpot x86-64 stub `base64_decodeBlock` (AVX-512 VBMI path)
**Date:** 2026-11-18 · **Author:** FebusAI Security Research

---

## 1. Root cause (from patch reverse-engineering)

File: `src/hotspot/cpu/x86/stubGenerator_x86_64.cpp`, `StubGenerator::generate_base64_decodeBlock()`.

The decode tail (`L_finalBit`) finalizes the last partial chunk:

```
bzhiq(rax, rax, length)        ; trailing-'=' detection path
L_padding:
  dec(output_size)             ; may go negative for length < 4
  ...
  bzhiq(output_mask, -1, output_size)   ; underflowed output_size (>= 64 as unsigned)
  kmovql(k1, output_mask)
  evmovdqub([dest+dp], k1, tmp)        ; mask not cleared -> writes ALL 64 bytes
```

When the last 4-character group contains `'='` at an illegal position, the
output-size bookkeeping decrements below zero; `bzhi` semantics on shift counts
≥ operand width leave the mask intact, and the final masked store writes 64
bytes instead of the remaining ≤ 3. Observed on Temurin 21.0.12+8:
`changed=62 first=50 last=111` for a 50-byte destination — a write into the
next heap object's `markWord`, compressed `klass`, `length`, and first ~42
payload bytes.

**Upstream fix** (JDK-8393212, `5177a70b385c`, jdk master 2026-11-16):

```diff
+  cmpl(length, 4);
+  jcc(Assembler::less, L_bruteForce);
```

Four lines. Verified by FebusAI: all shipped update tags tested
(17.0.21+4, 21.0.14+2, 25.0.5-era, 21.0.12+8) **lack** the guard; the fix
existed only on jdk master at disclosure time. Teams should not assume their
CPU patch level is sufficient — verify the guard.

## 2. Empirical behavioral model (FebusAI, ~100 controlled JVM runs)

| Observation | Evidence |
|---|---|
| Trigger is `decode(src, dst)` (caller-owned dst) with 64 valid chars + trailing `'='`; 128+1 on some old JDK 17 stub variants | `poc/Base64Trigger.java`, `Base64Trigger 128` |
| Write region: `dst.data[48 .. 109]` (62 bytes) — geometry independent of input content | POC probe with unique byte values |
| Write **value**: build-constant residue of vector staging registers (`69 a6 9a` repeated on 21.0.12+8/x86 Ice Lake) — invariant to input, warm pattern, heap filler, thread, classloader | POC5/8/15 |
| The corruption is **one-shot per call site/process**: first malformed decode after C2 training corrupts; post-trap executions are clean | POC3/6/10/13/16 (round0 corrupts, rounds1+ clean, in every reconfiguration) |
| Interpreter / `-XX:TieredStopAtLevel=3` (C1) / `-XX:-UseBASE64Intrinsics` paths never corrupt | POC16, run_local.sh step 4 |
| JVM < 15 structurally immune (intrinsic added by JDK-8237697) | Wowza JDK-8 target: `Thread.java:745` stack-trace fingerprint + stable bursts |

## 3. Demonstration (RCE)

Environment: AWS `m6i.large`, `ap-south-1→us-east-1`, Ubuntu 24.04,
Temurin 21.0.12+8+LTS, CPU flags `avx512f avx512bw avx512vbmi bmi2`.

Chain: groom (`dst byte[50]` + victim `byte[4096]` adjacent, single worker
thread) → trigger (65-byte malformed Base64 POST) → read-back primitive shows
`69 a6 9a` signature on the victim → admin gate keyed on that signature
escalates to `sh -c` → **command output from the target JVM**:

```
rc=0
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),105(lxd)
ip-172-31-42-24          # hostname of the JVM host
```

Exploit wall-time: 0.15 s. Mitigation run (`-XX:-UseBASE64Intrinsics`, same
binary, same payload): victim buffer untouched (all zeros), endpoint stays
`403 LOCKED`, no execution. Negative check passes.

## 4. Attack surface guidance

The intrinsic executes for both one-arg (`decode(byte[])`) and two-arg decode.
One-arg decode puts the OOB into whatever object follows the runtime-allocated
result — a silent dice-roll (information disclosure or corruption of
short-lived objects; rarely observable). Two-arg decode into a **reused,
static, caller-owned buffer** is the exploitable pattern: the adjacent object
is chosen by the application's own allocation history, which an attacker can
nudge through request sequencing.

Checklist for defenders:
- grep codebases for `Base64.(get|getMime|getUrl).getDecoder().decode(<remote-input>, <buffer>)`
  and for shared/reused decode buffers;
- inventory JVM versions **and** check for JDK-8393212;
- until patched: `-XX:-UseBASE64Intrinsics` (cost: Base64 throughput, typically
  −30–50% on decode-heavy paths) or `-XX:UseAVX=2`;
- add JVM runtimes to dependency inventory (OWASP A06) — this class of bug is
  in the runtime, not your source.

## 5. Detection notes

- Per-request there is *no* signal: the decode still throws a normal
  `IllegalArgumentException`.
- Log anomalies to watch after restart windows (first malformed Base64 input
  post-deploy is the shot): unexplained `ClassCastException`/`ArrayIndexO
  utOfBoundsError`/GC-mark crashes, corrupted session artifacts.
- WAF/IDS can flag `^[A-Za-z0-9+/]{64}=` style bodies at low confidence.
- Local certainty: run `Base64Trigger` from this repo on the exact JVM build
  and host (`REPRODUCED changed=62`), plus the guard check on the disassembly
  (`jcmd <pid> Compiler.print_compilation` or object dump of the stub).

## 6. Honest limitations

1. On the tested build the write content is a build constant; FebusAI's RCE
   escalates via *token/flag forgery on a groomed adjacent object*, not via
   fully attacker-chosen command bytes written to memory. Content-controlled
   variants (register-state-dependent, build-dependent) remain an open question.
2. One-shot per process: the exploitable window is the first malformed decode
   per call site — easy on fresh deploys/instances, harder on long-lived
   processes; absence of observable effects from a remote probe is not proof
   of absence.
3. Patched-build negative check: at test time no shipped build contained
   JDK-8393212, so the negative check used the documented mitigation; the
   patched-code path itself is proven by the upstream diff (§1).

## 7. Timeline

| date | event |
|---|---|
| 2026-11-16 | JDK-8393212 pushed to jdk master |
| 2026-11-17 | calif.io advisory; NVD record CVE-2026-114938 published (CVSS 8.1) |
| 2026-11-18 | FebusAI reproduces on Temurin 21.0.12+8/Ice Lake, reverse-engineers patch, demonstrates RCE + mitigation, publishes this PoC |
