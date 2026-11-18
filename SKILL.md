---
name: java4shell-poc
description: Esegue la verifica e lo sfruttamento di CVE-2026-114938 (Java4Shell, overflow AVX-512 VBMI nel decoder Base64 di OpenJDK) su target locali o HTTP remoti. Da usare quando l'utente chiede di testare/sfruttare Java4Shell, o di verificare se un host/JVM è esposto al bug Base64 di JDK.
---

# Skill: Java4Shell (CVE-2026-114938) — procedura per agenti

## Decision tree (segui nell'ordine)

1. **Tipo di accesso?**
   - *locale/shell sul target* → `scripts/run_local.sh` (catena completa con CPU gate).
   - *solo HTTP remoto* → `scripts/probe_remote.sh <url> [loops]`.
2. **CPU gate (locale):** `grep -c avx512vbmi /proc/cpuinfo`. 0 → dichiara NON VULNERABILE
   (la path non viene mai eseguita; niente altro da testare) ed esci.
3. **JVM gate:**
   - remoto: il probe estrarre `jvmGuess` dagli stacktrace divulgati (`Thread.java:745`→JDK8
     → **non applicabile**, `Thread.java:1568`→JDK17/21 → applicabile se build ≤ 17.0.20/21.0.12).
   - locale: `java -version`. JDK<15 → NON applicabile (intrinsic assente, JDK-8237697 partì in 15).
4. **Esegui e interpreta** (sotto).

## Comandi

```bash
./scripts/build.sh
./scripts/run_local.sh 'id; hostname'          # locale: gate→PoC→RCE→mitigato; exit 0 = RCE ok
./scripts/probe_remote.sh http://T:PORT/path 50
```

`RemoteProbe` exit/summary:
- exit 2 → target irraggiungibile (ritenta una volta, poi dichiara "non raggiungibile").
- exit 1 + `jvmGuess` "8 …"/"11 …" → **CVE NON APPLICABILE** (chiudi con questa prova).
- exit 1 + `jvmGuess` 17/21+ + `stable` → decoder raggiunto senza effetti: **una** di queste:
  one-shot già consumato (normale su processi long-lived) oppure corruzione silenziosa su
  oggetti effimeri. Dichiara "nessun effetto osservabile; non confermabile da remoto senza restart".
- exit 0 + `ANOMALY` → le risposte HTTP differiscono tra ripetizioni identiche del trigger:
  forte candidato corruzione. Raccogli le risposte divergenti (status/size/sha nel JSONL),
  cerca segnali di auth-bypass/500/stacktrace, e riporta i campioni come evidenza.

## Formato output (machine-readable)

RemoteProbe stampa JSONL: righe `{"variant",...,"status","bytes"[,"distinctResponses"]}`
e una riga finale `{"summary":"ANOMALY|stable","jvmGuess":...,
"javaVersionApplicable":bool,"stackOrErrorDisclosed":bool,"recommendation":"..."}`.

## Regole d'ingaggio (non negoziabili)

- Il trigger remoto è **non-distruttivo** (un GET con header/query malformati), ma può in
  linea di principio corrompere l'heap del target → **usare solo su sistemi posseduti o
  autorizzati**. Mai su Shodan/terzi senza permesso scritto.
- NON dichiarare "vulnerabile" solo perché il trigger produce un errore 4xx Base64: il
  decoder custom (Winstone/Spring/commons-codec) non è l'intrinsic. La prova è: (a) PoC
  locale `REPRODUCED changed=62`, o (b) anomalia comportamentale con JVM 17/21 pre-patch.
- NON dichiarare "patchato" dopo un probe stabile su JVM 17/21: la one-shot potrebbe essere
  già consumata. La prova di patch è il version/build check (JDK-8393212 `5177a70b`).

## Interpretazione (lezione Wowza, esempio reale in examples/)

Stacktrace JDK8 esatti (`Thread.java:745`, `FutureTask:266`) = JVM bundlato vecchio →
verdetto negativo in 1 richiesta, senza need di burst. Sempre *fingerprintare prima*,
splamare dopo.

## Riferimenti rapidi

- Trigger canonico: `"A"*64 + "="` (65 byte); JDK 17 vecchi: `"A"*128 + "="`.
- Firma landing osservata (build 21.0.12+8/x86 Ice Lake): `69 a6 9a` ripetuti, 42 byte di
  data + header dell'oggetto adiacente.
- Root cause: `L_finalBit`→`L_padding` decrementa `output_size` → underflow → `bzhiq`
  mask non azzerata → `evmovdqub` scrive 64B da `dst+48` (62B OOB).
- Mitigazione: `-XX:-UseBASE64Intrinsics`; patch: JDK-8393212 (master ≥ 2026-11-16).
