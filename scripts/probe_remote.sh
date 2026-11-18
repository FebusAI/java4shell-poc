#!/usr/bin/env bash
# probe_remote.sh - probe di applicabilita' CVE-2026-114938 su target HTTP remoto.
# 用法: ./probe_remote.sh <url> [loops]     (richiede build: scripts/build.sh)
# exit: 0 anomalia | 1 stabile/JDK<15 | 2 irraggiungibile
set -e
cd "$(dirname "$0")/.."
[ -d out ] || ./scripts/build.sh
java -cp out RemoteProbe "$@"
