#!/usr/bin/env bash
# build.sh - compila tutto con un JDK >= 17 (nessuna dipendenza). Output in ../out
set -e
cd "$(dirname "$0")/.."
${JAVA:-javac} -d out src/*.java && echo BUILD_OK "($(ls out | wc -l | tr -d ' ') classi)"
