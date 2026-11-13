#!/usr/bin/env bash
# Build and run the GNSSIntegrity host unit tests.
# The engine sources are compiled with ArduPilot-like strict flags (including
# -fsingle-precision-constant, as on ChibiOS boards); the simulator/test file
# uses double-precision truth and is compiled without that flag.
# Usage: CXX=g++ ./run_tests.sh [output-dir]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/../AP_IDS/GNSSIntegrity"
out="${1:-${TMPDIR:-/tmp}}"
cxx="${CXX:-g++}"
strict="-std=gnu++11 -O2 -Wall -Wextra -Werror -Wshadow -Wdouble-promotion -Wfloat-conversion -fno-exceptions -fno-rtti"
objs=()
for f in "$src"/*.cpp; do
    o="$out/gnssint_$(basename "$f" .cpp).o"
    "$cxx" $strict -fsingle-precision-constant -I "$src" -c "$f" -o "$o"
    objs+=("$o")
done
"$cxx" -std=gnu++11 -O2 -Wall -Wextra -Werror -fno-exceptions -fno-rtti -I "$src" -c "$here/test_gnss_integrity.cpp" -o "$out/gnssint_test.o"
"$cxx" "$out/gnssint_test.o" "${objs[@]}" -o "$out/test_gnss_integrity"
"$out/test_gnss_integrity"
