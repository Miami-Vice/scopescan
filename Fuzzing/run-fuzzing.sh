#!/usr/bin/env bash
#
# Builds and runs the libFuzzer harnesses against ScopeScanCore.
#
# The targets are compiled with swiftc rather than SwiftPM because libFuzzer
# supplies the executable's `main`, which fights SwiftPM's own entry point.
# -parse-as-library stops Swift generating a main of its own.
#
# Linux is the supported host: that is where the Swift toolchain ships the
# libFuzzer runtime used by -sanitize=fuzzer. CI runs this on ubuntu-latest.
#
#   FUZZ_SECONDS=60 bash Fuzzing/run-fuzzing.sh
#
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
seconds="${FUZZ_SECONDS:-60}"
build="$root/Fuzzing/.build"

mkdir -p "$build"

# target-name:corpus-directory
targets=(
    "IPv4Address:ipv4-address"
    "IPv4Network:ipv4-network"
    "ScanScope:scan-scope"
    "OSVersion:os-version"
)

core_sources=("$root"/ScopeScanCore/Sources/ScopeScanCore/*.swift)

echo "fuzzing for ${seconds}s per target with $(swiftc --version | head -n 1)"

for entry in "${targets[@]}"; do
    name="${entry%%:*}"
    corpus="${entry##*:}"
    binary="$build/Fuzz$name"

    echo "::group::Fuzz$name"

    swiftc -parse-as-library -O -g -sanitize=fuzzer,address \
        -module-name "Fuzz$name" \
        -o "$binary" \
        "$root/Fuzzing/Harnesses.swift" \
        "$root/Fuzzing/Targets/Fuzz$name.swift" \
        "${core_sources[@]}"

    mkdir -p "$root/Fuzzing/corpus/$corpus" "$root/Fuzzing/artifacts/$name"

    "$binary" "$root/Fuzzing/corpus/$corpus" \
        -max_total_time="$seconds" \
        -timeout=10 \
        -rss_limit_mb=2048 \
        -artifact_prefix="$root/Fuzzing/artifacts/$name/" \
        -print_final_stats=1

    echo "::endgroup::"
done
