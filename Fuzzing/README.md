# Fuzzing

libFuzzer harnesses for the ScopeScanCore parsers — the code that consumes
bytes from untrusted LAN devices.

## Why this is not a SwiftPM target

libFuzzer supplies the executable's `main`. SwiftPM wants to own an executable's
entry point too, so the targets are compiled with `swiftc` directly:

```
swiftc -parse-as-library -sanitize=fuzzer,address ...
```

`-parse-as-library` stops Swift from emitting its own `main`, leaving libFuzzer's.

**Linux is the supported host.** Apple's toolchain does not ship the libFuzzer
runtime, and the Windows toolchain rejects all `-sanitize=` options. CI runs
this on `ubuntu-latest`.

## Running

```bash
FUZZ_SECONDS=60 bash Fuzzing/run-fuzzing.sh
```

Corpus lives in `corpus/<target>/`. Crashing or property-violating inputs are
written to `artifacts/<target>/`, which is git-ignored and uploaded by CI on
failure.

## Targets

| Target | Parser | Property |
|---|---|---|
| `FuzzIPv4Address` | `IPv4Address(string:)` | accepted input ⇒ `description` re-parses to the same address |
| `FuzzIPv4Network` | `IPv4Network(cidr:)` | network contains its own and broadcast address; canonical form round-trips |
| `FuzzScanScope` | `ScanScope(cidr:)` | never accepts larger than /22, never exceeds 1024 hosts, hosts are unique and inside the network |
| `FuzzOSVersion` | `OSVersion(string:)` | accepted input ⇒ `description` re-parses to the same version |

A failed property calls `precondition`, which traps — libFuzzer treats that
exactly like a crash and saves the input.

## Adding M2/M3 parsers

1. Add the parser to `ScopeScanCore` with unit tests.
2. Add `Targets/Fuzz<Parser>.swift` with the `LLVMFuzzerTestOneInput` wrapper.
3. Add a property function to `Harnesses.swift`.
4. Add `"<Parser>:<corpus-dir>"` to the `targets` array in `run-fuzzing.sh` and
   seed `corpus/<corpus-dir>/` with valid and invalid examples.

Target files must not share a basename with a core source file: the harness is
compiled into the same module as the core sources, and Swift rejects duplicate
filenames within a module.
