# ScopeScan

An iOS **posture and exposure auditor** for the device it runs on and the local
network it sits in. It inventories attack surface and misconfiguration, and
tells you how to fix it.

It is *not* an exploit finder. Nothing running in an iOS sandbox can be — see
[What this cannot do](#what-this-cannot-do).

## Status

M0 is complete and M1 is complete and verified on hardware: the app reports
one informational finding (active VPN) on a healthy device, with every check's
collected value matching the raw diagnostics baseline.

| Milestone | Scope | State |
|---|---|---|
| M0 | Scaffold, `ScopeScanCore`, XcodeGen, CI, unsigned IPA, on-device install | complete |
| M1 | Posture checks + findings model | complete, device-verified |
| M2 | Scope validation, discovery, port inventory, Bonjour enumeration | core complete and unit-tested; app layer awaiting device verification |
| M3 | TLS grading, banner fingerprinting, remediation | planned |
| M4 | Encrypted storage, redacted export, hardening | planned |

## What this cannot do

Worth being explicit, because these limits are architectural:

- **Read other apps.** No process introspection, no other apps' files, no other
  apps' memory. The sandbox forbids it.
- **Capture packets.** No `pcap`, no promiscuous mode, no raw sockets.
- **Scan for zero-days.** Novel bug discovery needs fuzzing harnesses, binary
  diffing and host-side tooling. An on-device scanner cannot do it.
- **Read the ARP or routing table.** `sysctl NET_RT_FLAGS` is denied, so host
  discovery is probe-based and will miss quiet hosts.
- **Send ICMP.** No raw sockets, so no ping. Reachability is a TCP connect.
- **Probe credentials.** Never implemented. Automated credential attempts
  against hosts you may not own is the line this project does not cross.
- **Read the current Wi-Fi security type.** `NEHotspotNetwork.fetchCurrent`
  needs `com.apple.developer.networking.wifi-info`, a restricted entitlement a
  free personal team cannot be granted. The check reports *not determined*.

## Architecture

```
ScopeScanCore/          SwiftPM package, zero Apple-framework dependencies
  Sources/ScopeScanCore/
    IPv4Address.swift   dotted-quad parsing, classification
    IPv4Network.swift   CIDR maths, host enumeration
    ScanScope.swift     the authorization enforcement point
    Finding.swift       finding model + severity ordering
    Severity.swift      ordered info → critical
    OSVersion.swift     semantic version, comparable
    WifiSecurity.swift  reported link security
    PostureObservation.swift  raw facts, every field optional
    PostureEvaluator.swift    pure rules that turn facts into findings
  Tests/                runs with `swift test` on macOS **and Windows**

App/                    SwiftUI app target (iOS 17+)
  Features/Posture/     collector, detectors, store, report UI
  Features/Diagnostics/ the device-feedback harness
  Support/              getifaddrs, sysctl, NWConnection probing
Tests/ScopeScanAppTests/
Fuzzing/                libFuzzer harnesses for the untrusted-input parsers
project.yml             XcodeGen input; the .xcodeproj is generated, never committed
scripts/
  ci-destination.sh     picks a simulator for CI
  build-ipa.sh          local unsigned-IPA build (needs a Mac)
  test-core.ps1         local core tests on Windows
  usbmux-diag.py        proves the USB device stack works before sideloading
  ocr-image.ps1         Windows OCR for phone screenshots (device feedback loop)
  generate-icon.ps1     regenerates the app icon
```

Anything that can be tested without Apple frameworks lives in `ScopeScanCore`,
because CI-only development makes a fast local test loop worth a lot.

A deliberate invariant runs through the posture layer: **an unknown observation
never becomes a pass.** Every field in `PostureObservation` is optional, a check
that cannot run produces no finding, and the UI lists it as *not determined*
rather than omitting it. Absence of a warning is never evidence of safety.

## Why CI-only

There is no Mac in the loop. The app is built on GitHub Actions and installed by
re-signing an unsigned IPA on device with **Sideloadly** over USB:

1. `unsigned ipa` workflow produces `ScopeScan-unsigned.ipa`.
2. Download it to the Windows box, start Sideloadly, and drag the IPA in.
3. Sideloadly signs with your free Apple ID and installs over the same
   usbmux channel Xcode would use.
4. Re-sign every 7 days — a free Apple ID cannot issue longer-lived profiles.

AltStore was tried first and abandoned: its device-to-server discovery relies on
Apple's Bonjour service, and recovering a missing Bonjour without reinstalling
the whole iTunes bundle is not reliable. Sideloadly removes that dependency
entirely. `scripts/usbmux-diag.py` distinguishes "the phone is plugged in" from
"the USB device stack works", which is the failure that otherwise looks
identical.

Consequences baked into the project:

- **No custom entitlements anywhere.** A free personal team cannot be granted
  `com.apple.developer.networking.multicast`, so multicast mDNS is out. Discovery
  uses Bonjour via `NWBrowser`, which needs only `NSBonjourServices`.
- **`SWIFT_VERSION: 5.0`** for the app target while the pipeline is being
  stabilised; `ScopeScanCore` builds in Swift 6 language mode. Flip the app to 6
  once CI is green and the surface stops moving.
- **The diagnostics screen is load-bearing.** CI can compile and unit-test, but
  only real hardware can confirm that `LAContext`, `sysctl`, `getifaddrs` and the
  local-network permission behave as expected. Copy the report off the device.
- **Scope selection is constrained.** Only RFC1918 `en0` addresses are offered:
  `pdp_ip0` carries carrier CGNAT and must never be scanned, and an active
  `ipsec`/`utun` tunnel is surfaced as a warning because it can absorb traffic
  the scanner believes is going to the LAN.

## Local development

```powershell
# Core tests (Windows, needs winget install Swift.Toolchain + VS Build Tools)
.\scripts\test-core.ps1
```

```bash
# Full build + tests (needs macOS, Xcode 16+, XcodeGen)
brew install xcodegen
xcodegen generate
xcodebuild -project ScopeScan.xcodeproj -scheme ScopeScan \
  -destination 'platform=iOS Simulator,name=iPhone 16' test
```

## Fuzzing

The parsers that consume bytes from LAN devices are fuzzed with libFuzzer in the
`fuzz` workflow: 60 seconds per target on pull requests, 10 minutes nightly,
with the corpus cached between runs and crashing inputs uploaded as artifacts.

Harnesses live in `Fuzzing/` and are compiled with `swiftc` rather than SwiftPM,
because libFuzzer supplies the executable's `main`. Linux is the supported host —
it is the only toolchain that ships the fuzzer runtime.

```bash
FUZZ_SECONDS=60 bash Fuzzing/run-fuzzing.sh
```

## Legal

Only scan networks you own or have written authorization to test. Unauthorized
scanning is an offence under the US CFAA, the UK Computer Misuse Act, and
equivalents elsewhere. `ScanScope` refuses loopback, link-local, multicast and
reserved space, and caps a sweep at 1024 hosts, but it cannot verify that you
own the network you typed in. That part is on you.

## License

MIT. See [LICENSE](LICENSE).
