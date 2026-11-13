# ScopeScan

An iOS **posture and exposure auditor** for the device it runs on and the local
network it sits in. It inventories attack surface and misconfiguration, and
tells you how to fix it.

It is *not* an exploit finder. Nothing running in an iOS sandbox can be — see
[What this cannot do](#what-this-cannot-do).

## Status

M0 — scaffolding, CI pipeline, and the diagnostics harness. No scanning yet.

| Milestone | Scope | State |
|---|---|---|
| M0 | Scaffold, `ScopeScanCore`, XcodeGen, CI, unsigned IPA, on-device install | in progress |
| M1 | Posture checks + findings model | planned |
| M2 | Scope validation, discovery, Bonjour enumeration | planned |
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

## Architecture

```
ScopeScanCore/          SwiftPM package, zero Apple-framework dependencies
  Sources/ScopeScanCore/
    IPv4Address.swift   dotted-quad parsing, classification
    IPv4Network.swift   CIDR maths, host enumeration
    ScanScope.swift     the authorization enforcement point
    Finding.swift       finding model + severity ordering
  Tests/                runs with `swift test` on macOS **and Windows**

App/                    SwiftUI app target (iOS 17+)
  Features/Diagnostics/ the device-feedback harness
  Support/              getifaddrs, sysctl, NWConnection probing
Tests/ScopeScanAppTests/
project.yml             XcodeGen input; the .xcodeproj is generated, never committed
scripts/
  ci-destination.sh     picks a simulator for CI
  build-ipa.sh          local unsigned-IPA build (needs a Mac)
  test-core.ps1         local core tests on Windows
  generate-icon.ps1     regenerates the app icon
```

Anything that can be tested without Apple frameworks lives in `ScopeScanCore`,
because CI-only development makes a fast local test loop worth a lot.

## Why CI-only

There is no Mac in the loop. The app is built on GitHub Actions and installed by
re-signing an unsigned IPA on device:

1. `unsigned ipa` workflow produces `ScopeScan-unsigned.ipa`.
2. Download it, open it in **AltStore** (AltServer running on the Windows box).
3. AltStore signs with your free Apple ID and installs.
4. Re-sign every 7 days. AltStore does this in the background while on the same
   network as AltServer.

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

## Legal

Only scan networks you own or have written authorization to test. Unauthorized
scanning is an offence under the US CFAA, the UK Computer Misuse Act, and
equivalents elsewhere. `ScanScope` refuses loopback, link-local, multicast and
reserved space, and caps a sweep at 1024 hosts, but it cannot verify that you
own the network you typed in. That part is on you.

## License

MIT. See [LICENSE](LICENSE).
