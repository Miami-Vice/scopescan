#!/usr/bin/env bash
# Prints an xcodebuild -destination value for the newest installed iOS runtime,
# using a simulator created on the fly. Avoids hardcoding a device name that
# disappears whenever the runner's Xcode version changes.
set -euo pipefail

runtime=$(xcrun simctl list runtimes available --json | python3 -c '
import json, sys
runtimes = [r for r in json.load(sys.stdin)["runtimes"]
            if r.get("platform") == "iOS" and r.get("isAvailable")]
if not runtimes:
    sys.exit("no available iOS runtime")
runtimes.sort(key=lambda r: [int(p) for p in r["version"].split(".")])
print(runtimes[-1]["identifier"])
')

device_type=$(xcrun simctl list devicetypes --json | python3 -c '
import json, sys
types = [d for d in json.load(sys.stdin)["devicetypes"]
         if d["name"].startswith("iPhone")]
if not types:
    sys.exit("no iPhone device type")
print(types[0]["identifier"])
')

udid=$(xcrun simctl create "ScopeScanCI" "$device_type" "$runtime")
echo "platform=iOS Simulator,id=$udid"
