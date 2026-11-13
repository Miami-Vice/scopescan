#!/usr/bin/env bash
# Produces an unsigned IPA locally. Requires Xcode and XcodeGen.
# CI uses .github/workflows/ipa.yml instead; this exists for anyone with a Mac.
set -euo pipefail

cd "$(dirname "$0")/.."

xcodegen generate

rm -rf build
xcodebuild archive \
  -project ScopeScan.xcodeproj \
  -scheme ScopeScan \
  -configuration Release \
  -destination 'generic/platform=iOS' \
  -archivePath build/ScopeScan.xcarchive \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" \
  DEVELOPMENT_TEAM=""

app="build/ScopeScan.xcarchive/Products/Applications/ScopeScan.app"
[ -d "$app" ] || { echo "archive did not produce $app" >&2; exit 1; }

mkdir -p build/Payload
cp -R "$app" build/Payload/
(cd build && zip -qry ScopeScan-unsigned.ipa Payload)

echo "Wrote build/ScopeScan-unsigned.ipa"
