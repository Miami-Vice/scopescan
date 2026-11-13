# Runs the platform-free core test suite on Windows.
#
# Requires a Swift toolchain for Windows:
#   winget install Swift.Toolchain
# and the Visual Studio Build Tools C++ workload.
#
# This is the fast local loop. Anything touching Network.framework, Security or
# LocalAuthentication lives in the app target and only CI can verify it.

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    swift test --package-path ScopeScanCore
}
finally {
    Pop-Location
}
