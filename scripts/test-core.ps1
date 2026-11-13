#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the platform-free ScopeScanCore test suite on Windows.

.DESCRIPTION
    Swift on Windows needs three things that a plain shell does not have:

      1. The MSVC linker and Windows SDK libs  -> from vcvars64.bat
      2. The Swift runtime DLLs on PATH        -> from the Runtimes tree
      3. SDKROOT pointing at Windows.sdk       -> the installer sets this at
                                                  machine scope, so a shell that
                                                  started before the install
                                                  never sees it

    This script assembles that environment and runs `swift test`. Nothing here
    touches Apple frameworks, so the result is the same as the macOS CI job.

.EXAMPLE
    .\scripts\test-core.ps1
    .\scripts\test-core.ps1 -Filter ScanScopeTests
#>
param(
    [string] $Filter = ''
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$packagePath = Join-Path $repoRoot 'ScopeScanCore'

# --- Swift toolchain -------------------------------------------------------

$swiftRoot = Join-Path $env:LOCALAPPDATA 'Programs\Swift'
if (-not (Test-Path $swiftRoot)) {
    throw "Swift toolchain not found at $swiftRoot. Install it with: winget install Swift.Toolchain"
}

function Get-NewestChild([string] $path) {
    if (-not (Test-Path $path)) { return $null }
    Get-ChildItem $path -Directory |
        Sort-Object { [version]($_.Name -replace '[^0-9.].*$', '') } -ErrorAction SilentlyContinue |
        Select-Object -Last 1
}

$toolchain = Get-NewestChild (Join-Path $swiftRoot 'Toolchains')
$runtime = Get-NewestChild (Join-Path $swiftRoot 'Runtimes')
$platform = Get-NewestChild (Join-Path $swiftRoot 'Platforms')

if (-not $toolchain -or -not $runtime -or -not $platform) {
    throw "Incomplete Swift installation under $swiftRoot"
}

$swiftBin = Join-Path $toolchain.FullName 'usr\bin'
$runtimeBin = Join-Path $runtime.FullName 'usr\bin'
$sdkRoot = Join-Path $platform.FullName 'Windows.platform\Developer\SDKs\Windows.sdk'

foreach ($path in @($swiftBin, $runtimeBin, $sdkRoot)) {
    if (-not (Test-Path $path)) { throw "Missing expected Swift component: $path" }
}

# --- MSVC environment ------------------------------------------------------

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found. Install Visual Studio Build Tools with the C++ workload."
}

$vsInstall = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath

if (-not $vsInstall) {
    throw "No Visual Studio installation with the C++ toolset. Install the 'Desktop development with C++' workload."
}

$vcvars = Join-Path $vsInstall 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found under $vsInstall" }

Write-Host "Importing MSVC environment from $vcvars"
& $env:ComSpec /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
    $separator = $_.IndexOf('=')
    if ($separator -gt 0) {
        $name = $_.Substring(0, $separator)
        $value = $_.Substring($separator + 1)
        Set-Item -Path "Env:$name" -Value $value -ErrorAction SilentlyContinue
    }
}

$env:PATH = "$swiftBin;$runtimeBin;$env:PATH"
$env:SDKROOT = $sdkRoot

Write-Host "Swift: $swiftBin"
Write-Host "SDKROOT: $env:SDKROOT"

# --- Run -------------------------------------------------------------------

$arguments = @('test', '--package-path', $packagePath)
if ($Filter) { $arguments += @('--filter', $Filter) }

Push-Location $repoRoot
try {
    & swift @arguments
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
