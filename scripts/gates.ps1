# IAMT-10 quality gates for iamtunnel (SPEC section 8).
#
# Runs every CI check in one command. Each gate prints exactly one mark:
# "[GATE n/18 PASS]" or "[GATE n/18 FAIL]". On the FIRST failure of a gate the
# rest of that gate is skipped, but every other gate still runs to the end -
# the user sees the state of all eighteen, not just the first red one. The exit
# code is non-zero iff at least one gate failed (so a CI consumer still sees
# the failure); a human reader also gets the summary table at the bottom.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\gates.ps1
# Works from any working directory; locates the repo root itself.
#
# Tools are resolved from PATH first, then installed into GOPATH\bin with
# "go install ...@latest" (never system-wide).
#
# Note on gate 5: "go test -race" requires CGO_ENABLED=1 on windows/amd64
# (the race runtime needs a C toolchain). The flag is raised for the test
# process only; gate 6 separately proves the shipped binaries are built
# with CGO_ENABLED=0 by reading the fact back from the binary itself.
#
# Note on IAMT-252: on GOOS=linux the ui package (and cmd/iamtunnel, which
# now opens the window) is built WITH cgo on purpose — gio talks to
# X11/Wayland through cgo. That is the one sanctioned departure from
# CGO_ENABLED=0. A Windows host has no linux/cgo toolchain, so the
# linux CGO_ENABLED=0 passes below cover every package EXCEPT those two,
# and the full-tree linux build with CGO_ENABLED=1 is proven on the
# Linux host by scripts/gates.sh — which also measures the linux binary
# sizes gate 8 no longer can.

[CmdletBinding()]
param(
    [switch]$SelftestClassify,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$script:GateIndex = 0
$script:GateName = ""
$script:GateTotal = 18
# Per-gate outcomes recorded for the summary table at the end. Each entry:
# @{ Index = <int>; Name = <string>; Status = "PASS" | "FAIL"; Detail = <string> }
$script:GateResults = New-Object System.Collections.Generic.List[object]
$script:OverallFailed = $false
# Per-target binary sizes recorded by gate 8 so the summary table can echo
# them in the PASS line without re-reading the temp directory (which is
# already cleaned up by then). Key: "GOOS/GOARCH", value: <double MB>.
$script:sizeByTarget = @{}

function Step([string]$Name) {
    $script:GateIndex++
    $script:GateName = $Name
    Write-Host ""
    Write-Host (">>> gate {0}/{2}: {1}" -f $script:GateIndex, $Name, $script:GateTotal)
}

# recordResult stashes the verdict for the current gate and echoes the
# one-line mark the old behaviour printed.
function recordResult([string]$Status, [string]$Detail) {
    $entry = [pscustomobject]@{
        Index  = $script:GateIndex
        Name   = $script:GateName
        Status = $Status
        Detail = $Detail
    }
    [void]$script:GateResults.Add($entry)
    if ($Status -eq "FAIL") { $script:OverallFailed = $true }
}

# Native checks $LASTEXITCODE of the native command that just ran. Unlike the
# pre-change behaviour it does NOT exit: it marks the gate FAIL, skips the
# remaining steps of the gate, and lets the harness keep running.
function Native([string]$Context) {
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("[GATE {0}/{1} FAIL] {2} ({3}) - exit code {4}" -f `
            $script:GateIndex, $script:GateTotal, $script:GateName, $Context, $LASTEXITCODE)
        recordResult "FAIL" $Context
        throw ([System.Exception]::new("gate-failed"))
    }
}

# Deny fails the current gate with an explicit reason. Same harness behaviour
# as Native: the gate goes FAIL, but the rest of the script keeps running.
function Deny([string]$Reason) {
    Write-Host ("[GATE {0}/{1} FAIL] {2} - {3}" -f `
        $script:GateIndex, $script:GateTotal, $script:GateName, $Reason)
    recordResult "FAIL" $Reason
    throw ([System.Exception]::new("gate-failed"))
}

function Passed([string]$Detail) {
    if ($Detail) {
        Write-Host ("[GATE {0}/{1} PASS] {2} - {3}" -f `
            $script:GateIndex, $script:GateTotal, $script:GateName, $Detail)
    } else {
        Write-Host ("[GATE {0}/{1} PASS] {2}" -f `
            $script:GateIndex, $script:GateTotal, $script:GateName)
    }
    recordResult "PASS" $Detail
}

# runGate wraps the body of a single gate so a FAIL from Native/Deny aborts
# only that gate and the harness proceeds to the next one.
function runGate([scriptblock]$Body) {
    try {
        & $Body
    } catch {
        # Re-throw only for unexpected exceptions; gate-failed ones are
        # already recorded and we just want to leave the gate block.
        if ($_.Exception.Message -ne "gate-failed") { throw }
    }
}

function Get-ModuleToolchain() {
    $tc = ""
    $goVer = ""
    if (Test-Path "go.mod") {
        foreach ($line in (Get-Content "go.mod")) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^toolchain\s+(\S+)') {
                $tc = $matches[1]
                break
            }
            if (-not $goVer -and $trimmed -match '^go\s+(\S+)') {
                $goVer = $matches[1]
            }
        }
        if (-not $tc -and $goVer) {
            if ($goVer.StartsWith("go")) { $tc = $goVer } else { $tc = "go" + $goVer }
        }
    }
    if (-not $tc) {
        $tc = (go env GOVERSION).Trim()
    }
    return $tc
}

function Parse-GoVersion([string]$Ver) {
    if (-not $Ver) { return @(0, 0, 0) }
    $v = $Ver
    if ($v.StartsWith("go")) { $v = $v.Substring(2) }
    if ($v -match '^([0-9]+(?:\.[0-9]+)*)') {
        $v = $matches[1]
    }
    $parts = $v.Split('.')
    $maj = if ($parts.Length -ge 1) { [int]$parts[0] } else { 0 }
    $min = if ($parts.Length -ge 2) { [int]$parts[1] } else { 0 }
    $pat = if ($parts.Length -ge 3) { [int]$parts[2] } else { 0 }
    return @($maj, $min, $pat)
}

function Test-GoVersionOlder([string]$V1, [string]$V2) {
    $p1 = Parse-GoVersion $V1
    $p2 = Parse-GoVersion $V2
    if ($p1[0] -lt $p2[0]) { return $true }
    if ($p1[0] -gt $p2[0]) { return $false }
    if ($p1[1] -lt $p2[1]) { return $true }
    if ($p1[1] -gt $p2[1]) { return $false }
    if ($p1[2] -lt $p2[2]) { return $true }
    return $false
}

function Get-BinaryGoVersion([string]$Path) {
    try {
        $meta = go version -m $Path
        if ($LASTEXITCODE -ne 0 -or -not $meta) { return $null }
        $first = $meta | Select-Object -First 1
        $tokens = $first.ToString().Split(' ')
        foreach ($t in $tokens) {
            $trimmed = $t.Trim()
            if ($trimmed -match '^go[0-9]') {
                return $trimmed
            }
        }
    } catch {}
    return $null
}

# ToolOrInstall returns the full path of <name>.exe, installing it into
# GOPATH\bin via go install if it is not already resolvable or was built
# with an older Go toolchain than the module requires. Failure here
# (e.g. network down) is treated like any other gate failure: the gate goes
# FAIL, the harness continues.
function ToolOrInstall([string]$Name, [string]$ModulePath) {
    $modTc = Get-ModuleToolchain
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    $bindir = (go env GOPATH).Trim()
    $gobin = (go env GOBIN).Trim()
    if ($gobin) { $bindir = $gobin } else { $bindir = Join-Path $bindir "bin" }
    $exe = $null
    if ($cmd) {
        $exe = $cmd.Source
    } else {
        $candidate = Join-Path $bindir ($Name + ".exe")
        if (Test-Path $candidate) { $exe = $candidate }
    }

    if ($exe -and (Test-Path $exe)) {
        $toolVer = Get-BinaryGoVersion $exe
        if ($toolVer -and $modTc) {
            if (-not (Test-GoVersionOlder $toolVer $modTc)) {
                return $exe
            }
            Write-Host ("      {0} was built with {1} (older than module {2}); reinstalling via GOTOOLCHAIN={2} go install {3}@latest" -f $Name, $toolVer, $modTc, $ModulePath)
        } else {
            Write-Host ("      {0} Go version unknown; reinstalling via GOTOOLCHAIN={1} go install {2}@latest" -f $Name, $modTc, $ModulePath)
        }
    } else {
        Write-Host ("      {0} not found; installing into GOPATH via GOTOOLCHAIN={1} go install {2}@latest" -f $Name, $modTc, $ModulePath)
    }

    $prevToolchain = $env:GOTOOLCHAIN
    try {
        if ($modTc) { $env:GOTOOLCHAIN = $modTc }
        go install ($ModulePath + "@latest")
        if ($LASTEXITCODE -ne 0) { Deny ("go install " + $ModulePath + "@latest failed") }
    } catch {
        Deny ("go install " + $ModulePath + "@latest failed")
    } finally {
        $env:GOTOOLCHAIN = $prevToolchain
    }

    $targetExe = Join-Path $bindir ($Name + ".exe")
    if (Test-Path $targetExe) {
        return $targetExe
    }
    $cmdAfter = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmdAfter) { return $cmdAfter.Source }
    Deny ("installed but not found at " + $targetExe)
}

function FmtMB([double]$Bytes) {
    return ($Bytes / 1MB).ToString("0.0", [System.Globalization.CultureInfo]::InvariantCulture)
}

function Classify-StaticcheckOutput($lines) {
    # 1. Load/compile problem wins: line ending in (compile) or (config),
    #    or containing 'package requires newer Go version', 'could not load', 'failed to load'.
    $patLoad = '\((compile|config)\)$|package requires newer Go version|could not load|failed to load'
    foreach ($item in $lines) {
        $str = $item.ToString().TrimEnd("
").Trim()
        if ($str -match $patLoad) {
            return "could not load the module: $str"
        }
    }

    # 2. Finding line: ^<path>:<line>:<col>: .* \((SA|ST|S|QF|U)[0-9]+\)$
    $patFind = '^.+:\d+:\d+: .* \((SA|ST|S|QF|U)\d+\)$'
    foreach ($item in $lines) {
        $str = $item.ToString().TrimEnd("
").Trim()
        if ($str -match $patFind) {
            return "reported findings"
        }
    }

    # 3. Otherwise, first non-empty line
    foreach ($item in $lines) {
        $str = $item.ToString().TrimEnd("
").Trim()
        if ($str) {
            return "staticcheck failed: $str"
        }
    }

    return "clean"
}

function Selftest-Classify {
    $failed = 0
    $c1Input = "internal/server/run_darwin.go:126:10: error strings should not be capitalized (ST1005)"
    $c1Expected = "reported findings"
    $c1Actual = Classify-StaticcheckOutput @($c1Input)
    if ($c1Actual -ne $c1Expected) {
        Write-Error "[SELFTEST FAIL] canary 1 (finding): expected '$c1Expected', got '$c1Actual'"
        $failed++
    } else {
        Write-Host "[SELFTEST OK] canary 1 (finding) -> $c1Actual"
    }

    $c2Input = "internal/server/run_darwin.go:10:2: undeclared name: foo (compile)"
    $c2Expected = "could not load the module: internal/server/run_darwin.go:10:2: undeclared name: foo (compile)"
    $c2Actual = Classify-StaticcheckOutput @($c2Input)
    if ($c2Actual -ne $c2Expected) {
        Write-Error "[SELFTEST FAIL] canary 2 (compile): expected '$c2Expected', got '$c2Actual'"
        $failed++
    } else {
        Write-Host "[SELFTEST OK] canary 2 (compile) -> $c2Actual"
    }

    $c3Input = @($c1Input, $c2Input)
    $c3Expected = $c2Expected
    $c3Actual = Classify-StaticcheckOutput $c3Input
    if ($c3Actual -ne $c3Expected) {
        Write-Error "[SELFTEST FAIL] canary 3 (both together): expected '$c3Expected', got '$c3Actual'"
        $failed++
    } else {
        Write-Host "[SELFTEST OK] canary 3 (both together) -> $c3Actual"
    }

    if ($failed -ne 0) {
        Write-Error "selftest-classify failed ($failed errors)"
        exit 1
    }
    Write-Host "selftest-classify PASS (all 3 canaries matched expected verdicts)"
}

if ($SelftestClassify.IsPresent -or ($RemainingArgs -contains "--selftest-classify") -or ($RemainingArgs -contains "-selftest-classify")) {
    Selftest-Classify
    exit 0
}

# ---------------------------------------------------------------- gate 1
runGate {
    Step "go build (windows full, linux/darwin without the cgo UI packages, all five GOOS/GOARCH, CGO_ENABLED=0; the full linux tree is built on the Linux host — IAMT-252/262)"
    $env:CGO_ENABLED = "0"
    foreach ($pair in @(
        @{ GOOS = "windows"; GOARCH = "amd64" },
        @{ GOOS = "linux";   GOARCH = "amd64" },
        @{ GOOS = "linux";   GOARCH = "arm64" },
        @{ GOOS = "darwin";  GOARCH = "amd64" },
        @{ GOOS = "darwin";  GOARCH = "arm64" }
    )) {
        $env:GOOS = $pair.GOOS; $env:GOARCH = $pair.GOARCH
        if ($pair.GOOS -eq "linux" -or $pair.GOOS -eq "darwin") {
            # IAMT-252/IAMT-262: on linux AND darwin the ui package (and
            # cmd/iamtunnel, which opens the window on both) needs cgo —
            # gio talks to X11/Wayland through it on linux and to Cocoa on
            # darwin. The CGO_ENABLED=0 pass covers every other package
            # with the target GOOS already set above, so windows-only
            # packages drop out of go list by themselves. The full linux
            # tree is built with CGO_ENABLED=1 on the Linux host
            # (scripts/gates.sh); the full darwin tree needs a Mac with an
            # Apple toolchain, which no gates host has (IAMT-262).
            # IAMT-332 round 9: scripts is excluded the same way — every
            # non-test file there is `//go:build ignore` (the check_*.go
            # tools run via `go run`, never built as a package), but
            # go list -e reports it as a real package once it has a
            # _test.go (added by gate 16's check_rawfileio_test.go),
            # and go build fails a NAMED package it cannot build instead
            # of silently dropping it the way `go build ./...` would.
            $scoped = @(go list -e ./... | Where-Object { $_ -ne "github.com/ultrathinker/iamtunnel/cmd/iamtunnel" -and $_ -ne "github.com/ultrathinker/iamtunnel/internal/ui" -and $_ -ne "github.com/ultrathinker/iamtunnel/scripts" })
            go build $scoped
        } else {
            go build ./...
        }
        if ($LASTEXITCODE -ne 0) {
            Native ("GOOS=" + $pair.GOOS + " GOARCH=" + $pair.GOARCH + " go build")
        }
    }
    # THE HEADLESS BUILD, the one that ships to a gateway (IAMT-439).
    #
    # Built here and not only on the Linux host, because this is the
    # variant with no cgo in it at all: -tags nogui drops internal/ui and
    # every file that opens a window, so cmd/iamtunnel -- excluded from
    # the pass above for exactly that reason -- comes back INTO scope and
    # is compiled whole, from Windows, for Linux.
    #
    # It is the artefact on the one machine with a port open to the
    # internet, and a tag that stops compiling would be found by whoever
    # next installs a gateway rather than here. So: both variants, every
    # run.
    #
    # Windows is in the list too (IAMT-470): a file that needs the window
    # and is tagged only "windows", not "windows && !nogui", breaks the
    # headless build on Windows alone - and no gate built that pair, so
    # the one such test file stayed broken until somebody ran it by hand.
    foreach ($pair in @(
        @{ GOOS = "windows"; GOARCH = "amd64" },
        @{ GOOS = "linux";  GOARCH = "amd64" },
        @{ GOOS = "linux";  GOARCH = "arm64" },
        @{ GOOS = "darwin"; GOARCH = "amd64" }
    )) {
        $env:GOOS = $pair.GOOS; $env:GOARCH = $pair.GOARCH
        $scoped = @(go list -e ./... | Where-Object { $_ -ne "github.com/ultrathinker/iamtunnel/internal/ui" -and $_ -ne "github.com/ultrathinker/iamtunnel/scripts" })
        go build -tags nogui $scoped
        if ($LASTEXITCODE -ne 0) {
            Native ("GOOS=" + $pair.GOOS + " GOARCH=" + $pair.GOARCH + " go build -tags nogui")
        }
    }
    $env:GOOS = ""; $env:GOARCH = ""
    Passed "all five targets compile, and the headless build on four of them"
}

# ---------------------------------------------------------------- gate 2
runGate {
    Step "go vet (windows full, linux/darwin without the cgo UI packages, all five GOOS/GOARCH; the full linux tree is vetted on the Linux host — IAMT-252/262)"
    foreach ($pair in @(
        @{ GOOS = "windows"; GOARCH = "amd64" },
        @{ GOOS = "linux";   GOARCH = "amd64" },
        @{ GOOS = "linux";   GOARCH = "arm64" },
        @{ GOOS = "darwin";  GOARCH = "amd64" },
        @{ GOOS = "darwin";  GOARCH = "arm64" }
    )) {
        $env:GOOS = $pair.GOOS; $env:GOARCH = $pair.GOARCH
        if ($pair.GOOS -eq "linux" -or $pair.GOOS -eq "darwin") {
            # Same scope as gate 1: see the IAMT-252/262 and IAMT-332 notes there.
            $scoped = @(go list -e ./... | Where-Object { $_ -ne "github.com/ultrathinker/iamtunnel/cmd/iamtunnel" -and $_ -ne "github.com/ultrathinker/iamtunnel/internal/ui" -and $_ -ne "github.com/ultrathinker/iamtunnel/scripts" })
            go vet $scoped
        } else {
            go vet ./...
        }
        if ($LASTEXITCODE -ne 0) {
            Native ("GOOS=" + $pair.GOOS + " GOARCH=" + $pair.GOARCH + " go vet")
        }
    }
    # And the headless variant, same reason as in gate 1: a build nobody
    # vets is a build whose mistakes are found on a gateway. Vet, unlike
    # build, compiles the test files: it is the step that catches a test
    # which needs the window but is not tagged !nogui (IAMT-470).
    foreach ($pair in @(
        @{ GOOS = "windows"; GOARCH = "amd64" },
        @{ GOOS = "linux";  GOARCH = "amd64" },
        @{ GOOS = "darwin"; GOARCH = "amd64" }
    )) {
        $env:GOOS = $pair.GOOS; $env:GOARCH = $pair.GOARCH
        $scoped = @(go list -e ./... | Where-Object { $_ -ne "github.com/ultrathinker/iamtunnel/internal/ui" -and $_ -ne "github.com/ultrathinker/iamtunnel/scripts" })
        go vet -tags nogui $scoped
        if ($LASTEXITCODE -ne 0) {
            Native ("GOOS=" + $pair.GOOS + " GOARCH=" + $pair.GOARCH + " go vet -tags nogui")
        }
    }
    $env:GOOS = ""; $env:GOARCH = ""
    # THE LINUX HALF OF THIS GATE, on the host that has it (R2, 24.09.2026).
    #
    # Every pass above vetts linux/darwin WITHOUT cmd/iamtunnel and
    # internal/ui - the cgo UI packages this host cannot compile (the
    # IAMT-252/262 note in gate 1) - so the window's own test files were
    # compiled by nobody here. Round 2 fell straight into that hole: they
    # stopped compiling on linux, every Windows pass stayed green, and
    # nothing anywhere was looking. When Docker IS present, the container
    # is the Linux host this gate's step text always named: the same
    # repository mounted read-only in spirit (nothing in it is written -
    # the container's caches live inside the container), the FULL tree,
    # cgo and the window's tests included. go vet, like build, compiles
    # test files, so this is the step that would have caught that
    # breakage. A host without Docker - or with the daemon down - still
    # gates on everything above; the skip says which one it was, out
    # loud, because a check that does not run explains itself (gate 10).
    $dockerVet = "SKIPPED: docker not found on this host"
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($docker) {
        & { $ErrorActionPreference = 'Continue'; docker info 2>&1 | Out-Null }
        if ($LASTEXITCODE -ne 0) {
            $dockerVet = "SKIPPED: docker is installed but its daemon is unreachable"
            Write-Host ("      SKIP: full-linux go vet - {0}" -f $dockerVet)
        } else {
            $payload = 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq pkg-config libwayland-dev libx11-dev libx11-xcb-dev libxkbcommon-x11-dev libgles2-mesa-dev libegl1-mesa-dev libffi-dev libxcursor-dev libvulkan-dev >/dev/null 2>&1 && CGO_ENABLED=1 go vet ./...'
            Write-Host "      full-linux go vet (golang:1.27 container, --rm):"
            & { $ErrorActionPreference = 'Continue'; docker run --rm -v "$($RepoRoot):/src" -w /src -e GOFLAGS=-buildvcs=false golang:1.27 bash -c $payload 2>&1 } | ForEach-Object { Write-Host ("      | " + $_) }
            if ($LASTEXITCODE -ne 0) {
                Native ("full-linux go vet in the golang:1.27 container")
            }
            $dockerVet = "the full tree vetted in the golang:1.27 container"
        }
    } else {
        Write-Host ("      SKIP: full-linux go vet - {0}" -f $dockerVet)
    }
    Passed ("vet is clean on all five targets, and on the headless build; linux: {0}" -f $dockerVet)
}

# ---------------------------------------------------------------- gate 3
runGate {
    Step "staticcheck ./..."
    $staticcheck = ToolOrInstall "staticcheck" "honnef.co/go/tools/cmd/staticcheck"
    $output = & $staticcheck ./... 2>&1
    $ec = $LASTEXITCODE
    if ($output) {
        $output | ForEach-Object { Write-Host $_ }
    }
    if ($ec -ne 0) {
        $verdict = Classify-StaticcheckOutput $output
        if ($verdict -ne "clean") {
            Deny $verdict
        } else {
            Deny ("staticcheck failed: exit code " + $ec)
        }
        return
    }
    Passed "no findings"
}

# ---------------------------------------------------------------- gate 4
runGate {
    Step "govulncheck ./..."
    $govulncheck = ToolOrInstall "govulncheck" "golang.org/x/vuln/cmd/govulncheck"
    $output = & $govulncheck ./... 2>&1
    $ec = $LASTEXITCODE
    if ($output) {
        $output | ForEach-Object { Write-Host $_ }
    }
    if ($ec -ne 0) {
        $loadErr = $null
        foreach ($item in $output) {
            $str = $item.ToString().Trim()
            if ($str -match 'loading packages|package requires newer Go version|could not load|failed to load|^govulncheck:') {
                $loadErr = $str
                break
            }
        }
        if ($ec -ne 3 -or $loadErr) {
            if (-not $loadErr) {
                foreach ($item in $output) {
                    $str = $item.ToString().Trim()
                    if ($str) { $loadErr = $str; break }
                }
            }
            if (-not $loadErr) { $loadErr = "exit code " + $ec }
            Deny ("govulncheck could not load the module: " + $loadErr)
        } else {
            Deny "govulncheck ./... found vulnerabilities reachable from this code"
        }
    }
    Passed "no reachable vulnerabilities"
}

# ---------------------------------------------------------------- gate 5
runGate {
    Step "go test ./... -race -count=1"
    # -race needs CGO_ENABLED=1 on windows/amd64; scoped to this gate only.
    #
    # -count=1 is mandatory, and it is not decoration. Go caches test
    # results, and a run under the race detector is cached too. Without
    # -count=1 a single accidentally green run makes the gate green
    # forever -- and a race is, by nature, not caught every time. That
    # is exactly how IAMT-68 with a real race inside was accepted on
    # 13.09: the first run was green, the next one produced four
    # WARNING: DATA RACE lines. A gate that a cache can satisfy is a
    # dud.
    $env:CGO_ENABLED = "1"
    go test ./... -race -count=1
    if ($LASTEXITCODE -ne 0) { Native "go test ./... -race -count=1" }
    $env:CGO_ENABLED = "0"
    # THE HEADLESS VARIANT'S OWN TESTS (R1-CX F-05). Gates 1 and 2 build
    # and vet it; nothing ran its tests, and the one test that tells the
    # variants apart demanded "full" unconditionally - so the documented
    # go test -tags nogui ./... was red, and nobody saw it. Only the
    # packages whose file set the tag changes run again: for the rest the
    # headless test binary is the one that has just passed.
    $listFmt = '{{.ImportPath}}|{{.GoFiles}}{{.TestGoFiles}}{{.XTestGoFiles}}'
    $fullFiles = @{}
    foreach ($row in @(go list -e -f $listFmt ./...)) {
        $parts = $row.Split("|", 2)
        $fullFiles[$parts[0]] = $parts[1]
    }
    if ($LASTEXITCODE -ne 0) { Native "go list" }
    $headlessRows = @(go list -e -tags nogui -f $listFmt ./...)
    if ($LASTEXITCODE -ne 0) { Native "go list -tags nogui" }
    $differ = @()
    foreach ($row in $headlessRows) {
        $parts = $row.Split("|", 2)
        if ($fullFiles[$parts[0]] -ne $parts[1]) { $differ += $parts[0] }
    }
    if ($differ.Count -eq 0) {
        Deny "no package changes under -tags nogui: either the headless variant is gone or this check no longer sees it"
    }
    go test -tags nogui -count=1 $differ
    if ($LASTEXITCODE -ne 0) { Native ("go test -tags nogui -count=1 " + ($differ -join " ")) }
    # And the headless program itself starts and says which build it is:
    # the third line of "version" is what an operator reads on a gateway.
    $said = (& go run -tags nogui ./cmd/iamtunnel version 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { Native "go run -tags nogui ./cmd/iamtunnel version" }
    if ($said -notmatch "(?m)^build headless") {
        Deny ("the headless build does not call itself headless in its version: " + $said)
    }
    Passed "all tests pass under the race detector, and the headless variant's own tests pass too"
}

# ---------------------------------------------------------------- gate 6
runGate {
    Step "CGO_ENABLED=0 enforced in binary build info"
    # Builds exactly like gate 8, then reads CGO_ENABLED back from the binary
    # with "go version -m" instead of trusting the environment. A build made
    # with CGO_ENABLED=1 fails right here.
    $env:CGO_ENABLED = "0"   # IAMT-10 canary: set to "1" to see this gate fail
    $env:GOOS = "windows"; $env:GOARCH = "amd64"
    $tmp = Join-Path $env:TEMP ("iamt-gates-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory $tmp | Out-Null
    go build -trimpath -ldflags "-s -w" -o (Join-Path $tmp "iamtunnel.exe") ./cmd/iamtunnel
    if ($LASTEXITCODE -ne 0) { Native "go build cmd/iamtunnel" }
    $env:GOOS = ""
    $meta = go version -m (Join-Path $tmp "iamtunnel.exe")
    if ($LASTEXITCODE -ne 0) { Native "go version -m" }
    $line = $meta | Select-String -Pattern "^\s*build\s+CGO_ENABLED=" | Select-Object -First 1
    if (-not $line) {
        Deny "no CGO_ENABLED line in binary build info; cannot prove CGO was disabled"
    }
    $value = ($line.Line.Split("=")[1]).Trim()
    if ($value -ne "0") {
        Deny ("binary was built with CGO_ENABLED=" + $value + ", policy is CGO_ENABLED=0 (SPEC 4.1)")
    }
    Remove-Item -Recurse -Force $tmp
    Passed "binary build info says CGO_ENABLED=0"
}

# ---------------------------------------------------------------- gate 7
runGate {
    Step "forbidden dependencies absent (gliderlabs/gorm/sqlite/docker/fsnotify)"
    $forbidden = "gliderlabs", "gorm", "sqlite", "docker", "fsnotify"
    foreach ($pair in @(
        @{ GOOS = "windows"; GOARCH = "amd64" },
        @{ GOOS = "linux";   GOARCH = "amd64" },
        @{ GOOS = "linux";   GOARCH = "arm64" },
        @{ GOOS = "darwin";  GOARCH = "amd64" },
        @{ GOOS = "darwin";  GOARCH = "arm64" }
    )) {
        $env:GOOS = $pair.GOOS; $env:GOARCH = $pair.GOARCH
        if ($pair.GOOS -eq "linux" -or $pair.GOOS -eq "darwin") {
            # Same scope as gate 1: see the IAMT-252/262 and IAMT-332
            # notes there. The full linux dependency graph (with gio in
            # it) is checked on the Linux host by scripts/gates.sh; the
            # darwin one needs a Mac, for the same reason the darwin
            # build does.
            $scoped = @(go list -e ./... | Where-Object { $_ -ne "github.com/ultrathinker/iamtunnel/cmd/iamtunnel" -and $_ -ne "github.com/ultrathinker/iamtunnel/internal/ui" -and $_ -ne "github.com/ultrathinker/iamtunnel/scripts" })
            $deps = go list -deps $scoped
        } else {
            $deps = go list -deps ./...
        }
        if ($LASTEXITCODE -ne 0) { Native ("GOOS=" + $pair.GOOS + " GOARCH=" + $pair.GOARCH + " go list -deps") }
        $hits = @()
        foreach ($dep in $deps) {
            foreach ($word in $forbidden) {
                if ($dep -match $word) { $hits += $dep; break }
            }
        }
        if ($hits.Count -gt 0) {
            Deny ("GOOS=" + $pair.GOOS + " GOARCH=" + $pair.GOARCH + " dependency graph contains forbidden packages: " + ($hits -join ", "))
        }
    }
    $env:GOOS = ""; $env:GOARCH = ""
    Passed "no forbidden packages in any of the five dependency graphs"
}

# ---------------------------------------------------------------- gate 8
runGate {
    Step "binary size ceiling (windows <= 20.0 MB, CGO_ENABLED=0, -ldflags -s -w; linux sizes are measured on the Linux host by scripts/gates.sh, CGO_ENABLED=1 since IAMT-252; darwin/arm64 measured 19.3 MB on a real Mac 15.09, ceiling 22.0 MB — IAMT-262)"
    # If the actual size exceeds the ceiling, the gate dumps it into a
    # FAIL and does not raise the ceiling silently -- the maintainer
    # decides on a new boundary.
    #
    # There are no Linux rows here anymore (IAMT-252): the Linux binary
    # now carries the window and is built with CGO_ENABLED=1, which
    # cannot be done from a Windows host, and the old CGO_ENABLED=0
    # binary no longer exists. scripts/gates.sh measures them on the
    # Linux host under the 16.0 MB ceiling.
    #
    # There are no Darwin rows here anymore either (IAMT-262): the
    # macOS binary now also carries the window and needs cgo+Cocoa, so
    # a CGO_ENABLED=0 darwin build does not exist (gioui.org/internal/gl
    # does not build without cgo), and the Apple toolchain is present
    # neither on this host nor on the Linux host. The darwin binary
    # size is only measured on a live Mac.
    #
    # On 15.09 SSH access to a real Apple-silicon Mac was obtained and
    # darwin/arm64 was built by hand: 19.3 MB. The previously proposed
    # ceiling of 12.0 MB was an estimate without a measurement -- it
    # was raised to 22.0 MB (a decision taken on the actual numbers,
    # the same principle as for linux/amd64 in IAMT-252).
    #
    # On 24.09 (1.48) windows/amd64 crossed 18.0 MB: 1.47 weighed
    # 17.998 MB, and IAMT-499 added the Manage/Keys panels and the
    # Gateway subtab to the window -- 18.1 MB. The ceiling was raised
    # to 20.0 MB (a decision taken on the actual numbers, as for
    # linux/amd64 and darwin): headroom for the window to grow, not a
    # permission to double in size.
    $env:CGO_ENABLED = "0"
    $tmp = Join-Path $env:TEMP ("iamt-gates-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory $tmp | Out-Null
    $sizes = @()
    foreach ($pair in @(
        @{ GOOS = "windows"; GOARCH = "amd64"; Ceiling = 20.0; Bin = "iamtunnel.exe" }
    )) {
        $env:GOOS = $pair.GOOS; $env:GOARCH = $pair.GOARCH
        $outPath = Join-Path $tmp $pair.Bin
        go build -trimpath -ldflags "-s -w" -o $outPath ./cmd/iamtunnel
        if ($LASTEXITCODE -ne 0) {
            Native ("GOOS=" + $pair.GOOS + " GOARCH=" + $pair.GOARCH + " go build -ldflags -s -w")
        }
        $mb = [double](FmtMB (Get-Item $outPath).Length)
        $sizes += $pair
        $script:sizeByTarget[$pair.GOOS + "/" + $pair.GOARCH] = $mb
        Write-Host (("      {0}/{1}: {2} MB (ceiling {3} MB)" -f $pair.GOOS, $pair.GOARCH, $mb, $pair.Ceiling))
        if ($mb -gt $pair.Ceiling) {
            Deny (("GOOS={0} GOARCH={1} binary {2} MB exceeds the {3} MB ceiling (SPEC 9); " -f $pair.GOOS, $pair.GOARCH, $mb, $pair.Ceiling) +
                "this gate does not raise the ceiling — that is the maintainer's decision, taken on the actual numbers above")
        }
    }
    $env:GOOS = ""; $env:GOARCH = ""
    Remove-Item -Recurse -Force $tmp
    $summary = ($sizes | ForEach-Object { "{0}/{1}={2} MB" -f $_.GOOS, $_.GOARCH, $script:sizeByTarget[$_.GOOS + "/" + $_.GOARCH] }) -join ", "
    Passed ("sizes within ceiling: " + $summary)
}

# ---------------------------------------------------------------- gate 9
runGate {
    Step "no test that cannot go red (failure path or helper-with-t in every Test*)"
    # The rule: a test function counts as a dud if its body contains
    # neither a call to a failure/skip means (t.Fatal, t.Errorf,
    # t.Skip...) nor a call to a same-package helper that is passed a
    # *testing.T. t.Run subtests count -- the check may live inside a
    # closure.
    #
    # Exceptions are allowed, but each one is a separate line in the
    # list below, with the reason next to it. There must be no silent
    # bypass: a gate that can be quietly circumvented becomes a dud
    # itself.
    $gate9Allow = @(
        @{ Name = "TestChannelConn_ImplementsNetConn";
           Reason = 'compile-time assertion: the body contains `var c net.Conn = NewChannelConn(nil)` -- if the contract breaks, the package will not compile; by design it cannot go red through the body' }
    )
    $allowSpec = ($gate9Allow | ForEach-Object { "{0} ==>{1}" -f $_.Name, $_.Reason }) -join ";;"
    $pkgs = @(
        "./cmd/iamtunnel",
        "./internal/admin",
        "./internal/client",
        "./internal/config",
        "./internal/elevate",
        "./internal/gateway",
        "./internal/gateway/acl",
        "./internal/gateway/auth",
        "./internal/gateway/core",
        "./internal/gateway/events",
        "./internal/gateway/record",
        "./internal/gateway/state",
        "./internal/macos",
        "./internal/paste",
        "./internal/proto",
        "./internal/record/export",
        "./internal/server",
        "./internal/sshx",
        "./internal/ui",
        "./internal/ui/design",
        "./internal/ui/macfonts",
        "./internal/ui/winfonts",
        "./internal/winkeys",
        "./test/e2e"
    )
    $env:CGO_ENABLED = "0"
    # Native stderr under ErrorActionPreference=Stop is a terminating error in PS 5.1;
    # scope it so a failing check reports FAIL instead of crashing the script.
    $out = & { $ErrorActionPreference = 'Continue'; go run scripts/check_noempty.go -allow $allowSpec ($pkgs) 2>&1 }
    $rc = $LASTEXITCODE
    if ($out) { $out | ForEach-Object { Write-Host ("      " + $_) } }
    # Print the exception list itself, so that a gate that can be
    # quietly circumvented becomes a dud itself: every time it is
    # visible what is allowed and why.
    if ($gate9Allow.Count -gt 0) {
        Write-Host "      exceptions on file (each line is a separate allow):"
        foreach ($e in $gate9Allow) {
            Write-Host ("        - {0}: {1}" -f $e.Name, $e.Reason)
        }
    } else {
        Write-Host "      no exceptions on file"
    }
    if ($rc -ne 0) { Deny "empty Test* functions with no failure path and no helper-with-t call" }
    Passed "every Test* has a failure path or a helper-with-t call"
}

# ---------------------------------------------------------------- gate 10
runGate {
    Step "every skipped check is visible and explains itself"
    # Gate 9 catches a test that cannot go red. This one catches the
    # second way to get a green run without checking anything: t.Skip.
    # A run of nineteen scenarios, four of them skipped, prints "ok"
    # and reads as nineteen checks -- while there are fifteen. That is
    # exactly what happened on 12.09 with the end-to-end scenarios of
    # the specification §8.
    #
    # The gate does NOT forbid skips: a platform skip is a legitimate
    # thing. It demands that no skip be invisible and that each one
    # carry a clear reason, so that it can later be lifted.
    $pkgs10 = @(
        "./cmd/iamtunnel",
        "./internal/admin",
        "./internal/client",
        "./internal/config",
        "./internal/elevate",
        "./internal/gateway",
        "./internal/gateway/acl",
        "./internal/gateway/auth",
        "./internal/gateway/core",
        "./internal/gateway/events",
        "./internal/gateway/record",
        "./internal/gateway/state",
        "./internal/macos",
        "./internal/paste",
        "./internal/proto",
        "./internal/record/export",
        "./internal/server",
        "./internal/sshx",
        "./internal/ui",
        "./internal/ui/design",
        "./internal/ui/macfonts",
        "./internal/ui/winfonts",
        "./internal/winkeys",
        "./test/e2e"
    )
    $env:CGO_ENABLED = "0"
    $out = & { $ErrorActionPreference = 'Continue'; go run scripts/check_skips.go ($pkgs10) 2>&1 }
    $rc = $LASTEXITCODE
    if ($out) { $out | ForEach-Object { Write-Host ("      " + $_) } }
    if ($rc -ne 0) { Deny "a skipped check gives no usable reason" }
    Passed "every skipped check is listed above with its reason"
}

# ---------------------------------------------------------------- gate 11
runGate {
    Step "no test writes into the maintainer's system"
    # The maintainer's machine is not a test bench. The rule appeared
    # on 12.09, when the test of one agent switched the Windows theme
    # to light, and it was checked with a grep before running other
    # agents' tests. On 13.09 the grep missed that trouble: the tests
    # of IAMT-73 left state.json, state.lock and machine.key in the
    # real ProgramData\iamtunnel directory -- the path came not from a
    # string in the test but from a fallback value inside
    # config.DirsFor when the test environment has no ProgramData. A
    # grep cannot catch that in principle, so the check here is by
    # fact: look before the run, look after, compare.
    $watch = @(
        (Join-Path $env:ProgramData 'iamtunnel'),
        (Join-Path $env:LOCALAPPDATA 'iamtunnel'),
        (Join-Path $env:APPDATA 'iamtunnel')
    )
    # The real ssh directory is a separate line: this machine's
    # nightly backup goes through it, and it must never be touched.
    $sshKeys = Join-Path (Join-Path $env:ProgramData 'ssh') 'administrators_authorized_keys'
    $themePath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    $svcRegKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\iamtunnel-gateway'

    $themeBefore = try { (Get-ItemProperty -Path $themePath -ErrorAction Stop).AppsUseLightTheme } catch { 'absent' }
    $sshBefore = if (Test-Path $sshKeys) { (Get-FileHash $sshKeys -Algorithm SHA256).Hash } else { 'absent' }
    $servicesBefore = @(Get-Service -Name 'iamtunnel*' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $svcRegBefore = Test-Path $svcRegKey
    $regServicesBefore = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like 'iamtunnel*' } | ForEach-Object { $_.Name })
    $beforePresent = @($watch | Where-Object { Test-Path $_ })
    $treeBefore = (& git status --porcelain) -join "`n"
    $shownBefore = if ($beforePresent.Count) { $beforePresent -join '; ' } else { 'none' }
    $shownSvcBefore = if ($servicesBefore.Count) { $servicesBefore -join '; ' } else { 'none' }
    Write-Host ('      before: theme={0} sshkeys={1} services={2} role dirs present={3}' -f $themeBefore, $sshBefore, $shownSvcBefore, $shownBefore)

    $env:CGO_ENABLED = '1'
    # The output is KEPT, not piped into Out-Null: when the suite goes red the
    # name of the failing test is the only evidence there is, and discarding it
    # is how IAMT-146 lost its trail and had to be hunted down separately.
    $suiteOut = & go test ./... -count=1 2>&1
    $rc = $LASTEXITCODE

    $themeAfter = try { (Get-ItemProperty -Path $themePath -ErrorAction Stop).AppsUseLightTheme } catch { 'absent' }
    $sshAfter = if (Test-Path $sshKeys) { (Get-FileHash $sshKeys -Algorithm SHA256).Hash } else { 'absent' }
    $servicesAfter = @(Get-Service -Name 'iamtunnel*' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    $svcRegAfter = Test-Path $svcRegKey
    $regServicesAfter = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like 'iamtunnel*' } | ForEach-Object { $_.Name })
    $afterPresent = @($watch | Where-Object { Test-Path $_ })
    $treeAfter = (& git status --porcelain) -join "`n"
    $shownAfter = if ($afterPresent.Count) { $afterPresent -join '; ' } else { 'none' }
    $shownSvcAfter = if ($servicesAfter.Count) { $servicesAfter -join '; ' } else { 'none' }
    Write-Host ('      after:  theme={0} sshkeys={1} services={2} role dirs present={3}' -f $themeAfter, $sshAfter, $shownSvcAfter, $shownAfter)

    if ($rc -ne 0) {
        $failed = @($suiteOut | Select-String -Pattern '^--- FAIL: (\S+)' |
            ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -Unique)
        $badPkgs = @($suiteOut | Select-String -Pattern '^FAIL\s+(\S+)' |
            ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -Unique)
        foreach ($line in @($suiteOut | Select-String -Pattern '(^--- FAIL|_test\.go:[0-9]+|^panic:|test timed out)' |
            Select-Object -First 40)) { Write-Host ('      | ' + $line) }
        $names = if ($failed.Count) { $failed -join ', ' } else { '(no FAIL line at all: the run died before any test reported)' }
        $where = if ($badPkgs.Count) { $badPkgs -join ', ' } else { '(no package line)' }
        Deny ('the suite itself is red, so this gate cannot judge the run. Failed tests: ' +
            $names + '. Failed packages: ' + $where)
    }

    $svcAppeared = @($servicesAfter | Where-Object { $servicesBefore -notcontains $_ })
    if ($svcAppeared.Count -gt 0) {
        foreach ($s in $svcAppeared) {
            Write-Host ('      APPEARED service ' + $s)
        }
        Deny ('a test registered a real Windows service: ' + ($svcAppeared -join '; '))
    }

    $regAppeared = @($regServicesAfter | Where-Object { $regServicesBefore -notcontains $_ })
    if ($regAppeared.Count -gt 0) {
        foreach ($k in $regAppeared) {
            Write-Host ('      APPEARED registry key ' + $k)
        }
        Deny ('a test created a real service registry key: ' + ($regAppeared -join '; '))
    } elseif (-not $svcRegBefore -and $svcRegAfter) {
        Write-Host ('      APPEARED registry key ' + $svcRegKey)
        Deny ('a test created a real service registry key: ' + $svcRegKey)
    }

    $appeared = @($afterPresent | Where-Object { $beforePresent -notcontains $_ })
    if ($appeared.Count -gt 0) {
        foreach ($a in $appeared) {
            Write-Host ('      APPEARED ' + $a)
            Get-ChildItem -Recurse -Force $a -ErrorAction SilentlyContinue | ForEach-Object { Write-Host ('        ' + $_.FullName) }
        }
        Deny ('a test created a real role directory: ' + ($appeared -join '; '))
    }
    if ("$themeAfter" -ne "$themeBefore") { Deny ('a test changed the owner Windows theme: {0} -> {1}' -f $themeBefore, $themeAfter) }
    if ("$sshAfter" -ne "$sshBefore") { Deny 'a test touched this machine real administrators_authorized_keys' }
    if ($treeAfter -ne $treeBefore) {
        Write-Host '      working tree changed during the run:'
        Write-Host ('      before: ' + $treeBefore)
        Write-Host ('      after:  ' + $treeAfter)
        Deny 'a test left files behind in the working tree'
    }
    Passed 'the theme, the real ssh keys, the services, the registry, the role directories and the working tree are all as they were'
}

# ---------------------------------------------------------------- gate 12
runGate {
    Step "the event dictionary in PROTOCOL matches the code"
    # The events.jsonl journal is the proof, and an outside parser
    # reads it by the list of names from PROTOCOL 1.7. On 13.09 the
    # document held thirty-nine names, the code nineteen, three
    # matched -- and not a single run noticed. The tests of the events
    # package check the serialisability of the very names they
    # themselves list, that is, they cannot check the completeness of
    # the list in principle (measured by the canary of 13.09: removed
    # a name from the test's list -- the test stayed green). This gate
    # is the only guard.
    #
    # The selftest runs FIRST deliberately: otherwise a broken detector
    # would pass green off as an absence of disagreements.
    $env:CGO_ENABLED = "0"
    go run scripts/check_eventdict.go -selftest
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_eventdict.go -selftest" }
    go run scripts/check_eventdict.go
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_eventdict.go" }
    Passed "the document and the code name the same event types, and every one of them is allowed"
}

# ---------------------------------------------------------------- gate 13
runGate {
    Step "the event names in RUNBOOK and THREATS match the code"
    # RUNBOOK and THREATS are read by the on-duty engineer at three in
    # the morning, and they trust the document, not the code. The
    # tagged block in each document is the list of event names the
    # document mentions, each marked with whether the code writes it.
    # A name from the dictionary that the code does not write is
    # allowed only with a live "not written in this build" caveat: the
    # gate checks the caveat is still true, it does not remove it from
    # the document.
    #
    # The selftest runs FIRST deliberately: otherwise a broken detector
    # would pass green off as an absence of disagreements.
    $env:CGO_ENABLED = "0"
    go run scripts/check_runbookevents.go -selftest
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_runbookevents.go -selftest" }
    go run scripts/check_runbookevents.go
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_runbookevents.go" }
    go run scripts/check_runbookevents.go -runbook docs/THREATS.md
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_runbookevents.go -runbook docs/THREATS.md" }
    Passed "every event name RUNBOOK and THREATS name is a real EventType, and each not-written caveat is still true"
}

# ---------------------------------------------------------------- gate 14
runGate {
    Step "the error-code dictionary in PROTOCOL matches the code"
    # Gate 12 holds the event dictionary, gate 13 -- the event names in
    # RUNBOOK. This one holds the error-code dictionary of PROTOCOL
    # 6.1 -- the iamtunnel-error-codes-v1 block, which until now was
    # compared with nothing. The block holds two kinds of codes: wire
    # (22) must exist in the product as exact string literals,
    # internal (31) is a classification of causes without literals;
    # absent is a machine-readable exception for codes named in the
    # prose as non-existent. Demanding a literal from an internal code
    # would mean going red from day one, and a gate that cries "wolf"
    # is worse than a missing one.
    #
    # The selftest runs FIRST deliberately: otherwise a broken detector
    # would pass green off as an absence of disagreements.
    $env:CGO_ENABLED = "0"
    go run scripts/check_errdict.go -selftest
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_errdict.go -selftest" }
    go run scripts/check_errdict.go
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_errdict.go" }
    Passed "every wire code is a real literal, every literal is marked wire, and the prose names no code outside the block"
}

# ---------------------------------------------------------------- gate 15
runGate {
    Step "the command lists in client, CLI usage and gateway match"
    # Gate 15 compares three command lists: the client library
    # (internal/admin, internal/client), the CLI usage
    # (cmd/iamtunnel/usage.go) and the gateway's dispatch table
    # (internal/gateway/admin_role.go commandTable). The comparison is
    # two-way: exceptions are documented explicitly in the checker's
    # code. The selftest runs FIRST deliberately.
    $env:CGO_ENABLED = "0"
    go run scripts/check_commands.go -selftest
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_commands.go -selftest" }
    go run scripts/check_commands.go
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_commands.go" }
    Passed "every client command is handled by the gateway, every gateway command is called, and CLI usage matches"
}

# ---------------------------------------------------------------- gate 16
runGate {
    Step "no raw os pathname I/O outside internal/datafile and the allowlist"
    # Gate 16 (IAMT-332, report §5.3): an AST walk over all non-test
    # .go files -- no writer/reader/metamorphoser of os pathnames
    # bypasses internal/datafile, except allowlist entries with a
    # mandatory reason. A stale entry (a file no longer produces
    # findings) is a refusal too: the allowlist keeps no dead souls.
    # The engine's selftest runs FIRST deliberately. The same run also
    # lives as go test (scripts/check_rawfileio_test.go), so the
    # protection fires in every ordinary `go test ./...` as well.
    $env:CGO_ENABLED = "0"
    go run scripts/check_rawfileio.go scripts/rawfileio_types.go -selftest
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_rawfileio.go scripts/rawfileio_types.go -selftest" }
    go run scripts/check_rawfileio.go scripts/rawfileio_types.go
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_rawfileio.go scripts/rawfileio_types.go" }
    Passed "every pathname I/O call routes through internal/datafile or carries an allowlist reason, and no allowlist entry is stale"
}

# ---------------------------------------------------------------- gate 17
runGate {
    Step "no sub-tab needs scrolling in a window of the default size"
    # Gate 17 (IAMT-336, SPEC 7.1/8): every tab's every sub-tab is
    # rendered offscreen at the real default window size and must draw no
    # scroll thumb. The rule it enforces is 7.1's — a sub-tab that no
    # longer fits is a signal to divide it further, not a reason to lean
    # on the scrollbar. Without the gate that rule lasts until the next
    # card somebody adds, which is exactly how the Admin tab grew to
    # eight cards down one page and hid the pairing flow from the
    # maintainer.
    # The test carries its own canary (TestGate17TheGateCanActuallyFail):
    # a pixel gate that quietly stopped finding the bar would report all
    # clear forever, which is worse than no gate at all.
    $env:CGO_ENABLED = "1"
    go test ./internal/ui/ -run "TestGate17" -count=1
    if ($LASTEXITCODE -ne 0) { Native "go test ./internal/ui/ -run TestGate17 -count=1" }
    $env:CGO_ENABLED = "0"
    Passed "every sub-tab of every tab fits the default window, and the detector proved it can still fail"
}

# ---------------------------------------------------------------- gate 18
runGate {
    Step "no Cyrillic in user-facing string literals under internal/ and cmd/"
    # AST-based check: comments and _test.go diagnostics remain free to use
    # native-language notes, while production string literals must be English.
    $env:CGO_ENABLED = "0"
    go run scripts/check_cyrillic.go -selftest
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_cyrillic.go -selftest" }
    go run scripts/check_cyrillic.go
    if ($LASTEXITCODE -ne 0) { Native "go run scripts/check_cyrillic.go" }
    Passed "every non-test string literal under internal/ and cmd/ is free of Cyrillic"
}

# ---------------------------------------------------------------- summary
Write-Host ""
Write-Host "================================================================"
Write-Host "Gate summary"
Write-Host "================================================================"
$padName = 0
foreach ($r in $script:GateResults) {
    if ($r.Name.Length -gt $padName) { $padName = $r.Name.Length }
}
foreach ($r in $script:GateResults) {
    $mark = if ($r.Status -eq "PASS") { "PASS" } else { "FAIL" }
    Write-Host ("  [{0}] gate {1}/{2}: {3}" -f $mark, $r.Index, $script:GateTotal, $r.Name)
    if ($r.Status -eq "FAIL" -and $r.Detail) {
        Write-Host ("         reason: {0}" -f $r.Detail)
    }
}
Write-Host "================================================================"
if ($script:OverallFailed) {
    $fails = 0
    foreach ($r in $script:GateResults) {
        if ($r.Status -eq "FAIL") { $fails++ }
    }
    Write-Host ("RESULT: FAIL ({0} of {1} gates red)" -f $fails, $script:GateTotal)
    exit 1
} else {
    Write-Host ("RESULT: PASS (all {0} gates green)" -f $script:GateTotal)
    exit 0
}
