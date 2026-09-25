# Builds the shipped binaries into _publish/ (SPEC §9): iamtunnel.exe for
# Windows, CGO off; and iamtunnel for Linux, which since IAMT-252 carries
# the window and is built WITH cgo (gio talks to X11/Wayland through it —
# the one sanctioned departure from CGO_ENABLED=0). The cgo build has to
# happen on a Linux host (scripts/gates.sh's host): cross-compiling
# linux/cgo from Windows needs a linux cross toolchain this repo does not
# assume, so on a Windows host the Linux leg is skipped with a warning
# instead of failing the whole build. Version and git sha are injected via
# -ldflags. Without commits the sha is "nogit".
param(
    [string]$Version = "0.0.0-skeleton"
)

$ErrorActionPreference = "Stop"

$sha = "nogit"
try {
    $gitSha = & git rev-parse --short=12 HEAD
    if ($LASTEXITCODE -eq 0 -and $gitSha) { $sha = "$gitSha".Trim() }
} catch { }

$env:CGO_ENABLED = "0"
$flags = "-s -w -X main.version=$Version -X main.gitSHA=$sha"
if (-not (Test-Path _publish)) { New-Item -ItemType Directory _publish | Out-Null }

$env:GOOS = "windows"; $env:GOARCH = "amd64"
# -H windowsgui: link for the GUI subsystem so Windows never creates a
# console for this process. It used to, and hideOwnConsole freed it after
# the fact -- which meant a black window appeared beside the program's own
# and vanished again, every launch. The command line still prints:
# attachParentConsole (cmd/iamtunnel/console_windows.go) joins the
# caller's console when there is one.
go build -trimpath -ldflags "$flags -H windowsgui" -o _publish/iamtunnel.exe ./cmd/iamtunnel
if ($LASTEXITCODE -ne 0) { throw "windows build failed" }

$env:GOOS = "linux"; $env:GOARCH = "amd64"
if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)) {
    $env:CGO_ENABLED = "1"
    go build -trimpath -ldflags $flags -o _publish/iamtunnel ./cmd/iamtunnel
    if ($LASTEXITCODE -ne 0) { throw "linux build failed" }
    $env:CGO_ENABLED = "0"
    Write-Output "built _publish/iamtunnel.exe and _publish/iamtunnel ($Version, sha $sha)"
} else {
    Write-Warning "linux leg skipped: the full iamtunnel needs CGO_ENABLED=1 (IAMT-252, gio/X11) and must be built on a Linux host"
    Write-Output "built _publish/iamtunnel.exe ($Version, sha $sha); _publish/iamtunnel was NOT built here"
}

# THE HEADLESS LINUX BINARY -- the one that goes on a gateway (IAMT-439).
#
# It is built HERE, on any host, because -tags nogui leaves no cgo in it:
# the window, internal/ui and the X11/Wayland/Cocoa bindings are all
# compiled out. The full Linux binary still needs a Linux host with the
# desktop dev packages, and still exists for a person running the window
# on Linux -- but a gateway never opens a window, and until today it
# still demanded eight graphics libraries to start at all (live install
# on AWS, 23.09.2026: exit 127 before main, on a clean Ubuntu Server).
$env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -trimpath -tags nogui -ldflags $flags -o _publish/iamtunnel-headless ./cmd/iamtunnel
if ($LASTEXITCODE -ne 0) { throw "headless linux build failed" }
Write-Output "built _publish/iamtunnel-headless for linux/amd64 ($Version, sha $sha) -- no window, no cgo, the gateway artefact"
$env:GOOS = ""; $env:GOARCH = ""
