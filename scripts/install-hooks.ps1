# IAMT-10: installs the pre-commit hook into a git repository.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\install-hooks.ps1
#       installs into the repository this scripts\ directory belongs to;
#   powershell ... -File scripts\install-hooks.ps1 -RepoRoot <path>
#       installs into another checkout (used by the IAMT-10 acceptance test
#       against a scratch clone, never against a live repository by agents).
#
# The hook blocks commits while any quality gate fails. It is NOT installed
# by the build or by gates.ps1 - only by an explicit run of this script.

param(
    [string]$RepoRoot = ""
)

$ErrorActionPreference = "Stop"

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}
$hookDir = Join-Path $RepoRoot ".git\hooks"
if (-not (Test-Path $hookDir)) {
    throw ".git\hooks not found under '$RepoRoot' - is it a git checkout?"
}

$src = Join-Path $PSScriptRoot "pre-commit"
if (-not (Test-Path $src)) {
    throw "hook source not found: $src"
}
$dst = Join-Path $hookDir "pre-commit"
Copy-Item $src $dst -Force

# The executable bit matters on Linux checkouts. On Windows this is a no-op,
# so failure is fine; prefer the bash that ships with Git for Windows, because
# a bare "bash" on PATH may resolve to a WSL install instead.
try {
    $gitBash = $null
    $gitSrc = (Get-Command git -ErrorAction SilentlyContinue).Source
    if ($gitSrc) {
        foreach ($cand in @(
            (Join-Path (Split-Path $gitSrc) "..\bin\bash.exe"),
            (Join-Path (Split-Path $gitSrc) "..\usr\bin\bash.exe")
        )) {
            if (Test-Path $cand) { $gitBash = $cand; break }
        }
    }
    if ($gitBash) {
        & $gitBash -c "chmod +x '$dst'" 2>$null
    } else {
        & bash -c "chmod +x '$dst'" 2>$null
    }
} catch { }

Write-Output ("installed pre-commit hook: " + $dst)
