#!/usr/bin/env bash
# IAMT-10 quality gates for iamtunnel (SPEC section 8) - Linux twin of
# scripts/gates.ps1.
#
# Runs every CI check in one command. Each gate prints exactly one mark:
# "[GATE n/18 PASS]" or "[GATE n/18 FAIL]". On the FIRST failure of a gate the
# rest of that gate is skipped, but every other gate still runs to the end -
# the user sees the state of all eighteen, not just the first red one. The exit
# code is non-zero iff at least one gate failed (so a CI consumer still sees
# the failure); a human reader also gets the summary table at the bottom.
#
# Usage:  ./scripts/gates.sh
# Tools are resolved from PATH first, then installed into GOPATH/bin with
# "go install ...@latest" (never system-wide).
#
# Note on gate 5: "go test -race" requires CGO_ENABLED=1 (the race runtime
# needs a C toolchain). The flag is raised for the test process only; gate 6
# separately proves the shipped binaries are built with CGO_ENABLED=0 by
# reading the fact back from the binary itself.
#
# Note on IAMT-252: the ui package (and cmd/iamtunnel, which now opens the
# window) is built WITH cgo on linux on purpose — gio talks to X11/Wayland
# through cgo. That is the one sanctioned departure from CGO_ENABLED=0, and
# THIS is the host that proves it: gates 1, 2 and 7 additionally run the
# full tree with CGO_ENABLED=1, and gate 8 measures the real linux binary.
# It needs the desktop dev packages: libx11-dev libxkbcommon-dev
# libxkbcommon-x11-dev libxcursor-dev libxfixes-dev libwayland-dev
# libvulkan-dev (headers only; nothing is opened, no display is required
# to compile).
#
# Note on IAMT-300: gates 3 and 4 join that list on a native linux/darwin
# host, because staticcheck and govulncheck cannot even load the module with
# CGO_ENABLED=0 there (the same Gio packages). They raise the flag for their
# own invocation only — see with_native_cgo below — so every other gate still
# runs CGO_ENABLED=0, and gates.ps1 on Windows is unaffected.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

if ! command -v go >/dev/null 2>&1; then
    echo "ERROR: 'go' is not found in PATH" >&2
    exit 1
fi

HOST_OS="$(uname -s)"
HOST_ARCH="$(go env GOARCH)"

GATE=0
CURRENT_GATE=""
GATE_NAME=""
GATE_TOTAL=18
# Each entry: "<index>|<name>|<status>|<detail>" — one line per gate. Used
# only for the summary table at the bottom.
GATE_RESULTS=()
OVERALL_FAILED=0

step() {
    if [ -n "$CURRENT_GATE" ]; then
        GATE="$CURRENT_GATE"
    else
        GATE=$((GATE + 1))
    fi
    GATE_NAME="$1"
    echo
    echo ">>> gate ${GATE}/${GATE_TOTAL}: ${GATE_NAME}"
}

# record_result stashes a row and updates the global failure flag.
record_result() {
    local status="$1" detail="$2"
    GATE_RESULTS+=("${GATE}|${GATE_NAME}|${status}|${detail}")
    if [ "$status" = "FAIL" ]; then OVERALL_FAILED=1; fi
}

passed() {
    if [ "$#" -gt 0 ]; then
        echo "[GATE ${GATE}/${GATE_TOTAL} PASS] ${GATE_NAME} - $1"
        record_result "PASS" "$1"
    else
        echo "[GATE ${GATE}/${GATE_TOTAL} PASS] ${GATE_NAME}"
        record_result "PASS" ""
    fi
}

# deny records the gate as FAIL, prints the message, and returns 1 from the
# caller via the surrounding run_gate wrapper. The script itself does NOT
# exit here, so the harness keeps running.
deny() {
    echo "[GATE ${GATE}/${GATE_TOTAL} FAIL] ${GATE_NAME} - $1" >&2
    record_result "FAIL" "$1"
    return 1
}

# skipped records the gate as SKIP, prints the mark, and returns 0.
skipped() {
    if [ "$#" -gt 0 ]; then
        echo "[GATE ${GATE}/${GATE_TOTAL} SKIP] ${GATE_NAME} - $1"
        record_result "SKIP" "$1"
    else
        echo "[GATE ${GATE}/${GATE_TOTAL} SKIP] ${GATE_NAME}"
        record_result "SKIP" ""
    fi
}

# sha256_of prints the SHA-256 hash of a file using sha256sum or shasum (BSD).
sha256_of() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | cut -d' ' -f1
    else
        echo "sha256_tool_missing"
    fi
}

# run_gate is kept for symmetry with the PowerShell harness; it does nothing
# extra here because each gate function is responsible for calling deny() and
# returning a non-zero status, which the outer loop discards with `|| true`.
run_gate() {
    "$@"
}

# with_native_cgo runs a command with CGO_ENABLED=1 on a native linux/darwin
# host, and with the ambient CGO_ENABLED anywhere else.
#
# IAMT-300: gates 3 (staticcheck) and 4 (govulncheck) have to LOAD the whole
# module, and since IAMT-252/262 the Gio window in cmd/iamtunnel and
# internal/ui is a cgo package on linux and darwin — with CGO_ENABLED=0 the
# analysers cannot even type-check it, and the gates reported
# "could not load the module: .../gioui.org@v.../internal/gl/util.go:60:24:
# undefined: Functions (compile)" on a real Mac while passing by hand with
# CGO_ENABLED=1. The environment is scoped to these two invocations exactly
# as gate 2 scopes `go vet` and gate 5 scopes -race; everything else in this
# script still runs with CGO_ENABLED=0 (gate 1 exports it and never unsets
# it), and the analysis itself does not need cgo — only the ability to load
# the cgo-dependent packages.
#
# The host test is HOST_OS (the uname -s this script already resolved at the
# top) rather than GOOS: windows/amd64 cross-passes set GOOS for a moment, and
# this helper must answer for the machine running the analyser. On a Windows
# host (gates.ps1 is the harness there) the ambient environment is kept
# unchanged, which is the pre-IAMT-300 behaviour.
with_native_cgo() {
    local host="${HOST_OS:-}"
    [ -n "$host" ] || host="$(uname -s 2>/dev/null)"
    case "$host" in
        Linux | Darwin) CGO_ENABLED=1 "$@" ;;
        *) "$@" ;;
    esac
}

# get_module_toolchain returns the Go toolchain/version required by the module:
# derived from go.mod ('toolchain' line, else 'go' line), falling back to
# 'go env GOVERSION' inside the module.
get_module_toolchain() {
    local tc="" go_ver="" key val rest
    if [ -f "go.mod" ]; then
        while read -r key val rest; do
            if [ "$key" = "toolchain" ] && [ -n "$val" ]; then
                tc="$val"
                break
            elif [ "$key" = "go" ] && [ -n "$val" ] && [ -z "$go_ver" ]; then
                go_ver="$val"
            fi
        done < go.mod
        if [ -z "$tc" ] && [ -n "$go_ver" ]; then
            case "$go_ver" in
                go*) tc="$go_ver" ;;
                *)   tc="go${go_ver}" ;;
            esac
        fi
    fi
    if [ -z "$tc" ]; then
        tc="$(go env GOVERSION 2>/dev/null || true)"
    fi
    echo "$tc"
}

# get_binary_go_version returns the Go version used to build the binary,
# extracted from the first line of 'go version -m <binary>' (e.g. 'go1.27.0').
get_binary_go_version() {
    local bin="$1"
    local first_line word
    first_line="$(go version -m "$bin" 2>/dev/null | head -n 1 || true)"
    for word in $first_line; do
        case "$word" in
            go[0-9]*)
                echo "$word"
                return 0
                ;;
        esac
    done
    return 1
}

# parse_go_version parses a Go version string like 'go1.27.0' or '1.27'
# into V_MAJ, V_MIN, V_PAT numbers.
parse_go_version() {
    local v="${1#go}"
    v="${v%%[^0-9.]*}"
    local p1 p2 p3
    p1="${v%%.*}"
    v="${v#"$p1"}"
    v="${v#.}"
    if [ -n "$v" ]; then
        p2="${v%%.*}"
        v="${v#"$p2"}"
        v="${v#.}"
        p3="${v:-0}"
    else
        p2=0
        p3=0
    fi
    V_MAJ="${p1:-0}"
    V_MIN="${p2:-0}"
    V_PAT="${p3:-0}"
}

# version_older_than returns 0 (true) if v1 < v2, else 1 (false).
version_older_than() {
    local v1="$1" v2="$2"
    local V_MAJ V_MIN V_PAT
    parse_go_version "$v1"
    local m1="$V_MAJ" n1="$V_MIN" p1="$V_PAT"
    parse_go_version "$v2"
    local m2="$V_MAJ" n2="$V_MIN" p2="$V_PAT"

    if [ "$m1" -lt "$m2" ]; then return 0; fi
    if [ "$m1" -gt "$m2" ]; then return 1; fi
    if [ "$n1" -lt "$n2" ]; then return 0; fi
    if [ "$n1" -gt "$n2" ]; then return 1; fi
    if [ "$p1" -lt "$p2" ]; then return 0; fi
    return 1
}

# tool_or_install <name> <module path>; echoes the tool path. Failure is
# signalled by returning non-zero; the surrounding gate handles it.
# Verifies that the tool was built with a Go toolchain >= the module's toolchain.
# If missing or built with an older Go, installs/reinstalls using GOTOOLCHAIN=<mod_tc>.
tool_or_install() {
    local name="$1" mod="$2" bindir exe mod_tc tool_ver
    mod_tc="$(get_module_toolchain)"
    bindir="$(go env GOPATH)/bin"
    if [ -n "$(go env GOBIN)" ]; then bindir="$(go env GOBIN)"; fi

    exe="$(command -v "$name" 2>/dev/null || true)"
    if [ -z "$exe" ] && [ -x "${bindir}/${name}" ]; then
        exe="${bindir}/${name}"
    fi

    if [ -n "$exe" ] && [ -x "$exe" ]; then
        tool_ver="$(get_binary_go_version "$exe" || true)"
        if [ -n "$tool_ver" ] && [ -n "$mod_tc" ]; then
            if ! version_older_than "$tool_ver" "$mod_tc"; then
                echo "$exe"
                return 0
            fi
            echo "      ${name} was built with ${tool_ver} (older than module ${mod_tc}); reinstalling with GOTOOLCHAIN=${mod_tc}" >&2
        else
            echo "      ${name} Go version unknown; reinstalling with GOTOOLCHAIN=${mod_tc}" >&2
        fi
    else
        echo "      ${name} not found; installing into GOPATH via GOTOOLCHAIN=${mod_tc} go install ${mod}@latest" >&2
    fi

    if [ -n "$mod_tc" ]; then
        GOTOOLCHAIN="$mod_tc" go install "${mod}@latest" || return 1
    else
        go install "${mod}@latest" || return 1
    fi

    exe="${bindir}/${name}"
    if [ ! -x "$exe" ]; then
        exe="$(command -v "$name" 2>/dev/null || true)"
    fi
    if [ ! -x "$exe" ]; then
        return 1
    fi
    echo "$exe"
}

# ---------------------------------------------------------------- gate 1
gate_1() {
    step "go build (windows full, linux/darwin without the cgo UI packages, all five GOOS/GOARCH, CGO_ENABLED=0; native full, CGO_ENABLED=1 — IAMT-252/262/300)"
    export CGO_ENABLED=0
    local pair goos goarch scoped
    for pair in "windows amd64" "linux amd64" "linux arm64" "darwin amd64" "darwin arm64"; do
        goos="${pair% *}"
        goarch="${pair#* }"
        if [ "$goos" = "linux" ] || [ "$goos" = "darwin" ]; then
            # IAMT-252/IAMT-262: on linux AND darwin the ui package (and
            # cmd/iamtunnel, which opens the window on both) needs cgo — gio
            # talks to X11/Wayland through it on linux and to Cocoa on darwin.
            # The CGO_ENABLED=0 pass covers every other package with the
            # target's own GOOS set (so windows-only packages like
            # internal/ui/winfonts drop out by themselves). The full linux
            # tree goes below with cgo; the full darwin tree needs a Mac with
            # an Apple toolchain and is nobody's job on these hosts.
            # IAMT-332 round 9: scripts is excluded the same way — every
            # non-test file there is `//go:build ignore` (the check_*.go
            # tools run via `go run`, never built as a package), but
            # go list -e reports it as a real package once it has a
            # _test.go (added by gate 16's check_rawfileio_test.go), and
            # a NAMED package go build cannot build fails hard instead of
            # silently dropping the way `go build ./...` would.
            scoped="$(GOOS="$goos" GOARCH="$goarch" go list -e ./... | grep -v -x -e 'github.com/ultrathinker/iamtunnel/cmd/iamtunnel' -e 'github.com/ultrathinker/iamtunnel/internal/ui' -e 'github.com/ultrathinker/iamtunnel/scripts' || true)"
            GOOS="$goos" GOARCH="$goarch" go build $scoped || {
                deny "GOOS=${goos} GOARCH=${goarch} go build (without the cgo UI packages) failed"; return 1;
            }
        else
            GOOS="$goos" GOARCH="$goarch" go build ./... || {
                deny "GOOS=${goos} GOARCH=${goarch} go build ./... failed"; return 1;
            }
        fi
    done
    unset GOOS GOARCH
    # The native full-tree build with cgo: on Linux this compiles X11/Wayland (IAMT-252);
    # on macOS this compiles Cocoa natively with Xcode CLT (IAMT-262/300).
    export CGO_ENABLED=1
    go build ./... || {
        if [ "$HOST_OS" = "Darwin" ]; then
            deny "native CGO_ENABLED=1 go build ./... failed (is Xcode Command Line Tools installed?)"; return 1;
        else
            deny "native CGO_ENABLED=1 go build ./... failed (are the X11/Wayland/vulkan dev packages installed?)"; return 1;
        fi
    }
    export CGO_ENABLED=0
    # THE HEADLESS BUILD, the artefact that ships to a gateway (IAMT-439).
    #
    # -tags nogui drops internal/ui and every file that opens a window, so
    # there is no cgo in it at all -- and cmd/iamtunnel, excluded from the
    # cross pass above for needing cgo, is back in scope and compiled
    # whole. It runs on the machine with a port open to the internet; a
    # tag that stopped compiling would otherwise be found by whoever next
    # installs a gateway. Windows is in the list too (IAMT-470): a file
    # that needs the window and is tagged only "windows", not
    # "windows && !nogui", breaks the headless build on Windows alone,
    # and no gate built that pair.
    for pair in "windows amd64" "linux amd64" "linux arm64" "darwin amd64"; do
        goos="${pair% *}"
        goarch="${pair#* }"
        scoped="$(GOOS="$goos" GOARCH="$goarch" go list -e ./... | grep -v -x -e 'github.com/ultrathinker/iamtunnel/internal/ui' -e 'github.com/ultrathinker/iamtunnel/scripts' || true)"
        GOOS="$goos" GOARCH="$goarch" go build -tags nogui $scoped || {
            deny "GOOS=${goos} GOARCH=${goarch} go build -tags nogui failed"; return 1;
        }
    done
    unset GOOS GOARCH
    passed "all five targets compile, the native tree compiles with cgo, and the headless build compiles"
}

# ---------------------------------------------------------------- gate 2
gate_2() {
    step "go vet (windows full, linux/darwin without the cgo UI packages; native full with cgo — IAMT-252/262/300)"
    local pair goos goarch scoped
    for pair in "windows amd64" "linux amd64" "linux arm64" "darwin amd64" "darwin arm64"; do
        goos="${pair% *}"
        goarch="${pair#* }"
        if [ "$goos" = "linux" ] || [ "$goos" = "darwin" ]; then
            # Same scope as gate 1: see the IAMT-252/262 and IAMT-332 notes there.
            scoped="$(GOOS="$goos" GOARCH="$goarch" go list -e ./... | grep -v -x -e 'github.com/ultrathinker/iamtunnel/cmd/iamtunnel' -e 'github.com/ultrathinker/iamtunnel/internal/ui' -e 'github.com/ultrathinker/iamtunnel/scripts' || true)"
            GOOS="$goos" GOARCH="$goarch" go vet $scoped || {
                deny "GOOS=${goos} GOARCH=${goarch} go vet (without the cgo UI packages) failed"; return 1;
            }
        else
            GOOS="$goos" GOARCH="$goarch" go vet ./... || {
                deny "GOOS=${goos} GOARCH=${goarch} go vet ./... failed"; return 1;
            }
        fi
    done
    unset GOOS GOARCH
    CGO_ENABLED=1 go vet ./... || {
        deny "native CGO_ENABLED=1 go vet ./... failed"; return 1;
    }
    # And the headless variant, same reason as in gate 1. Vet, unlike
    # build, compiles the test files: it is the step that catches a test
    # which needs the window but is not tagged !nogui (IAMT-470).
    for pair in "windows amd64" "linux amd64" "darwin amd64"; do
        goos="${pair% *}"
        goarch="${pair#* }"
        scoped="$(GOOS="$goos" GOARCH="$goarch" go list -e ./... | grep -v -x -e 'github.com/ultrathinker/iamtunnel/internal/ui' -e 'github.com/ultrathinker/iamtunnel/scripts' || true)"
        GOOS="$goos" GOARCH="$goarch" go vet -tags nogui $scoped || {
            deny "GOOS=${goos} GOARCH=${goarch} go vet -tags nogui failed"; return 1;
        }
    done
    unset GOOS GOARCH
    passed "vet is clean on all five targets, on the native cgo tree and on the headless build"
}

# classify_staticcheck_output <file_or_string>
# Classifies staticcheck output into:
#   1. "could not load the module: <first such line>"
#   2. "reported findings"
#   3. "staticcheck failed: <first non-empty line>"
#   4. "clean"
classify_staticcheck_output() {
    local target="$1"
    local load_line first_line

    if [ -f "$target" ]; then
        load_line="$(grep -E '\((compile|config)\)$|package requires newer Go version|could not load|failed to load' "$target" | head -n 1 || true)"
        if [ -n "$load_line" ]; then
            echo "could not load the module: ${load_line}"
            return 0
        fi
        if grep -q -E '^.+:[0-9]+:[0-9]+: .* \((SA|ST|S|QF|U)[0-9]+\)$' "$target"; then
            echo "reported findings"
            return 0
        fi
        first_line="$(grep -v '^[[:space:]]*$' "$target" | head -n 1 || true)"
        if [ -n "$first_line" ]; then
            echo "staticcheck failed: ${first_line}"
            return 0
        fi
    else
        load_line="$(printf '%s\n' "$target" | grep -E '\((compile|config)\)$|package requires newer Go version|could not load|failed to load' | head -n 1 || true)"
        if [ -n "$load_line" ]; then
            echo "could not load the module: ${load_line}"
            return 0
        fi
        if printf '%s\n' "$target" | grep -q -E '^.+:[0-9]+:[0-9]+: .* \((SA|ST|S|QF|U)[0-9]+\)$'; then
            echo "reported findings"
            return 0
        fi
        first_line="$(printf '%s\n' "$target" | grep -v '^[[:space:]]*$' | head -n 1 || true)"
        if [ -n "$first_line" ]; then
            echo "staticcheck failed: ${first_line}"
            return 0
        fi
    fi
    echo "clean"
    return 0
}

selftest_classify() {
    local failed=0
    local c1_input="internal/server/run_darwin.go:126:10: error strings should not be capitalized (ST1005)"
    local c1_expected="reported findings"
    local c1_actual
    c1_actual="$(classify_staticcheck_output "$c1_input")"
    if [ "$c1_actual" != "$c1_expected" ]; then
        echo "[SELFTEST FAIL] canary 1 (finding): expected '$c1_expected', got '$c1_actual'" >&2
        failed=$((failed + 1))
    else
        echo "[SELFTEST OK] canary 1 (finding) -> $c1_actual"
    fi

    local c2_input="internal/server/run_darwin.go:10:2: undeclared name: foo (compile)"
    local c2_expected="could not load the module: internal/server/run_darwin.go:10:2: undeclared name: foo (compile)"
    local c2_actual
    c2_actual="$(classify_staticcheck_output "$c2_input")"
    if [ "$c2_actual" != "$c2_expected" ]; then
        echo "[SELFTEST FAIL] canary 2 (compile): expected '$c2_expected', got '$c2_actual'" >&2
        failed=$((failed + 1))
    else
        echo "[SELFTEST OK] canary 2 (compile) -> $c2_actual"
    fi

    local c3_input
    c3_input="$(printf '%s\n%s' "$c1_input" "$c2_input")"
    local c3_expected="$c2_expected"
    local c3_actual
    c3_actual="$(classify_staticcheck_output "$c3_input")"
    if [ "$c3_actual" != "$c3_expected" ]; then
        echo "[SELFTEST FAIL] canary 3 (both together): expected '$c3_expected', got '$c3_actual'" >&2
        failed=$((failed + 1))
    else
        echo "[SELFTEST OK] canary 3 (both together) -> $c3_actual"
    fi

    if [ "$failed" -ne 0 ]; then
        echo "selftest-classify failed (${failed} errors)" >&2
        return 1
    fi
    echo "selftest-classify PASS (all 3 canaries matched expected verdicts)"
    return 0
}

# ---------------------------------------------------------------- gate 3
gate_3() {
    step "staticcheck ./... (native cgo tree — IAMT-300)"
    STATICCHECK="$(tool_or_install staticcheck honnef.co/go/tools/cmd/staticcheck)" || {
        deny "staticcheck tool not available"
        return 1
    }
    local out_file
    out_file="$(mktemp "${TMPDIR:-/tmp}/staticcheck.XXXXXX")"
    with_native_cgo "$STATICCHECK" ./... >"$out_file" 2>&1
    local ec=$?
    cat "$out_file"
    if [ $ec -ne 0 ]; then
        local verdict
        verdict="$(classify_staticcheck_output "$out_file")"
        rm -f "$out_file"
        if [ "$verdict" != "clean" ]; then
            deny "$verdict"
        else
            deny "staticcheck failed: exit code ${ec}"
        fi
        return 1
    fi
    rm -f "$out_file"
    passed "no findings"
}

# ---------------------------------------------------------------- gate 4
gate_4() {
    step "govulncheck ./... (native cgo tree — IAMT-300)"
    GOVULNCHECK="$(tool_or_install govulncheck golang.org/x/vuln/cmd/govulncheck)" || {
        deny "govulncheck tool not available"
        return 1
    }
    local out_file
    out_file="$(mktemp "${TMPDIR:-/tmp}/govulncheck.XXXXXX")"
    with_native_cgo "$GOVULNCHECK" ./... >"$out_file" 2>&1
    local ec=$?
    cat "$out_file"
    if [ $ec -ne 0 ]; then
        local err_line
        err_line="$(grep -E 'loading packages|package requires newer Go version|could not load|failed to load|^govulncheck:' "$out_file" | head -n 1 || true)"
        if [ $ec -ne 3 ] || [ -n "$err_line" ]; then
            if [ -z "$err_line" ]; then
                err_line="$(grep -v '^[[:space:]]*$' "$out_file" | head -n 1 || true)"
            fi
            if [ -z "$err_line" ]; then
                err_line="exit code ${ec}"
            fi
            rm -f "$out_file"
            deny "govulncheck could not load the module: ${err_line}"
            return 1
        else
            rm -f "$out_file"
            deny "govulncheck ./... found vulnerabilities reachable from this code"
            return 1
        fi
    fi
    rm -f "$out_file"
    passed "no reachable vulnerabilities"
}

# ---------------------------------------------------------------- gate 5
gate_5() {
    step "go test ./... -race -count=1"
    # -race needs CGO_ENABLED=1; scoped to this gate only.
    #
    # -count=1 is mandatory: Go caches test results, and a run under
    # the race detector is cached too. Without -count=1 a single
    # accidentally green run makes the gate green forever, while a race
    # is not caught every time. That is exactly how the edit with a
    # real race inside was accepted on 13.09.
    CGO_ENABLED=1 go test ./... -race -count=1 || { deny "go test ./... -race -count=1 failed"; return 1; }
    CGO_ENABLED=0
    # THE HEADLESS VARIANT'S OWN TESTS (R1-CX F-05), the twin of gate 5 in
    # gates.ps1: gates 1 and 2 build and vet it, nothing ran its tests, and
    # the one test that tells the variants apart demanded "full"
    # unconditionally. Only the packages whose file set the tag changes run
    # again.
    local list_fmt='{{.ImportPath}}|{{.GoFiles}}{{.TestGoFiles}}{{.XTestGoFiles}}'
    local full_rows headless_rows differ said
    full_rows=$(go list -e -f "$list_fmt" ./... | sort) || { deny "go list failed"; return 1; }
    headless_rows=$(go list -e -tags nogui -f "$list_fmt" ./... | sort) || { deny "go list -tags nogui failed"; return 1; }
    differ=$(comm -13 <(printf '%s\n' "$full_rows") <(printf '%s\n' "$headless_rows") | cut -d'|' -f1)
    [ -n "$differ" ] || { deny "no package changes under -tags nogui: either the headless variant is gone or this check no longer sees it"; return 1; }
    # shellcheck disable=SC2086 # one import path per word, on purpose
    CGO_ENABLED=0 go test -tags nogui -count=1 $differ || { deny "go test -tags nogui -count=1 failed"; return 1; }
    # And the headless program itself starts and says which build it is.
    said=$(CGO_ENABLED=0 go run -tags nogui ./cmd/iamtunnel version 2>&1) || { deny "go run -tags nogui ./cmd/iamtunnel version failed: $said"; return 1; }
    printf '%s\n' "$said" | grep -q '^build headless' || { deny "the headless build does not call itself headless in its version: $said"; return 1; }
    passed "all tests pass under the race detector, and the headless variant's own tests pass too"
}

# ---------------------------------------------------------------- gate 6
gate_6() {
    step "CGO_ENABLED=0 enforced in binary build info (windows binary; the linux binary is legitimately cgo since IAMT-252)"
    # Builds exactly like gate 8, then reads CGO_ENABLED back from the binary
    # with "go version -m" instead of trusting the environment. A build made
    # with CGO_ENABLED=1 fails right here.
    #
    # The check is made on the WINDOWS binary (IAMT-252): the linux binary
    # now contains the window and is deliberately built with
    # CGO_ENABLED=1 — gio talks to X11/Wayland through cgo — so the
    # "no cgo" policy this gate asserts is the windows one.
    CGO_ENABLED=0   # IAMT-10 canary: set to 1 to see this gate fail
    tmp="$(mktemp -d)"
    GOOS=windows go build -trimpath -ldflags "-s -w" -o "${tmp}/iamtunnel.exe" ./cmd/iamtunnel \
        || { deny "GOOS=windows go build cmd/iamtunnel failed"; rm -rf "$tmp"; return 1; }
    meta="$(go version -m "${tmp}/iamtunnel.exe")" || { deny "go version -m failed"; rm -rf "$tmp"; return 1; }
    line="$(printf '%s\n' "$meta" | grep -E '^[[:space:]]*build[[:space:]]+CGO_ENABLED=' || true)"
    if [ -z "$line" ]; then
        deny "no CGO_ENABLED line in binary build info; cannot prove CGO was disabled"
        rm -rf "$tmp"
        return 1
    fi
    value="${line##*=}"
    if [ "$value" != "0" ]; then
        deny "binary was built with CGO_ENABLED=${value}, policy is CGO_ENABLED=0 (SPEC 4.1)"
        rm -rf "$tmp"
        return 1
    fi
    rm -rf "$tmp"
    passed "windows binary build info says CGO_ENABLED=0"
}

# ---------------------------------------------------------------- gate 7
gate_7() {
    step "forbidden dependencies absent (gliderlabs/gorm/sqlite/docker/fsnotify)"
    local pair goos goarch scoped deps hits
    for pair in "windows amd64" "linux amd64" "linux arm64" "darwin amd64" "darwin arm64"; do
        goos="${pair% *}"
        goarch="${pair#* }"
        if [ "$goos" = "linux" ] || [ "$goos" = "darwin" ]; then
            # Same scope as gate 1: see the IAMT-252/262 and IAMT-332 notes
            # there. The list is computed with the target GOOS so that
            # packages with no files for it (internal/ui/winfonts) drop out;
            # ui and cmd/iamtunnel are filtered because their graph needs cgo.
            scoped="$(GOOS="$goos" GOARCH="$goarch" go list -e ./... | grep -v -x -e 'github.com/ultrathinker/iamtunnel/cmd/iamtunnel' -e 'github.com/ultrathinker/iamtunnel/internal/ui' -e 'github.com/ultrathinker/iamtunnel/scripts' || true)"
            deps="$(GOOS="$goos" GOARCH="$goarch" go list -deps $scoped)" || {
                deny "GOOS=${goos} GOARCH=${goarch} go list -deps failed"; return 1;
            }
        else
            deps="$(GOOS="$goos" GOARCH="$goarch" go list -deps ./...)" || {
                deny "GOOS=${goos} GOARCH=${goarch} go list -deps ./... failed"; return 1;
            }
        fi
        hits="$(printf '%s\n' $deps | grep -Ei 'gliderlabs|gorm|sqlite|docker|fsnotify' || true)"
        if [ -n "$hits" ]; then
            deny "GOOS=${goos} GOARCH=${goarch} dependency graph contains forbidden packages: $(printf '%s; ' $hits)"
            return 1
        fi
    done
    # The full native linux graph — the one that actually carries gio —
    # is checked here on the host that builds it (IAMT-252). cgo on:
    # without it the ui package's dependencies do not resolve.
    deps="$(CGO_ENABLED=1 go list -deps ./...)" || {
        deny "native go list -deps ./... failed"; return 1;
    }
    hits="$(printf '%s\n' $deps | grep -Ei 'gliderlabs|gorm|sqlite|docker|fsnotify' || true)"
    if [ -n "$hits" ]; then
        deny "native dependency graph contains forbidden packages: $(printf '%s; ' $hits)"
        return 1
    fi
    passed "no forbidden packages in the five dependency graphs or in the native cgo graph"
}

# ---------------------------------------------------------------- gate 8
gate_8() {
    # The binary sizes this host can really build. If the actual size
    # exceeds the ceiling, the gate dumps it into a FAIL and does not
    # raise the ceiling silently -- the maintainer decides on a new
    # boundary.
    #
    # linux/amd64 is measured on Linux natively with CGO_ENABLED=1
    # (IAMT-252: the binary carries the window, gio goes through cgo).
    # linux/arm64 would need a separate toolchain.
    #
    # darwin (macOS) is measured on a real Mac natively with
    # CGO_ENABLED=1 (IAMT-262/300): the binary carries the window and
    # needs cgo+Cocoa.
    # On 15.09 darwin/arm64 was measured by hand on a real Mac Air
    # M1: 19.3 MB. Ceiling 22.0 MB (IAMT-262).
    #
    # The cross-build of windows/amd64 (CGO_ENABLED=0) runs on both
    # hosts (ceiling 20.0 MB since 1.48: 18.1 MB after IAMT-499, a
    # decision taken by the maintainer).
    step "binary size ceiling (windows <= 20.0 MB, CGO_ENABLED=0; linux/amd64 <= 16.0 MB native CGO_ENABLED=1 — IAMT-252; darwin native <= 22.0 MB CGO_ENABLED=1 — IAMT-262/300)"
    export CGO_ENABLED=0
    tmp="$(mktemp -d)"
    local summary=""
    local pairs=()
    pairs+=("windows amd64 20.0 iamtunnel.exe cross")
    if [ "$HOST_OS" = "Darwin" ]; then
        pairs+=("darwin ${HOST_ARCH} 22.0 iamtunnel-darwin-${HOST_ARCH} native")
    else
        pairs+=("linux amd64 16.0 iamtunnel-linux-amd64 native")
    fi
    local item goos goarch ceiling bin mode outpath mb
    for item in "${pairs[@]}"; do
        goos="$(echo "$item" | awk '{print $1}')"
        goarch="$(echo "$item" | awk '{print $2}')"
        ceiling="$(echo "$item" | awk '{print $3}')"
        bin="$(echo "$item" | awk '{print $4}')"
        mode="$(echo "$item" | awk '{print $5}')"
        outpath="${tmp}/${bin}"
        if [ "$mode" = "native" ]; then
            CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o "$outpath" ./cmd/iamtunnel \
                || { deny "${goos}/${goarch} native CGO_ENABLED=1 go build -ldflags -s -w failed"; rm -rf "$tmp"; return 1; }
        else
            GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "-s -w" -o "$outpath" ./cmd/iamtunnel \
                || { deny "GOOS=${goos} GOARCH=${goarch} go build -ldflags -s -w failed"; rm -rf "$tmp"; return 1; }
        fi
        mb="$(awk -v n="$(wc -c < "$outpath")" 'BEGIN{printf "%.1f", n/1048576}')"
        echo "      ${goos}/${goarch}: ${mb} MB (ceiling ${ceiling} MB)"
        if [ "$(awk -v m="$mb" -v c="$ceiling" 'BEGIN{print (m>c)?1:0}')" = "1" ]; then
            deny "GOOS=${goos} GOARCH=${goarch} binary ${mb} MB exceeds the ${ceiling} MB ceiling (SPEC 9); this gate does not raise the ceiling — that is the maintainer's decision, taken on the actual numbers above"
            rm -rf "$tmp"
            return 1
        fi
        if [ -z "$summary" ]; then
            summary="${goos}/${goarch}=${mb} MB"
        else
            summary="${summary}, ${goos}/${goarch}=${mb} MB"
        fi
    done
    rm -rf "$tmp"
    if [ "$HOST_OS" = "Darwin" ]; then
        summary="${summary} (linux sizes are measured on Linux — IAMT-252)"
    else
        summary="${summary} (darwin sizes are measured on a Mac — IAMT-262)"
    fi
    passed "sizes within ceiling: ${summary}"
}

# ---------------------------------------------------------------- gate 9
gate_9() {
    step "no test that cannot go red (failure path or helper-with-t in every Test*)"

    # The rule: a test function counts as a dud if its body contains
    # neither a call to a test failure/skip means (t.Fatal, t.Errorf,
    # t.Skip and the like) nor a call to a same-package helper that is
    # passed a *testing.T. Subtests count: the check may live inside a
    # closure passed to t.Run, so the AST walk descends into the bodies
    # of function literals having *testing.T.
    #
    # Exceptions are allowed, but each one is a separate line in the
    # list below, with the reason next to it. There must be no silent
    # bypass: a gate that can be quietly circumvented becomes a dud
    # itself.
    #
    # The slot for the second category ("a test for the race detector")
    # is reserved in advance: a test whose
    # assertion is done by the detector, not by the body. There is none
    # now; the place in the list remains so that adding one goes
    # through an explicit exception, not a silent bypass.
    gate9_exceptions=(
        "TestChannelConn_ImplementsNetConn|compile-time assertion: the body contains \`var c net.Conn = NewChannelConn(nil)\` -- if the contract breaks, the package will not compile; by design it cannot go red through the body"
    )

    allow_spec=""
    for entry in "${gate9_exceptions[@]}"; do
        name="${entry%%|*}"
        reason="${entry#*|}"
        formatted="${name} ==>${reason}"
        if [ -z "$allow_spec" ]; then
            allow_spec="${formatted}"
        else
            allow_spec="${allow_spec};;${formatted}"
        fi
    done

    pkgs=(
        ./cmd/iamtunnel
        ./internal/admin
        ./internal/client
        ./internal/config
        ./internal/elevate
        ./internal/gateway
        ./internal/gateway/acl
        ./internal/gateway/auth
        ./internal/gateway/core
        ./internal/gateway/events
        ./internal/gateway/record
        ./internal/gateway/state
        ./internal/macos
        ./internal/paste
        ./internal/proto
        ./internal/record/export
        ./internal/server
        ./internal/sshx
        ./internal/ui
        ./internal/ui/design
        ./internal/ui/macfonts
        ./internal/ui/winfonts
        ./internal/winkeys
        ./test/e2e
    )

    export CGO_ENABLED=0
    gate9_tmp="$(mktemp)"
    go run scripts/check_noempty.go -allow "$allow_spec" "${pkgs[@]}" >"$gate9_tmp" 2>&1
    rc=$?
    if [ -s "$gate9_tmp" ]; then
        sed 's/^/      /' "$gate9_tmp"
    fi
    rm -f "$gate9_tmp"
    # Print the exception list itself, so that a gate that can be
    # quietly circumvented becomes a dud itself: every time it is
    # visible what is allowed and why.
    if [ "${#gate9_exceptions[@]}" -gt 0 ]; then
        echo "      exceptions on file (each line is a separate allow):"
        for entry in "${gate9_exceptions[@]}"; do
            name="${entry%%|*}"
            reason="${entry#*|}"
            echo "        - ${name}: ${reason}"
        done
    else
        echo "      no exceptions on file"
    fi
    if [ "$rc" -ne 0 ]; then
        deny "empty Test* functions with no failure path and no helper-with-t call"
        return 1
    fi
    passed "every Test* has a failure path or a helper-with-t call"
}

# Each gate is wrapped in `|| true` so its return code does not abort the
# outer script. The deny() inside each gate has already recorded the FAIL;
# the row appears in the summary regardless. This is the seam between
# "gate failure" and "script stop": the gate-failed signal no longer
# escapes, only "set -u" / genuine shell errors do.
# ---------------------------------------------------------------- gate 10
gate_10() {
    step "every skipped check is visible and explains itself"
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
    local pkgs10 gate10_tmp rc
    pkgs10=(
        ./cmd/iamtunnel
        ./internal/admin
        ./internal/client
        ./internal/config
        ./internal/elevate
        ./internal/gateway
        ./internal/gateway/acl
        ./internal/gateway/auth
        ./internal/gateway/core
        ./internal/gateway/events
        ./internal/gateway/record
        ./internal/gateway/state
        ./internal/macos
        ./internal/paste
        ./internal/proto
        ./internal/record/export
        ./internal/server
        ./internal/sshx
        ./internal/ui
        ./internal/ui/design
        ./internal/ui/macfonts
        ./internal/ui/winfonts
        ./internal/winkeys
        ./test/e2e
    )
    export CGO_ENABLED=0
    gate10_tmp="$(mktemp)"
    go run scripts/check_skips.go "${pkgs10[@]}" >"$gate10_tmp" 2>&1
    rc=$?
    if [ -s "$gate10_tmp" ]; then
        sed 's/^/      /' "$gate10_tmp"
    fi
    rm -f "$gate10_tmp"
    if [ "$rc" -ne 0 ]; then
        deny "a skipped check gives no usable reason"
        return 1
    fi
    passed "every skipped check is listed above with its reason"
}

# get_watched_surfaces lists all existing files and directories that belong to
# the watched product surfaces for this host platform (macOS: IAMT-300; Linux: IAMT-301).
get_watched_surfaces() {
    shopt -s nullglob
    if [ "$HOST_OS" = "Darwin" ]; then
        set -- \
            "$HOME/Library/Application Support/iamtunnel" \
            "/Library/Application Support/iamtunnel" \
            "/Library/Logs/iamtunnel" \
            "/var/lib/iamtunnel-machine" \
            "/var/lib/iamtunnel" \
            "/etc/iamtunnel" \
            "/etc/iamtunnel-machine" \
            /Library/LaunchDaemons/com.iamtunnel.* \
            "$HOME"/Library/LaunchAgents/com.iamtunnel.* \
            "${TMPDIR:-/tmp}"/iamtunnel-connect-*.sh
    else
        set -- \
            "${XDG_DATA_HOME:-$HOME/.local/share}/iamtunnel" \
            "/etc/iamtunnel" \
            "/etc/iamtunnel-machine" \
            "/var/lib/iamtunnel" \
            "/var/lib/iamtunnel-machine" \
            /etc/systemd/system/iamtunnel*.service \
            /etc/systemd/system/*.wants/iamtunnel* \
            "$HOME/.local/share/applications"/iamtunnel*.desktop \
            "$HOME/.local/share/icons/hicolor"/*/apps/iamtunnel*
    fi
    shopt -u nullglob
    local p
    for p in "$@"; do
        if [ -e "$p" ] || [ -L "$p" ]; then
            printf '%s\n' "$p"
        fi
    done
}

gate_11() {
    step "no test writes into the maintainer's system"
    # The maintainer's machine is not a test bench. The role
    # directories, the real ssh directory and the working tree are
    # checked, as well as services, daemons and temporary scripts
    # (IAMT-300, IAMT-301). The check is by fact, not by grep: look
    # before the run, look after, compare.
    local ssh_keys="${HOME}/.ssh/authorized_keys"

    local f_surf_before f_surf_after f_surf_diff
    local f_cont_before f_cont_after f_cont_diff
    f_surf_before="$(mktemp)"
    f_surf_after="$(mktemp)"
    f_surf_diff="$(mktemp)"
    f_cont_before="$(mktemp)"
    f_cont_after="$(mktemp)"
    f_cont_diff="$(mktemp)"

    get_watched_surfaces | sort -u > "$f_surf_before"
    while IFS= read -r d; do
        [ -d "$d" ] && find "$d" 2>/dev/null
    done < "$f_surf_before" | sort -u > "$f_cont_before"

    local ssh_before ssh_after
    if [ -f "$ssh_keys" ]; then
        ssh_before="$(sha256_of "$ssh_keys")"
    else
        ssh_before="absent"
    fi

    local dscl_before="absent" dscl_after="absent"
    if [ "$HOST_OS" = "Darwin" ]; then
        if dscl . -read /Users/_iamtunnel >/dev/null 2>&1; then
            dscl_before="present"
        else
            dscl_before="absent"
        fi
    fi

    local tree_before tree_after
    tree_before="$(git status --porcelain)"

    local before_shown
    before_shown="$(tr '\n' ' ' < "$f_surf_before" | sed 's/[[:space:]]*$//')"
    if [ "$HOST_OS" = "Darwin" ]; then
        echo "      before: sshkeys=${ssh_before} user=${dscl_before} role dirs present=${before_shown:- none}"
    else
        echo "      before: sshkeys=${ssh_before} role dirs present=${before_shown:- none}"
    fi

    CGO_ENABLED=1 go test ./... -count=1 >/dev/null 2>&1
    local rc=$?

    get_watched_surfaces | sort -u > "$f_surf_after"
    while IFS= read -r d; do
        [ -d "$d" ] && find "$d" 2>/dev/null
    done < "$f_surf_before" | sort -u > "$f_cont_after"

    if [ -f "$ssh_keys" ]; then
        ssh_after="$(sha256_of "$ssh_keys")"
    else
        ssh_after="absent"
    fi

    if [ "$HOST_OS" = "Darwin" ]; then
        if dscl . -read /Users/_iamtunnel >/dev/null 2>&1; then
            dscl_after="present"
        else
            dscl_after="absent"
        fi
    fi

    tree_after="$(git status --porcelain)"

    local after_shown
    after_shown="$(tr '\n' ' ' < "$f_surf_after" | sed 's/[[:space:]]*$//')"
    if [ "$HOST_OS" = "Darwin" ]; then
        echo "      after:  sshkeys=${ssh_after} user=${dscl_after} role dirs present=${after_shown:- none}"
    else
        echo "      after:  sshkeys=${ssh_after} role dirs present=${after_shown:- none}"
    fi

    if [ "$rc" -ne 0 ]; then
        rm -f "$f_surf_before" "$f_surf_after" "$f_surf_diff" "$f_cont_before" "$f_cont_after" "$f_cont_diff"
        deny 'the suite itself is red; this gate cannot judge a failed run'
        return 1
    fi

    comm -13 "$f_surf_before" "$f_surf_after" > "$f_surf_diff"
    comm -13 "$f_cont_before" "$f_cont_after" > "$f_cont_diff"

    local appeared_any=0
    local appeared_list=""

    if [ -s "$f_surf_diff" ]; then
        while IFS= read -r a; do
            [ -n "$a" ] || continue
            appeared_any=1
            appeared_list="${appeared_list:+${appeared_list} }${a}"
            echo "      APPEARED $a"
            find "$a" 2>/dev/null | sed 's/^/        /'
        done < "$f_surf_diff"
    fi

    if [ -s "$f_cont_diff" ]; then
        while IFS= read -r a; do
            [ -n "$a" ] || continue
            appeared_any=1
            appeared_list="${appeared_list:+${appeared_list} }${a}"
            echo "      APPEARED $a"
            echo "        $a"
        done < "$f_cont_diff"
    fi

    if [ "$HOST_OS" = "Darwin" ] && [ "$dscl_before" = "absent" ] && [ "$dscl_after" = "present" ]; then
        echo "      APPEARED user _iamtunnel"
        rm -f "$f_surf_before" "$f_surf_after" "$f_surf_diff" "$f_cont_before" "$f_cont_after" "$f_cont_diff"
        deny "a test created the service user _iamtunnel"
        return 1
    fi

    if [ "$appeared_any" -ne 0 ]; then
        rm -f "$f_surf_before" "$f_surf_after" "$f_surf_diff" "$f_cont_before" "$f_cont_after" "$f_cont_diff"
        deny "a test created a real role directory or system file: ${appeared_list}"
        return 1
    fi

    rm -f "$f_surf_before" "$f_surf_after" "$f_surf_diff" "$f_cont_before" "$f_cont_after" "$f_cont_diff"

    if [ "$ssh_after" != "$ssh_before" ]; then
        deny 'a test touched this machine real authorized_keys'
        return 1
    fi
    if [ "$tree_after" != "$tree_before" ]; then
        echo '      working tree changed during the run:'
        echo "      before: $tree_before"
        echo "      after:  $tree_after"
        deny 'a test left files behind in the working tree'
        return 1
    fi
    passed 'the real ssh keys, the role directories and the working tree are all as they were'
}
# ---------------------------------------------------------------- gate 12
gate_12() {
    step "the event dictionary in PROTOCOL matches the code"
    # See the comment in gates.ps1: the tests of the events package
    # cannot check the completeness of the name list, they check only
    # the names they themselves list. The guard here is single -- this
    # gate.
    export CGO_ENABLED=0
    go run scripts/check_eventdict.go -selftest || {
        deny "the event-dictionary checker fails its own selftest"
        return 1
    }
    go run scripts/check_eventdict.go || {
        deny "the event dictionary in docs/PROTOCOL.md and internal/gateway/events/event.go disagree"
        return 1
    }
    passed "the document and the code name the same event types, and every one of them is allowed"
}

# ---------------------------------------------------------------- gate 13
gate_13() {
    step "the event names in RUNBOOK and THREATS match the code"
    # The iamtunnel-runbook-events-v1 block in each document lists the
    # names it calls events, and the gate compares them with the
    # constants and with the real write sites; the
    # not-written-this-build caveat must stay true.
    export CGO_ENABLED=0
    go run scripts/check_runbookevents.go -selftest || {
        deny "the runbook-events checker fails its own selftest"
        return 1
    }
    go run scripts/check_runbookevents.go || {
        deny "the event block in docs/RUNBOOK.md disagrees with internal/gateway/events/event.go or with the places that write events"
        return 1
    }
    go run scripts/check_runbookevents.go -runbook docs/THREATS.md || {
        deny "the event block in docs/THREATS.md disagrees with internal/gateway/events/event.go or with the places that write events"
        return 1
    }
    passed "every event name RUNBOOK and THREATS name is a real EventType, and each not-written caveat is still true"
}

# ---------------------------------------------------------------- gate 14
gate_14() {
    step "the error-code dictionary in PROTOCOL matches the code"
    # See the comment in gates.ps1: the error-code dictionary of
    # PROTOCOL 6.1 (the iamtunnel-error-codes-v1 block) was compared
    # with nothing before this gate. wire codes must be product
    # literals, internal is a classification without literals, absent
    # is a documented absence. The check is two-way, and silently
    # shrinking the block is forbidden.
    export CGO_ENABLED=0
    go run scripts/check_errdict.go -selftest || {
        deny "the error-code checker fails its own selftest"
        return 1
    }
    go run scripts/check_errdict.go || {
        deny "the error-code block in docs/PROTOCOL.md disagrees with the E_* literals in internal/ and cmd/"
        return 1
    }
    passed "every wire code is a real literal, every literal is marked wire, and the prose names no code outside the block"
}

# ---------------------------------------------------------------- gate 15
gate_15() {
    step "the command lists in client, CLI usage and gateway match"
    export CGO_ENABLED=0
    go run scripts/check_commands.go -selftest || {
        deny "the command-list checker fails its own selftest"
        return 1
    }
    go run scripts/check_commands.go || {
        deny "discrepancy found between client library, CLI usage and gateway commandTable"
        return 1
    }
    passed "every client command is handled by the gateway, every gateway command is called, and CLI usage matches"
}

# ---------------------------------------------------------------- gate 16
gate_16() {
    step "no raw os pathname I/O outside internal/datafile and the allowlist"
    # Gate 16 (IAMT-332, report §5.3): an AST walk over all non-test
    # .go files -- no writer/reader/metamorphoser of os pathnames
    # bypasses internal/datafile, except allowlist entries with a
    # mandatory reason. A stale entry (a file no longer produces
    # findings) is a refusal too: the allowlist keeps no dead souls.
    # The engine's selftest runs FIRST deliberately. The same run also
    # lives as go test (scripts/check_rawfileio_test.go), so the
    # protection fires in every ordinary `go test ./...` as well.
    export CGO_ENABLED=0
    go run scripts/check_rawfileio.go scripts/rawfileio_types.go -selftest || {
        deny "the raw-file-I/O checker fails its own selftest"
        return 1
    }
    go run scripts/check_rawfileio.go scripts/rawfileio_types.go || {
        deny "raw os pathname I/O found outside internal/datafile without an allowlist reason, or a stale allowlist entry"
        return 1
    }
    passed "every pathname I/O call routes through internal/datafile or carries an allowlist reason, and no allowlist entry is stale"
}

# ---------------------------------------------------------------- gate 17
gate_17() {
    step "no sub-tab needs scrolling in a window of the default size"
    # Gate 17 (IAMT-336, SPEC 7.1/8) is measured by rendering the real
    # window offscreen and looking for a scroll thumb, and that renderer
    # (internal/ui.Shot) is Windows-only in this tree. So this host does
    # not run it and says so, exactly as gate 8 does for the Windows
    # binary size: an honest skip with a reason, never a silent pass.
    # The Windows host runs it in scripts/gates.ps1.
    skipped "the offscreen renderer the gate measures with is Windows-only; scripts/gates.ps1 runs it on the Windows host"
}

# ---------------------------------------------------------------- gate 18
gate_18() {
    step "no Cyrillic in user-facing string literals under internal/ and cmd/"
    export CGO_ENABLED=0
    go run scripts/check_cyrillic.go -selftest || {
        deny "the Cyrillic string-literal checker fails its own selftest"
        return 1
    }
    go run scripts/check_cyrillic.go || {
        deny "Cyrillic found in a non-test string literal under internal/ or cmd/"
        return 1
    }
    passed "every non-test string literal under internal/ and cmd/ is free of Cyrillic"
}

if [ "$#" -gt 0 ]; then
    case "$1" in
        --selftest-classify|-selftest-classify)
            selftest_classify
            exit $?
            ;;
    esac
    gates_to_run=()
    for arg in "$@"; do
        case "$arg" in
            gate_*) gates_to_run+=("$arg") ;;
            [0-9]*) gates_to_run+=("gate_${arg}") ;;
            *) echo "Unknown gate: $arg" >&2; exit 1 ;;
        esac
    done
else
    gates_to_run=(
        gate_1 gate_2 gate_3 gate_4 gate_5 gate_6 gate_7 gate_8
        gate_9 gate_10 gate_11 gate_12 gate_13 gate_14 gate_15 gate_16 gate_17 gate_18
    )
fi

for g in "${gates_to_run[@]}"; do
    CURRENT_GATE="${g#gate_}"
    "$g" || true
done

# ---------------------------------------------------------------- summary
echo
echo "================================================================"
echo "Gate summary"
echo "================================================================"
fails=0
if [ "${#GATE_RESULTS[@]}" -gt 0 ]; then
    for row in "${GATE_RESULTS[@]}"; do
        idx="${row%%|*}"
        rest="${row#*|}"
        name="${rest%%|*}"
        rest2="${rest#*|}"
        status="${rest2%%|*}"
        detail="${rest2#*|}"
        if [ "$status" = "PASS" ]; then
            echo "  [PASS] gate ${idx}/${GATE_TOTAL}: ${name}"
        elif [ "$status" = "SKIP" ]; then
            echo "  [SKIP] gate ${idx}/${GATE_TOTAL}: ${name}"
            if [ -n "$detail" ]; then
                echo "         reason: ${detail}"
            fi
        else
            echo "  [FAIL] gate ${idx}/${GATE_TOTAL}: ${name}"
            if [ -n "$detail" ]; then
                echo "         reason: ${detail}"
            fi
            fails=$((fails + 1))
        fi
    done
fi
echo "================================================================"
if [ "$OVERALL_FAILED" -ne 0 ]; then
    echo "RESULT: FAIL (${fails} of ${GATE_TOTAL} gates red)"
    exit 1
fi
echo "RESULT: PASS (all ${GATE_TOTAL} gates green)"
exit 0
