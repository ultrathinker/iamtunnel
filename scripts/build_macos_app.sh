#!/usr/bin/env bash
# scripts/build_macos_app.sh — IAMT-298: build the iamtunnel.app bundle
# + a .dmg on a real Mac (Apple Silicon arm64 or Intel amd64). The
# resulting bundle is what an end-user double-clicks to start the
# gateway / server role — the same binary cmdServerInstall / etc.
# use, packaged in the shape macOS expects.
#
# The script is intentionally self-contained: it does not call
# xcodebuild, does not depend on the App Store toolchain, and does
# not require an Apple Developer ID. The bundle is ad-hoc signed
# (\`codesign --sign -\`) so Gatekeeper opens it on the build host
# and on the operator's Mac; a Developer ID + notarization pass
# is opt-in via environment variables (see "Signing" below).
#
# Usage:
#   ./scripts/build_macos_app.sh                  # host arch, ad-hoc
#   ./scripts/build_macos_app.sh arm64           # force a specific arch
#   ./scripts/build_macos_app.sh amd64
#   IAMT_SIGN_IDENTITY="Developer ID Application: …" \
#     IAMT_NOTARY_PROFILE="iamtunnel-notary" \
#     ./scripts/build_macos_app.sh              # real signing
#
# Output:
#   dist/iamtunnel-<version>-<arch>.app           the bundle
#   dist/iamtunnel-<version>-<arch>.dmg           the disk image
#   dist/iamtunnel-<version>-<arch>-raw           the raw executable(s)
#
# Re-runs are idempotent: dist/ is wiped before the run.

set -euo pipefail

# --- paths ----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

DIST="$REPO_ROOT/dist"
WORK="$DIST/.work"
RAW="$DIST/_raw"
rm -rf "$DIST"
mkdir -p "$DIST" "$WORK" "$RAW"

# --- version -------------------------------------------------------------
# git describe honours annotated tags; if none exist, fall back to
# "dev-<sha>" so the bundle name is never empty. The Info.plist
# CFBundleShortVersionString / CFBundleVersion carry the same value.
if git describe --tags --dirty --always >/dev/null 2>&1; then
  VERSION="$(git describe --tags --dirty --always)"
else
  VERSION="dev-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
fi
# Normalise: \`git describe\` may prefix with "v"; Info.plist is happy
# either way, but the file name looks cleaner without.
VERSION="${VERSION#v}"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  arm64)  HOST_ARCH=arm64 ;;
  x86_64) HOST_ARCH=amd64 ;;
  *)
    echo "build_macos_app.sh: unsupported host arch $ARCH_RAW — run on Apple Silicon or Intel macOS" >&2
    exit 2
    ;;
esac
BUILD_ARCH="${1:-$HOST_ARCH}"

echo ">>> build_macos_app.sh: host=$HOST_ARCH requested=$BUILD_ARCH version=$VERSION"

# --- preflight ------------------------------------------------------------
# Every tool we depend on MUST be present; refusing honestly beats
# a half-built bundle. The script is run interactively and on CI; both
# care about a clear refusal.
need() {
  command -v "$1" >/dev/null 2>&1 || { echo "build_macos_app.sh: missing tool: $1 — install via xcode-select --install" >&2; exit 2; }
}
need go
need lipo
need sips
need iconutil
need codesign
need hdiutil
need plutil   # /usr/bin/plutil for Info.plist validation
need xcrun

# --- build per-arch --------------------------------------------------------
# macOS uses Cocoa, which is cgo-only (IAMT-262). arm64 and amd64 each
# take their own build. If amd64 cgo is unavailable on this host
# (Apple Silicon-only toolchain), the script prints the reason and
# falls back to the native arch only — the final artefact is the
# host's binary, not a universal one. The build log states what was
# skipped and why; the operator decides whether to re-run on the
# missing arch's Mac.
RAW_BINS=()
for A in $BUILD_ARCH; do
  OUT="$RAW/iamtunnel-$A"
  echo ">>> build_macos_app.sh: go build CGO_ENABLED=1 GOOS=darwin GOARCH=$A -> $OUT"
  if ! CGO_ENABLED=1 GOOS=darwin GOARCH="$A" \
        go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
        -o "$OUT" ./cmd/iamtunnel; then
    if [ "$A" != "$HOST_ARCH" ]; then
      echo "build_macos_app.sh: GOARCH=$A cgo build failed on $HOST_ARCH — skipping that arch (run natively on an $A Mac for the missing half)" >&2
      continue
    fi
    echo "build_macos_app.sh: native arch cgo build failed; aborting" >&2
    exit 1
  fi
  RAW_BINS+=("$OUT")
done
if [ "${#RAW_BINS[@]}" -eq 0 ]; then
  echo "build_macos_app.sh: no binaries built (every requested arch failed)" >&2
  exit 1
fi

# --- universal binary (lipo) ----------------------------------------------
# lipo -create produces a multi-arch Mach-O when both halves exist;
# otherwise the single arch is used unchanged and a note is printed.
LIPO_IN=()
for B in "${RAW_BINS[@]}"; do LIPO_IN+=("$B"); done
if [ "${#LIPO_IN[@]}" -eq 1 ]; then
  BUILT_BIN="${LIPO_IN[0]}"
  echo ">>> build_macos_app.sh: only $BUILD_ARCH arch available — bundle carries the single-arch binary"
else
  BUILT_BIN="$RAW/iamtunnel-universal"
  lipo -create -output "$BUILT_BIN" "${LIPO_IN[@]}"
  echo ">>> build_macos_app.sh: lipo -create -> $BUILT_BIN (${#LIPO_IN[@]} arches)"
fi
chmod +x "$BUILT_BIN"

# --- assemble .app bundle --------------------------------------------------
APP_NAME="iamtunnel"
# CFBundleIdentifier names the .app, NOT the LaunchDaemon. The
# LaunchDaemon that installs alongside the .app is com.iamtunnel.gateway
# (cmd/iamtunnel/gateway_launchd.go::darwinPlistLabel) and lives at
# /Library/LaunchDaemons/com.iamtunnel.gateway.plist — that label and
# this bundle id are separate names for separate things. The .app is
# the client/window the user double-clicks; the LaunchDaemon is the
# gateway daemon install writes into launchd. A bundle id ending in
# ".gateway" would tell Gatekeeper the .app IS the daemon, which it
# is not.
BUNDLE_ID="com.iamtunnel.app"
DISPLAY_NAME="iamtunnel"
APP_BUNDLE="$DIST/${APP_NAME}-${VERSION}-${BUILD_ARCH}.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_RES="$APP_CONTENTS/Resources"
mkdir -p "$APP_MACOS" "$APP_RES"

cp "$BUILT_BIN" "$APP_MACOS/$APP_NAME"
chmod +x "$APP_MACOS/$APP_NAME"

# --- icons: build .icns from the bundled 256/48 PNGs ----------------------
# macOS reads .icns (CFBundleIconFile); we produce one from the same
# PNG source assets/icon/iamtunnel-<size>.png that the Linux .desktop
# uses (IAMT-255). sips + iconutil make a standard icns in seconds.
ICONSET="$WORK/icon.iconset"
mkdir -p "$ICONSET"
for SIZE in 16 32 64 128 256 512; do
  SRC=""
  case "$SIZE" in
    16|32|48|64|128|256) SRC="assets/icon/iamtunnel-$SIZE.png" ;;
    512) SRC="assets/icon/iamtunnel-256.png" ;;  # 512x512 derived from 256 (App Store best)
  esac
  if [ -n "$SRC" ] && [ -f "$SRC" ]; then
    # The 16/32/64/128 icns entries macOS wants are smaller than 256; sips
    # can resample down on the fly without an external image tool.
    sips -z "$SIZE" "$SIZE" "$SRC" --out "$ICONSET/icon_${SIZE}x${SIZE}.png" >/dev/null
  fi
done
# iconutil wants exactly the canonical names; the @2x retina pair is
# optional but the .icns is more useful with them.
if [ -f "$ICONSET/icon_256x256.png" ]; then
  cp "$ICONSET/icon_256x256.png" "$ICONSET/icon_128x128@2x.png"
fi
# CFBundleIconFile names a file inside Contents/Resources — a bare
# name (no extension); macOS appends .icns itself. The single-letter
# "C" is a leftover from the test fixture convention, not a real
# product artefact; the canonical product icon is iamtunnel.icns.
ICON_FILE="$APP_RES/iamtunnel.icns"
iconutil -c icns "$ICONSET" -o "$ICON_FILE"
echo ">>> build_macos_app.sh: iconutil -c icns -> $ICON_FILE"

# --- Info.plist ------------------------------------------------------------
# CFBundleIdentifier / CFBundleExecutable / CFBundleIconFile are the
# minimum macOS asks for; CFBundleShortVersionString +
# CFBundleVersion carry the version; LSMinimumSystemVersion +
# NSHighResolutionCapable are SPEC's "macOS 13+, retina by default"
# promises. Values that take user input are shell-quoted here, so a
# hostile VERSION (\$(rm -rf /)) becomes the value, not a command.
q() { printf '%s' "$1" | sed "s/'/'\\\\''/g"; }
INFO_PLIST="$APP_CONTENTS/Info.plist"
cat > "$INFO_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>          <string>en</string>
  <key>CFBundleDisplayName</key>                <string>$(q "$DISPLAY_NAME")</string>
  <key>CFBundleExecutable</key>                 <string>$(q "$APP_NAME")</string>
  <key>CFBundleIconFile</key>                   <string>iamtunnel</string>
  <key>CFBundleIdentifier</key>                 <string>$(q "$BUNDLE_ID")</string>
  <key>CFBundleInfoDictionaryVersion</key>      <string>6.0</string>
  <key>CFBundleName</key>                       <string>$(q "$APP_NAME")</string>
  <key>CFBundlePackageType</key>                 <string>APPL</string>
  <key>CFBundleShortVersionString</key>         <string>$(q "$VERSION")</string>
  <key>CFBundleVersion</key>                    <string>$(q "$VERSION")</string>
  <key>LSMinimumSystemVersion</key>             <string>13.0</string>
  <key>NSHighResolutionCapable</key>            <true/>
  <key>NSPrincipalClass</key>                   <string>NSApplication</string>
</dict>
</plist>
EOF
plutil -lint "$INFO_PLIST" >/dev/null

# --- signing ----------------------------------------------------------------
# Three layers: (1) ad-hoc, always; (2) Developer ID with --options
# runtime when IAMT_S; (3) notarytool + stapler only when
# IAMT_NOTARY_PROFILE is set. The same identity signs the binary and
# the bundle; nested signatures are what Gatekeeper checks.
SIGN_IDENTITY="${IAMT_SIGN_IDENTITY:-}"
NOTARY_PROFILE="${IAMT_NOTARY_PROFILE:-}"

echo ">>> build_macos_app.sh: codesign (ad-hoc) -> $APP_BUNDLE"
codesign --force --sign - --timestamp=none "$APP_BUNDLE"

if [ -n "$SIGN_IDENTITY" ]; then
  echo ">>> build_macos_app.sh: codesign (Developer ID, hardened runtime) -> $APP_BUNDLE"
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP_BUNDLE"
fi

# --- DMG --------------------------------------------------------------------
DMG_PATH="$DIST/${APP_NAME}-${VERSION}-${BUILD_ARCH}.dmg"
echo ">>> build_macos_app.sh: hdiutil create -> $DMG_PATH"
# UDRO (read-only), UDZO (compressed) — UDRO is the default; UDZO
# shrinks the image 3–5x for a small program. We pick UDRO because the
# image is single-file and the speedup on a developer Mac is
# negligible; final users mounting from .dmg rarely need compression.
MOUNT_DIR="$WORK/dmg-mount"
mkdir -p "$MOUNT_DIR"
cp -R "$APP_BUNDLE" "$MOUNT_DIR/"
hdiutil create -volname "$APP_NAME $VERSION" -srcfolder "$MOUNT_DIR" \
  -ov -format UDRO "$DMG_PATH" >/dev/null

if [ -n "$SIGN_IDENTITY" ] && [ -n "$NOTARY_PROFILE" ]; then
  echo ">>> build_macos_app.sh: notarytool submit --wait + stapler staple"
  xcrun notarytool submit "$DMG_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$DMG_PATH"
fi

# --- summary ----------------------------------------------------------------
rm -rf "$WORK"
echo
echo "build_macos_app.sh: ok"
echo "  bundle : $APP_BUNDLE"
echo "  dmg    : $DMG_PATH"
if [ "${#RAW_BINS[@]}" -gt 1 ]; then
  echo "  raw    : ${RAW_BINS[*]} (lipo'd into the bundle)"
else
  echo "  raw    : $BUILT_BIN (single-arch; cross-arch lipo skipped)"
fi