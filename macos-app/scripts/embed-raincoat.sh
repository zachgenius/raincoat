#!/usr/bin/env bash
#
# Build the raincoat C++ CLI and embed it into Raincoat.app/Contents/Helpers/raincoat, signed.
# This is what makes the app self-contained: RaincoatLocator finds this copy as a fallback (so
# the GUI works with no prior install), and the in-app "Install" button symlinks it onto $PATH.
#
# Usage:
#   embed-raincoat.sh <path-to-Raincoat.app> [sign-identity]
#     sign-identity defaults to "-" (ad-hoc). From an Xcode Run Script phase, pass
#     "$EXPANDED_CODE_SIGN_IDENTITY". Set RAINCOAT_UNIVERSAL=1 for a fat arm64+x86_64 build.
#
# NON-FATAL by design: if cmake is missing or the build fails, it warns and leaves the app
# WITHOUT a bundled CLI (the app still runs; the installer reports "not found"). This keeps
# `swift build` / Xcode builds green on machines without a C++ toolchain.
set -uo pipefail

APP="${1:?usage: embed-raincoat.sh <Raincoat.app> [identity]}"
IDENTITY="${2:--}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"   # macos-app/scripts -> repo root
BUILD_DIR="$REPO_ROOT/build"
HELPERS="$APP/Contents/Helpers"

find_cmake() {
  if command -v cmake >/dev/null 2>&1; then command -v cmake; return 0; fi
  for c in /opt/homebrew/bin/cmake /usr/local/bin/cmake; do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  return 1
}

CMAKE="$(find_cmake)" || {
  echo "warning: cmake not found; skipping bundled raincoat CLI (app will run without it)" >&2
  exit 0
}

echo "==> building raincoat with $CMAKE"
ARCH_FLAG=()
[ "${RAINCOAT_UNIVERSAL:-0}" = "1" ] && ARCH_FLAG=(-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64")
# Expand safely even when empty (macOS bash 3.2 + `set -u` errors on "${arr[@]}" if unset).
if ! "$CMAKE" -S "$REPO_ROOT" -B "$BUILD_DIR" ${ARCH_FLAG[@]+"${ARCH_FLAG[@]}"} >/dev/null; then
  echo "warning: cmake configure failed; skipping bundled CLI" >&2; exit 0
fi
if ! "$CMAKE" --build "$BUILD_DIR" --target raincoat -j >/dev/null; then
  echo "warning: raincoat build failed; skipping bundled CLI" >&2; exit 0
fi

BIN="$BUILD_DIR/raincoat"
[ -x "$BIN" ] || { echo "warning: $BIN missing after build; skipping bundled CLI" >&2; exit 0; }

echo "==> embedding into $HELPERS"
mkdir -p "$HELPERS"
cp "$BIN" "$HELPERS/raincoat"
chmod 755 "$HELPERS/raincoat"

# Sign the nested executable BEFORE the app's outer signature seals the bundle. Hardened
# runtime (--options runtime) matches the app target's ENABLE_HARDENED_RUNTIME so a notarized
# build stays consistent; ad-hoc "-" is fine for local dev. The entitlements disable library
# validation so the CLI can load its third-party dylibs (e.g. Homebrew OpenSSL) — without this
# a hardened-signed raincoat SIGABRTs at launch (dyld "different Team IDs").
ENTITLEMENTS="$(cd "$(dirname "$0")" && pwd)/raincoat-helper.entitlements"
echo "==> codesign helper (identity: $IDENTITY)"
codesign --force --options runtime --entitlements "$ENTITLEMENTS" --sign "$IDENTITY" "$HELPERS/raincoat" \
  || echo "warning: codesign of bundled raincoat failed (continuing)" >&2

echo "done: embedded raincoat CLI at $HELPERS/raincoat"
