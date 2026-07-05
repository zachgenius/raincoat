#!/usr/bin/env bash
#
# Wrap the SwiftPM executable into Raincoat.app (a menu-bar agent bundle).
#
# Usage:
#   scripts/make-app-bundle.sh [debug|release]   # default: release
#
# Produces macos-app/Raincoat.app. The bundle's Info.plist (with LSUIElement) is the
# same one embedded into the binary, so the app is a Dock-less agent either way.
set -euo pipefail

CONFIG="${1:-release}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXE_NAME="RaincoatMenuBar"
APP="$ROOT/Raincoat.app"

echo "==> swift build -c $CONFIG"
( cd "$ROOT" && swift build -c "$CONFIG" )

BIN="$ROOT/.build/$CONFIG/$EXE_NAME"
[ -x "$BIN" ] || { echo "error: built binary not found at $BIN" >&2; exit 1; }

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/$EXE_NAME"
# Info.plist lives with the library sources (embedded into the exe via -sectcreate too).
cp "$ROOT/Sources/RaincoatMenuBarKit/Info.plist" "$APP/Contents/Info.plist"

# Build + embed the raincoat CLI into Contents/Helpers (self-contained app). Non-fatal: if
# cmake is missing the app is assembled without it. Must run BEFORE the outer signature below
# so the app seals the nested binary.
echo "==> embedding raincoat CLI"
"$ROOT/scripts/embed-raincoat.sh" "$APP" -

# Ad-hoc signature so Gatekeeper on this Mac will run it locally. For distribution,
# replace with: codesign --deep --force --options runtime --sign "Developer ID Application: …"
echo "==> ad-hoc codesign (local dev only)"
codesign --force --sign - "$APP" 2>/dev/null || echo "   (codesign skipped)"

echo "done: $APP"
echo "run it with: open \"$APP\"   (or double-click in Finder)"
