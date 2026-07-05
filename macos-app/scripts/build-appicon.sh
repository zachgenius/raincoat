#!/usr/bin/env bash
#
# Regenerate the placeholder AppIcon.appiconset from the CoreGraphics generator.
# Produces the 10 standard macOS icon sizes via sips + a warning-free Contents.json.
# Replace scripts/make-appicon.swift (or the PNGs) with real artwork later.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SET="$ROOT/App/Assets.xcassets/AppIcon.appiconset"
BASE="$(mktemp -d)/icon-1024.png"

echo "==> generating base 1024×1024"
swift "$ROOT/scripts/make-appicon.swift" "$BASE"

mkdir -p "$SET"

# role -> pixel size
emit() { # <pixels> <filename>
    sips -z "$1" "$1" "$BASE" --out "$SET/$2" >/dev/null
}
echo "==> downscaling"
emit 16   icon_16x16.png
emit 32   icon_16x16@2x.png
emit 32   icon_32x32.png
emit 64   icon_32x32@2x.png
emit 128  icon_128x128.png
emit 256  icon_128x128@2x.png
emit 256  icon_256x256.png
emit 512  icon_256x256@2x.png
emit 512  icon_512x512.png
cp "$BASE" "$SET/icon_512x512@2x.png"   # 1024, no resize

cat > "$SET/Contents.json" <<'JSON'
{
  "images" : [
    { "idiom" : "mac", "size" : "16x16",   "scale" : "1x", "filename" : "icon_16x16.png" },
    { "idiom" : "mac", "size" : "16x16",   "scale" : "2x", "filename" : "icon_16x16@2x.png" },
    { "idiom" : "mac", "size" : "32x32",   "scale" : "1x", "filename" : "icon_32x32.png" },
    { "idiom" : "mac", "size" : "32x32",   "scale" : "2x", "filename" : "icon_32x32@2x.png" },
    { "idiom" : "mac", "size" : "128x128", "scale" : "1x", "filename" : "icon_128x128.png" },
    { "idiom" : "mac", "size" : "128x128", "scale" : "2x", "filename" : "icon_128x128@2x.png" },
    { "idiom" : "mac", "size" : "256x256", "scale" : "1x", "filename" : "icon_256x256.png" },
    { "idiom" : "mac", "size" : "256x256", "scale" : "2x", "filename" : "icon_256x256@2x.png" },
    { "idiom" : "mac", "size" : "512x512", "scale" : "1x", "filename" : "icon_512x512.png" },
    { "idiom" : "mac", "size" : "512x512", "scale" : "2x", "filename" : "icon_512x512@2x.png" }
  ],
  "info" : { "version" : 1, "author" : "xcode" }
}
JSON

echo "done: $SET"
