#!/usr/bin/env bash
# Build VulnRadar.app from source with swiftc. No Xcode project needed.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="VulnRadar"
DEST="${1:-$HOME/Applications}"
APP="${DEST}/${APP_NAME}.app"
BUNDLE_ID="dev.local.vulnradar"
VERSION="1.0"

command -v swiftc >/dev/null || { echo "swiftc not found — install Xcode or the command line tools" >&2; exit 1; }

echo "building ${APP_NAME}…"
rm -rf "$APP"
mkdir -p "${APP}/Contents/MacOS" "${APP}/Contents/Resources"

cat > "${APP}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>${APP_NAME}</string>
  <key>CFBundleDisplayName</key><string>Vulnerability Radar</string>
  <key>CFBundleExecutable</key><string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>ATSApplicationFontsPath</key><string>Fonts</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

# Bundle the typefaces: CoreText cannot load woff2, so fetch real TTFs once and cache them.
FONT_CACHE="$HOME/.claude/vuln-radar/vendor/fonts"
mkdir -p "$FONT_CACHE" "${APP}/Contents/Resources/Fonts"
/usr/bin/python3 -I - "$FONT_CACHE" <<'FONTS' || echo "note: font download skipped; the app falls back to the system face"
import re, sys, urllib.request, pathlib
cache = pathlib.Path(sys.argv[1])
specs = {"Instrument+Sans:wght@400;500;600;700": "InstrumentSans",
         "JetBrains+Mono:wght@400;500": "JetBrainsMono"}
for spec, stem in specs.items():
    url = "https://fonts.googleapis.com/css2?family=%s&display=swap" % spec
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/4.0"})
    css = urllib.request.urlopen(req, timeout=30).read().decode()
    for block in css.split("@font-face")[1:]:
        weight = re.search(r"font-weight:\s*(\d+)", block)
        src = re.search(r"url\((https://[^)]+\.ttf)\)", block)
        if not (weight and src):
            continue
        out = cache / ("%s-%s.ttf" % (stem, weight.group(1)))
        if not out.exists():
            out.write_bytes(urllib.request.urlopen(src.group(1), timeout=30).read())
FONTS
cp "$FONT_CACHE"/*.ttf "${APP}/Contents/Resources/Fonts/" 2>/dev/null || true

swiftc -O -swift-version 5 \
  -framework AppKit -framework SwiftUI -framework UserNotifications \
  -o "${APP}/Contents/MacOS/${APP_NAME}" \
  "${SRC_DIR}"/Sources/*.swift

# Draw the app icon so the Finder entry is not a generic placeholder.
TMP="$(mktemp -d)"
ICONSET="${TMP}/AppIcon.iconset"
mkdir -p "$ICONSET"
if swift "${SRC_DIR}/mkicon.swift" "$ICONSET" >/dev/null 2>&1 && ls "$ICONSET"/*.png >/dev/null 2>&1; then
  for size in 16 32 128 256 512; do
    double=$((size * 2))
    if [ -f "${ICONSET}/icon_${double}x${double}.png" ]; then
      cp "${ICONSET}/icon_${double}x${double}.png" "${ICONSET}/icon_${size}x${size}@2x.png"
    fi
  done
  rm -f "${ICONSET}/icon_1024x1024.png"
  iconutil -c icns "$ICONSET" -o "${APP}/Contents/Resources/AppIcon.icns" 2>/dev/null \
    || echo "note: icon generation skipped"
else
  echo "note: icon generation skipped"
fi
rm -rf "$TMP"

# Ad-hoc signature: required on Apple silicon for the bundle to launch.
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 \
  || echo "note: ad-hoc codesign failed; the app may be blocked by Gatekeeper"

echo "built: $APP"
echo "launch with: open \"$APP\""
