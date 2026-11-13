#!/bin/bash
# Builds dist/Mac Cleanup.app (universal: arm64 + x86_64) and dist/MacCleanup.dmg.
#   ./build_app.sh            build app + dmg
#   ./build_app.sh --install  also copy the app to /Applications
# Needs Xcode or the Command Line Tools (swiftc, iconutil). Ad-hoc signed for local use.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="Mac Cleanup"
VERSION="$(grep -m1 '^__version__' "$DIR/macguard.py" | cut -d'"' -f2)"
BUILD="$DIR/build"
DIST="$DIR/dist"
APP="$DIST/$NAME.app"
MIN_OS=13.0

rm -rf "$BUILD" "$APP" "$DIST/MacCleanup.dmg"
mkdir -p "$BUILD" "$APP/Contents/MacOS" "$APP/Contents/Resources"

for t in swiftc lipo iconutil sips codesign hdiutil; do
  command -v "$t" >/dev/null || { echo "Missing $t: install Apple's Command Line Tools (xcode-select --install), then retry."
                                  echo "The CLI and web UI work without the app: ./setup.sh, then macguard ui"; exit 1; }
done

echo "==> Compiling native wrapper"
for arch in arm64 x86_64; do
  swiftc -O -swift-version 5 -target "$arch-apple-macos$MIN_OS" -o "$BUILD/MacCleanup-$arch" "$DIR/app/main.swift"
done
lipo -create -output "$APP/Contents/MacOS/MacCleanup" "$BUILD"/MacCleanup-arm64 "$BUILD"/MacCleanup-x86_64

echo "==> Drawing icon"
swiftc -O -swift-version 5 -o "$BUILD/make_icon" "$DIR/app/make_icon.swift"
"$BUILD/make_icon" "$BUILD/icon-1024.png"
ICONSET="$BUILD/AppIcon.iconset"; mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s "$BUILD/icon-1024.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  sips -z $((s*2)) $((s*2)) "$BUILD/icon-1024.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"

echo "==> Bundling engine"
# every engine module (macguard.py loads the others on demand) plus the page
cp "$DIR"/macguard*.py "$DIR/ui.html" "$APP/Contents/Resources/"
# the Photo sorter's Apple Vision helper, prebuilt so users don't need Swift
mkdir -p "$APP/Contents/Resources/helpers"
for arch in arm64 x86_64; do
  swiftc -O -swift-version 5 -target "$arch-apple-macos$MIN_OS" -o "$BUILD/photo_sense-$arch" "$DIR/helpers/photo_sense.swift"
done
lipo -create -output "$APP/Contents/Resources/helpers/photo_sense" "$BUILD"/photo_sense-arm64 "$BUILD"/photo_sense-x86_64
# fail the build, not the user's first click, if a module is missing or broken
/usr/bin/python3 -c "import sys; sys.path.insert(0, sys.argv[1]); import macguard, macguard_mcp, macguard_capture, macguard_devsec, macguard_tools, macguard_recover, macguard_carve, macguard_aicheck, macguard_photos" \
  "$APP/Contents/Resources" || { echo "The bundled engine does not import; see the error above."; exit 1; }
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>$NAME</string>
  <key>CFBundleDisplayName</key><string>$NAME</string>
  <key>CFBundleIdentifier</key><string>ai.macguard.cleanup</string>
  <key>CFBundleExecutable</key><string>MacCleanup</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>$MIN_OS</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSLocalNetworkUsageDescription</key><string>Mac Cleanup inspects open ports and network connections on this Mac to detect exposed services and attacks. Nothing is sent anywhere.</string>
  <key>NSHumanReadableCopyright</key><string>mac-cleanup · local-only Mac maintenance</string>
</dict></plist>
EOF

echo "==> Signing (ad-hoc)"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"

echo "==> Packaging DMG"
STAGE="$BUILD/dmg"; mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$NAME" -srcfolder "$STAGE" -ov -format UDZO "$DIST/MacCleanup.dmg" >/dev/null

if [[ "${1:-}" == "--install" ]]; then
  rm -rf "/Applications/$NAME.app" && cp -R "$APP" /Applications/
  echo "==> Installed to /Applications/$NAME.app"
fi
rm -rf "$BUILD"
echo
echo "Built: $APP"
echo "       $DIST/MacCleanup.dmg"
du -sh "$APP" "$DIST/MacCleanup.dmg" | sed 's/^/       /'
