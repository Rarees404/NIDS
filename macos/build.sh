#!/bin/bash
# Build the PyNIDS menu bar app + desktop widget with the Xcode command line
# tools only (no Xcode project needed).
#
#   macos/build.sh              build into macos/build.noindex/PyNIDS.app
#   macos/build.sh --install    also copy to ~/Applications, register the widget, and launch
#
# The bundle is ad-hoc signed ("Sign to Run Locally").  It runs on the Mac that
# built it; distributing it to other Macs needs a Developer ID signature.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/src"
# ".noindex" keeps Spotlight / Launchpad from listing the build copy as a second app.
OUT="$HERE/build.noindex"
APP="$OUT/PyNIDS.app"
APPEX="$APP/Contents/PlugIns/PyNIDSWidget.appex"
INSTALL=0
[[ "${1:-}" == "--install" ]] && INSTALL=1

SDK="$(xcrun --sdk macosx --show-sdk-path)"
ARCH="$(uname -m)"
TARGET="$ARCH-apple-macos14.0"
VERSION="$(grep -m1 '^version' "$HERE/../pyproject.toml" | cut -d'"' -f2)"
# Monotonic build number that fits in 32 bits (minutes since the Unix epoch);
# WidgetKit compares it against LaunchServices' record of the installed app.
BUILD="$(( $(date +%s) / 60 ))"
SDK_VERSION="$(xcrun --sdk macosx --show-sdk-version)"
SDK_BUILD="$(xcrun --sdk macosx --show-sdk-build-version 2>/dev/null || echo "")"
SWIFTC=(xcrun --sdk macosx swiftc -sdk "$SDK" -target "$TARGET" -swift-version 5 -O -parse-as-library)

echo "==> Building PyNIDS $VERSION ($ARCH)"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APPEX/Contents/MacOS"

echo "==> Compiling menu bar app"
"${SWIFTC[@]}" "$SRC"/Shared/*.swift "$SRC"/App/*.swift \
  -o "$APP/Contents/MacOS/PyNIDS"

echo "==> Compiling widget extension"
# Extensions must start in Foundation's NSExtensionMain (what Xcode links with),
# which initialises the extension runtime before handing over to WidgetKit.
"${SWIFTC[@]}" -application-extension "$SRC"/Shared/*.swift "$SRC"/Widget/*.swift \
  -Xlinker -e -Xlinker _NSExtensionMain \
  -o "$APPEX/Contents/MacOS/PyNIDSWidget"

for pair in "App-Info.plist:$APP/Contents/Info.plist" "Widget-Info.plist:$APPEX/Contents/Info.plist"; do
  src="${pair%%:*}"; dst="${pair#*:}"
  sed -e "s/__VERSION__/$VERSION/" -e "s/__BUILD__/$BUILD/" \
      -e "s/__SDK_VERSION__/$SDK_VERSION/g" -e "s/__SDK_BUILD__/$SDK_BUILD/g" \
      "$SRC/Resources/$src" > "$dst"
done
printf 'APPL????' > "$APP/Contents/PkgInfo"

echo "==> Signing (ad-hoc)"
codesign --force --sign - --timestamp=none --options runtime \
  --entitlements "$SRC/Resources/Widget.entitlements" "$APPEX"
codesign --force --sign - --timestamp=none --options runtime \
  --entitlements "$SRC/Resources/App.entitlements" "$APP"
codesign --verify --deep --strict "$APP"
echo "    built $APP"

if [[ $INSTALL -eq 1 ]]; then
  DEST="$HOME/Applications"
  mkdir -p "$DEST"
  echo "==> Installing to $DEST"
  pkill -x PyNIDS 2>/dev/null || true
  rm -rf "$DEST/PyNIDS.app"
  cp -R "$APP" "$DEST/"
  LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
  # Only the installed copy may be registered: a second copy (the build
  # folder) makes WidgetKit reject timelines with "Bundle version did not match".
  "$LSREGISTER" -u "$APP" >/dev/null 2>&1 || true
  "$LSREGISTER" -f "$DEST/PyNIDS.app" || true
  pluginkit -a "$DEST/PyNIDS.app/Contents/PlugIns/PyNIDSWidget.appex" || true
  # A widget process from the previous build would keep serving stale
  # timelines that WidgetKit discards — stop it so the new one launches.
  pkill -x PyNIDSWidget 2>/dev/null || true
  rm -rf "$APP"   # the installed copy is the only one that should exist
  open "$DEST/PyNIDS.app"
  echo
  echo "PyNIDS is in your menu bar."
  echo "Add the widget: right-click the desktop → Edit Widgets → search \"PyNIDS\"."
fi
