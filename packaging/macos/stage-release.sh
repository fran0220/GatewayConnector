#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
metadata_path="$root/release-metadata.json"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "this staging script produces only native macOS artifacts" >&2
  exit 1
fi

python3 - "$metadata_path" <<'PY'
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text())
if (
    metadata["release_mode"] != "unsigned-manual"
    or metadata["signed"]
    or metadata["notarized"]
    or metadata["updater"]
    or metadata["release_feed"]
):
    raise SystemExit(
        "release metadata must describe an unsigned manual artifact with no notarization, updater, or feed"
    )
if metadata["desktop_release_targets"] != ["macos", "windows"] or metadata["browser_target"]:
    raise SystemExit("release metadata must describe only the native macOS and Windows desktop targets")
if metadata["macos_target"] != "macos-arm64" or metadata["macos_rust_target"] != "aarch64-apple-darwin":
    raise SystemExit("release metadata must select the native macOS arm64 target")
if metadata["macos_architecture"] != "arm64":
    raise SystemExit("release metadata must select the arm64 Mach-O architecture")
PY

metadata_value() {
  python3 - "$metadata_path" "$1" <<'PY'
import json
import pathlib
import sys

print(json.loads(pathlib.Path(sys.argv[1]).read_text())[sys.argv[2]])
PY
}

version="$(metadata_value version)"
product_name="$(metadata_value product_name)"
binary_name="$(metadata_value binary_name)"
rust_target="$(metadata_value macos_rust_target)"
architecture="$(metadata_value macos_architecture)"
target_name="$(metadata_value macos_target)"
artifact_name="$(metadata_value macos_artifact)"
artifact_name="${artifact_name//\{version\}/$version}"
icon_source="$root/$(metadata_value neutral_icon_source)"

if [[ "$(uname -m)" != "$architecture" ]]; then
  echo "macOS release staging requires native $architecture, got $(uname -m)" >&2
  exit 1
fi
if [[ ! -f "$icon_source" ]]; then
  echo "neutral icon source is missing: $icon_source" >&2
  exit 1
fi

cd "$root"
cargo_metadata="$(cargo metadata --locked --no-deps --format-version 1)"
app_version="$(python3 -c 'import json,sys; packages=[p for p in json.load(sys.stdin)["packages"] if p["name"] == "gateway-connector-app"]; assert len(packages) == 1; print(packages[0]["version"])' <<<"$cargo_metadata")"
target_directory="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])' <<<"$cargo_metadata")"
if [[ "$app_version" != "$version" ]]; then
  echo "release metadata version $version does not match Cargo version $app_version" >&2
  exit 1
fi

cargo build --locked --release --target "$rust_target" \
  -p gateway-connector-app --features gpui-app --bin gateway-connector

dist="$root/dist"
stage="$dist/$target_name"
app="$stage/$product_name.app"
contents="$app/Contents"
macos="$contents/MacOS"
resources="$contents/Resources"
artifact="$dist/$artifact_name"
rm -rf "$stage"
mkdir -p "$macos" "$resources"
install -m 755 "$target_directory/$rust_target/release/$binary_name" "$macos/$binary_name"

icon_work="$(mktemp -d "$dist/.GatewayConnector-icons.XXXXXX")"
iconset="$icon_work/GatewayConnector.iconset"
mkdir "$iconset"
cleanup() {
  rm -rf "$icon_work"
}
trap cleanup EXIT
while read -r filename size; do
  sips -z "$size" "$size" "$icon_source" --out "$iconset/$filename" >/dev/null
done <<'SIZES'
icon_16x16.png 16
icon_16x16@2x.png 32
icon_32x32.png 32
icon_32x32@2x.png 64
icon_128x128.png 128
icon_128x128@2x.png 256
icon_256x256.png 256
icon_256x256@2x.png 512
icon_512x512.png 512
icon_512x512@2x.png 1024
SIZES
iconutil -c icns "$iconset" -o "$resources/GatewayConnector.icns"

python3 - "$metadata_path" "$contents/Info.plist" <<'PY'
import json
import pathlib
import plistlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text())
plist = {
    "CFBundleDevelopmentRegion": "en",
    "CFBundleDisplayName": metadata["product_name"],
    "CFBundleExecutable": metadata["binary_name"],
    "CFBundleIconFile": "GatewayConnector.icns",
    "CFBundleIdentifier": metadata["macos_bundle_id"],
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": metadata["product_name"],
    "CFBundlePackageType": "APPL",
    "CFBundleShortVersionString": metadata["version"],
    "CFBundleSupportedPlatforms": ["MacOSX"],
    "CFBundleVersion": metadata["version"],
    "LSArchitecturePriority": [metadata["macos_architecture"]],
    "NSHighResolutionCapable": True,
    "NSHumanReadableCopyright": metadata["legal_copyright"],
}
with pathlib.Path(sys.argv[2]).open("wb") as output:
    plistlib.dump(plist, output, fmt=plistlib.FMT_XML, sort_keys=True)
PY

cp "$root/LICENSE" "$stage/LICENSE"
cp "$metadata_path" "$stage/release-metadata.json"
rm -f "$artifact"
COPYFILE_DISABLE=1 tar -czf "$artifact" -C "$stage" \
  "$product_name.app" LICENSE release-metadata.json

printf '%s\n' "$artifact"
