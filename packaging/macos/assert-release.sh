#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
metadata_path="$root/release-metadata.json"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS release assertions require macOS" >&2
  exit 1
fi

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
architecture="$(metadata_value macos_architecture)"
artifact_name="$(metadata_value macos_artifact)"
artifact_name="${artifact_name//\{version\}/$version}"
artifact="$root/dist/$artifact_name"

if [[ ! -f "$artifact" ]]; then
  echo "macOS release artifact is missing: $artifact" >&2
  exit 1
fi

extracted="$(mktemp -d "${TMPDIR:-/tmp}/gateway-connector-macos-release.XXXXXX")"
icon_work="$(mktemp -d "${TMPDIR:-/tmp}/gateway-connector-macos-icon.XXXXXX")"
iconset="$icon_work/GatewayConnector.iconset"
cleanup() {
  rm -rf "$extracted" "$icon_work"
}
trap cleanup EXIT

COPYFILE_DISABLE=1 tar -xzf "$artifact" -C "$extracted"
app="$extracted/$product_name.app"
contents="$app/Contents"
binary="$contents/MacOS/$binary_name"
icon="$contents/Resources/GatewayConnector.icns"
plist="$contents/Info.plist"

python3 - "$extracted" "$metadata_path" <<'PY'
import json
import os
import pathlib
import plistlib
import sys

root = pathlib.Path(sys.argv[1])
metadata_path = pathlib.Path(sys.argv[2])
metadata = json.loads(metadata_path.read_text())
app_name = metadata["product_name"] + ".app"
expected_directories = {
    app_name,
    f"{app_name}/Contents",
    f"{app_name}/Contents/MacOS",
    f"{app_name}/Contents/Resources",
}
expected_files = {
    "LICENSE",
    "release-metadata.json",
    f"{app_name}/Contents/Info.plist",
    f"{app_name}/Contents/MacOS/{metadata['binary_name']}",
    f"{app_name}/Contents/Resources/GatewayConnector.icns",
}
actual_directories = set()
actual_files = set()
for path in root.rglob("*"):
    relative = path.relative_to(root).as_posix()
    if path.is_symlink():
        raise SystemExit(f"release archive contains a symlink: {relative}")
    if path.is_dir():
        actual_directories.add(relative)
    elif path.is_file():
        actual_files.add(relative)
    else:
        raise SystemExit(f"release archive contains a special entry: {relative}")
if actual_directories != expected_directories or actual_files != expected_files:
    raise SystemExit(
        f"release archive contents differ: directories={sorted(actual_directories)}, files={sorted(actual_files)}"
    )
if (root / "LICENSE").read_bytes() != (metadata_path.parent / "LICENSE").read_bytes():
    raise SystemExit("release LICENSE differs from the repository source")
if (root / "release-metadata.json").read_bytes() != metadata_path.read_bytes():
    raise SystemExit("release metadata differs from the repository source of truth")

plist_path = root / app_name / "Contents" / "Info.plist"
with plist_path.open("rb") as source:
    plist = plistlib.load(source)
expected_plist = {
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
if plist != expected_plist:
    raise SystemExit(f"Info.plist differs from release metadata: {plist!r}")
binary = root / app_name / "Contents" / "MacOS" / metadata["binary_name"]
if not os.access(binary, os.X_OK):
    raise SystemExit("release binary is not executable")
PY

plutil -lint "$plist" >/dev/null
actual_architectures="$(lipo -archs "$binary")"
if [[ "$actual_architectures" != "$architecture" ]]; then
  echo "Mach-O architecture expected $architecture, got $actual_architectures" >&2
  exit 1
fi
if ! file "$binary" | grep -Fq "Mach-O 64-bit executable $architecture"; then
  echo "release binary is not the expected native Mach-O executable: $(file "$binary")" >&2
  exit 1
fi

iconutil -c iconset "$icon" -o "$iconset"
python3 - "$iconset" <<'PY'
import pathlib
import sys

iconset = pathlib.Path(sys.argv[1])
expected = {
    "icon_16x16.png",
    "icon_16x16@2x.png",
    "icon_32x32.png",
    "icon_32x32@2x.png",
    "icon_128x128.png",
    "icon_128x128@2x.png",
    "icon_256x256.png",
    "icon_256x256@2x.png",
    "icon_512x512.png",
    "icon_512x512@2x.png",
}
actual = {path.name for path in iconset.iterdir() if path.is_file()}
if actual != expected:
    raise SystemExit(f"macOS icon representations differ: {sorted(actual)}")
PY

python3 - "$metadata_path" "$artifact" "$actual_architectures" <<'PY'
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(json.dumps({
    "artifact": sys.argv[2],
    "bundle": metadata["product_name"] + ".app",
    "bundle_id": metadata["macos_bundle_id"],
    "version": metadata["version"],
    "architecture": sys.argv[3],
    "icon": "GatewayConnector.icns",
    "signed": metadata["signed"],
    "notarized": metadata["notarized"],
    "updater": metadata["updater"],
    "release_feed": metadata["release_feed"],
}, indent=2))
PY
