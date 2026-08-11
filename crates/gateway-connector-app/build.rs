use std::{env, fs, path::Path};

fn main() {
    const METADATA_PATH: &str = "../../release-metadata.json";
    const ICON_PATH: &str = "../../packaging/windows/icon.ico";

    println!("cargo:rerun-if-changed={METADATA_PATH}");
    println!("cargo:rerun-if-changed={ICON_PATH}");

    let metadata_bytes = fs::read(METADATA_PATH).expect("read neutral release metadata");
    let metadata: serde_json::Value =
        serde_json::from_slice(&metadata_bytes).expect("parse neutral release metadata");
    let version = field(&metadata, "version");
    assert_eq!(
        version,
        env::var("CARGO_PKG_VERSION").expect("Cargo package version"),
        "release metadata version must match the Cargo workspace version"
    );

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    assert!(
        Path::new(ICON_PATH).is_file(),
        "neutral Windows icon missing"
    );
    let packed_version = packed_version(version);
    let mut resource = winresource::WindowsResource::new();
    resource
        .set_language(0x0409)
        .set_icon(ICON_PATH)
        .set("ProductName", field(&metadata, "product_name"))
        .set("FileDescription", field(&metadata, "file_description"))
        .set("CompanyName", field(&metadata, "company_name"))
        .set("LegalCopyright", field(&metadata, "legal_copyright"))
        .set("OriginalFilename", field(&metadata, "original_filename"))
        .set("InternalName", field(&metadata, "binary_name"))
        .set("FileVersion", version)
        .set("ProductVersion", version)
        .set_version_info(winresource::VersionInfo::FILEVERSION, packed_version)
        .set_version_info(winresource::VersionInfo::PRODUCTVERSION, packed_version)
        .compile()
        .expect("embed neutral GatewayConnector Windows resources");
}

fn field<'a>(metadata: &'a serde_json::Value, name: &str) -> &'a str {
    metadata
        .get(name)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| panic!("release metadata field {name} must be a non-empty string"))
}

fn packed_version(version: &str) -> u64 {
    let core = version
        .split_once('-')
        .map_or(version, |(core, _prerelease)| core);
    let mut values = core
        .split('.')
        .map(|value| value.parse::<u16>().expect("numeric release version"))
        .collect::<Vec<_>>();
    assert!(
        (1..=4).contains(&values.len()),
        "release version must contain one to four numeric components"
    );
    values.resize(4, 0);
    (u64::from(values[0]) << 48)
        | (u64::from(values[1]) << 32)
        | (u64::from(values[2]) << 16)
        | u64::from(values[3])
}
