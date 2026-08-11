use gateway_connector_core::CanonicalBaseUrl;
use thiserror::Error;
use url::Url;

/// Compile-time product boundary. Values are borrowed so distributions add no
/// runtime configuration machinery.
#[derive(Debug, Clone, Copy)]
pub struct Distribution {
    pub product_id: &'static str,
    pub product_name: &'static str,
    pub expected_platform_id: Option<&'static str>,
    pub default_gateway_url: Option<&'static str>,
    pub manifest_url: Option<&'static str>,
    pub allow_custom_urls: bool,
    /// Allows the generic acceptance-only `--isolated-root` launch mode.
    /// Downstream distributions should leave this disabled.
    pub allow_isolated_root: bool,
    pub qualifier: &'static str,
    pub organization: &'static str,
    pub application: &'static str,
    pub keyring_service: &'static str,
    pub bundle_id: &'static str,
    pub supported_locales: &'static [&'static str],
    pub asset_identity: Option<AssetIdentity>,
    pub release_metadata: Option<ReleaseMetadata>,
    /// Schema-v2 `client` value. This is the only product identifier sent to auth.
    pub pkce_client_id: &'static str,
    pub device_name: &'static str,
}

pub const GENERIC_DISTRIBUTION: Distribution = Distribution {
    product_id: "gateway-connector",
    product_name: "GatewayConnector",
    expected_platform_id: None,
    default_gateway_url: None,
    manifest_url: None,
    allow_custom_urls: true,
    allow_isolated_root: true,
    qualifier: "dev",
    organization: "gateway-connector",
    application: "gateway-connector",
    keyring_service: "gateway-connector",
    bundle_id: "dev.gateway-connector",
    supported_locales: &["en", "zh-CN"],
    asset_identity: None,
    release_metadata: None,
    pkce_client_id: "gateway-connector",
    device_name: "GatewayConnector",
};

impl Distribution {
    pub fn validate(&self) -> Result<(), DistributionError> {
        for (name, value) in [
            ("product_id", self.product_id),
            ("qualifier", self.qualifier),
            ("organization", self.organization),
            ("application", self.application),
            ("keyring_service", self.keyring_service),
            ("bundle_id", self.bundle_id),
            ("pkce_client_id", self.pkce_client_id),
        ] {
            if !portable_id(value) {
                return Err(DistributionError::InvalidId(name));
            }
        }
        if self.product_name.trim().is_empty() || self.device_name.trim().is_empty() {
            return Err(DistributionError::InvalidText);
        }
        if let Some(id) = self.expected_platform_id
            && !portable_id(id)
        {
            return Err(DistributionError::InvalidId("expected_platform_id"));
        }
        if let Some(url) = self.default_gateway_url {
            CanonicalBaseUrl::parse(url)
                .map_err(|_| DistributionError::InvalidUrl("default_gateway_url"))?;
        } else if !self.allow_custom_urls {
            return Err(DistributionError::MissingDefaultGateway);
        }
        if let Some(url) = self.manifest_url {
            secure_url(url).map_err(|_| DistributionError::InvalidUrl("manifest_url"))?;
        }
        if self.supported_locales.is_empty()
            || self.supported_locales.iter().any(|v| !locale_tag(v))
        {
            return Err(DistributionError::InvalidId("supported_locales"));
        }
        Ok(())
    }
}

pub(crate) fn portable_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|b| !b.is_ascii_uppercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !is_windows_reserved(value)
}

fn is_windows_reserved(value: &str) -> bool {
    let stem = value.split('.').next().unwrap_or(value);
    matches!(stem, "con" | "prn" | "aux" | "nul" | "clock$")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn locale_tag(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 35
        && value.split('-').all(|part| {
            !part.is_empty() && part.len() <= 8 && part.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

#[derive(Debug, Clone, Copy)]
pub struct AssetIdentity {
    pub icon_key: &'static str,
    pub icon_path: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct ReleaseMetadata {
    pub repository: &'static str,
    pub download_url: Option<&'static str>,
}

fn secure_url(value: &str) -> Result<Url, ()> {
    let url = Url::parse(value).map_err(|_| ())?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(());
    }
    Ok(url)
}

#[derive(Debug, Error)]
pub enum DistributionError {
    #[error("distribution field {0} is not a portable identifier")]
    InvalidId(&'static str),
    #[error("distribution names must not be empty")]
    InvalidText,
    #[error("distribution field {0} is not a secure URL")]
    InvalidUrl(&'static str),
    #[error("a distribution that disables custom URLs must configure a default Gateway URL")]
    MissingDefaultGateway,
}
