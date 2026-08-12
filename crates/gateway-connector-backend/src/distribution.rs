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
    pub bundle_id: &'static str,
    pub supported_locales: &'static [&'static str],
    /// Optional wrapper-owned icon rendered by the shared connected shell.
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
        if let Some(identity) = self.asset_identity {
            if !portable_id(identity.icon_key) {
                return Err(DistributionError::InvalidId("asset_identity.icon_key"));
            }
            if !embedded_svg_path(identity.icon_path) {
                return Err(DistributionError::InvalidAssetPath);
            }
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

fn embedded_svg_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.ends_with(".svg")
        && value.split('/').all(|component| {
            !component.is_empty()
                && component.len() <= 128
                && !matches!(component, "." | "..")
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetIdentity {
    /// Stable GPUI element identity for the distribution-owned shell icon.
    pub icon_key: &'static str,
    /// Relative virtual SVG path served by the active GPUI `AssetSource`.
    pub icon_path: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct ReleaseMetadata {
    pub repository: &'static str,
    pub download_url: Option<&'static str>,
}

fn secure_url(value: &str) -> Result<Url, ()> {
    let url = Url::parse(value).map_err(|_| ())?;
    // Production distributions use HTTPS. Loopback HTTP is allowed so native
    // acceptance tests can pin an explicit manifest on a local mock server.
    let scheme_ok = match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
            None => false,
        },
        _ => false,
    };
    if !scheme_ok
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
    #[error("distribution asset icon path must be a safe relative virtual .svg path")]
    InvalidAssetPath,
    #[error("a distribution that disables custom URLs must configure a default Gateway URL")]
    MissingDefaultGateway,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn branded_distribution() -> Distribution {
        Distribution {
            product_id: "example-connector",
            product_name: "Example Connector",
            allow_isolated_root: false,
            asset_identity: Some(AssetIdentity {
                icon_key: "example-connector-shell-icon",
                icon_path: "brand/example-connector.svg",
            }),
            ..GENERIC_DISTRIBUTION
        }
    }

    #[test]
    fn validates_embedded_distribution_asset_identity() {
        let branded = branded_distribution();
        branded.validate().expect("valid branded distribution");
        assert!(!branded.allow_isolated_root);

        let invalid_key = Distribution {
            asset_identity: Some(AssetIdentity {
                icon_key: "Example Connector",
                icon_path: "brand/example.svg",
            }),
            ..branded
        };
        assert!(matches!(
            invalid_key.validate(),
            Err(DistributionError::InvalidId("asset_identity.icon_key"))
        ));

        for icon_path in [
            "",
            "/brand/example.svg",
            "../brand/example.svg",
            "brand/../example.svg",
            "brand\\example.svg",
            "brand//example.svg",
            "brand/example.png",
            "https://example.com/icon.svg",
        ] {
            let invalid_path = Distribution {
                asset_identity: Some(AssetIdentity {
                    icon_key: "example-connector-shell-icon",
                    icon_path,
                }),
                ..branded
            };
            assert!(matches!(
                invalid_path.validate(),
                Err(DistributionError::InvalidAssetPath)
            ));
        }
    }
}
