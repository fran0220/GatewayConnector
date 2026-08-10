# Downstream distribution API

GatewayConnector separates shared behavior from compile-time product identity.
`gateway_connector_backend::Distribution` is the only product configuration
accepted by the shared backend and GPUI runner.

```rust
use gateway_connector_backend::{Distribution, ReleaseMetadata};

pub static DISTRIBUTION: Distribution = Distribution {
    product_id: "example-connector",
    product_name: "Example Connector",
    expected_platform_id: Some("example-platform"),
    default_gateway_url: Some("https://gateway.example/v1"),
    manifest_url: Some("https://gateway.example/connector-manifest.json"),
    allow_custom_urls: false,
    qualifier: "com",
    organization: "example",
    application: "connector",
    keyring_service: "com.example.connector",
    bundle_id: "com.example.connector",
    supported_locales: &["en", "zh-CN"],
    asset_identity: None,
    release_metadata: Some(ReleaseMetadata {
        repository: "example/connector",
        download_url: None,
    }),
    pkce_client_id: "example-connector",
    device_name: "Example Connector",
};

fn main() {
    gateway_connector_app::gpui_app::run(&DISTRIBUTION);
}
```

Enable the app crate's `gpui-app` feature. The runner validates the distribution
before vault, profile, or network access and uses it for:

- product and platform identity;
- custom-URL policy, default Gateway, and optional explicit manifest;
- `ProjectDirs` state identity and OS keyring service;
- window title and supported neutral locales;
- browser-PKCE client/device values;
- optional compile-time asset and release metadata for the wrapper/packager.

`expected_platform_id` pins a manifest's platform. Setting
`allow_custom_urls=false` requires `default_gateway_url`; saved profiles and
new probes must continue to match the configured Gateway and manifest. An
explicit manifest URL must have the same origin as the configured Gateway.

The shared projection coordinator intentionally does **not** use downstream
state identity. Every wrapper uses
`ProjectDirs("dev", "GatewayConnector", "ProjectionCoordinator")` so ownership
leases remain interoperable. Do not fork or namespace that format.

## What stays downstream

A wrapper may provide its own binary entry point, assets, localized product
name, bundle/keyring identity, platform pin, packaging, signing, and release
metadata. It must not copy the connector engine or change persisted projection,
coordinator, or ownership-receipt formats.

OAuth client registration, platform URLs, account policy, signing identities,
update feeds, and branded assets are never neutral defaults. The generic
binary intentionally has no updater metadata and can be packaged as unsigned
manual artifacts.
