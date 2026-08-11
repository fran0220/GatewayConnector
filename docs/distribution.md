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
    allow_isolated_root: false,
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

Wrappers that embed branded assets can call
`gateway_connector_app::gpui_app::run_with_assets(&DISTRIBUTION, assets)`.
Their `AssetSource` should delegate unknown neutral icon and font paths to
`gpui_kit::assets::Assets`; the generic `run` function does this automatically.

`expected_platform_id` pins a manifest's platform. Setting
`allow_custom_urls=false` requires `default_gateway_url`; saved profiles and
new probes must continue to match the configured Gateway and manifest. An
explicit manifest URL must have the same origin as the configured Gateway.

`allow_isolated_root` is deny-by-default policy for downstream definitions;
only the neutral generic binary opts in. It accepts the exact production option
`--isolated-root <absolute-path>` and derives state, an isolated coordinator,
and all five fixture Agent roots beneath that one validated root. It is intended
for portable acceptance, not as a security sandbox. Branded wrappers should
keep the flag `false` unless they deliberately expose and test this generic
acceptance facility. There are no per-Agent, coordinator, HOME, or XDG override
arguments.

The shared projection coordinator intentionally does **not** use downstream
state identity. Every wrapper uses
`ProjectDirs("dev", "GatewayConnector", "ProjectionCoordinator")` so ownership
leases remain interoperable. Do not fork or namespace that format.

## Neutral target policy

The neutral desktop release targets are macOS and Windows. The repository's
current unsigned manual contracts produce a native macOS arm64 `.app.tar.gz`
and Windows x64 `.zip`; neither is signed, notarized, or connected to an
updater/feed. Linux desktop is deferred, unsupported, and non-gating. The
portable core/backend code and best-effort Linux orb setup remain available for
development, but they are not release evidence. GatewayConnector has no
browser/WebAssembly application target; schema-v2 browser PKCE is only an
authentication flow launched by the native desktop client.

## What stays downstream

A wrapper may provide its own binary entry point, assets, localized product
name, bundle/keyring identity, platform pin, packaging, signing, and release
metadata. It must not copy the connector engine or change persisted projection,
coordinator, or ownership-receipt formats.

OAuth client registration, platform URLs, account policy, signing identities,
update feeds, and branded assets are never neutral defaults. The generic
binary intentionally has no updater metadata and can be packaged as unsigned
manual artifacts.
