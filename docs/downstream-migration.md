# Migrating branded wrappers to GatewayConnector

OriginGame and BoxAI should become thin downstream distributions after native
acceptance of this neutral upstream. This repository does not edit or release
either wrapper.

## Dependency policy

Each wrapper must consume all three crates from one exact GatewayConnector
commit. Do not follow `main`, mix revisions, or copy crate directories:

```toml
[dependencies]
gateway-connector-app = {
  git = "https://github.com/fran0220/GatewayConnector",
  rev = "<40-character-reviewed-commit>",
  features = ["gpui-app"]
}
gateway-connector-backend = {
  git = "https://github.com/fran0220/GatewayConnector",
  rev = "<same-40-character-reviewed-commit>"
}
gateway-connector-core = {
  git = "https://github.com/fran0220/GatewayConnector",
  rev = "<same-40-character-reviewed-commit>"
}
```

Commit `Cargo.lock` in each application wrapper. Revision bumps should be a
single reviewable dependency update after the neutral Linux gate and wrapper
acceptance pass.

## Extraction sequence

1. Freeze connector behavior in the wrapper and record the currently owned
   Agent roots, coordinator state, and disconnect behavior.
2. Add one compile-time `Distribution` value using wrapper-owned product IDs,
   URLs, platform pin, keyring/bundle identity, locales, assets, and release
   metadata.
3. Replace the copied connector client entry point with
   `gateway_connector_app::gpui_app::run(&DISTRIBUTION)`.
4. Remove duplicated neutral core/backend/app modules only after the wrapper
   compiles and reads existing shared coordinator ownership correctly.
5. Keep platform account/OAuth registration, branded pages/assets, packaging,
   signing, and release infrastructure in the wrapper. Do not move them into
   neutral crates.
6. Test connect, preview, apply, verify, reconnect, and disconnect against the
   wrapper's pinned platform. Test coexistence with the other distribution so
   one owner cannot overwrite or remove another owner's Agent projection.
7. Run native visual acceptance on Windows and macOS before publishing a
   branded artifact.

## Compatibility rules

- Preserve `ProjectDirs("dev", "GatewayConnector", "ProjectionCoordinator")`.
- Preserve the coordinator, lease, and encrypted ownership-receipt schemas.
- Keep the one-profile credential reference bound to its profile UUID.
- Never persist API keys, access tokens, refresh tokens, or account payloads in
  profile JSON.
- Keep direct mode free of inferred MCP/Skills and fake platform records.
- Treat top-level provisioning models as Agent-selectable; Model Plaza remains
  display-only.
- Do not introduce a local relay, custom session JWT, or alternate crypto.

If a wrapper needs a behavior change, implement and test it here first, bump
the exact revision in each downstream independently, and retain wrapper-only
identity at the distribution boundary.
