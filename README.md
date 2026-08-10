# GatewayConnector

GatewayConnector is the neutral open-source upstream for desktop Gateway
connection and Agent projection. Branded distributions inject their own
identity, assets, platform manifest, OAuth/account integration, packaging, and
release process; none of those concerns belong in this repository.

The generic path requires only an HTTPS Gateway base URL and API key. It tests
the connection with authenticated `GET` model discovery, then lets the user
select a protocol and model for each of five supported Agents. An enhanced
Gateway may optionally advertise schema-v2 browser PKCE and provisioning from
the exact-origin `/.well-known/gateway-connector` document. A missing
well-known document is normal and falls back to the generic path.

The Gateway URL may be an origin, a nested prefix, an API base ending in
`/v1`, or the full `/v1/models` endpoint. Resolution is deterministic and does
not scan other endpoints:

| Gateway URL path | Requested model path |
| --- | --- |
| `/` | `/v1/models` |
| `/v1` | `/v1/models` |
| `/v1/models` | `/v1/models` |
| `/proxy` | `/proxy/v1/models` |
| `/proxy/v1` | `/proxy/v1/models` |

## Architecture

```text
gateway-connector-core
  Canonical URL + versioned, secret-free persisted profile model
  Five-Agent native projection and discovery engine
  Plan/preview/apply/verify/disconnect, coordinator leases, encrypted receipts,
  and crash-safe staging/rollback

gateway-connector-backend
  Exact-origin HTTP and OpenAI-compatible model discovery
  Optional schema-v2 well-known/explicit manifest and provisioning flow
  Standard browser PKCE with access-token-only persistence
  OS credential-store abstraction + in-memory test vault
  Thin compile-time Distribution boundary for neutral/downstream identity

gateway-connector-app
  Pure application state
  Optional GPUI/gpui-kit binary with first-run, discovery, Agent selection,
  connected summary, and preview flow
```

The projection engine retains the proven five adapters—Claude Code, Codex CLI,
Gemini CLI, Grok Build, and OpenCode. It uses plan → preview → apply → verify →
disconnect, preserves unrelated JSON/JSONC/TOML/env configuration, rejects
symlink and ownership collisions, requires a fresh preview before apply, and
coordinates singleton Agent files across distributions through the shared
`ProjectDirs("dev", "GatewayConnector", "ProjectionCoordinator")` contract.

## Security boundary

- Profiles persist a stable UUID, canonical URL, connection mode/platform,
  display name, per-Agent choices, and an opaque credential reference. They
  never contain a plaintext API key or access token. Legacy schema-1 direct
  profiles migrate to schema 2 on load, and every credential reference is
  bound to its profile UUID. The vault envelope also binds the credential to
  the canonical Gateway, mode, platform, credential kind, and manifest
  location, so editing profile JSON cannot redirect an existing bearer.
- API keys and PKCE access tokens are stored through `CredentialStore`; the
  desktop binary uses the OS credential store and tests use
  `InMemoryCredentialStore`. Refresh tokens and provider account blobs are not
  retained. Failed vault commits keep a newly minted credential reachable for
  explicit retry or confirmed remote revocation.
- Remote gateways require HTTPS. Plain HTTP is allowed only for literal
  loopback development hosts, and loopback HTTP always bypasses ambient proxy
  configuration so a local bearer cannot be exposed to a forward proxy.
- The bearer is attached only to requests whose scheme, host, and effective
  port exactly match the configured base URL.
- Redirects are handled manually. Same-origin redirects are bounded; a
  cross-origin redirect is rejected before contacting the target, so the
  bearer cannot leak.
- Model and manifest responses are limited to 2 MiB.
- Manifest discovery is optional and unauthenticated. Generic gateways need
  only the OpenAI-compatible `/v1/models` endpoint. Well-known 404 is direct
  mode; an injected explicit manifest is required and does not silently fall
  back on 404. Provisioning receives a bearer only when its exact origin is in
  the manifest allowlist, and its top-level chat model catalog—not Model
  Plaza—is the Agent selector source.
- Browser authentication is standard S256 PKCE over a loopback callback. The
  authorization code exchange does not follow redirects and accepts only a
  Bearer `access_token` response.
- Official downstream builds can disable custom Gateway URLs and pin both the
  platform identity and manifest endpoint through `Distribution`; generic
  builds remain user-configurable. Neutral defaults contain no branded URLs,
  OAuth IDs, assets, account assumptions, or updater metadata.
- Profile creation is singleton and guarded by both an in-process connection
  lock and an inter-process profile-file lock. Profile writes use private
  temporary files and replace atomically on Linux, macOS, and Windows.
- There is no local relay, embedded Agent runtime, custom cryptography, or
  hard-coded MCP/Skill catalog.

## Development

Rust 1.97 is pinned. In an Amp orb, `.agents/setup` installs Rust and the Linux
libraries used by GPUI.

```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The UI dependencies are optional so core/backend tests stay portable and do
not need a display server:

```bash
cargo check -p gateway-connector-app --features gpui-app
cargo run -p gateway-connector-app --features gpui-app --bin gateway-connector
```

## Demonstrated phase-1 flow

1. Enter a Gateway base URL, API key, and initial protocol.
2. **Connect / Test** canonicalizes the URL and resolves its model endpoint as
   shown above, without changing the configured origin.
3. A successful OpenAI-style `{ "data": [...] }` response is normalized,
   deduplicated, sorted, and shown in one model picker per Agent.
4. The connected summary shows the canonical Gateway and discovered model
   count. Protocol/model changes are serialized through an ordered save queue
   and persisted without the credential; save failures stay visible.
5. **Preview projection** shows all five intended selections and explicitly
   states that no Agent files were changed.
6. A later launch reloads the profile, retrieves the key from the OS vault, and
   refreshes `/v1/models` while preserving the stable profile ID and valid
   Agent selections.

## Next extraction steps

The next coherent backend change is online catalog synchronization: consume
only provisioned schema-v2 MCP/Skill records, enforce archive origin/hash/size
and portable-path limits, safely extract ZIPs through staging and rollback, and
feed synchronized services into the existing neutral projection engine. Direct
mode will continue to expose no invented MCP or Skills.

The GPUI shell then needs to surface the implemented browser-login gate,
connection edit/disconnect, model refresh/search and unavailable selections,
five Agent pages with real discovery/ownership status, and preview/apply/verify.
English and Simplified Chinese plus system/light/dark theme remain the neutral
upstream locales. Provisioning-only account or catalog pages must stay hidden
when those records are absent.

Packaging, OAuth client IDs, account/billing schemas, brand assets, product
URLs, signing, update feeds, and release infrastructure remain downstream.

## License

Apache-2.0. See [LICENSE](LICENSE).
