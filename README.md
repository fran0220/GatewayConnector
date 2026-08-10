# GatewayConnector

GatewayConnector is the neutral open-source upstream for desktop Gateway
connection and Agent projection. Branded distributions inject their own
identity, assets, platform manifest, OAuth/account integration, packaging, and
release process; none of those concerns belong in this repository.

Phase 1 intentionally implements one complete, useful path: enter an HTTPS
Gateway base URL and API key, test the connection with authenticated
`GET <base>/v1/models`, select a protocol and model for each of five supported
Agents, and preview the intended neutral projection. It does **not** write Agent
configuration yet.

## Architecture

```text
gateway-connector-core
  Canonical URL + persisted profile model
  Five Agent IDs and per-Agent protocol/model selections
  Secret-free projection/coordinator interfaces

gateway-connector-backend
  Exact-origin HTTP and OpenAI-compatible model discovery
  Optional /.well-known/gateway-connector or explicit-manifest fetch seam
  OS credential-store abstraction + in-memory test vault
  JSON profile store containing credential references, never API keys

gateway-connector-app
  Pure application state
  Optional GPUI/gpui-kit binary with first-run, discovery, Agent selection,
  connected summary, and preview flow
```

The projection contract deliberately retains the proven five adapters—Claude
Code, Codex CLI, Gemini CLI, Grok Build, and OpenCode—and a secret-free shared
coordinator lease. A future implementation must use plan → preview → apply →
verify → disconnect, preserve unrelated configuration, reject symlink/ownership
collisions, and coordinate singleton Agent files across distributions.

## Security boundary

- Profiles persist a stable UUID, canonical URL, display name, per-Agent
  choices, and an opaque credential reference. They never contain a plaintext
  API key.
- API keys are stored through `CredentialStore`; the desktop binary uses the OS
  credential store and tests use `InMemoryCredentialStore`. On restart, the
  single phase-1 profile is resumed with the same ID and vault reference.
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
  only the OpenAI-compatible `/v1/models` endpoint. The phase-1 seam preserves
  the manifest as versioned JSON rather than inventing platform capability
  fields prematurely.
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
2. **Connect / Test** canonicalizes the URL and requests `<base>/v1/models`.
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

## Phase 2 extraction

The next coherent change is the shared projection implementation behind
`ProjectionBackend`: side-effect-free Agent discovery; native-format merges;
secret-free coordinator locking and leases; immutable file snapshots; encrypted
ownership receipts using established cryptographic libraries; preview/apply
credential binding; rollback, verification, and ownership-aware disconnect.
After that, versioned manifest interpretation can add browser PKCE,
provisioning, advertised MCP, and verified Skill synchronization. Each remains
optional for a generic `/v1/models` Gateway.

Packaging, OAuth client IDs, account/billing schemas, brand assets, product
URLs, signing, update feeds, and release infrastructure remain downstream.

## License

Apache-2.0. See [LICENSE](LICENSE).
