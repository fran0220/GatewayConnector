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

The enhanced wire contract is documented in
[`docs/protocol-v2.md`](docs/protocol-v2.md).

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
  Transactional, integrity-checked online Skill synchronization
  OS credential-store abstraction + in-memory test vault
  Thin compile-time Distribution boundary for neutral/downstream identity

gateway-connector-app
  Pure application state
  Optional GPUI/gpui-kit binary with first-run, discovery, Agent selection,
  conditional connected shell, and real preview/apply/verify/disconnect flow
  Credential-free locale/theme preferences replaced atomically
  Generic-only one-root portable acceptance mode
```

The projection engine retains the proven five adapters—Claude Code, Codex CLI,
Gemini CLI, Grok Build, and OpenCode. It uses plan → preview → apply → verify →
disconnect, preserves unrelated JSON/JSONC/TOML/env configuration, rejects
symlink and ownership collisions, requires a fresh preview before apply, and
coordinates singleton Agent files across distributions through the shared
`ProjectDirs("dev", "GatewayConnector", "ProjectionCoordinator")` contract.
JSON/JSONC changes are surgical: unrelated comments and formatting survive
apply and disconnect, while duplicate keys or unsupported ambiguous syntax
fail closed without rewriting the file.

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
- Direct `/v1/models` records use a three-state chat capability: positive,
  negative, or unknown. GatewayConnector never infers chat capability merely
  because a record appears in the catalog and never auto-selects an unknown
  model. Explicitly non-chat records are excluded; an unknown record requires
  an explicit picker choice whose confirmation is persisted on that profile.
- Manifest discovery is optional and unauthenticated. Generic gateways need
  only the OpenAI-compatible `/v1/models` endpoint. Well-known 404 is direct
  mode; an injected explicit manifest is required and does not silently fall
  back on 404. Provisioning receives a bearer only when its exact origin is in
  the manifest allowlist, and its top-level chat model catalog—not Model
  Plaza—is the Agent selector source.
- Browser authentication is standard S256 PKCE over a loopback callback. The
  authorization code exchange does not follow redirects and accepts only a
  Bearer `access_token` response.
- Provisioned Skills are downloaded only from validated schema-v2 records.
  Authenticated archives require an exact allowlisted origin; redirects are
  bounded and cannot cross origins. Exact declared size and lowercase SHA-256
  are required before ZIP extraction. Traversal, symlink/special entries,
  duplicate or non-portable paths, overlapping data, and expansion beyond the
  single catalog-wide 256-entry/256-MiB budget are rejected before
  transactional publication. The same checked budget is decremented during
  extraction rather than reset per archive. Direct mode downloads and
  projects no MCP or Skills.
- Official downstream builds can disable custom Gateway URLs and pin both the
  platform identity and manifest endpoint through `Distribution`; generic
  builds remain user-configurable. Neutral defaults contain no branded URLs,
  OAuth IDs, assets, account assumptions, or updater metadata.
- The generic executable alone enables `--isolated-root <absolute-path>` for
  portable acceptance. Argument and root validation finish before any normal
  `ProjectDirs`, shared coordinator, profile/preference store, home directory,
  or default Agent discovery is constructed. A new/empty root receives a
  durable schema-1 marker bound to its canonical path and physical directory
  identity; non-empty unmarked, malformed, symlinked, junction, reparse, and
  special-component roots fail closed. All mutable connector state and fixed
  Claude/Codex/Gemini/Grok Build/OpenCode fixture roots are derived beneath
  that one root. Credentials still use the native OS vault, under a stable
  root-specific service and the existing profile-specific account, so
  disconnect removes only that isolated profile credential. Isolated mode is
  portable acceptance isolation against accidental real-state access, not a
  security sandbox against another same-user process. Normal no-argument
  startup retains the shared neutral ProjectionCoordinator and installed-Agent
  discovery unchanged.
- Profile creation is singleton and guarded by both an in-process connection
  lock and an inter-process profile-file lock. Profile writes use private
  unique `create_new` temporary files, no-follow/reparse checks, durable file
  flushes, parent-directory sync on Unix, and write-through replacement on
  Windows.
- Projection apply and disconnect share one coordinator-global lock and a
  `Clean → Prepared → Committed → Clean` write-ahead journal. Before the first
  Agent, Skill, ownership, or receipt mutation, GatewayConnector encrypts and
  authenticates prior/intended snapshot descriptors plus parent transitions,
  flushes a bundle that embeds a duplicate authenticated transaction header,
  and durably publishes the same header as the active pointer. The embedded
  copy makes a missing active pointer recoverable rather than grounds for
  deleting an orphan bundle; missing/tampered manifests, wrong credentials,
  and mismatched platforms preserve all artifacts and fail closed. Complete
  Skill trees are built and flushed in sibling staging directories; existing
  destinations are retained under authenticated displaced names until every
  destination—including coordinator and receipt—has been installed. Only
  then is the commit marker flushed. Startup, preview, apply, status, and
  disconnect recover Prepared transactions by renaming exact prior snapshots
  back and recover Committed transactions by verifying intent before cleanup.
  Subprocess-abort tests exercise every parent, stage, displacement,
  installation, commit, and cleanup boundary for both apply and disconnect.
- Every projection path is checked at planning, under the shared lock, and
  immediately around mutation. Canonical containment, stable parent file IDs,
  component metadata, no-follow file opens, and Windows reparse checks reject
  lexical aliases, symlinks, junctions, and parent replacement. Directory
  operations remain path-based, so the security model assumes no hostile
  same-user process wins the final sub-operation race between a successful
  component check and the matching filesystem call. Such races fail closed
  when observed; moving every directory operation to platform-specific
  descriptor-relative APIs is future hardening rather than a wire/schema
  change.
- Unix persists rename/remove ordering by syncing parent directories. Windows
  flushes created files and uses `MOVEFILE_WRITE_THROUGH`; Windows does not
  expose a documented POSIX-equivalent parent-directory fsync through these
  APIs, so recovery tolerates either side of a rename becoming visible after
  power loss.
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

For portable development or acceptance without touching normal connector state
or installed Agent roots, pass one new or empty absolute directory:

```bash
cargo run -p gateway-connector-app --features gpui-app --bin gateway-connector -- \
  --isolated-root /absolute/path/to/gateway-connector-acceptance
```

The window displays a persistent **Isolated mode** banner and canonical path.
Its managed fixtures are fixed at
`agents/{claude,codex,gemini,grokbuild,opencode}` under that root. Do not point
this option at an existing non-empty directory; only a root carrying its valid
GatewayConnector marker can be reopened.

```text
<isolated-root>/
  .gateway-connector-isolated-root.json  Versioned path/directory marker
  data/                                  Profile and UI preferences
  state/                                 Catalog, staging/recovery, receipts, journals
  coordinator/                           Isolated coordinator locks and leases
  agents/{claude,codex,gemini,grokbuild,opencode}/
```

The marker and all directory components are revalidated before lifecycle
actions. The catalog and projection layers retain their own no-follow/reparse
guards immediately around staging, recovery, and mutation.

## Demonstrated phase-1 flow

1. Enter a Gateway base URL, API key, and initial protocol.
2. **Connect / Test** canonicalizes the URL and resolves its model endpoint as
   shown above, without changing the configured origin.
   If the exact-origin manifest advertises browser PKCE, the app instead shows
   an explicit browser-login gate; the API-key field may be left blank for
   that flow.
3. A successful OpenAI-style `{ "data": [...] }` response is normalized,
   deduplicated, sorted, and shown in one model picker per Agent.
4. The authenticated shell shows the canonical Gateway and discovered model
   count. The catalog can be refreshed and filtered by model ID/provider; a
   saved choice missing from a refreshed catalog remains visibly unavailable.
   “Use for all Agents” sets a shared protocol/model before per-Agent
   overrides. Changes are serialized through an ordered save queue and
   persisted without the credential; save failures stay visible.
5. Five distinct Agent pages show each canonical root, detection state,
   ownership, protocol, and model. **Preview changes** builds a fresh read-only
   plan and lists every managed path without changing Agent files. Apply stays
   disabled with an explicit reason until a current preview exists.
6. **Apply** rechecks the vault credential and every previewed file/receipt
   snapshot, performs the transaction, and verifies the result. **Verify** can
   be rerun to report later drift. **Disconnect** removes owned configuration
   before deleting the only credential that can open the ownership receipt.
7. Provisioned MCP/Skills and account, usage, billing, and Model Plaza pages
   appear only when the schema-v2 response supplies their source records.
   Direct connections have none of these pages and invent no service data.
   The full Model Plaza catalog is searchable but is never used for Agent
   selectors.
8. Settings persist English/Simplified Chinese and system/light/dark appearance
   outside profile JSON. A later launch reloads the profile, retrieves the key
   from the OS vault, and refreshes `/v1/models` while preserving the stable
   profile ID and valid Agent selections.

## Next extraction steps

CI runs the Linux behavior gate and Windows/macOS GPUI compile checks. Native
Windows CI also builds and inspects the unsigned manual release package,
including its GUI subsystem, embedded neutral icon/version resources, and ZIP
contents. Build the same artifact locally on Windows with:

```powershell
./packaging/windows/stage-release.ps1
./packaging/windows/test-release-assertions.ps1
```

The output is `dist/GatewayConnector-<version>-windows-x64.zip`, containing
only `gateway-connector.exe`, `LICENSE`, and `release-metadata.json`. It is not
signed and has no updater or latest-release feed. `release-metadata.json` is
the neutral packaging contract and is checked against the Cargo workspace
version during both compilation and staging. The original icon source and its
license notice live in `packaging/windows/`; builds use the tracked `.ico`
without downloading or generating assets.

macOS remains compile-checked only; this repository does not currently claim a
macOS package, signature, or notarization. The compile-time wrapper boundary
and exact-revision migration are documented in
[`docs/distribution.md`](docs/distribution.md) and
[`docs/downstream-migration.md`](docs/downstream-migration.md). Native Windows
visual acceptance remains required before calling the desktop client complete.

Run native Windows acceptance against the exact staged production executable,
not `cargo run`, so the GUI-subsystem and embedded-resource artifact is tested:

```powershell
$acceptanceRoot = Join-Path $env:TEMP 'GatewayConnector-Acceptance'
# Use a new/empty path, or the same previously marked GatewayConnector root.
& .\dist\windows-x64\gateway-connector.exe --isolated-root $acceptanceRoot
```

The banner must show the canonical `$acceptanceRoot`. Connection, model
discovery, preview, apply, verify, resume, and disconnect then operate only on
the five fixture Agent roots beneath it. The OS credential vault deliberately
remains native so credential persistence and cleanup receive real acceptance
coverage.

Branded packaging, OAuth client IDs, account/billing schemas, brand assets,
product URLs, signing, update feeds, and automated release infrastructure
remain downstream.

## License

Apache-2.0. See [LICENSE](LICENSE).
