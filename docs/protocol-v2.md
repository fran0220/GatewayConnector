# GatewayConnector protocol v2

GatewayConnector has two deliberately separate connection modes. A generic
Gateway needs only the direct contract. The enhanced contract is optional and
advertises capabilities rather than changing the direct security boundary.

## Direct OpenAI-compatible mode

The client takes a user-supplied Gateway URL, canonicalizes it, and sends:

```http
GET <resolved-model-endpoint>
Accept: application/json
Authorization: Bearer <api-key>
```

The deterministic endpoint mapping is documented in the project README. The
response is the normal OpenAI list shape:

```json
{
  "data": [
    {
      "id": "model-id",
      "owned_by": "optional-provider",
      "created": 1700000000,
      "object": "model"
    }
  ]
}
```

`id` is required. Unknown per-model fields are retained as metadata. The client
trims IDs, merges duplicate IDs without discarding useful optional metadata,
and sorts by ID. `auto` means this conservative OpenAI-compatible discovery;
it does not scan speculative endpoints.

## Manifest discovery

Unless a distribution injects an explicit URL, the only manifest probe is an
unauthenticated exact-origin request to:

```text
<configured-origin>/.well-known/gateway-connector
```

A well-known `404` selects direct mode. Other errors are reported. An explicit
manifest is required: its `404` is an error. Manifest redirects are bounded to
the configured origin. The request never contains the connection bearer.

The response envelope and schema-v2 document are:

```json
{
  "success": true,
  "data": {
    "schema_version": 2,
    "platform": {
      "id": "portable-platform-id",
      "name": "Platform display name"
    },
    "authentication": {
      "type": "browser_pkce",
      "authorize_url": "https://platform.example/authorize",
      "token_url": "https://platform.example/token"
    },
    "gateway": {
      "base_url": "https://gateway.example/v1",
      "protocols": ["openai_chat", "openai_responses"]
    },
    "provisioning_url": "https://platform.example/api/connector/provisioning",
    "connection_bearer_origins": [
      "https://gateway.example/",
      "https://platform.example/"
    ],
    "supported_agents": [
      "claude",
      "codex",
      "gemini",
      "grokbuild",
      "opencode"
    ]
  }
}
```

`authentication` is optional. URLs must use HTTPS, except literal loopback HTTP
for development. Each `connection_bearer_origins` entry must be an origin—no
path, query, fragment, or userinfo—and must include both the Gateway and
provisioning origins. Supported protocol IDs are `auto`, `openai_chat`,
`openai_responses`, `anthropic`, and `gemini`.

## Browser PKCE

When `authentication.type` is `browser_pkce`, the client opens the advertised
authorization URL with these query parameters:

- `client`: the compile-time distribution client ID
- `device_name`: the compile-time distribution display value
- `redirect_uri`: an ephemeral `http://127.0.0.1:<port>/callback`
- `code_challenge`: base64url SHA-256 challenge
- `code_challenge_method=S256`
- `state`: a random anti-forgery value

This is a native desktop authentication flow, not a browser/WebAssembly
GatewayConnector target. The neutral project currently ships desktop release
contracts only for macOS and Windows.

The callback must return the same `state` and either `code` or `error`. The
client posts JSON to `token_url`:

```json
{
  "code": "authorization-code",
  "code_verifier": "pkce-verifier",
  "redirect_uri": "http://127.0.0.1:49152/callback"
}
```

The token endpoint must not redirect and must return a Bearer
`access_token`. GatewayConnector stores only that access token in the OS vault;
it does not persist refresh tokens or account payloads.

## Provisioning

Provisioning is an authenticated exact-origin `GET` to the manifest's
`provisioning_url`. The response uses the same `{ "success": true, "data": … }`
envelope:

```json
{
  "success": true,
  "data": {
    "schema_version": 2,
    "models": [
      {
        "id": "chat-model",
        "chat_capable": true,
        "description": "Optional description",
        "tags": ["reasoning"],
        "vendor": { "id": 1, "name": "Provider" }
      }
    ],
    "default_model": "chat-model",
    "mcp_servers": [
      {
        "id": "docs",
        "name": "Documentation",
        "url": "https://services.example/mcp/docs",
        "authorization": "connection_bearer"
      }
    ],
    "skills": [
      {
        "id": "review",
        "name": "Review",
        "version": "1.0.0",
        "archive": {
          "url": "https://downloads.example/review.zip",
          "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "size_bytes": 1234,
          "format": "zip",
          "authorization": "none"
        }
      }
    ]
  }
}
```

The top-level `models` array is the complete Agent-selectable catalog and every
entry must be chat-capable. `default_model` must be empty only when that array
is empty; otherwise it must name an entry. Optional `model_plaza.models` can
contain non-chat models and is display-only—it never enters Agent selectors.

Optional `account`, `usage`, `billing`, and `model_plaza` records control
whether their UI pages exist. Their absence is not replaced by zeros or fake
metrics. `mcp_servers` and `skills` are likewise online provisioning records;
direct mode has no inferred catalog.

Authenticated MCP and Skill origins must be present in
`connection_bearer_origins`. Skill archives declare exact lowercase SHA-256,
exact compressed size, ZIP format, and either `none` or `connection_bearer`
authorization. Catalog and extraction limits are enforced by the client before
transactional publication.

## Redirect and bearer rule

Every request carrying the API key or access token is evaluated before each
send. Its scheme, host, and effective port must equal an allowed origin.
Redirects are processed manually, are bounded, and are rejected before any
cross-origin target is contacted. There is no local relay or session-token
exchange.
