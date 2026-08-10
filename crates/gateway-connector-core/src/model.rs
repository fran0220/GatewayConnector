use crate::{AgentId, Error, Result};
use serde::Deserialize;
use std::{collections::BTreeSet, fmt};
use url::Url;

pub const SCHEMA_VERSION: u32 = 2;
pub const MAX_SKILL_ARCHIVE_SIZE: u64 = 64 * 1024 * 1024;
pub const MAX_CATALOG_ENTRIES: usize = 256;
pub const MAX_MODEL_CATALOG_ENTRIES: usize = 4096;
pub const MAX_MCP_DESCRIPTION_BYTES: usize = 1024;
pub const MAX_MODEL_TAGS: usize = 64;
pub const MAX_MODEL_TEXT_BYTES: usize = 4096;

#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);
impl Secret {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(Error::Validation("invalid bearer".into()));
        }
        Ok(Self(value))
    }
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Platform {
    pub id: String,
    pub name: String,
}
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    BrowserPkce,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Authentication {
    #[serde(rename = "type")]
    pub kind: AuthType,
    pub authorize_url: Url,
    pub token_url: Url,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Gateway {
    pub base_url: Url,
    pub protocols: Vec<String>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionManifest {
    pub schema_version: u32,
    pub platform: Platform,
    #[serde(default)]
    pub authentication: Option<Authentication>,
    pub gateway: Gateway,
    pub provisioning_url: Url,
    pub connection_bearer_origins: Vec<Url>,
    pub supported_agents: Vec<AgentId>,
}

#[derive(Deserialize)]
struct ResponseEnvelope<T> {
    success: bool,
    data: T,
}
impl ConnectionManifest {
    /// Builds a validated direct-mode contract without browser authentication,
    /// MCP servers, Skills, or inferred network endpoints.
    pub fn direct(
        platform: Platform,
        gateway: Gateway,
        provisioning_url: Url,
        supported_agents: Vec<AgentId>,
    ) -> Result<Self> {
        let origin = Url::parse(&gateway.base_url.origin().ascii_serialization())
            .map_err(|error| Error::Validation(error.to_string()))?;
        let manifest = Self {
            schema_version: SCHEMA_VERSION,
            platform,
            authentication: None,
            gateway,
            provisioning_url,
            connection_bearer_origins: vec![origin],
            supported_agents,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let envelope: ResponseEnvelope<Self> =
            serde_json::from_slice(bytes).map_err(|e| Error::Validation(e.to_string()))?;
        if !envelope.success {
            return Err(Error::Validation("unsuccessful envelope".into()));
        }
        let value = envelope.data;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        schema(self.schema_version)?;
        path_id(&self.platform.id, "platform id")?;
        if let Some(authentication) = &self.authentication {
            secure(&authentication.authorize_url)?;
            secure(&authentication.token_url)?;
        }
        secure(&self.gateway.base_url)?;
        secure(&self.provisioning_url)?;
        if self.connection_bearer_origins.is_empty() {
            return Err(Error::Validation(
                "connection_bearer_origins is empty".into(),
            ));
        }
        let mut bearer_origins = BTreeSet::new();
        for url in &self.connection_bearer_origins {
            secure(url)?;
            if url.cannot_be_a_base()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(Error::Validation(format!(
                    "connection bearer allowlist entry is not an origin: {url}"
                )));
            }
            if !bearer_origins.insert(url.origin().ascii_serialization()) {
                return Err(Error::Validation(format!(
                    "duplicate connection bearer origin {}",
                    url.origin().ascii_serialization()
                )));
            }
        }
        if !bearer_origins.contains(&self.gateway.base_url.origin().ascii_serialization()) {
            return Err(Error::Validation(
                "gateway origin is not allowed for connection bearer".into(),
            ));
        }
        if !bearer_origins.contains(&self.provisioning_url.origin().ascii_serialization()) {
            return Err(Error::Validation(
                "provisioning origin is not allowed for connection bearer".into(),
            ));
        }
        if self.supported_agents.is_empty() {
            return Err(Error::Validation("supported_agents is empty".into()));
        }
        unique(
            self.supported_agents.iter().map(|a| a.as_str()),
            "supported agent",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Model {
    pub id: String,
    #[serde(default)]
    pub chat_capable: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub vendor: Option<ModelVendor>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct ModelVendor {
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub icon: Option<String>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub group: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Usage {
    pub wallet_quota_remaining: i64,
    pub lifetime_quota_used: i64,
    pub lifetime_request_count: i64,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Subscription {
    pub id: i64,
    pub plan_id: i64,
    pub status: String,
    pub unlimited: bool,
    pub quota_total: i64,
    pub quota_used_current_period: i64,
    pub current_period_start: i64,
    pub end_time: i64,
    pub next_reset_time: i64,
    pub wallet_fallback: bool,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Billing {
    pub portal_url: Url,
    pub wallet_fallback_allowed: bool,
    pub subscriptions: Vec<Subscription>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct ModelPlaza {
    pub portal_url: Url,
    #[serde(default)]
    pub models: Vec<Model>,
}
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpAuthorization {
    ConnectionBearer,
}
#[derive(Debug, Clone, Deserialize)]
pub struct McpServer {
    pub id: String,
    pub name: String,
    pub url: Url,
    pub authorization: McpAuthorization,
    #[serde(default)]
    pub description: Option<String>,
}
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillArchiveAuthorization {
    None,
    ConnectionBearer,
}
#[derive(Debug, Clone, Deserialize)]
pub struct SkillArchive {
    pub url: Url,
    pub sha256: String,
    pub size_bytes: u64,
    pub format: String,
    pub authorization: SkillArchiveAuthorization,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Skill {
    pub id: String,
    pub name: String,
    pub version: String,
    pub archive: SkillArchive,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Provisioning {
    pub schema_version: u32,
    #[serde(default)]
    pub account: Option<Account>,
    #[serde(default)]
    pub usage: Option<Usage>,
    #[serde(default)]
    pub billing: Option<Billing>,
    #[serde(default)]
    pub model_plaza: Option<ModelPlaza>,
    pub models: Vec<Model>,
    pub default_model: String,
    pub mcp_servers: Vec<McpServer>,
    pub skills: Vec<Skill>,
}
impl Provisioning {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let envelope: ResponseEnvelope<Self> =
            serde_json::from_slice(bytes).map_err(|e| Error::Validation(e.to_string()))?;
        if !envelope.success {
            return Err(Error::Validation("unsuccessful envelope".into()));
        }
        let value = envelope.data;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        schema(self.schema_version)?;
        if let Some(account) = &self.account {
            validate_account(account)?;
        }
        if self.usage.as_ref().is_some_and(|usage| {
            usage.wallet_quota_remaining < 0
                || usage.lifetime_quota_used < 0
                || usage.lifetime_request_count < 0
        }) {
            return Err(Error::Validation("invalid account usage".into()));
        }
        if let Some(billing) = &self.billing {
            secure(&billing.portal_url)?;
        }
        if let Some(model_plaza) = &self.model_plaza {
            secure(&model_plaza.portal_url)?;
            if model_plaza.models.len() > MAX_MODEL_CATALOG_ENTRIES {
                return Err(Error::Validation(format!(
                    "Model Plaza catalog exceeds {MAX_MODEL_CATALOG_ENTRIES} entries"
                )));
            }
        }
        if self
            .billing
            .as_ref()
            .is_some_and(|billing| billing.subscriptions.len() > MAX_CATALOG_ENTRIES)
        {
            return Err(Error::Validation(format!(
                "subscription catalog exceeds {MAX_CATALOG_ENTRIES} entries"
            )));
        }
        if let Some(billing) = &self.billing {
            for subscription in &billing.subscriptions {
                bounded_text(&subscription.status, "subscription status", 128, false)?;
                if subscription.id <= 0
                    || subscription.plan_id <= 0
                    || subscription.quota_total < 0
                    || subscription.quota_used_current_period < 0
                    || subscription.current_period_start < 0
                    || subscription.end_time < 0
                    || subscription.next_reset_time < 0
                    || subscription.unlimited != (subscription.quota_total == 0)
                    || (!subscription.unlimited
                        && subscription.quota_used_current_period > subscription.quota_total)
                {
                    return Err(Error::Validation("invalid subscription usage".into()));
                }
            }
        }
        if self.models.len() > MAX_MODEL_CATALOG_ENTRIES {
            return Err(Error::Validation(format!(
                "model catalog exceeds {MAX_MODEL_CATALOG_ENTRIES} entries"
            )));
        }
        if self.mcp_servers.len() > MAX_CATALOG_ENTRIES {
            return Err(Error::Validation(format!(
                "MCP catalog exceeds {MAX_CATALOG_ENTRIES} entries"
            )));
        }
        if self.skills.len() > MAX_CATALOG_ENTRIES {
            return Err(Error::Validation(format!(
                "Skill catalog exceeds {MAX_CATALOG_ENTRIES} entries"
            )));
        }
        let ids = validate_models(&self.models, true)?;
        if let Some(model_plaza) = &self.model_plaza {
            let plaza_ids = validate_models(&model_plaza.models, false)?;
            for model in &self.models {
                if !plaza_ids.contains(model.id.as_str())
                    || !model_plaza
                        .models
                        .iter()
                        .any(|plaza| plaza.id == model.id && plaza.chat_capable)
                {
                    return Err(Error::Validation(
                        "Agent model is missing from the chat-capable Model Plaza catalog".into(),
                    ));
                }
            }
        }
        if ids.is_empty() && !self.default_model.is_empty() {
            return Err(Error::Validation(
                "catalog without a chat-capable model requires empty default_model".into(),
            ));
        }
        if !ids.is_empty() && !ids.contains(self.default_model.as_str()) {
            return Err(Error::Validation(
                "default_model is not a chat-capable catalog model".into(),
            ));
        }
        let mut mcp_ids = BTreeSet::new();
        for m in &self.mcp_servers {
            id(&m.id, "MCP id")?;
            name(&m.name, "MCP name")?;
            if m.description.as_ref().is_some_and(|description| {
                description.len() > MAX_MCP_DESCRIPTION_BYTES
                    || description.chars().any(char::is_control)
            }) {
                return Err(Error::Validation("invalid MCP description".into()));
            }
            if m.url.scheme() != "https" {
                return Err(Error::Validation("MCP URL must use HTTPS".into()));
            }
            if !mcp_ids.insert(&m.id) {
                return Err(Error::Validation(format!("duplicate MCP id {}", m.id)));
            }
        }
        let mut skill_ids = BTreeSet::new();
        for s in &self.skills {
            path_id(&s.id, "skill id")?;
            name(&s.name, "skill name")?;
            version(&s.version)?;
            secure(&s.archive.url)?;
            if s.archive.sha256.len() != 64
                || !s
                    .archive
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Error::Validation("invalid Skill SHA-256".into()));
            }
            if s.archive.size_bytes == 0 || s.archive.size_bytes > MAX_SKILL_ARCHIVE_SIZE {
                return Err(Error::Validation("invalid Skill archive size".into()));
            }
            if s.archive.format != "zip" {
                return Err(Error::Validation("Skill archive format must be zip".into()));
            }
            if !skill_ids.insert(&s.id) {
                return Err(Error::Validation(format!("duplicate skill id {}", s.id)));
            }
        }
        Ok(())
    }

    pub fn validate_for(&self, manifest: &ConnectionManifest) -> Result<()> {
        self.validate()?;
        let allowed: BTreeSet<String> = manifest
            .connection_bearer_origins
            .iter()
            .map(|url| url.origin().ascii_serialization())
            .collect();
        for server in &self.mcp_servers {
            if !allowed.contains(&server.url.origin().ascii_serialization()) {
                return Err(Error::Validation(format!(
                    "authenticated MCP origin is not allowed: {}",
                    server.url.origin().ascii_serialization()
                )));
            }
        }
        for skill in &self.skills {
            if skill.archive.authorization == SkillArchiveAuthorization::ConnectionBearer
                && !allowed.contains(&skill.archive.url.origin().ascii_serialization())
            {
                return Err(Error::Validation(
                    "authenticated Skill archive origin is not allowed".into(),
                ));
            }
        }
        Ok(())
    }
}
fn validate_models(models: &[Model], require_chat: bool) -> Result<BTreeSet<&str>> {
    let mut ids = BTreeSet::new();
    for model in models {
        model_id(&model.id)?;
        if require_chat && !model.chat_capable {
            return Err(Error::Validation(format!(
                "Agent model {} is not chat-capable",
                model.id
            )));
        }
        if model.description.as_ref().is_some_and(|value| {
            value.len() > MAX_MODEL_TEXT_BYTES || value.chars().any(char::is_control)
        }) {
            return Err(Error::Validation("invalid model description".into()));
        }
        if let Some(icon) = &model.icon {
            bounded_text(icon, "model icon", MAX_MODEL_TEXT_BYTES, false)?;
        }
        if model.tags.len() > MAX_MODEL_TAGS {
            return Err(Error::Validation("model has too many tags".into()));
        }
        for tag in &model.tags {
            bounded_text(tag, "model tag", 128, false)?;
        }
        unique(model.tags.iter().map(String::as_str), "model tag")?;
        if let Some(vendor) = &model.vendor {
            if vendor.id <= 0 {
                return Err(Error::Validation("invalid model vendor id".into()));
            }
            name(&vendor.name, "model vendor name")?;
            if let Some(icon) = &vendor.icon {
                bounded_text(icon, "model vendor icon", MAX_MODEL_TEXT_BYTES, false)?;
            }
        }
        if !ids.insert(model.id.as_str()) {
            return Err(Error::Validation(format!(
                "duplicate model id {}",
                model.id
            )));
        }
    }
    Ok(ids)
}
fn validate_account(account: &Account) -> Result<()> {
    bounded_text(&account.username, "account username", 256, false)?;
    bounded_text(&account.display_name, "account display name", 256, true)?;
    bounded_text(&account.email, "account email", 320, true)?;
    bounded_text(&account.group, "account group", 128, true)
}
fn bounded_text(value: &str, label: &str, max: usize, empty: bool) -> Result<()> {
    if value.len() <= max
        && (empty || !value.trim().is_empty())
        && !value.chars().any(char::is_control)
    {
        Ok(())
    } else {
        Err(Error::Validation(format!("invalid {label}")))
    }
}
fn unique<'a>(values: impl Iterator<Item = &'a str>, label: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(Error::Validation(format!("duplicate {label} {value}")));
        }
    }
    Ok(())
}
fn schema(v: u32) -> Result<()> {
    if v == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(Error::Validation(format!("unsupported schema version {v}")))
    }
}
fn id(v: &str, label: &str) -> Result<()> {
    if !v.trim().is_empty()
        && v.len() <= 128
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        Ok(())
    } else {
        Err(Error::Validation(format!("invalid {label}")))
    }
}
fn path_id(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let endpoint = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let portable = !bytes.is_empty()
        && bytes.len() <= 64
        && endpoint(bytes[0])
        && endpoint(bytes[bytes.len() - 1])
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && !windows_reserved_component(value);
    if portable {
        Ok(())
    } else {
        Err(Error::Validation(format!("invalid {label}")))
    }
}
fn windows_reserved_component(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
}
fn name(value: &str, label: &str) -> Result<()> {
    if !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(Error::Validation(format!("invalid {label}")))
    }
}
fn version(value: &str) -> Result<()> {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
        && value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && value
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        Ok(())
    } else {
        Err(Error::Validation("invalid skill version".into()))
    }
}
fn model_id(value: &str) -> Result<()> {
    // Model IDs are opaque Gateway catalog values, not local path or table
    // keys. Providers commonly use names such as `openai/gpt-5` and
    // `publisher:model`; reject only values that cannot be projected safely.
    if !value.trim().is_empty() && value.len() <= 255 && !value.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(Error::Validation("invalid model id".into()))
    }
}
fn secure(url: &Url) -> Result<()> {
    let secure_transport = url.scheme() == "https"
        || (url.scheme() == "http"
            && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1")));
    if secure_transport
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
    {
        Ok(())
    } else {
        Err(Error::Validation(format!("insecure endpoint {url}")))
    }
}
