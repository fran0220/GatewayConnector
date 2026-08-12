use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use url::{Host, Url};
use uuid::Uuid;

/// The five Agent adapters supported by the shared projection contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentId {
    Claude,
    Codex,
    Gemini,
    Grokbuild,
    Opencode,
}

impl AgentId {
    pub const ALL: [Self; 5] = [
        Self::Claude,
        Self::Codex,
        Self::Gemini,
        Self::Grokbuild,
        Self::Opencode,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
            Self::Grokbuild => "grokbuild",
            Self::Opencode => "opencode",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::Codex => "Codex CLI",
            Self::Gemini => "Gemini CLI",
            Self::Grokbuild => "Grok Build",
            Self::Opencode => "OpenCode",
        }
    }

    /// Persisted choices that this Agent can actually consume. `Auto` records
    /// user intent; projection resolves it to one concrete wire protocol.
    pub const fn supported_protocols(self) -> &'static [Protocol] {
        match self {
            Self::Claude => &[Protocol::Auto, Protocol::Anthropic],
            Self::Codex => &[Protocol::Auto, Protocol::OpenaiResponses],
            Self::Gemini => &[Protocol::Auto, Protocol::Gemini],
            Self::Grokbuild => &[
                Protocol::Auto,
                Protocol::OpenaiChat,
                Protocol::OpenaiResponses,
                Protocol::Anthropic,
            ],
            Self::Opencode => &Protocol::ALL,
        }
    }

    pub const fn supported_wire_protocols(self) -> &'static [WireProtocol] {
        match self {
            Self::Claude => &[WireProtocol::Anthropic],
            Self::Codex => &[WireProtocol::OpenaiResponses],
            Self::Gemini => &[WireProtocol::Gemini],
            Self::Grokbuild => &[
                WireProtocol::OpenaiChat,
                WireProtocol::OpenaiResponses,
                WireProtocol::Anthropic,
            ],
            Self::Opencode => &WireProtocol::ALL,
        }
    }

    /// Stable preference order for `Auto`. Gateway manifest ordering never
    /// changes the selected wire protocol.
    pub const fn auto_protocols(self) -> &'static [WireProtocol] {
        self.supported_wire_protocols()
    }

    pub fn resolve_protocol(
        self,
        selection: Protocol,
        advertised: Option<&BTreeSet<WireProtocol>>,
    ) -> Result<WireProtocol, ProfileError> {
        if selection == Protocol::Auto {
            return self
                .auto_protocols()
                .iter()
                .copied()
                .find(|protocol| advertised.is_none_or(|values| values.contains(protocol)))
                .ok_or(ProfileError::NoCompatibleProtocol(self));
        }
        let protocol = selection
            .wire_protocol()
            .expect("a non-Auto protocol has a concrete representation");
        if !self.supported_wire_protocols().contains(&protocol) {
            return Err(ProfileError::UnsupportedAgentProtocol {
                agent: self,
                protocol,
            });
        }
        if advertised.is_some_and(|values| !values.contains(&protocol)) {
            return Err(ProfileError::ProtocolNotAdvertised {
                agent: self,
                protocol,
            });
        }
        Ok(protocol)
    }
}

/// Wire protocol selected for an Agent projection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    Auto,
    OpenaiChat,
    OpenaiResponses,
    Anthropic,
    Gemini,
}

impl Protocol {
    pub const ALL: [Self; 5] = [
        Self::Auto,
        Self::OpenaiChat,
        Self::OpenaiResponses,
        Self::Anthropic,
        Self::Gemini,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::OpenaiChat => "openai_chat",
            Self::OpenaiResponses => "openai_responses",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Auto => "Auto (best protocol for this Agent)",
            Self::OpenaiChat => "OpenAI Chat Completions",
            Self::OpenaiResponses => "OpenAI Responses",
            Self::Anthropic => "Anthropic Messages",
            Self::Gemini => "Gemini",
        }
    }

    pub const fn wire_protocol(self) -> Option<WireProtocol> {
        match self {
            Self::Auto => None,
            Self::OpenaiChat => Some(WireProtocol::OpenaiChat),
            Self::OpenaiResponses => Some(WireProtocol::OpenaiResponses),
            Self::Anthropic => Some(WireProtocol::Anthropic),
            Self::Gemini => Some(WireProtocol::Gemini),
        }
    }
}

impl FromStr for Protocol {
    type Err = ProfileError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|protocol| protocol.as_str() == value)
            .ok_or_else(|| ProfileError::UnknownProtocol(value.to_owned()))
    }
}

/// A concrete protocol written to an Agent configuration. Unlike the
/// persisted [`Protocol`], this type cannot represent unresolved `Auto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireProtocol {
    OpenaiChat,
    OpenaiResponses,
    Anthropic,
    Gemini,
}

impl WireProtocol {
    pub const ALL: [Self; 4] = [
        Self::OpenaiChat,
        Self::OpenaiResponses,
        Self::Anthropic,
        Self::Gemini,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenaiChat => "openai_chat",
            Self::OpenaiResponses => "openai_responses",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
        }
    }

    pub const fn protocol(self) -> Protocol {
        match self {
            Self::OpenaiChat => Protocol::OpenaiChat,
            Self::OpenaiResponses => Protocol::OpenaiResponses,
            Self::Anthropic => Protocol::Anthropic,
            Self::Gemini => Protocol::Gemini,
        }
    }
}

impl fmt::Display for WireProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for WireProtocol {
    type Err = ProfileError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|protocol| protocol.as_str() == value)
            .ok_or_else(|| ProfileError::UnknownProtocol(value.to_owned()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSelection {
    pub protocol: Protocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
}

impl AgentSelection {
    pub fn new() -> Self {
        Self {
            protocol: Protocol::Auto,
            default_model: None,
        }
    }
}

impl Default for AgentSelection {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(Uuid);

impl ProfileId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ProfileId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Stable local credential id for a profile (`profile:<uuid>`).
/// Secrets are stored on the profile document itself, not in an OS keychain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CredentialRef(String);

impl CredentialRef {
    pub fn for_profile(profile_id: ProfileId) -> Self {
        Self(format!("profile:{profile_id}"))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ProfileError> {
        let value = value.into();
        if value.is_empty() || value.len() > 200 || value.chars().any(char::is_control) {
            return Err(ProfileError::InvalidCredentialReference);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CredentialRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// Canonical HTTP(S) gateway base. HTTP is accepted only on loopback.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalBaseUrl(Url);

impl CanonicalBaseUrl {
    pub fn parse(input: &str) -> Result<Self, ProfileError> {
        let mut url = Url::parse(input.trim()).map_err(ProfileError::InvalidBaseUrl)?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ProfileError::UnsupportedScheme(url.scheme().to_owned()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ProfileError::UserInfoNotAllowed);
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ProfileError::QueryOrFragmentNotAllowed);
        }
        let host = url.host().ok_or(ProfileError::MissingHost)?;
        if url.scheme() == "http" && !is_loopback(host) {
            return Err(ProfileError::InsecureRemoteUrl);
        }

        let normalized_path = match url.path().trim_end_matches('/') {
            "" => "/".to_owned(),
            path => path.to_owned(),
        };
        url.set_path(&normalized_path);
        Ok(Self(url))
    }

    pub fn as_url(&self) -> &Url {
        &self.0
    }

    pub fn origin(&self) -> url::Origin {
        self.0.origin()
    }

    pub fn endpoint(&self, relative_path: &str) -> Url {
        let mut endpoint = self.0.clone();
        let base = endpoint.path().trim_end_matches('/');
        endpoint.set_path(&format!("{base}/{}", relative_path.trim_start_matches('/')));
        endpoint
    }

    pub fn models_endpoint(&self) -> Url {
        let path = self.0.path();
        if path.ends_with("/v1/models") {
            self.0.clone()
        } else if path.ends_with("/v1") {
            self.endpoint("models")
        } else {
            self.endpoint("v1/models")
        }
    }

    pub fn suggested_display_name(&self) -> String {
        self.0
            .host()
            .map(|host| host.to_string())
            .filter(|host| !host.is_empty() && host.len() <= 128)
            .unwrap_or_else(|| "Gateway".to_owned())
    }
}

impl fmt::Display for CanonicalBaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0.as_str();
        if self.0.path() == "/" {
            write!(formatter, "{}", value.trim_end_matches('/'))
        } else {
            formatter.write_str(value)
        }
    }
}

impl FromStr for CanonicalBaseUrl {
    type Err = ProfileError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for CanonicalBaseUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CanonicalBaseUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedConnectionProfile")]
pub struct ConnectionProfile {
    pub schema_version: u32,
    pub id: ProfileId,
    pub display_name: String,
    pub base_url: CanonicalBaseUrl,
    pub credential: CredentialRef,
    /// API key or access token stored in the app profile config file.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credential_secret: String,
    pub mode: ConnectionMode,
    pub credential_kind: CredentialKind,
    pub platform_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_url: Option<Url>,
    pub agents: BTreeMap<AgentId, AgentSelection>,
    /// Direct-discovery models whose unknown capability the user explicitly accepted.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub confirmed_direct_models: BTreeSet<String>,
}

impl fmt::Debug for ConnectionProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionProfile")
            .field("schema_version", &self.schema_version)
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("base_url", &self.base_url)
            .field("credential", &self.credential)
            .field("credential_secret", &"[REDACTED]")
            .field("mode", &self.mode)
            .field("credential_kind", &self.credential_kind)
            .field("platform_id", &self.platform_id)
            .field("manifest_url", &self.manifest_url)
            .field("agents", &self.agents)
            .field("confirmed_direct_models", &self.confirmed_direct_models)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    #[default]
    Direct,
    Provisioned,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    #[default]
    ApiKey,
    AccessToken,
}

impl ConnectionProfile {
    pub const SCHEMA_VERSION: u32 = 3;

    pub fn new(
        display_name: impl Into<String>,
        base_url: CanonicalBaseUrl,
    ) -> Result<Self, ProfileError> {
        let display_name = display_name.into().trim().to_owned();
        if display_name.is_empty()
            || display_name.len() > 128
            || display_name.chars().any(char::is_control)
        {
            return Err(ProfileError::InvalidDisplayName);
        }
        let id = ProfileId::new();
        let credential = CredentialRef::for_profile(id);
        let agents = AgentId::ALL
            .into_iter()
            .map(|agent| (agent, AgentSelection::new()))
            .collect();
        Ok(Self {
            schema_version: Self::SCHEMA_VERSION,
            id,
            display_name,
            base_url,
            credential,
            credential_secret: String::new(),
            mode: ConnectionMode::Direct,
            credential_kind: CredentialKind::ApiKey,
            platform_id: "gateway-connector".into(),
            manifest_url: None,
            agents,
            confirmed_direct_models: BTreeSet::new(),
        })
    }

    pub fn new_connection(
        display_name: impl Into<String>,
        base_url: CanonicalBaseUrl,
        mode: ConnectionMode,
        credential_kind: CredentialKind,
        platform_id: impl Into<String>,
        manifest_url: Option<Url>,
    ) -> Result<Self, ProfileError> {
        let mut value = Self::new(display_name, base_url)?;
        value.mode = mode;
        value.credential_kind = credential_kind;
        value.platform_id = platform_id.into();
        value.manifest_url = manifest_url;
        value.validate()?;
        Ok(value)
    }

    pub fn reconfigured(
        mut existing: Self,
        display_name: impl Into<String>,
        base_url: CanonicalBaseUrl,
    ) -> Result<Self, ProfileError> {
        let display_name = validated_display_name(display_name.into())?;
        existing.schema_version = Self::SCHEMA_VERSION;
        existing.display_name = display_name;
        existing.base_url = base_url;
        for selection in existing.agents.values_mut() {
            selection.protocol = Protocol::Auto;
            selection.default_model = None;
        }
        existing.confirmed_direct_models.clear();
        existing.validate()?;
        Ok(existing)
    }

    /// Records an explicit user decision to use an unknown-capability direct model.
    pub fn confirm_direct_model(
        &mut self,
        model_id: impl Into<String>,
    ) -> Result<(), ProfileError> {
        if self.mode != ConnectionMode::Direct {
            return Err(ProfileError::InvalidDirectModelConfirmation);
        }
        let model_id = model_id.into();
        validate_model_id(&model_id)?;
        self.confirmed_direct_models.insert(model_id);
        Ok(())
    }

    pub fn unconfirm_direct_model(&mut self, model_id: &str) {
        self.confirmed_direct_models.remove(model_id);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reconfigured_connection(
        mut existing: Self,
        display_name: impl Into<String>,
        base_url: CanonicalBaseUrl,
        mode: ConnectionMode,
        credential_kind: CredentialKind,
        platform_id: impl Into<String>,
        manifest_url: Option<Url>,
    ) -> Result<Self, ProfileError> {
        existing = Self::reconfigured(existing, display_name, base_url)?;
        existing.mode = mode;
        existing.credential_kind = credential_kind;
        existing.platform_id = platform_id.into();
        existing.manifest_url = manifest_url;
        existing.validate()?;
        Ok(existing)
    }

    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(ProfileError::UnsupportedSchemaVersion(self.schema_version));
        }
        validated_display_name(self.display_name.clone())?;
        CredentialRef::parse(self.credential.0.clone())?;
        if self.credential != CredentialRef::for_profile(self.id) {
            return Err(ProfileError::CredentialReferenceMismatch);
        }
        if !portable_id(&self.platform_id) {
            return Err(ProfileError::InvalidPlatformId);
        }
        if self.mode == ConnectionMode::Direct
            && (self.credential_kind != CredentialKind::ApiKey || self.manifest_url.is_some())
        {
            return Err(ProfileError::InvalidConnectionRelationship);
        }
        if self.credential_kind == CredentialKind::AccessToken
            && self.mode != ConnectionMode::Provisioned
        {
            return Err(ProfileError::InvalidConnectionRelationship);
        }
        if let Some(url) = &self.manifest_url {
            validate_manifest_url(url, &self.base_url)?;
        }
        if self.agents.len() != AgentId::ALL.len()
            || AgentId::ALL
                .into_iter()
                .any(|agent| !self.agents.contains_key(&agent))
        {
            return Err(ProfileError::InvalidAgentSelections);
        }
        for (agent, selection) in &self.agents {
            if !agent.supported_protocols().contains(&selection.protocol) {
                return Err(ProfileError::UnsupportedAgentProtocol {
                    agent: *agent,
                    protocol: selection
                        .protocol
                        .wire_protocol()
                        .expect("Auto is supported by every Agent"),
                });
            }
            if let Some(model) = &selection.default_model
                && validate_model_id(model).is_err()
            {
                return Err(ProfileError::InvalidModelId);
            }
        }
        for model in &self.confirmed_direct_models {
            validate_model_id(model)?;
        }
        if self.mode != ConnectionMode::Direct && !self.confirmed_direct_models.is_empty() {
            return Err(ProfileError::InvalidDirectModelConfirmation);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct UncheckedConnectionProfile {
    schema_version: u32,
    id: ProfileId,
    display_name: String,
    base_url: CanonicalBaseUrl,
    credential: CredentialRef,
    #[serde(default)]
    credential_secret: String,
    #[serde(default)]
    mode: Option<ConnectionMode>,
    #[serde(default)]
    credential_kind: Option<CredentialKind>,
    #[serde(default)]
    platform_id: Option<String>,
    #[serde(default)]
    manifest_url: Option<Url>,
    agents: BTreeMap<AgentId, AgentSelection>,
    #[serde(default)]
    confirmed_direct_models: BTreeSet<String>,
}

impl TryFrom<UncheckedConnectionProfile> for ConnectionProfile {
    type Error = ProfileError;

    fn try_from(unchecked: UncheckedConnectionProfile) -> Result<Self, Self::Error> {
        if !matches!(unchecked.schema_version, 1 | 2 | Self::SCHEMA_VERSION) {
            return Err(ProfileError::UnsupportedSchemaVersion(
                unchecked.schema_version,
            ));
        }
        let legacy = unchecked.schema_version == 1;
        let mut agents = unchecked.agents;
        if unchecked.schema_version < Self::SCHEMA_VERSION {
            // Protocol selections in schema 1/2 were persisted but ignored by
            // projection. Preserve the wire behavior users actually had.
            for (agent, selection) in &mut agents {
                selection.protocol = match agent {
                    AgentId::Claude => Protocol::Anthropic,
                    AgentId::Codex => Protocol::OpenaiResponses,
                    AgentId::Gemini => Protocol::Gemini,
                    AgentId::Grokbuild => Protocol::OpenaiResponses,
                    AgentId::Opencode => Protocol::OpenaiChat,
                };
            }
        }
        let profile = Self {
            schema_version: Self::SCHEMA_VERSION,
            id: unchecked.id,
            display_name: unchecked.display_name,
            base_url: unchecked.base_url,
            credential: unchecked.credential,
            credential_secret: if legacy {
                String::new()
            } else {
                unchecked.credential_secret
            },
            mode: if legacy {
                ConnectionMode::Direct
            } else {
                unchecked
                    .mode
                    .ok_or(ProfileError::MissingSchemaTwoField("mode"))?
            },
            credential_kind: if legacy {
                CredentialKind::ApiKey
            } else {
                unchecked
                    .credential_kind
                    .ok_or(ProfileError::MissingSchemaTwoField("credential_kind"))?
            },
            platform_id: if legacy {
                generic_platform()
            } else {
                unchecked
                    .platform_id
                    .ok_or(ProfileError::MissingSchemaTwoField("platform_id"))?
            },
            manifest_url: if legacy { None } else { unchecked.manifest_url },
            agents,
            confirmed_direct_models: unchecked.confirmed_direct_models,
        };
        profile.validate()?;
        Ok(profile)
    }
}

fn validate_model_id(model: &str) -> Result<(), ProfileError> {
    if model.trim().is_empty() || model.len() > 512 || model.chars().any(char::is_control) {
        Err(ProfileError::InvalidModelId)
    } else {
        Ok(())
    }
}

fn generic_platform() -> String {
    "gateway-connector".into()
}
fn portable_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|b| !b.is_ascii_uppercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !matches!(
            value.split('.').next(),
            Some("con" | "prn" | "aux" | "nul" | "clock$")
        )
        && !value.split('.').next().is_some_and(|stem| {
            stem.len() == 4
                && (stem.starts_with("com") || stem.starts_with("lpt"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9')
        })
}
fn validate_manifest_url(url: &Url, base: &CanonicalBaseUrl) -> Result<(), ProfileError> {
    if url.origin() != base.origin()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback_host(url.host())))
    {
        return Err(ProfileError::InvalidManifestUrl);
    }
    Ok(())
}

fn loopback_host(host: Option<Host<&str>>) -> bool {
    matches!(host, Some(Host::Domain("localhost")))
        || matches!(host, Some(Host::Ipv4(v)) if v.is_loopback())
        || matches!(host, Some(Host::Ipv6(v)) if v.is_loopback())
}

fn validated_display_name(value: String) -> Result<String, ProfileError> {
    let value = value.trim().to_owned();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(ProfileError::InvalidDisplayName);
    }
    Ok(value)
}

fn is_loopback(host: Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    }
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("the gateway URL is invalid: {0}")]
    InvalidBaseUrl(url::ParseError),
    #[error("gateway URL scheme `{0}` is unsupported; use https")]
    UnsupportedScheme(String),
    #[error("gateway URLs must not include a username or password")]
    UserInfoNotAllowed,
    #[error("gateway URLs must not include a query string or fragment")]
    QueryOrFragmentNotAllowed,
    #[error("the gateway URL must include a host")]
    MissingHost,
    #[error("remote gateways must use https; http is allowed only on loopback")]
    InsecureRemoteUrl,
    #[error("the connection display name must be 1-128 printable characters")]
    InvalidDisplayName,
    #[error("profile schema version {0} is unsupported")]
    UnsupportedSchemaVersion(u32),
    #[error("connection profile is missing required field `{0}`")]
    MissingSchemaTwoField(&'static str),
    #[error("a profile must contain exactly one selection for each supported Agent")]
    InvalidAgentSelections,
    #[error("the selected model ID is empty, overlong, or contains control characters")]
    InvalidModelId,
    #[error("unknown-capability model confirmations are valid only for direct connections")]
    InvalidDirectModelConfirmation,
    #[error("the credential reference is invalid")]
    InvalidCredentialReference,
    #[error("the credential reference must belong to the profile ID")]
    CredentialReferenceMismatch,
    #[error("the platform ID is not portable")]
    InvalidPlatformId,
    #[error("connection mode, credential kind, and manifest URL are inconsistent")]
    InvalidConnectionRelationship,
    #[error("the manifest URL must be secure and use the exact gateway origin")]
    InvalidManifestUrl,
    #[error("unknown protocol `{0}`")]
    UnknownProtocol(String),
    #[error("{agent:?} does not support the {protocol} protocol")]
    UnsupportedAgentProtocol {
        agent: AgentId,
        protocol: WireProtocol,
    },
    #[error("the Gateway does not advertise {protocol} required by {agent:?}")]
    ProtocolNotAdvertised {
        agent: AgentId,
        protocol: WireProtocol,
    },
    #[error("the Gateway does not advertise any protocol supported by {0:?}")]
    NoCompatibleProtocol(AgentId),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_base_urls_and_builds_endpoints() {
        let root = CanonicalBaseUrl::parse("  https://EXAMPLE.com:443///  ").expect("valid URL");
        assert_eq!(root.to_string(), "https://example.com");
        assert_eq!(
            root.endpoint("v1/models").as_str(),
            "https://example.com/v1/models"
        );

        let nested = CanonicalBaseUrl::parse("https://example.com/gateway/").expect("valid URL");
        assert_eq!(nested.to_string(), "https://example.com/gateway");
        assert_eq!(
            nested.endpoint("/v1/models").as_str(),
            "https://example.com/gateway/v1/models"
        );
    }

    #[test]
    fn resolves_supported_gateway_url_forms_to_model_endpoints() {
        for (input, expected) in [
            (
                "https://example.com:8443/",
                "https://example.com:8443/v1/models",
            ),
            (
                "https://example.com:8443/v1",
                "https://example.com:8443/v1/models",
            ),
            (
                "https://example.com:8443/v1/models",
                "https://example.com:8443/v1/models",
            ),
            (
                "https://example.com:8443/proxy",
                "https://example.com:8443/proxy/v1/models",
            ),
            (
                "https://example.com:8443/proxy/v1",
                "https://example.com:8443/proxy/v1/models",
            ),
        ] {
            let base = CanonicalBaseUrl::parse(input).expect("valid URL");
            assert_eq!(base.models_endpoint().as_str(), expected);
        }
    }

    #[test]
    fn rejects_unsafe_remote_urls() {
        assert!(matches!(
            CanonicalBaseUrl::parse("http://example.com"),
            Err(ProfileError::InsecureRemoteUrl)
        ));
        assert!(CanonicalBaseUrl::parse("http://127.0.0.1:8080").is_ok());
        assert!(CanonicalBaseUrl::parse("http://[::1]:8080").is_ok());
        assert!(matches!(
            CanonicalBaseUrl::parse("https://user@example.com"),
            Err(ProfileError::UserInfoNotAllowed)
        ));
    }

    #[test]
    fn persisted_profile_can_include_credential_secret_redacted_in_debug() {
        let mut profile = ConnectionProfile::new(
            "Example",
            CanonicalBaseUrl::parse("https://gateway.example").expect("valid URL"),
        )
        .expect("valid profile");
        profile.credential_secret = "sk-example".into();
        let json = serde_json::to_string_pretty(&profile).expect("serialize profile");
        assert!(json.contains("profile:"));
        assert!(json.contains("credential_kind"));
        assert!(json.contains("sk-example"));
        assert!(!format!("{profile:?}").contains("sk-example"));
        assert_eq!(profile.agents.len(), 5);

        let decoded: ConnectionProfile = serde_json::from_str(&json).expect("deserialize profile");
        assert_eq!(decoded, profile);
    }

    #[test]
    fn direct_model_confirmations_are_optional_persisted_and_cleared_on_reconfiguration() {
        let mut profile = ConnectionProfile::new(
            "Example",
            CanonicalBaseUrl::parse("https://gateway.example").expect("valid URL"),
        )
        .expect("valid profile");
        let mut old_schema_two = serde_json::to_value(&profile).expect("serialize profile");
        old_schema_two["schema_version"] = serde_json::json!(2);
        old_schema_two
            .as_object_mut()
            .expect("profile object")
            .remove("confirmed_direct_models");
        let decoded: ConnectionProfile =
            serde_json::from_value(old_schema_two).expect("older schema-2 profile loads");
        assert!(decoded.confirmed_direct_models.is_empty());

        profile
            .confirm_direct_model("unknown-model")
            .expect("confirmation");
        let decoded: ConnectionProfile =
            serde_json::from_str(&serde_json::to_string(&profile).expect("serialize confirmation"))
                .expect("reload confirmation");
        assert!(decoded.confirmed_direct_models.contains("unknown-model"));
        let reconfigured = ConnectionProfile::reconfigured(
            decoded,
            "Other",
            CanonicalBaseUrl::parse("https://other.example").expect("valid URL"),
        )
        .expect("reconfigure");
        assert!(reconfigured.confirmed_direct_models.is_empty());
    }

    #[test]
    fn migrates_schema_one_profile_without_serializing_a_secret() {
        let id = ProfileId::new();
        let mut agents = BTreeMap::new();
        for agent in AgentId::ALL {
            agents.insert(agent, AgentSelection::new());
        }
        let legacy = serde_json::json!({
            "schema_version": 1,
            "id": id,
            "display_name": "Legacy",
            "base_url": "https://gateway.example/",
            "credential": CredentialRef::for_profile(id),
            "agents": agents,
        });
        let profile: ConnectionProfile =
            serde_json::from_value(legacy).expect("schema-1 profile migrates");
        assert_eq!(profile.id, id);
        assert_eq!(profile.credential, CredentialRef::for_profile(id));
        assert_eq!(profile.schema_version, ConnectionProfile::SCHEMA_VERSION);
        assert_eq!(profile.mode, ConnectionMode::Direct);
        assert_eq!(profile.credential_kind, CredentialKind::ApiKey);
        let current = serde_json::to_string(&profile).expect("serialize current profile");
        assert!(current.contains("\"schema_version\":3"));
        assert!(!current.contains("secret"));
    }

    #[test]
    fn current_schema_requires_all_connection_security_fields() {
        let profile = ConnectionProfile::new(
            "Current",
            CanonicalBaseUrl::parse("https://gateway.example").expect("valid URL"),
        )
        .expect("valid profile");
        for field in ["mode", "credential_kind", "platform_id"] {
            let mut json = serde_json::to_value(&profile).expect("serialize profile");
            json.as_object_mut().expect("profile object").remove(field);
            let error = serde_json::from_value::<ConnectionProfile>(json)
                .expect_err("connection field is required");
            assert!(error.to_string().contains(field), "{error}");
        }
    }

    #[test]
    fn rejects_a_persisted_profile_with_another_profiles_credential_reference() {
        let profile = ConnectionProfile::new(
            "Example",
            CanonicalBaseUrl::parse("https://gateway.example").expect("valid URL"),
        )
        .expect("valid profile");
        let mut json = serde_json::to_value(profile).expect("serialize profile");
        json["credential"] =
            serde_json::json!(CredentialRef::for_profile(ProfileId::new()).as_str());

        let error = serde_json::from_value::<ConnectionProfile>(json)
            .expect_err("a profile must not redirect credential lookup");
        assert!(error.to_string().contains("belong to the profile ID"));
    }

    #[test]
    fn reconfiguration_preserves_identity_and_revalidates_loaded_profiles() {
        let profile = ConnectionProfile::new(
            "First",
            CanonicalBaseUrl::parse("https://one.example").expect("valid URL"),
        )
        .expect("valid profile");
        let id = profile.id;
        let credential = profile.credential.clone();
        let reconfigured = ConnectionProfile::reconfigured(
            profile,
            "Second",
            CanonicalBaseUrl::parse("https://two.example").expect("valid URL"),
        )
        .expect("reconfigure profile");
        assert_eq!(reconfigured.id, id);
        assert_eq!(reconfigured.credential, credential);

        let mut json = serde_json::to_value(&reconfigured).expect("serialize profile");
        json["agents"]
            .as_object_mut()
            .expect("Agent map")
            .remove("codex");
        let error = serde_json::from_value::<ConnectionProfile>(json)
            .expect_err("incomplete profiles must be rejected");
        assert!(error.to_string().contains("exactly one selection"));
    }

    #[test]
    fn agent_protocol_matrix_and_auto_resolution_are_explicit() {
        let all = WireProtocol::ALL.into_iter().collect::<BTreeSet<_>>();
        for (agent, expected) in [
            (AgentId::Claude, WireProtocol::Anthropic),
            (AgentId::Codex, WireProtocol::OpenaiResponses),
            (AgentId::Gemini, WireProtocol::Gemini),
            (AgentId::Grokbuild, WireProtocol::OpenaiChat),
            (AgentId::Opencode, WireProtocol::OpenaiChat),
        ] {
            assert_eq!(
                agent
                    .resolve_protocol(Protocol::Auto, Some(&all))
                    .expect("compatible protocol"),
                expected
            );
            assert_eq!(
                agent
                    .resolve_protocol(Protocol::Auto, None)
                    .expect("deterministic direct protocol"),
                expected
            );
        }
        assert_eq!(
            AgentId::Grokbuild
                .resolve_protocol(
                    Protocol::Auto,
                    Some(&BTreeSet::from([
                        WireProtocol::OpenaiResponses,
                        WireProtocol::Anthropic,
                    ]))
                )
                .expect("first compatible advertised protocol"),
            WireProtocol::OpenaiResponses
        );
        assert!(matches!(
            AgentId::Codex.resolve_protocol(Protocol::OpenaiChat, None),
            Err(ProfileError::UnsupportedAgentProtocol { .. })
        ));
        assert!(matches!(
            AgentId::Grokbuild.resolve_protocol(
                Protocol::Anthropic,
                Some(&BTreeSet::from([WireProtocol::OpenaiChat]))
            ),
            Err(ProfileError::ProtocolNotAdvertised { .. })
        ));
    }

    #[test]
    fn schema_two_migration_preserves_previously_effective_protocols() {
        let profile = ConnectionProfile::new(
            "Legacy",
            CanonicalBaseUrl::parse("https://gateway.example").expect("valid URL"),
        )
        .expect("profile");
        let mut json = serde_json::to_value(profile).expect("serialize profile");
        json["schema_version"] = serde_json::json!(2);
        for selection in json["agents"]
            .as_object_mut()
            .expect("Agent selections")
            .values_mut()
        {
            selection["protocol"] = serde_json::json!("gemini");
        }

        let migrated: ConnectionProfile =
            serde_json::from_value(json).expect("schema-2 profile migrates");
        assert_eq!(
            AgentId::ALL.map(|agent| migrated.agents[&agent].protocol),
            [
                Protocol::Anthropic,
                Protocol::OpenaiResponses,
                Protocol::Gemini,
                Protocol::OpenaiResponses,
                Protocol::OpenaiChat,
            ]
        );
    }
}
