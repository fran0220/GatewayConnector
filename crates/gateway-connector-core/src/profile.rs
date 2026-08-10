use std::{collections::BTreeMap, fmt, str::FromStr};

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
            Self::Auto => "Auto (OpenAI-compatible discovery)",
            Self::OpenaiChat => "OpenAI Chat Completions",
            Self::OpenaiResponses => "OpenAI Responses",
            Self::Anthropic => "Anthropic Messages",
            Self::Gemini => "Gemini",
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSelection {
    pub protocol: Protocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
}

impl AgentSelection {
    pub fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            default_model: None,
        }
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

/// Opaque account name used to retrieve a secret from a credential vault.
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

    pub fn well_known_endpoint(&self) -> Url {
        let mut endpoint = self.0.clone();
        endpoint.set_path("/.well-known/gateway-connector");
        endpoint
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedConnectionProfile")]
pub struct ConnectionProfile {
    pub schema_version: u32,
    pub id: ProfileId,
    pub display_name: String,
    pub base_url: CanonicalBaseUrl,
    pub credential: CredentialRef,
    pub agents: BTreeMap<AgentId, AgentSelection>,
}

impl ConnectionProfile {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn new(
        display_name: impl Into<String>,
        base_url: CanonicalBaseUrl,
        protocol: Protocol,
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
            .map(|agent| (agent, AgentSelection::new(protocol)))
            .collect();
        Ok(Self {
            schema_version: Self::SCHEMA_VERSION,
            id,
            display_name,
            base_url,
            credential,
            agents,
        })
    }

    pub fn reconfigured(
        mut existing: Self,
        display_name: impl Into<String>,
        base_url: CanonicalBaseUrl,
        protocol: Protocol,
    ) -> Result<Self, ProfileError> {
        let display_name = validated_display_name(display_name.into())?;
        existing.schema_version = Self::SCHEMA_VERSION;
        existing.display_name = display_name;
        existing.base_url = base_url;
        for selection in existing.agents.values_mut() {
            selection.protocol = protocol;
            selection.default_model = None;
        }
        existing.validate()?;
        Ok(existing)
    }

    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(ProfileError::UnsupportedSchemaVersion(self.schema_version));
        }
        validated_display_name(self.display_name.clone())?;
        CredentialRef::parse(self.credential.0.clone())?;
        if self.agents.len() != AgentId::ALL.len()
            || AgentId::ALL
                .into_iter()
                .any(|agent| !self.agents.contains_key(&agent))
        {
            return Err(ProfileError::InvalidAgentSelections);
        }
        for selection in self.agents.values() {
            if let Some(model) = &selection.default_model
                && (model.trim().is_empty()
                    || model.len() > 512
                    || model.chars().any(char::is_control))
            {
                return Err(ProfileError::InvalidModelId);
            }
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
    agents: BTreeMap<AgentId, AgentSelection>,
}

impl TryFrom<UncheckedConnectionProfile> for ConnectionProfile {
    type Error = ProfileError;

    fn try_from(unchecked: UncheckedConnectionProfile) -> Result<Self, Self::Error> {
        let profile = Self {
            schema_version: unchecked.schema_version,
            id: unchecked.id,
            display_name: unchecked.display_name,
            base_url: unchecked.base_url,
            credential: unchecked.credential,
            agents: unchecked.agents,
        };
        profile.validate()?;
        Ok(profile)
    }
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
    #[error("a profile must contain exactly one selection for each supported Agent")]
    InvalidAgentSelections,
    #[error("the selected model ID is empty, overlong, or contains control characters")]
    InvalidModelId,
    #[error("the credential reference is invalid")]
    InvalidCredentialReference,
    #[error("unknown protocol `{0}`")]
    UnknownProtocol(String),
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
        assert_eq!(
            nested.well_known_endpoint().as_str(),
            "https://example.com/.well-known/gateway-connector"
        );
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
    fn persisted_profile_contains_a_reference_not_a_secret() {
        let profile = ConnectionProfile::new(
            "Example",
            CanonicalBaseUrl::parse("https://gateway.example").expect("valid URL"),
            Protocol::Auto,
        )
        .expect("valid profile");
        let json = serde_json::to_string_pretty(&profile).expect("serialize profile");
        assert!(json.contains("profile:"));
        assert!(!json.contains("api_key"));
        assert_eq!(profile.agents.len(), 5);

        let decoded: ConnectionProfile = serde_json::from_str(&json).expect("deserialize profile");
        assert_eq!(decoded, profile);
    }

    #[test]
    fn reconfiguration_preserves_identity_and_revalidates_loaded_profiles() {
        let profile = ConnectionProfile::new(
            "First",
            CanonicalBaseUrl::parse("https://one.example").expect("valid URL"),
            Protocol::Auto,
        )
        .expect("valid profile");
        let id = profile.id;
        let credential = profile.credential.clone();
        let reconfigured = ConnectionProfile::reconfigured(
            profile,
            "Second",
            CanonicalBaseUrl::parse("https://two.example").expect("valid URL"),
            Protocol::Anthropic,
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
}
