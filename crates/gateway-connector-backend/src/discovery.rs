use std::{collections::BTreeMap, io::Read, time::Duration};

use gateway_connector_core::{CanonicalBaseUrl, ConnectionManifest, Provisioning};
use reqwest::{StatusCode, blocking::Response, header};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use url::Url;

use crate::ApiKey;

const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapability {
    Chat,
    NonChat,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelDescriptor {
    pub id: String,
    pub capability: ModelCapability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owned_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(flatten)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredManifest {
    pub url: Url,
    pub document: ConnectionManifest,
}

#[derive(Debug, Clone)]
pub struct GatewayClient {
    client: reqwest::blocking::Client,
    direct_client: reqwest::blocking::Client,
}

impl GatewayClient {
    pub fn new() -> Result<Self, DiscoveryError> {
        let client = client_builder()
            .build()
            .map_err(DiscoveryError::ClientSetup)?;
        let direct_client = client_builder()
            .no_proxy()
            .build()
            .map_err(DiscoveryError::ClientSetup)?;
        Ok(Self {
            client,
            direct_client,
        })
    }

    fn client_for(&self, url: &Url) -> &reqwest::blocking::Client {
        if url.scheme() == "http" {
            &self.direct_client
        } else {
            &self.client
        }
    }

    pub fn discover_models(
        &self,
        base_url: &CanonicalBaseUrl,
        api_key: &ApiKey,
    ) -> Result<Vec<ModelDescriptor>, DiscoveryError> {
        let endpoint = base_url.models_endpoint();
        let response =
            self.get_following_exact_origin(endpoint, base_url, Some(api_key.expose_secret()))?;
        match response.status() {
            StatusCode::UNAUTHORIZED => return Err(DiscoveryError::Unauthorized),
            StatusCode::FORBIDDEN => return Err(DiscoveryError::Forbidden),
            status if !status.is_success() => {
                return Err(DiscoveryError::HttpStatus(status.as_u16()));
            }
            _ => {}
        }

        let bytes = read_bounded(response)?;
        let response: ModelList = serde_json::from_slice(&bytes)
            .map_err(|source| DiscoveryError::InvalidSchema { source })?;
        normalize_models(response.data)
    }

    /// Fetches a compile-time distribution manifest. Manifest URLs are required
    /// contracts for branded platforms; the generic binary never probes for one.
    pub fn discover_manifest(
        &self,
        base_url: &CanonicalBaseUrl,
        manifest_url: Url,
    ) -> Result<DiscoveredManifest, DiscoveryError> {
        if has_userinfo(&manifest_url) {
            return Err(DiscoveryError::ManifestUrlCredentials);
        }
        if manifest_url.origin() != base_url.origin() {
            return Err(DiscoveryError::ManifestOriginMismatch(manifest_url));
        }
        let response = self.get_following_exact_origin(manifest_url, base_url, None)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(DiscoveryError::ExplicitManifestNotFound);
        }
        if !response.status().is_success() {
            return Err(DiscoveryError::ManifestHttpStatus(
                response.status().as_u16(),
            ));
        }
        let final_url = response.url().clone();
        let bytes = read_bounded(response)?;
        let document = ConnectionManifest::parse(&bytes).map_err(|source| {
            DiscoveryError::InvalidManifest {
                message: source.to_string(),
            }
        })?;
        Ok(DiscoveredManifest {
            url: final_url,
            document,
        })
    }

    pub fn fetch_provisioning(
        &self,
        manifest: &ConnectionManifest,
        bearer: &ApiKey,
    ) -> Result<Provisioning, DiscoveryError> {
        let provisioning_origin = manifest.provisioning_url.origin();
        if !manifest
            .connection_bearer_origins
            .iter()
            .any(|allowed| allowed.origin() == provisioning_origin)
        {
            return Err(DiscoveryError::OriginBoundary(
                manifest.provisioning_url.clone(),
            ));
        }
        let base = CanonicalBaseUrl::parse(&provisioning_origin.ascii_serialization()).map_err(
            |error| DiscoveryError::InvalidManifest {
                message: error.to_string(),
            },
        )?;
        let response = self.get_following_exact_origin(
            manifest.provisioning_url.clone(),
            &base,
            Some(bearer.expose_secret()),
        )?;
        if !response.status().is_success() {
            return Err(DiscoveryError::ProvisioningHttpStatus(
                response.status().as_u16(),
            ));
        }
        let bytes = read_bounded(response)?;
        let value = Provisioning::parse(&bytes)
            .map_err(|source| DiscoveryError::InvalidProvisioning(source.to_string()))?;
        value
            .validate_for(manifest)
            .map_err(|source| DiscoveryError::InvalidProvisioning(source.to_string()))?;
        Ok(value)
    }

    pub fn revoke_credential(
        &self,
        manifest: &ConnectionManifest,
        bearer: &ApiKey,
    ) -> Result<bool, DiscoveryError> {
        let mut endpoint = manifest.provisioning_url.clone();
        let path = endpoint.path().trim_end_matches('/');
        let prefix = path
            .strip_suffix("/provisioning")
            .ok_or(DiscoveryError::InvalidRevokeEndpoint)?;
        endpoint.set_path(&format!("{prefix}/revoke"));
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(DiscoveryError::ClientSetup)?;
        let request_url = endpoint.clone();
        let response = client
            .post(endpoint)
            .bearer_auth(bearer.expose_secret())
            .send()
            .map_err(|source| DiscoveryError::Network {
                url: request_url,
                source,
            })?;
        Ok(response.status().is_success() || response.status() == StatusCode::UNAUTHORIZED)
    }

    fn get_following_exact_origin(
        &self,
        mut url: Url,
        base_url: &CanonicalBaseUrl,
        bearer: Option<&str>,
    ) -> Result<Response, DiscoveryError> {
        for redirects in 0..=MAX_REDIRECTS {
            if has_userinfo(&url) {
                return Err(DiscoveryError::ManifestUrlCredentials);
            }
            if url.origin() != base_url.origin() {
                return Err(DiscoveryError::OriginBoundary(url));
            }
            let mut request = self
                .client_for(&url)
                .get(url.clone())
                .header(header::ACCEPT, "application/json");
            if let Some(bearer) = bearer {
                request = request.bearer_auth(bearer);
            }
            let response = request.send().map_err(|source| DiscoveryError::Network {
                url: url.clone(),
                source,
            })?;
            if !response.status().is_redirection() {
                return Ok(response);
            }
            if redirects == MAX_REDIRECTS {
                return Err(DiscoveryError::TooManyRedirects);
            }
            let location = response
                .headers()
                .get(header::LOCATION)
                .ok_or(DiscoveryError::RedirectWithoutLocation)?
                .to_str()
                .map_err(|_| DiscoveryError::InvalidRedirectLocation)?;
            let next = url
                .join(location)
                .map_err(|_| DiscoveryError::InvalidRedirectLocation)?;
            if has_userinfo(&next) {
                return Err(DiscoveryError::ManifestUrlCredentials);
            }
            if next.origin() != base_url.origin() {
                return Err(DiscoveryError::CrossOriginRedirect {
                    from: url.to_string(),
                    to: next.to_string(),
                });
            }
            url = next;
        }
        Err(DiscoveryError::TooManyRedirects)
    }
}

fn client_builder() -> reqwest::blocking::ClientBuilder {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("GatewayConnector/", env!("CARGO_PKG_VERSION")))
}

fn has_userinfo(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

impl Default for GatewayClient {
    fn default() -> Self {
        Self::new().expect("the built-in HTTP client configuration is valid")
    }
}

#[derive(Debug, Deserialize)]
struct ModelList {
    data: Vec<RawModel>,
}

#[derive(Debug, Deserialize)]
struct RawModel {
    id: String,
    #[serde(default)]
    owned_by: Option<String>,
    #[serde(default)]
    created: Option<i64>,
    #[serde(default)]
    object: Option<String>,
    #[serde(flatten)]
    metadata: Map<String, Value>,
}

fn normalize_models(models: Vec<RawModel>) -> Result<Vec<ModelDescriptor>, DiscoveryError> {
    let mut normalized: BTreeMap<String, (ModelDescriptor, CapabilityEvidence)> = BTreeMap::new();
    for (index, model) in models.into_iter().enumerate() {
        let id = model.id.trim().to_owned();
        if id.is_empty() || id.len() > 512 || id.chars().any(char::is_control) {
            return Err(DiscoveryError::InvalidModelId { index });
        }
        let evidence = capability_evidence(&model.metadata, model.object.as_deref());
        let candidate = ModelDescriptor {
            id: id.clone(),
            capability: evidence.capability(),
            owned_by: model.owned_by,
            created: model.created,
            object: model.object,
            metadata: model.metadata.into_iter().collect(),
        };
        normalized
            .entry(id)
            .and_modify(|(existing, existing_evidence)| {
                merge_metadata(existing, &candidate);
                existing_evidence.merge(evidence);
                existing.capability = existing_evidence.capability();
            })
            .or_insert((candidate, evidence));
    }
    Ok(normalized.into_values().map(|(model, _)| model).collect())
}

#[derive(Debug, Clone, Copy, Default)]
struct CapabilityEvidence {
    chat: bool,
    non_chat: bool,
}

impl CapabilityEvidence {
    fn merge(&mut self, other: Self) {
        self.chat |= other.chat;
        self.non_chat |= other.non_chat;
    }
    fn capability(self) -> ModelCapability {
        match (self.chat, self.non_chat) {
            (true, false) => ModelCapability::Chat,
            (false, true) => ModelCapability::NonChat,
            _ => ModelCapability::Unknown,
        }
    }
}

fn capability_evidence(metadata: &Map<String, Value>, object: Option<&str>) -> CapabilityEvidence {
    let mut evidence = CapabilityEvidence::default();
    if let Some(value) = metadata.get("chat_capable").and_then(Value::as_bool) {
        evidence.chat |= value;
        evidence.non_chat |= !value;
    }
    for container in ["capability", "capabilities", "supported_capabilities"] {
        if let Some(object) = metadata.get(container).and_then(Value::as_object) {
            for field in [
                "chat",
                "chat_capable",
                "chat_completion",
                "chat_completions",
            ] {
                if let Some(value) = object.get(field).and_then(Value::as_bool) {
                    evidence.chat |= value;
                    evidence.non_chat |= !value;
                }
            }
        }
    }
    for value in ["kind", "model_kind", "task", "model_task", "type"]
        .into_iter()
        .filter_map(|field| metadata.get(field).and_then(Value::as_str))
        .chain(object)
    {
        match value.trim().to_ascii_lowercase().as_str() {
            "chat" | "chat_completion" | "chat-completion" | "conversational" => {
                evidence.chat = true
            }
            "embedding" | "embeddings" | "rerank" | "reranking" | "image" | "image_generation"
            | "image-generation" => evidence.non_chat = true,
            _ => {}
        }
    }
    evidence
}

fn merge_metadata(existing: &mut ModelDescriptor, candidate: &ModelDescriptor) {
    if existing.owned_by.is_none() {
        existing.owned_by.clone_from(&candidate.owned_by);
    }
    if existing.created.is_none() {
        existing.created = candidate.created;
    }
    if existing.object.is_none() {
        existing.object.clone_from(&candidate.object);
    }
    for (key, value) in &candidate.metadata {
        existing
            .metadata
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
}

fn read_bounded(response: Response) -> Result<Vec<u8>, DiscoveryError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        return Err(DiscoveryError::ResponseTooLarge);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(DiscoveryError::ReadResponse)?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(DiscoveryError::ResponseTooLarge);
    }
    Ok(bytes)
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("could not initialize the HTTP client: {0}")]
    ClientSetup(reqwest::Error),
    #[error("could not reach {url}: {source}")]
    Network { url: Url, source: reqwest::Error },
    #[error("the Gateway rejected the API key (HTTP 401); check the key and try again")]
    Unauthorized,
    #[error("the API key is authenticated but cannot list models (HTTP 403)")]
    Forbidden,
    #[error("the Gateway model endpoint returned HTTP {0}")]
    HttpStatus(u16),
    #[error("the Gateway model response is not OpenAI-compatible JSON: {source}")]
    InvalidSchema { source: serde_json::Error },
    #[error("model entry {index} has an empty, overlong, or control-containing id")]
    InvalidModelId { index: usize },
    #[error("the Gateway response exceeds the 2 MiB safety limit")]
    ResponseTooLarge,
    #[error("could not read the Gateway response: {0}")]
    ReadResponse(std::io::Error),
    #[error("refused to send a credential outside the configured Gateway origin: {0}")]
    OriginBoundary(Url),
    #[error("refused cross-origin redirect from {from} to {to}; the API key was not forwarded")]
    CrossOriginRedirect { from: String, to: String },
    #[error("the Gateway returned a redirect without a Location header")]
    RedirectWithoutLocation,
    #[error("the Gateway returned an invalid redirect Location")]
    InvalidRedirectLocation,
    #[error("the Gateway exceeded the five-redirect limit")]
    TooManyRedirects,
    #[error("the explicit connector manifest must use the exact configured Gateway origin: {0}")]
    ManifestOriginMismatch(Url),
    #[error("connector manifest URLs and redirects must not include a username or password")]
    ManifestUrlCredentials,
    #[error("the connector manifest returned HTTP {0}")]
    ManifestHttpStatus(u16),
    #[error("the explicit connector manifest was not found (HTTP 404)")]
    ExplicitManifestNotFound,
    #[error("the connector manifest is invalid: {message}")]
    InvalidManifest { message: String },
    #[error("provisioning returned HTTP {0}")]
    ProvisioningHttpStatus(u16),
    #[error("provisioning is invalid: {0}")]
    InvalidProvisioning(String),
    #[error("provisioning URL does not end in /provisioning")]
    InvalidRevokeEndpoint,
}
