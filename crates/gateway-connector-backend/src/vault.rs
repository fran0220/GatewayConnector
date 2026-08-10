use std::{collections::HashMap, fmt, sync::Mutex};

use gateway_connector_core::{
    ConnectionMode, ConnectionProfile, CredentialKind, CredentialRef, ProfileId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const ENVELOPE_PREFIX: &str = "gateway-connector-credential-v1:";

/// Credential secret with redacted diagnostics and zeroized storage on drop.
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(value: impl Into<String>) -> Result<Self, VaultError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(VaultError::EmptyCredential);
        }
        Ok(Self(value))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl Clone for ApiKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKey([REDACTED])")
    }
}

impl Drop for ApiKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub trait CredentialStore: Send + Sync + fmt::Debug {
    fn get(&self, profile: &ConnectionProfile) -> Result<Option<ApiKey>, VaultError>;
    fn set(&self, profile: &ConnectionProfile, api_key: &ApiKey) -> Result<(), VaultError>;
    fn delete(&self, credential: &CredentialRef) -> Result<(), VaultError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CredentialBinding {
    schema_version: u32,
    profile_id: ProfileId,
    base_url: String,
    mode: ConnectionMode,
    credential_kind: CredentialKind,
    platform_id: String,
    manifest_url: Option<String>,
}

impl CredentialBinding {
    fn for_profile(profile: &ConnectionProfile) -> Self {
        Self {
            schema_version: 1,
            profile_id: profile.id,
            base_url: profile.base_url.to_string(),
            mode: profile.mode,
            credential_kind: profile.credential_kind,
            platform_id: profile.platform_id.clone(),
            manifest_url: profile.manifest_url.as_ref().map(ToString::to_string),
        }
    }
}

#[derive(Deserialize)]
struct CredentialEnvelope {
    binding: CredentialBinding,
    secret: String,
}

#[derive(Serialize)]
struct CredentialEnvelopeRef<'a> {
    binding: CredentialBinding,
    secret: &'a str,
}

fn encode(profile: &ConnectionProfile, api_key: &ApiKey) -> Result<Zeroizing<String>, VaultError> {
    let value = CredentialEnvelopeRef {
        binding: CredentialBinding::for_profile(profile),
        secret: api_key.expose_secret(),
    };
    serde_json::to_string(&value)
        .map(|json| Zeroizing::new(format!("{ENVELOPE_PREFIX}{json}")))
        .map_err(|error| VaultError::InvalidEnvelope(error.to_string()))
}

#[derive(Debug)]
pub struct OsCredentialStore {
    service: String,
}

impl OsCredentialStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, credential: &CredentialRef) -> Result<keyring::Entry, VaultError> {
        keyring::Entry::new(&self.service, credential.as_str())
            .map_err(|error| VaultError::Unavailable(error.to_string()))
    }
}

impl CredentialStore for OsCredentialStore {
    fn get(&self, profile: &ConnectionProfile) -> Result<Option<ApiKey>, VaultError> {
        match self.entry(&profile.credential)?.get_password() {
            Ok(value) => {
                let value = Zeroizing::new(value);
                if let Some(json) = value.strip_prefix(ENVELOPE_PREFIX) {
                    let envelope: CredentialEnvelope = serde_json::from_str(json)
                        .map_err(|error| VaultError::InvalidEnvelope(error.to_string()))?;
                    if envelope.binding != CredentialBinding::for_profile(profile) {
                        return Err(VaultError::BindingMismatch);
                    }
                    ApiKey::new(envelope.secret).map(Some)
                } else {
                    // Phase-1 credentials predate origin binding. Trust the
                    // already loaded profile once, then atomically replace the
                    // raw vault value with the bound envelope.
                    let api_key = ApiKey::new(value.to_string())?;
                    self.set(profile, &api_key)?;
                    Ok(Some(api_key))
                }
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(VaultError::Unavailable(error.to_string())),
        }
    }

    fn set(&self, profile: &ConnectionProfile, api_key: &ApiKey) -> Result<(), VaultError> {
        let encoded = encode(profile, api_key)?;
        self.entry(&profile.credential)?
            .set_password(&encoded)
            .map_err(|error| VaultError::Unavailable(error.to_string()))
    }

    fn delete(&self, credential: &CredentialRef) -> Result<(), VaultError> {
        match self.entry(credential)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(VaultError::Unavailable(error.to_string())),
        }
    }
}

#[derive(Debug, Default)]
pub struct InMemoryCredentialStore {
    entries: Mutex<HashMap<CredentialRef, (ApiKey, CredentialBinding)>>,
}

impl CredentialStore for InMemoryCredentialStore {
    fn get(&self, profile: &ConnectionProfile) -> Result<Option<ApiKey>, VaultError> {
        let entries = self.entries.lock().map_err(|_| VaultError::Poisoned)?;
        let Some((api_key, binding)) = entries.get(&profile.credential) else {
            return Ok(None);
        };
        if binding != &CredentialBinding::for_profile(profile) {
            return Err(VaultError::BindingMismatch);
        }
        Ok(Some(api_key.clone()))
    }

    fn set(&self, profile: &ConnectionProfile, api_key: &ApiKey) -> Result<(), VaultError> {
        self.entries
            .lock()
            .map_err(|_| VaultError::Poisoned)?
            .insert(
                profile.credential.clone(),
                (api_key.clone(), CredentialBinding::for_profile(profile)),
            );
        Ok(())
    }

    fn delete(&self, credential: &CredentialRef) -> Result<(), VaultError> {
        self.entries
            .lock()
            .map_err(|_| VaultError::Poisoned)?
            .remove(credential);
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("the credential is empty")]
    EmptyCredential,
    #[error("the operating-system credential store is unavailable: {0}")]
    Unavailable(String),
    #[error("the vault credential is bound to different connection security settings")]
    BindingMismatch,
    #[error("the vault credential envelope is invalid: {0}")]
    InvalidEnvelope(String),
    #[error("the in-memory credential store lock is poisoned")]
    Poisoned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_connector_core::{CanonicalBaseUrl, Protocol};

    #[test]
    fn in_memory_store_round_trips_without_exposing_debug_value() {
        let store = InMemoryCredentialStore::default();
        let profile = ConnectionProfile::new(
            "Test",
            CanonicalBaseUrl::parse("https://gateway.example").expect("base URL"),
            Protocol::Auto,
        )
        .expect("profile");
        let key = ApiKey::new("very-secret").expect("valid key");
        assert_eq!(format!("{key:?}"), "ApiKey([REDACTED])");
        store.set(&profile, &key).expect("store key");
        assert_eq!(
            store
                .get(&profile)
                .expect("read key")
                .expect("key exists")
                .expose_secret(),
            "very-secret"
        );
        store
            .delete(&profile.credential)
            .expect("delete credential");
        assert!(store.get(&profile).expect("read key").is_none());
    }
}
