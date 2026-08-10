use std::sync::Arc;

use gateway_connector_core::{CanonicalBaseUrl, ConnectionProfile, ProfileError, Protocol};
use thiserror::Error;

use crate::{
    ApiKey, CredentialStore, DiscoveryError, GatewayClient, ModelDescriptor, ProfileStore,
    StoreError, VaultError,
};

#[derive(Debug)]
pub struct ConnectRequest {
    pub display_name: String,
    pub base_url: String,
    pub api_key: ApiKey,
    pub protocol: Protocol,
}

#[derive(Debug, Clone)]
pub struct ConnectionResult {
    pub profile: ConnectionProfile,
    pub models: Vec<ModelDescriptor>,
}

#[derive(Debug)]
pub struct ConnectorBackend {
    client: GatewayClient,
    credentials: Arc<dyn CredentialStore>,
    profiles: Arc<dyn ProfileStore>,
}

impl ConnectorBackend {
    pub fn new(
        credentials: Arc<dyn CredentialStore>,
        profiles: Arc<dyn ProfileStore>,
    ) -> Result<Self, BackendError> {
        Ok(Self {
            client: GatewayClient::new()?,
            credentials,
            profiles,
        })
    }

    pub fn connect(&self, request: ConnectRequest) -> Result<ConnectionResult, BackendError> {
        let base_url = CanonicalBaseUrl::parse(&request.base_url)?;
        let previous = self.single_profile()?;
        let profile = match previous.clone() {
            Some(existing) => ConnectionProfile::reconfigured(
                existing,
                request.display_name,
                base_url,
                request.protocol,
            )?,
            None => ConnectionProfile::new(request.display_name, base_url, request.protocol)?,
        };
        let models = self
            .client
            .discover_models(&profile.base_url, &request.api_key)?;

        self.profiles.save(&profile)?;
        if let Err(source) = self.credentials.set(&profile.credential, &request.api_key) {
            let rollback = match previous {
                Some(previous) => self.profiles.save(&previous),
                None => self.profiles.delete(profile.id),
            };
            return match rollback {
                Ok(()) => Err(source.into()),
                Err(rollback) => Err(BackendError::CredentialCommit { source, rollback }),
            };
        }
        Ok(ConnectionResult { profile, models })
    }

    pub fn resume(&self, profile: ConnectionProfile) -> Result<ConnectionResult, BackendError> {
        profile.validate()?;
        let api_key = self
            .credentials
            .get(&profile.credential)?
            .ok_or(BackendError::MissingCredential)?;
        let models = self.client.discover_models(&profile.base_url, &api_key)?;
        Ok(ConnectionResult { profile, models })
    }

    pub fn resume_saved(&self) -> Result<Option<ConnectionResult>, BackendError> {
        self.single_profile()?
            .map(|profile| self.resume(profile))
            .transpose()
    }

    pub fn save_profile(&self, profile: &ConnectionProfile) -> Result<(), BackendError> {
        profile.validate()?;
        self.profiles.save(profile).map_err(Into::into)
    }

    pub fn profiles(&self) -> Result<Vec<ConnectionProfile>, BackendError> {
        let profiles = self.profiles.load()?;
        for profile in &profiles {
            profile.validate()?;
        }
        Ok(profiles)
    }

    pub fn disconnect(&self, profile: &ConnectionProfile) -> Result<(), BackendError> {
        self.credentials.delete(&profile.credential)?;
        self.profiles.delete(profile.id)?;
        Ok(())
    }

    fn single_profile(&self) -> Result<Option<ConnectionProfile>, BackendError> {
        let mut profiles = self.profiles()?;
        if profiles.len() > 1 {
            return Err(BackendError::MultipleProfiles);
        }
        Ok(profiles.pop())
    }
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error(transparent)]
    Profile(#[from] ProfileError),
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(
        "the saved profile has no credential in the operating-system vault; enter the API key again"
    )]
    MissingCredential,
    #[error("phase 1 supports one connection profile, but multiple profiles were found")]
    MultipleProfiles,
    #[error("credential storage failed ({source}) and profile rollback also failed ({rollback})")]
    CredentialCommit {
        source: VaultError,
        rollback: StoreError,
    },
}
