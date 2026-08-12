use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use gateway_connector_core::{
    AgentId, AgentInstall, ApplyInput, CanonicalBaseUrl, ConnectionManifest, ConnectionMode,
    ConnectionProfile, Connector, CredentialKind, Discovery, FixedAgentRoots, Gateway, Model, Plan,
    Platform, ProfileError, Protocol, Provisioning, Secret, Verification,
};
use thiserror::Error;

use crate::{
    ApiKey, Browser, CredentialStore, DiscoveryError, Distribution, DistributionError,
    GENERIC_DISTRIBUTION, GatewayClient, ModelCapability, ModelDescriptor, ProfileStore,
    StoreError, SystemBrowser, VaultError,
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
    pub manifest: Option<ConnectionManifest>,
    pub provisioning: Option<Provisioning>,
    pub synchronized_skills: BTreeMap<String, PathBuf>,
}

#[derive(Debug, Clone)]
pub enum ProbeResult {
    Direct {
        base_url: CanonicalBaseUrl,
    },
    Provisioned {
        base_url: CanonicalBaseUrl,
        manifest_url: url::Url,
        manifest: Box<ConnectionManifest>,
    },
}

#[derive(Debug, Clone)]
pub struct BrowserLoginOffer {
    pub request: ConnectRequestWithoutCredential,
    pub manifest_url: url::Url,
    pub manifest: ConnectionManifest,
}
#[derive(Debug, Clone)]
pub struct ConnectRequestWithoutCredential {
    pub display_name: String,
    pub base_url: String,
    pub protocol: Protocol,
}

#[derive(Debug)]
pub struct ConnectorBackend {
    client: GatewayClient,
    credentials: Arc<dyn CredentialStore>,
    profiles: Arc<dyn ProfileStore>,
    distribution: &'static Distribution,
    browser: Arc<dyn Browser>,
    connection_lock: Mutex<()>,
    pending_credential: Mutex<Option<PendingCredential>>,
    catalog: Option<crate::catalog::SkillCatalog>,
    projection: Option<ProjectionRuntime>,
    projection_lock: Mutex<()>,
}

#[derive(Debug, Clone)]
struct PendingCredential {
    token: ApiKey,
    profile: ConnectionProfile,
    manifest: ConnectionManifest,
}

#[derive(Debug)]
struct ProjectionRuntime {
    connector: Connector,
    discovery: RuntimeDiscovery,
}

#[derive(Debug)]
enum RuntimeDiscovery {
    System { discovery: Discovery, home: PathBuf },
    Fixed(FixedAgentRoots),
}

impl RuntimeDiscovery {
    fn discover(&self) -> Vec<AgentInstall> {
        match self {
            Self::System { discovery, home } => discovery.discover(home),
            Self::Fixed(roots) => roots.discover(),
        }
    }
}

impl ConnectorBackend {
    pub fn new(
        credentials: Arc<dyn CredentialStore>,
        profiles: Arc<dyn ProfileStore>,
    ) -> Result<Self, BackendError> {
        Self::with_dependencies(
            credentials,
            profiles,
            &GENERIC_DISTRIBUTION,
            Arc::new(SystemBrowser),
        )
    }

    pub fn with_dependencies(
        credentials: Arc<dyn CredentialStore>,
        profiles: Arc<dyn ProfileStore>,
        distribution: &'static Distribution,
        browser: Arc<dyn Browser>,
    ) -> Result<Self, BackendError> {
        distribution.validate()?;
        Ok(Self {
            client: GatewayClient::new()?,
            credentials,
            profiles,
            distribution,
            browser,
            connection_lock: Mutex::new(()),
            pending_credential: Mutex::new(None),
            catalog: None,
            projection: None,
            projection_lock: Mutex::new(()),
        })
    }

    /// Configures the explicit state directory used for transactional Skill catalogs.
    /// Without this configuration no catalog is downloaded or written.
    pub fn with_state_directory(
        mut self,
        state_dir: impl Into<PathBuf>,
    ) -> Result<Self, BackendError> {
        self.catalog = Some(
            crate::catalog::SkillCatalog::new(state_dir.into())
                .map_err(|error| BackendError::Catalog(error.to_string()))?,
        );
        Ok(self)
    }

    /// Configures provisioned Skill state and the neutral five-Agent runtime.
    /// Tests and downstream distributions inject these paths explicitly; the
    /// generic app uses the shared ProjectionCoordinator directory.
    pub fn with_runtime_directories(
        mut self,
        state_dir: impl Into<PathBuf>,
        coordinator_dir: impl Into<PathBuf>,
        home: impl Into<PathBuf>,
    ) -> Result<Self, BackendError> {
        let state_dir = state_dir.into();
        self.catalog = Some(
            crate::catalog::SkillCatalog::new(state_dir.clone())
                .map_err(|error| BackendError::Catalog(error.to_string()))?,
        );
        self.projection = Some(ProjectionRuntime {
            connector: Connector::with_coordinator(
                state_dir.join("connector"),
                coordinator_dir.into(),
            ),
            discovery: RuntimeDiscovery::System {
                discovery: Discovery::default(),
                home: home.into(),
            },
        });
        Ok(self)
    }

    /// Configures one root-derived runtime whose Agent discovery cannot read
    /// environment variables or operating-system home directories.
    pub fn with_isolated_runtime_directories(
        mut self,
        state_dir: impl Into<PathBuf>,
        coordinator_dir: impl Into<PathBuf>,
        agent_roots: FixedAgentRoots,
    ) -> Result<Self, BackendError> {
        let state_dir = state_dir.into();
        self.catalog = Some(
            crate::catalog::SkillCatalog::new(state_dir.clone())
                .map_err(|error| BackendError::Catalog(error.to_string()))?,
        );
        self.projection = Some(ProjectionRuntime {
            connector: Connector::with_coordinator(
                state_dir.join("connector"),
                coordinator_dir.into(),
            ),
            discovery: RuntimeDiscovery::Fixed(agent_roots),
        });
        Ok(self)
    }

    /// Pins Agent roots for an embedded distribution or deterministic test.
    /// Unspecified Agents continue to use environment and canonical roots.
    pub fn with_agent_root_overrides(
        mut self,
        overrides: BTreeMap<AgentId, PathBuf>,
    ) -> Result<Self, BackendError> {
        let runtime = self
            .projection
            .as_mut()
            .ok_or(BackendError::ProjectionNotConfigured)?;
        let RuntimeDiscovery::System { discovery, .. } = &mut runtime.discovery else {
            return Err(BackendError::ProjectionContext(
                "fixed isolated Agent roots cannot be overridden".into(),
            ));
        };
        discovery.overrides = overrides;
        Ok(self)
    }

    fn synchronize_skills(
        &self,
        manifest: &ConnectionManifest,
        provisioning: &Provisioning,
        token: &ApiKey,
    ) -> Result<BTreeMap<String, PathBuf>, BackendError> {
        self.catalog.as_ref().map_or_else(
            || Ok(BTreeMap::new()),
            |catalog| {
                catalog
                    .synchronize(manifest, provisioning, token)
                    .map_err(|error| BackendError::Catalog(error.to_string()))
            },
        )
    }

    pub fn discover_agents(&self) -> Result<Vec<AgentInstall>, BackendError> {
        let runtime = self
            .projection
            .as_ref()
            .ok_or(BackendError::ProjectionNotConfigured)?;
        Ok(runtime.discovery.discover())
    }

    pub fn managed_agents(
        &self,
        profile: &ConnectionProfile,
    ) -> Result<BTreeSet<AgentId>, BackendError> {
        let _guard = self
            .projection_lock
            .lock()
            .map_err(|_| BackendError::ProjectionLock)?;
        profile.validate()?;
        let runtime = self
            .projection
            .as_ref()
            .ok_or(BackendError::ProjectionNotConfigured)?;
        let bearer = self
            .credentials
            .get(profile)?
            .ok_or(BackendError::MissingCredential)?;
        let secret = core_secret(&bearer)?;
        runtime
            .connector
            .managed_agents(&profile.platform_id, &secret)
            .map_err(Into::into)
    }

    pub fn plan_projection(&self, connection: &ConnectionResult) -> Result<Plan, BackendError> {
        let _guard = self
            .projection_lock
            .lock()
            .map_err(|_| BackendError::ProjectionLock)?;
        connection.profile.validate()?;
        self.validate_distribution_profile(&connection.profile)?;
        let runtime = self
            .projection
            .as_ref()
            .ok_or(BackendError::ProjectionNotConfigured)?;
        if connection.profile.mode == ConnectionMode::Direct
            && self.single_profile()?.as_ref() != Some(&connection.profile)
        {
            return Err(BackendError::ProjectionContext(
                "the active direct profile must be saved exactly as edited before preview".into(),
            ));
        }
        let bearer = self
            .credentials
            .get(&connection.profile)?
            .ok_or(BackendError::MissingCredential)?;
        let secret = core_secret(&bearer)?;
        let installs = runtime.discovery.discover();
        let (manifest, provisioning) = self.projection_contracts(connection, &installs)?;
        let selected_models = connection
            .profile
            .agents
            .iter()
            .filter_map(|(agent, selection)| {
                selection
                    .default_model
                    .as_ref()
                    .map(|model| (*agent, model.clone()))
            })
            .collect();
        runtime
            .connector
            .plan(ApplyInput {
                manifest: &manifest,
                provisioning: &provisioning,
                bearer: &secret,
                selected_models,
                installs,
                synchronized_skills: connection.synchronized_skills.clone(),
            })
            .map_err(Into::into)
    }

    pub fn apply_projection(
        &self,
        profile: &ConnectionProfile,
        plan: &Plan,
    ) -> Result<(), BackendError> {
        let _guard = self
            .projection_lock
            .lock()
            .map_err(|_| BackendError::ProjectionLock)?;
        if plan.platform_id != profile.platform_id {
            return Err(BackendError::ProjectionContext(
                "preview belongs to another platform".into(),
            ));
        }
        let runtime = self
            .projection
            .as_ref()
            .ok_or(BackendError::ProjectionNotConfigured)?;
        let bearer = self
            .credentials
            .get(profile)?
            .ok_or(BackendError::MissingCredential)?;
        if !plan.credential_matches(&core_secret(&bearer)?)? {
            return Err(BackendError::ProjectionContext(
                "the Gateway credential changed after preview; preview again".into(),
            ));
        }
        runtime.connector.apply(plan).map_err(Into::into)
    }

    pub fn verify_projection(&self, plan: &Plan) -> Result<Verification, BackendError> {
        let _guard = self
            .projection_lock
            .lock()
            .map_err(|_| BackendError::ProjectionLock)?;
        self.projection
            .as_ref()
            .ok_or(BackendError::ProjectionNotConfigured)?
            .connector
            .verify(plan)
            .map_err(Into::into)
    }

    pub fn disconnect_projection(&self, profile: &ConnectionProfile) -> Result<(), BackendError> {
        let _guard = self
            .projection_lock
            .lock()
            .map_err(|_| BackendError::ProjectionLock)?;
        self.disconnect_projection_locked(profile)
    }

    pub fn probe(&self, base_url: &str) -> Result<ProbeResult, BackendError> {
        let base_url = CanonicalBaseUrl::parse(base_url)?;
        if !self.distribution.allow_custom_urls {
            let configured = self
                .distribution
                .default_gateway_url
                .ok_or(BackendError::DistributionGatewayRequired)
                .and_then(|value| CanonicalBaseUrl::parse(value).map_err(BackendError::Profile))?;
            if base_url != configured {
                return Err(BackendError::CustomGatewayUrlNotAllowed);
            }
        }
        // Enhanced mode is compile-time only: a distribution must pin
        // `manifest_url`. The generic binary never probes well-known or any
        // other discovery path and stays on direct OpenAI-compatible mode.
        let Some(manifest_url) = self
            .distribution
            .manifest_url
            .map(url::Url::parse)
            .transpose()
            .map_err(|_| BackendError::InvalidDistributionManifest)?
        else {
            return Ok(ProbeResult::Direct { base_url });
        };
        let found = self.client.discover_manifest(&base_url, manifest_url.clone())?;
        if let Some(expected) = self.distribution.expected_platform_id
            && found.document.platform.id != expected
        {
            return Err(BackendError::PlatformMismatch {
                expected: expected.into(),
                actual: found.document.platform.id,
            });
        }
        Ok(ProbeResult::Provisioned {
            base_url,
            manifest_url,
            manifest: Box::new(found.document),
        })
    }

    pub fn connect(&self, request: ConnectRequest) -> Result<ConnectionResult, BackendError> {
        let _connection_guard = self
            .connection_lock
            .lock()
            .map_err(|_| BackendError::ConnectionLock)?;
        if self.single_profile()?.is_some() {
            return Err(BackendError::AlreadyConnected);
        }
        let probe = self.probe(&request.base_url)?;
        let (
            base_url,
            mode,
            platform,
            manifest_url,
            manifest,
            provisioning,
            models,
            synchronized_skills,
        ) = match probe {
            ProbeResult::Direct { base_url } => {
                let models = self.client.discover_models(&base_url, &request.api_key)?;
                (
                    base_url,
                    ConnectionMode::Direct,
                    self.distribution.product_id.into(),
                    None,
                    None,
                    None,
                    models,
                    BTreeMap::new(),
                )
            }
            ProbeResult::Provisioned {
                base_url,
                manifest_url,
                manifest,
            } => {
                let manifest = *manifest;
                if manifest.authentication.is_some() {
                    return Err(BackendError::BrowserLoginRequired(Box::new(
                        BrowserLoginOffer {
                            request: ConnectRequestWithoutCredential {
                                display_name: request.display_name,
                                base_url: request.base_url,
                                protocol: request.protocol,
                            },
                            manifest_url,
                            manifest,
                        },
                    )));
                }
                let provisioning = self
                    .client
                    .fetch_provisioning(&manifest, &request.api_key)?;
                let models = models_from_provisioning(&provisioning);
                let synchronized_skills =
                    self.synchronize_skills(&manifest, &provisioning, &request.api_key)?;
                let platform = manifest.platform.id.clone();
                (
                    base_url,
                    ConnectionMode::Provisioned,
                    platform,
                    Some(manifest_url),
                    Some(manifest),
                    Some(provisioning),
                    models,
                    synchronized_skills,
                )
            }
        };
        let profile = ConnectionProfile::new_connection(
            request.display_name,
            base_url,
            request.protocol,
            mode,
            CredentialKind::ApiKey,
            platform,
            manifest_url,
        )?;

        if let Err(source) = self.profiles.create(&profile) {
            if matches!(source, StoreError::ActiveProfileExists) {
                return Err(BackendError::AlreadyConnected);
            }
            return Err(source.into());
        }
        if let Err(source) = self.credentials.set(&profile, &request.api_key) {
            let cleanup = self.credentials.delete(&profile.credential);
            if let Err(cleanup) = cleanup {
                return Err(BackendError::CredentialCleanup { source, cleanup });
            }
            let rollback = self.profiles.delete(profile.id);
            return match rollback {
                Ok(()) => Err(source.into()),
                Err(rollback) => Err(BackendError::CredentialCommit { source, rollback }),
            };
        }
        Ok(ConnectionResult {
            profile,
            models,
            manifest,
            provisioning,
            synchronized_skills,
        })
    }

    pub fn browser_login(
        &self,
        offer: BrowserLoginOffer,
    ) -> Result<ConnectionResult, BackendError> {
        let _connection_guard = self
            .connection_lock
            .lock()
            .map_err(|_| BackendError::ConnectionLock)?;
        let mut pending_guard = self
            .pending_credential
            .lock()
            .map_err(|_| BackendError::PendingLock)?;
        if pending_guard.is_some() || self.single_profile()?.is_some() {
            return Err(BackendError::AlreadyConnected);
        }
        offer
            .manifest
            .validate()
            .map_err(|error| BackendError::ManifestValidation(error.to_string()))?;
        if let Some(expected) = self.distribution.expected_platform_id
            && offer.manifest.platform.id != expected
        {
            return Err(BackendError::PlatformMismatch {
                expected: expected.to_owned(),
                actual: offer.manifest.platform.id,
            });
        }
        let authentication = offer
            .manifest
            .authentication
            .as_ref()
            .ok_or(BackendError::ManifestHasNoBrowserAuth)?;
        let base = CanonicalBaseUrl::parse(&offer.request.base_url)?;
        let profile = ConnectionProfile::new_connection(
            offer.request.display_name,
            base,
            offer.request.protocol,
            ConnectionMode::Provisioned,
            CredentialKind::AccessToken,
            offer.manifest.platform.id.clone(),
            Some(offer.manifest_url),
        )?;
        self.validate_distribution_profile(&profile)?;
        let token = crate::PkceFlow::random().login(
            &authentication.authorize_url,
            &authentication.token_url,
            self.distribution.pkce_client_id,
            self.distribution.device_name,
            self.browser.as_ref(),
        )?;
        let pending = PendingCredential {
            token,
            profile: profile.clone(),
            manifest: offer.manifest.clone(),
        };
        *pending_guard = Some(pending.clone());
        if let Err(source) = self.profiles.create(&profile) {
            if matches!(source, StoreError::ActiveProfileExists) {
                return Err(BackendError::AlreadyConnected);
            }
            return Err(source.into());
        }
        if let Err(source) = self.credentials.set(&profile, &pending.token) {
            // `set` failures are ambiguous: the vault may have committed and
            // then failed to acknowledge. Keep both the durable profile and
            // in-memory pending token reachable for retry or revocation.
            return Err(source.into());
        }
        *pending_guard = None;
        drop(pending_guard);
        // Persistence is complete before the bearer is used for provisioning. A
        // transient outage leaves the saved connection available to resume.
        let provisioning = self
            .client
            .fetch_provisioning(&offer.manifest, &pending.token)?;
        let models = models_from_provisioning(&provisioning);
        let synchronized_skills =
            self.synchronize_skills(&offer.manifest, &provisioning, &pending.token)?;
        Ok(ConnectionResult {
            profile,
            models,
            manifest: Some(offer.manifest),
            provisioning: Some(provisioning),
            synchronized_skills,
        })
    }

    pub fn resume(&self, profile: ConnectionProfile) -> Result<ConnectionResult, BackendError> {
        profile.validate()?;
        self.validate_distribution_profile(&profile)?;
        let api_key = self
            .credentials
            .get(&profile)?
            .ok_or(BackendError::MissingCredential)?;
        if let Some(runtime) = &self.projection {
            let _guard = self
                .projection_lock
                .lock()
                .map_err(|_| BackendError::ProjectionLock)?;
            runtime
                .connector
                .recover(&profile.platform_id, &core_secret(&api_key)?)?;
        }
        match profile.mode {
            ConnectionMode::Direct => {
                let models = self.client.discover_models(&profile.base_url, &api_key)?;
                Ok(ConnectionResult {
                    profile,
                    models,
                    manifest: None,
                    provisioning: None,
                    synchronized_skills: BTreeMap::new(),
                })
            }
            ConnectionMode::Provisioned => {
                let manifest_url = profile
                    .manifest_url
                    .clone()
                    .ok_or(BackendError::ManifestDisappeared)?;
                let found = self
                    .client
                    .discover_manifest(&profile.base_url, manifest_url)?;
                self.validate_platform(&profile, &found.document)?;
                let provisioning = self.client.fetch_provisioning(&found.document, &api_key)?;
                let models = models_from_provisioning(&provisioning);
                let synchronized_skills =
                    self.synchronize_skills(&found.document, &provisioning, &api_key)?;
                Ok(ConnectionResult {
                    profile,
                    models,
                    manifest: Some(found.document),
                    provisioning: Some(provisioning),
                    synchronized_skills,
                })
            }
        }
    }

    pub fn resume_saved(&self) -> Result<Option<ConnectionResult>, BackendError> {
        self.single_profile()?
            .map(|profile| self.resume(profile))
            .transpose()
    }

    pub fn refresh(&self, profile: ConnectionProfile) -> Result<ConnectionResult, BackendError> {
        self.resume(profile)
    }

    pub fn has_pending_credential(&self) -> Result<bool, BackendError> {
        Ok(self
            .pending_credential
            .lock()
            .map_err(|_| BackendError::PendingLock)?
            .is_some())
    }

    pub fn retry_pending_credential(&self) -> Result<ConnectionResult, BackendError> {
        let _connection_guard = self
            .connection_lock
            .lock()
            .map_err(|_| BackendError::ConnectionLock)?;
        let pending = self
            .pending_credential
            .lock()
            .map_err(|_| BackendError::PendingLock)?
            .clone()
            .ok_or(BackendError::NoPendingCredential)?;
        if self
            .single_profile()?
            .is_some_and(|active| active.id != pending.profile.id)
        {
            return Err(BackendError::AlreadyConnected);
        }
        self.profiles.save(&pending.profile)?;
        if let Err(source) = self.credentials.set(&pending.profile, &pending.token) {
            return Err(source.into());
        }
        *self
            .pending_credential
            .lock()
            .map_err(|_| BackendError::PendingLock)? = None;
        let provisioning = self
            .client
            .fetch_provisioning(&pending.manifest, &pending.token)?;
        let models = models_from_provisioning(&provisioning);
        let synchronized_skills =
            self.synchronize_skills(&pending.manifest, &provisioning, &pending.token)?;
        Ok(ConnectionResult {
            profile: pending.profile,
            models,
            manifest: Some(pending.manifest),
            provisioning: Some(provisioning),
            synchronized_skills,
        })
    }

    pub fn revoke_pending_credential(&self) -> Result<(), BackendError> {
        let _connection_guard = self
            .connection_lock
            .lock()
            .map_err(|_| BackendError::ConnectionLock)?;
        let mut guard = self
            .pending_credential
            .lock()
            .map_err(|_| BackendError::PendingLock)?;
        let pending = guard.as_ref().ok_or(BackendError::NoPendingCredential)?;
        if !self
            .client
            .revoke_credential(&pending.manifest, &pending.token)?
        {
            return Err(BackendError::RevocationInconclusive);
        }
        // A vault implementation may commit and still report an error. Keep a
        // durable profile reference until local cleanup is confirmed.
        self.profiles.save(&pending.profile)?;
        self.credentials.delete(&pending.profile.credential)?;
        self.profiles.delete(pending.profile.id)?;
        *guard = None;
        Ok(())
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
        let _connection_guard = self
            .connection_lock
            .lock()
            .map_err(|_| BackendError::ConnectionLock)?;
        if self.projection.is_some() {
            self.disconnect_projection(profile)?;
        }
        self.credentials.delete(&profile.credential)?;
        self.profiles.delete(profile.id)?;
        Ok(())
    }

    fn disconnect_projection_locked(
        &self,
        profile: &ConnectionProfile,
    ) -> Result<(), BackendError> {
        profile.validate()?;
        self.validate_distribution_profile(profile)?;
        let runtime = self
            .projection
            .as_ref()
            .ok_or(BackendError::ProjectionNotConfigured)?;
        let bearer = self
            .credentials
            .get(profile)?
            .ok_or(BackendError::MissingCredential)?;
        runtime
            .connector
            .disconnect(&profile.platform_id, &core_secret(&bearer)?)
            .map_err(Into::into)
    }

    fn projection_contracts(
        &self,
        connection: &ConnectionResult,
        installs: &[AgentInstall],
    ) -> Result<(ConnectionManifest, Provisioning), BackendError> {
        match connection.profile.mode {
            ConnectionMode::Direct => {
                if connection.manifest.is_some()
                    || connection.provisioning.is_some()
                    || !connection.synchronized_skills.is_empty()
                {
                    return Err(BackendError::ProjectionContext(
                        "direct connection contains platform-only data".into(),
                    ));
                }
                let catalog = connection
                    .models
                    .iter()
                    .map(|model| (model.id.as_str(), model))
                    .collect::<BTreeMap<_, _>>();
                let mut explicitly_selected = Vec::new();
                for install in installs.iter().filter(|install| install.detected) {
                    let model_id = connection.profile.agents[&install.agent]
                        .default_model
                        .as_deref()
                        .ok_or_else(|| {
                            BackendError::ProjectionContext(format!(
                                "{} requires an explicit direct model selection",
                                install.agent.display_name()
                            ))
                        })?;
                    let model = catalog.get(model_id).ok_or_else(|| {
                        BackendError::ProjectionContext(format!(
                            "selected direct model `{model_id}` is not in the discovered catalog"
                        ))
                    })?;
                    match model.capability {
                        ModelCapability::Chat => {}
                        ModelCapability::NonChat => {
                            return Err(BackendError::ProjectionContext(format!(
                                "selected direct model `{model_id}` is explicitly non-chat"
                            )));
                        }
                        ModelCapability::Unknown
                            if !connection
                                .profile
                                .confirmed_direct_models
                                .contains(model_id) =>
                        {
                            return Err(BackendError::ProjectionContext(format!(
                                "selected direct model `{model_id}` has unknown capability and is not confirmed"
                            )));
                        }
                        ModelCapability::Unknown => {}
                    }
                    explicitly_selected.push(model_id.to_owned());
                }
                let protocols = connection
                    .profile
                    .agents
                    .values()
                    .map(|selection| selection.protocol.as_str().to_owned())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let manifest = ConnectionManifest::direct(
                    Platform {
                        id: connection.profile.platform_id.clone(),
                        name: self.distribution.product_name.to_owned(),
                    },
                    Gateway {
                        base_url: connection.profile.base_url.as_url().clone(),
                        protocols,
                    },
                    connection.profile.base_url.as_url().clone(),
                    AgentId::ALL.to_vec(),
                )?;
                let models = connection
                    .models
                    .iter()
                    .filter(|model| explicitly_selected.contains(&model.id))
                    .map(|model| Model {
                        id: model.id.clone(),
                        chat_capable: true,
                        description: None,
                        icon: None,
                        tags: Vec::new(),
                        vendor: None,
                    })
                    .collect::<Vec<_>>();
                let default_model = explicitly_selected.first().cloned().ok_or_else(|| {
                    BackendError::ProjectionContext(
                        "no detected Agent is available for direct projection".into(),
                    )
                })?;
                Ok((manifest, Provisioning::direct(models, default_model)?))
            }
            ConnectionMode::Provisioned => {
                let manifest = connection.manifest.clone().ok_or_else(|| {
                    BackendError::ProjectionContext("provisioned connection has no manifest".into())
                })?;
                let provisioning = connection.provisioning.clone().ok_or_else(|| {
                    BackendError::ProjectionContext(
                        "provisioned connection has no provisioning catalog".into(),
                    )
                })?;
                if manifest.platform.id != connection.profile.platform_id {
                    return Err(BackendError::ProjectionContext(
                        "manifest platform does not match the active profile".into(),
                    ));
                }
                provisioning.validate_for(&manifest)?;
                Ok((manifest, provisioning))
            }
        }
    }

    fn single_profile(&self) -> Result<Option<ConnectionProfile>, BackendError> {
        let mut profiles = self.profiles()?;
        if profiles.len() > 1 {
            return Err(BackendError::MultipleProfiles);
        }
        Ok(profiles.pop())
    }

    fn validate_platform(
        &self,
        profile: &ConnectionProfile,
        manifest: &ConnectionManifest,
    ) -> Result<(), BackendError> {
        let expected = self.distribution.expected_platform_id;
        if manifest.platform.id != profile.platform_id
            || expected.is_some_and(|value| value != manifest.platform.id)
        {
            return Err(BackendError::PlatformMismatch {
                expected: expected.unwrap_or(&profile.platform_id).to_owned(),
                actual: manifest.platform.id.clone(),
            });
        }
        Ok(())
    }

    fn validate_distribution_profile(
        &self,
        profile: &ConnectionProfile,
    ) -> Result<(), BackendError> {
        if !self.distribution.allow_custom_urls {
            let configured = self
                .distribution
                .default_gateway_url
                .ok_or(BackendError::DistributionGatewayRequired)
                .and_then(|value| CanonicalBaseUrl::parse(value).map_err(BackendError::Profile))?;
            if profile.base_url != configured {
                return Err(BackendError::CustomGatewayUrlNotAllowed);
            }
        }
        if profile.mode == ConnectionMode::Provisioned {
            if let Some(expected) = self.distribution.expected_platform_id
                && profile.platform_id != expected
            {
                return Err(BackendError::PlatformMismatch {
                    expected: expected.to_owned(),
                    actual: profile.platform_id.clone(),
                });
            }
            if let Some(configured) = self.distribution.manifest_url {
                let configured = url::Url::parse(configured)
                    .map_err(|_| BackendError::InvalidDistributionManifest)?;
                if profile.manifest_url.as_ref() != Some(&configured) {
                    return Err(BackendError::DistributionManifestMismatch);
                }
            }
        }
        Ok(())
    }
}

fn core_secret(value: &ApiKey) -> Result<Secret, gateway_connector_core::Error> {
    Secret::new(value.expose_secret().to_owned())
}

fn models_from_provisioning(value: &Provisioning) -> Vec<ModelDescriptor> {
    let mut models: Vec<_> = value
        .models
        .iter()
        .filter(|m| m.chat_capable)
        .map(|m| ModelDescriptor {
            id: m.id.clone(),
            capability: ModelCapability::Chat,
            owned_by: m.vendor.as_ref().map(|v| v.name.clone()),
            created: None,
            object: Some("model".into()),
            metadata: Default::default(),
        })
        .collect();
    models.sort_by(|a, b| a.id.cmp(&b.id));
    models
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("Skill catalog synchronization failed: {0}")]
    Catalog(String),
    #[error(transparent)]
    Projection(#[from] gateway_connector_core::Error),
    #[error("projection context is invalid: {0}")]
    ProjectionContext(String),
    #[error("Agent projection runtime is not configured")]
    ProjectionNotConfigured,
    #[error("Agent projection operation lock is unavailable")]
    ProjectionLock,
    #[error(transparent)]
    Distribution(#[from] DistributionError),
    #[error(transparent)]
    Profile(#[from] ProfileError),
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(
        "the saved profile has no credential in the operating-system vault; enter the credential again"
    )]
    MissingCredential,
    #[error("phase 1 supports one connection profile, but multiple profiles were found")]
    MultipleProfiles,
    #[error("credential storage failed ({source}) and profile rollback also failed ({rollback})")]
    CredentialCommit {
        source: VaultError,
        rollback: StoreError,
    },
    #[error("credential storage failed ({source}) and local vault cleanup failed ({cleanup})")]
    CredentialCleanup {
        source: VaultError,
        cleanup: VaultError,
    },
    #[error("distribution manifest URL is invalid")]
    InvalidDistributionManifest,
    #[error("a distribution that disables custom URLs must configure a default Gateway URL")]
    DistributionGatewayRequired,
    #[error("this distribution accepts only its configured Gateway URL")]
    CustomGatewayUrlNotAllowed,
    #[error("the saved profile does not use this distribution's configured manifest")]
    DistributionManifestMismatch,
    #[error("manifest platform `{actual}` does not match required platform `{expected}`")]
    PlatformMismatch { expected: String, actual: String },
    #[error("browser login is required")]
    BrowserLoginRequired(Box<BrowserLoginOffer>),
    #[error("the saved provisioned manifest is no longer available")]
    ManifestDisappeared,
    #[error("manifest does not offer browser authentication")]
    ManifestHasNoBrowserAuth,
    #[error("manifest is invalid: {0}")]
    ManifestValidation(String),
    #[error(transparent)]
    Pkce(#[from] crate::PkceError),
    #[error("a connection is already active; disconnect it before starting another browser login")]
    AlreadyConnected,
    #[error("pending credential state is unavailable")]
    PendingLock,
    #[error("connection operation lock is unavailable")]
    ConnectionLock,
    #[error("there is no pending credential to recover")]
    NoPendingCredential,
    #[error("credential revocation was inconclusive; retry before discarding it")]
    RevocationInconclusive,
}
