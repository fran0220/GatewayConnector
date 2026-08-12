//! Network, local profile/credential config, and projection backend.

mod backend;
mod catalog;
mod discovery;
mod distribution;
mod pkce;
mod profile_store;
mod vault;

pub use backend::{
    BackendError, BrowserLoginOffer, ConnectRequest, ConnectRequestWithoutCredential,
    ConnectionResult, ConnectorBackend, ProbeResult,
};
pub use discovery::{
    DiscoveredManifest, DiscoveryError, GatewayClient, ModelCapability, ModelDescriptor,
};
pub use distribution::{
    AssetIdentity, Distribution, DistributionError, GENERIC_DISTRIBUTION, ReleaseMetadata,
};
pub use pkce::{Browser, PkceError, PkceFlow, SystemBrowser};
pub use profile_store::{InMemoryProfileStore, JsonProfileStore, ProfileStore, StoreError};
pub use vault::{
    ApiKey, CredentialStore, InMemoryCredentialStore, ProfileCredentialStore, VaultError,
};
