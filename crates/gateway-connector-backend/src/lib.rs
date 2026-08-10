//! Network, credential-vault, and profile persistence boundary.

mod backend;
mod discovery;
mod profile_store;
mod vault;

pub use backend::{BackendError, ConnectRequest, ConnectionResult, ConnectorBackend};
pub use discovery::{
    DiscoveredManifest, DiscoveryError, GatewayClient, ManifestLocation, ModelDescriptor,
};
pub use profile_store::{InMemoryProfileStore, JsonProfileStore, ProfileStore, StoreError};
pub use vault::{ApiKey, CredentialStore, InMemoryCredentialStore, OsCredentialStore, VaultError};
