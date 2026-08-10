//! Product-neutral profile and projection contracts.

mod profile;
mod projection;

pub use profile::{
    AgentId, AgentSelection, CanonicalBaseUrl, ConnectionProfile, CredentialRef, ProfileError,
    ProfileId, Protocol,
};
pub use projection::{
    ChangeKind, CoordinatorLease, ProjectedChange, ProjectionBackend, ProjectionError,
    ProjectionPlan, ProjectionResult, ProjectionTarget,
};
