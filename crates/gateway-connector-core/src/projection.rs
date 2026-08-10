use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{AgentId, ProfileId, Protocol};

/// A detected Agent installation. Discovery must not create this path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionTarget {
    pub agent: AgentId,
    pub root: PathBuf,
}

/// Secret-free ownership record shared by branded distributions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorLease {
    pub distribution_id: String,
    pub profile_id: ProfileId,
    pub agent: AgentId,
    pub canonical_root: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Create,
    Update,
    Remove,
}

/// One secret-free line in a projection preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectedChange {
    pub agent: AgentId,
    pub path: PathBuf,
    pub kind: ChangeKind,
    pub protocol: Protocol,
    pub model: String,
}

/// Immutable preview token. Implementations bind this to file snapshots and
/// the current vault credential before allowing apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionPlan {
    pub id: Uuid,
    pub profile_id: ProfileId,
    pub changes: Vec<ProjectedChange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionResult {
    pub changed_files: usize,
    pub verified: bool,
}

/// Phase-2 boundary for the shared plan/preview/apply/verify/disconnect engine.
/// Phase 1 intentionally provides no implementation that could write Agent
/// files without ownership receipts and coordinator locking.
pub trait ProjectionBackend: Send + Sync {
    fn preview(
        &self,
        profile_id: ProfileId,
        targets: &[ProjectionTarget],
    ) -> Result<ProjectionPlan, ProjectionError>;

    fn apply(&self, plan: &ProjectionPlan) -> Result<ProjectionResult, ProjectionError>;

    fn disconnect(&self, profile_id: ProfileId) -> Result<ProjectionResult, ProjectionError>;
}

#[derive(Debug, Error)]
pub enum ProjectionError {
    #[error("projection is not implemented by this backend")]
    Unsupported,
    #[error("projection plan is stale; preview the changes again")]
    StalePlan,
    #[error("Agent projection is owned by distribution `{owner}`")]
    OwnershipConflict { owner: String },
    #[error("projection failed: {0}")]
    Other(String),
}
