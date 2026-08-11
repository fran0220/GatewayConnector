//! Testable application state kept independent from GPUI rendering.

use std::collections::BTreeSet;

use gateway_connector_backend::{BrowserLoginOffer, ConnectionResult, ModelCapability};
use gateway_connector_core::{
    AgentId, AgentInstall, ConnectionMode, Plan, Protocol, Provisioning, Verification,
};

pub mod isolated;
pub mod preferences;

#[cfg(feature = "gpui-app")]
pub mod gpui_app;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Page {
    #[default]
    Overview,
    Agent(AgentId),
    Services,
    Account,
    Usage,
    Billing,
    ModelPlaza,
    Settings,
}

impl Page {
    pub const fn id(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Agent(AgentId::Claude) => "agent.claude",
            Self::Agent(AgentId::Codex) => "agent.codex",
            Self::Agent(AgentId::Gemini) => "agent.gemini",
            Self::Agent(AgentId::Grokbuild) => "agent.grokbuild",
            Self::Agent(AgentId::Opencode) => "agent.opencode",
            Self::Services => "services",
            Self::Account => "account",
            Self::Usage => "usage",
            Self::Billing => "billing",
            Self::ModelPlaza => "model-plaza",
            Self::Settings => "settings",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Some(match id {
            "overview" => Self::Overview,
            "agent.claude" => Self::Agent(AgentId::Claude),
            "agent.codex" => Self::Agent(AgentId::Codex),
            "agent.gemini" => Self::Agent(AgentId::Gemini),
            "agent.grokbuild" => Self::Agent(AgentId::Grokbuild),
            "agent.opencode" => Self::Agent(AgentId::Opencode),
            "services" => Self::Services,
            "account" => Self::Account,
            "usage" => Self::Usage,
            "billing" => Self::Billing,
            "model-plaza" => Self::ModelPlaza,
            "settings" => Self::Settings,
            _ => return None,
        })
    }

    pub fn available(self, provisioning: Option<&Provisioning>) -> bool {
        match self {
            Self::Services => provisioning
                .is_some_and(|value| !value.mcp_servers.is_empty() || !value.skills.is_empty()),
            Self::Account => provisioning.is_some_and(|value| value.account.is_some()),
            Self::Usage => provisioning.is_some_and(|value| value.usage.is_some()),
            Self::Billing => provisioning.is_some_and(|value| value.billing.is_some()),
            Self::ModelPlaza => provisioning.is_some_and(|value| value.model_plaza.is_some()),
            Self::Overview | Self::Agent(_) | Self::Settings => true,
        }
    }
}

#[derive(Debug, Default)]
pub enum AppState {
    #[default]
    Loading,
    FirstRun,
    Connecting,
    BrowserLogin(Box<BrowserLoginOffer>),
    Connected {
        connection: Box<ConnectionResult>,
        installs: QueryStatus<Vec<AgentInstall>>,
        managed_agents: QueryStatus<BTreeSet<AgentId>>,
        projection: ProjectionLifecycle,
    },
    Failed(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum QueryStatus<T> {
    #[default]
    Unknown,
    Known(T),
    Error(String),
}

#[derive(Debug, Default)]
pub enum ProjectionLifecycle {
    #[default]
    NotPreviewed,
    ManagedExisting,
    PreviewReady(Box<Plan>),
    Applying,
    AppliedAwaitingVerification(Box<Plan>),
    Verifying,
    Verified(Verification),
    VerificationFailed(Verification),
    ApplyFailed,
    VerificationError,
    Disconnecting,
    DisconnectFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionSemantic {
    PreviewRequired,
    ManagedExisting,
    PreviewReady,
    Applying,
    AppliedAwaitingVerification,
    Verifying,
    Verified,
    VerificationFailed,
    ApplyFailed,
    VerificationError,
    Disconnecting,
    DisconnectFailed,
}

impl ProjectionLifecycle {
    pub const fn semantic(&self) -> ProjectionSemantic {
        match self {
            Self::NotPreviewed => ProjectionSemantic::PreviewRequired,
            Self::ManagedExisting => ProjectionSemantic::ManagedExisting,
            Self::PreviewReady(_) => ProjectionSemantic::PreviewReady,
            Self::Applying => ProjectionSemantic::Applying,
            Self::AppliedAwaitingVerification(_) => ProjectionSemantic::AppliedAwaitingVerification,
            Self::Verifying => ProjectionSemantic::Verifying,
            Self::Verified(_) => ProjectionSemantic::Verified,
            Self::VerificationFailed(_) => ProjectionSemantic::VerificationFailed,
            Self::ApplyFailed => ProjectionSemantic::ApplyFailed,
            Self::VerificationError => ProjectionSemantic::VerificationError,
            Self::Disconnecting => ProjectionSemantic::Disconnecting,
            Self::DisconnectFailed => ProjectionSemantic::DisconnectFailed,
        }
    }

    pub fn preview(&self) -> Option<&Plan> {
        match self {
            Self::PreviewReady(plan) => Some(plan),
            _ => None,
        }
    }

    pub fn preview_plan(&self) -> Option<&Plan> {
        self.preview()
    }

    pub fn verification(&self) -> Option<&Verification> {
        match self {
            Self::Verified(verification) | Self::VerificationFailed(verification) => {
                Some(verification)
            }
            _ => None,
        }
    }

    pub const fn can_apply(&self) -> bool {
        matches!(self, Self::PreviewReady(_))
    }

    pub const fn can_verify(&self) -> bool {
        matches!(self, Self::AppliedAwaitingVerification(_))
    }

    pub const fn requires_preview(&self) -> bool {
        matches!(
            self,
            Self::NotPreviewed
                | Self::ManagedExisting
                | Self::VerificationFailed(_)
                | Self::ApplyFailed
                | Self::VerificationError
                | Self::DisconnectFailed
        )
    }

    const fn has_projection_ownership(&self) -> bool {
        matches!(
            self,
            Self::AppliedAwaitingVerification(_)
                | Self::Verifying
                | Self::Verified(_)
                | Self::VerificationFailed(_)
                | Self::VerificationError
        )
    }
}

impl ProjectionSemantic {
    pub const fn message(self) -> &'static str {
        match self {
            Self::PreviewRequired => "Preview is required before Apply.",
            Self::ManagedExisting => {
                "Managed files exist. Preview changes or disconnect this connection."
            }
            Self::PreviewReady => "Fresh preview ready. No Agent files have been changed yet.",
            Self::Applying => "Applying managed files…",
            Self::AppliedAwaitingVerification => {
                "Changes applied. Verify the managed files before continuing."
            }
            Self::Verifying => "Verifying managed files…",
            Self::Verified => "Managed files verified against the applied changes.",
            Self::VerificationFailed => "Verification found drift. Preview again before applying.",
            Self::ApplyFailed => "Apply failed. Preview again before applying.",
            Self::VerificationError => "Verification failed. Preview again before applying.",
            Self::Disconnecting => "Disconnecting managed files…",
            Self::DisconnectFailed => "Disconnect failed. Managed files may still be present.",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpEvidence {
    AvailableFromPlatform,
    ConfiguredForAgents,
}

impl McpEvidence {
    pub const fn label(self) -> &'static str {
        match self {
            Self::AvailableFromPlatform => "Available from platform",
            Self::ConfiguredForAgents => "Configured for Agents",
        }
    }
}

impl AppState {
    pub fn connected(result: ConnectionResult) -> Self {
        Self::Connected {
            connection: Box::new(result),
            installs: QueryStatus::Unknown,
            managed_agents: QueryStatus::Unknown,
            projection: ProjectionLifecycle::NotPreviewed,
        }
    }

    pub fn update_protocol(&mut self, agent: AgentId, protocol: Protocol) {
        if let Self::Connected {
            connection,
            managed_agents,
            projection,
            ..
        } = self
            && let Some(selection) = connection.profile.agents.get_mut(&agent)
        {
            selection.protocol = protocol;
            *projection = projection_after_edit(managed_agents);
        }
    }

    pub fn update_model(&mut self, agent: AgentId, model: String) {
        if let Self::Connected {
            connection,
            managed_agents,
            projection,
            ..
        } = self
            && let Some(selection) = connection.profile.agents.get_mut(&agent)
        {
            selection.default_model = Some(model);
            *projection = projection_after_edit(managed_agents);
        }
    }

    /// Applies an explicit picker choice, including the confirmation required for an
    /// unknown-capability model in direct mode.
    pub fn select_model(&mut self, agent: AgentId, model_id: String) -> Result<(), String> {
        let Self::Connected {
            connection,
            managed_agents,
            projection,
            ..
        } = self
        else {
            return Ok(());
        };
        let capability = connection
            .models
            .iter()
            .find(|model| model.id == model_id)
            .map(|model| model.capability)
            .ok_or_else(|| format!("Model `{model_id}` is not in the catalog"))?;
        if capability == ModelCapability::NonChat {
            return Err(format!("Model `{model_id}` is not chat-capable"));
        }
        if connection.profile.mode == ConnectionMode::Direct
            && capability == ModelCapability::Unknown
        {
            connection
                .profile
                .confirm_direct_model(model_id.clone())
                .map_err(|error| error.to_string())?;
        }
        connection
            .profile
            .agents
            .get_mut(&agent)
            .expect("all Agent selections exist")
            .default_model = Some(model_id);
        *projection = projection_after_edit(managed_agents);
        Ok(())
    }

    pub fn set_projection_status(
        &mut self,
        installs: QueryStatus<Vec<AgentInstall>>,
        managed_agents: QueryStatus<BTreeSet<AgentId>>,
    ) {
        if let Self::Connected {
            installs: current_installs,
            managed_agents: current_managed,
            projection,
            ..
        } = self
        {
            let has_managed =
                matches!(&managed_agents, QueryStatus::Known(agents) if !agents.is_empty());
            *current_installs = installs;
            *current_managed = managed_agents;
            if matches!(
                projection,
                ProjectionLifecycle::NotPreviewed | ProjectionLifecycle::ManagedExisting
            ) {
                *projection = if has_managed {
                    ProjectionLifecycle::ManagedExisting
                } else {
                    ProjectionLifecycle::NotPreviewed
                };
            }
        }
    }

    pub fn set_preview(&mut self, plan: Plan) {
        if let Self::Connected { projection, .. } = self {
            *projection = ProjectionLifecycle::PreviewReady(Box::new(plan));
        }
    }

    pub fn start_apply(&mut self) -> Option<Plan> {
        let Self::Connected { projection, .. } = self else {
            return None;
        };
        let ProjectionLifecycle::PreviewReady(plan) = projection else {
            return None;
        };
        let plan = plan.as_ref().clone();
        *projection = ProjectionLifecycle::Applying;
        Some(plan)
    }

    pub fn finish_apply(&mut self, plan: Plan) {
        if let Self::Connected { projection, .. } = self
            && matches!(projection, ProjectionLifecycle::Applying)
        {
            *projection = ProjectionLifecycle::AppliedAwaitingVerification(Box::new(plan));
        }
    }

    pub fn fail_apply(&mut self) {
        if let Self::Connected { projection, .. } = self
            && matches!(projection, ProjectionLifecycle::Applying)
        {
            *projection = ProjectionLifecycle::ApplyFailed;
        }
    }

    pub fn start_verify(&mut self) -> Option<Plan> {
        let Self::Connected { projection, .. } = self else {
            return None;
        };
        let plan = match projection {
            ProjectionLifecycle::AppliedAwaitingVerification(plan) => plan.as_ref().clone(),
            _ => return None,
        };
        *projection = ProjectionLifecycle::Verifying;
        Some(plan)
    }

    pub fn finish_verify(&mut self, verification: Verification) {
        if let Self::Connected { projection, .. } = self
            && matches!(projection, ProjectionLifecycle::Verifying)
        {
            *projection = if verification.ok {
                ProjectionLifecycle::Verified(verification)
            } else {
                ProjectionLifecycle::VerificationFailed(verification)
            };
        }
    }

    pub fn fail_verify(&mut self) {
        if let Self::Connected { projection, .. } = self
            && matches!(projection, ProjectionLifecycle::Verifying)
        {
            *projection = ProjectionLifecycle::VerificationError;
        }
    }

    pub fn start_disconnect(&mut self) {
        if let Self::Connected { projection, .. } = self {
            *projection = ProjectionLifecycle::Disconnecting;
        }
    }

    pub fn fail_disconnect(&mut self) {
        if let Self::Connected { projection, .. } = self
            && matches!(projection, ProjectionLifecycle::Disconnecting)
        {
            *projection = ProjectionLifecycle::DisconnectFailed;
        }
    }

    pub fn mcp_evidence(&self) -> McpEvidence {
        match self {
            Self::Connected { projection, .. } if projection.has_projection_ownership() => {
                McpEvidence::ConfiguredForAgents
            }
            _ => McpEvidence::AvailableFromPlatform,
        }
    }
}

fn projection_after_edit(managed_agents: &QueryStatus<BTreeSet<AgentId>>) -> ProjectionLifecycle {
    if matches!(managed_agents, QueryStatus::Known(agents) if !agents.is_empty()) {
        ProjectionLifecycle::ManagedExisting
    } else {
        ProjectionLifecycle::NotPreviewed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_connector_backend::ModelDescriptor;
    use gateway_connector_core::{CanonicalBaseUrl, ConnectionProfile};

    #[test]
    fn selection_invalidates_preview() {
        let profile = ConnectionProfile::new(
            "Test",
            CanonicalBaseUrl::parse("https://example.com").expect("URL"),
            Protocol::Auto,
        )
        .expect("profile");
        let mut state = AppState::connected(ConnectionResult {
            profile,
            models: Vec::new(),
            manifest: None,
            provisioning: None,
            synchronized_skills: Default::default(),
        });
        let preview = PlanFixture::plan();
        state.set_preview(preview);
        state.update_protocol(AgentId::Codex, Protocol::OpenaiResponses);
        state.update_model(AgentId::Codex, "model-a".to_owned());
        let AppState::Connected { projection, .. } = state else {
            panic!("connected state")
        };
        assert!(matches!(projection, ProjectionLifecycle::NotPreviewed));
    }

    #[test]
    fn successful_apply_consumes_preview_and_verify_consumes_applied_plan() {
        let mut state = connected_fixture(Vec::new());
        state.set_preview(PlanFixture::plan());
        assert_eq!(
            projection_semantic(&state),
            ProjectionSemantic::PreviewReady
        );
        assert!(projection_lifecycle(&state).can_apply());
        assert!(!projection_lifecycle(&state).can_verify());
        assert_eq!(
            projection_semantic(&state).message(),
            "Fresh preview ready. No Agent files have been changed yet."
        );

        let plan = state.start_apply().expect("fresh preview can apply");
        assert_eq!(projection_semantic(&state), ProjectionSemantic::Applying);
        state.finish_apply(plan);
        assert_eq!(
            projection_semantic(&state),
            ProjectionSemantic::AppliedAwaitingVerification
        );
        assert!(!projection_lifecycle(&state).can_apply());
        assert!(projection_lifecycle(&state).can_verify());
        assert!(projection_lifecycle(&state).preview_plan().is_none());
        assert_eq!(
            projection_semantic(&state).message(),
            "Changes applied. Verify the managed files before continuing."
        );
        assert_eq!(state.mcp_evidence(), McpEvidence::ConfiguredForAgents);
        assert!(state.start_apply().is_none(), "preview token was consumed");

        assert!(
            state.start_verify().is_some(),
            "applied plan can verify once"
        );
        assert_eq!(projection_semantic(&state), ProjectionSemantic::Verifying);
        state.finish_verify(Verification {
            ok: true,
            mismatches: Vec::new(),
        });
        assert_eq!(projection_semantic(&state), ProjectionSemantic::Verified);
        assert!(state.start_verify().is_none(), "verified plan was consumed");
    }

    #[test]
    fn failed_operations_never_restore_a_consumed_preview() {
        let mut state = connected_fixture(Vec::new());
        state.set_preview(PlanFixture::plan());
        assert!(state.start_apply().is_some());
        state.fail_apply();
        assert_eq!(projection_semantic(&state), ProjectionSemantic::ApplyFailed);
        assert!(state.start_apply().is_none());

        state.set_preview(PlanFixture::plan());
        let plan = state.start_apply().expect("apply transition");
        state.finish_apply(plan);
        assert!(state.start_verify().is_some());
        state.fail_verify();
        assert_eq!(
            projection_semantic(&state),
            ProjectionSemantic::VerificationError
        );
        assert!(state.start_verify().is_none());

        state.start_disconnect();
        state.fail_disconnect();
        assert_eq!(
            projection_semantic(&state),
            ProjectionSemantic::DisconnectFailed
        );
    }

    #[test]
    fn receipt_status_and_edits_are_managed_existing_not_preview_ready() {
        let mut state = connected_fixture(Vec::new());
        state.set_projection_status(
            QueryStatus::Known(Vec::new()),
            QueryStatus::Known(BTreeSet::from([AgentId::Codex])),
        );
        assert_eq!(
            projection_semantic(&state),
            ProjectionSemantic::ManagedExisting
        );
        assert_eq!(state.mcp_evidence(), McpEvidence::AvailableFromPlatform);

        state.set_preview(PlanFixture::plan());
        state.update_protocol(AgentId::Codex, Protocol::OpenaiResponses);
        assert_eq!(
            projection_semantic(&state),
            ProjectionSemantic::ManagedExisting
        );
        assert_ne!(
            projection_semantic(&state),
            ProjectionSemantic::PreviewReady
        );
    }

    #[test]
    fn lifecycle_and_mcp_evidence_render_truthfully_in_both_locales() {
        use crate::preferences::Locale;

        let applied = ProjectionSemantic::AppliedAwaitingVerification.message();
        assert_eq!(
            Locale::En.text(applied),
            "Changes applied. Verify the managed files before continuing."
        );
        assert_eq!(
            Locale::ZhCn.text(applied),
            "更改已应用。请先验证托管文件再继续。"
        );
        for (evidence, english, chinese) in [
            (
                McpEvidence::AvailableFromPlatform,
                "Available from platform",
                "平台提供",
            ),
            (
                McpEvidence::ConfiguredForAgents,
                "Configured for Agents",
                "已为 Agent 配置",
            ),
        ] {
            assert_eq!(evidence.label(), english);
            assert_eq!(Locale::En.text(evidence.label()), english);
            assert_eq!(Locale::ZhCn.text(evidence.label()), chinese);
        }
    }

    #[test]
    fn direct_mode_has_no_invented_service_or_platform_pages() {
        for page in [
            Page::Services,
            Page::Account,
            Page::Usage,
            Page::Billing,
            Page::ModelPlaza,
        ] {
            assert!(!page.available(None), "{page:?}");
        }
        assert!(Page::Agent(AgentId::Claude).available(None));
        assert!(Page::Settings.available(None));
    }

    #[test]
    fn projection_status_preserves_independent_errors() {
        let mut state = connected_fixture(Vec::new());
        state.set_projection_status(
            QueryStatus::Error("discovery failed".into()),
            QueryStatus::Error("coordinator failed".into()),
        );
        let AppState::Connected {
            installs,
            managed_agents,
            ..
        } = state
        else {
            panic!("connected")
        };
        assert!(matches!(installs, QueryStatus::Error(error) if error == "discovery failed"));
        assert_eq!(
            managed_agents,
            QueryStatus::Error("coordinator failed".into())
        );
    }

    #[test]
    fn explicit_unknown_selection_confirms_but_non_chat_is_rejected() {
        let models = [
            ("unknown", ModelCapability::Unknown),
            ("embedding", ModelCapability::NonChat),
        ]
        .into_iter()
        .map(|(id, capability)| ModelDescriptor {
            id: id.into(),
            capability,
            owned_by: None,
            created: None,
            object: None,
            metadata: Default::default(),
        })
        .collect();
        let mut state = connected_fixture(models);
        state
            .select_model(AgentId::Claude, "unknown".into())
            .expect("explicit confirmation");
        let AppState::Connected { connection, .. } = &state else {
            panic!("connected")
        };
        assert!(
            connection
                .profile
                .confirmed_direct_models
                .contains("unknown")
        );
        assert!(
            state
                .select_model(AgentId::Claude, "embedding".into())
                .is_err()
        );
    }

    fn connected_fixture(models: Vec<ModelDescriptor>) -> AppState {
        let profile = ConnectionProfile::new(
            "Test",
            CanonicalBaseUrl::parse("https://example.com").expect("URL"),
            Protocol::Auto,
        )
        .expect("profile");
        AppState::connected(ConnectionResult {
            profile,
            models,
            manifest: None,
            provisioning: None,
            synchronized_skills: Default::default(),
        })
    }

    fn projection_semantic(state: &AppState) -> ProjectionSemantic {
        projection_lifecycle(state).semantic()
    }

    fn projection_lifecycle(state: &AppState) -> &ProjectionLifecycle {
        let AppState::Connected { projection, .. } = state else {
            panic!("connected")
        };
        projection
    }

    struct PlanFixture;

    impl PlanFixture {
        fn plan() -> Plan {
            use gateway_connector_core::{
                AgentInstall, ApplyInput, ConnectionManifest, Connector, Gateway, Model, Platform,
                Provisioning, Secret,
            };
            let temp = tempfile::tempdir().expect("temp");
            let temp_root = std::fs::canonicalize(temp.path()).expect("canonical temp root");
            let root = temp_root.join("codex");
            std::fs::create_dir(&root).expect("Agent root");
            let manifest = ConnectionManifest::direct(
                Platform {
                    id: "test".into(),
                    name: "Test".into(),
                },
                Gateway {
                    base_url: "https://gateway.example".parse().expect("URL"),
                    protocols: vec!["openai_responses".into()],
                },
                "https://gateway.example".parse().expect("URL"),
                vec![AgentId::Codex],
            )
            .expect("manifest");
            let provisioning = Provisioning::direct(
                vec![Model {
                    id: "model-a".into(),
                    chat_capable: true,
                    description: None,
                    icon: None,
                    tags: Vec::new(),
                    vendor: None,
                }],
                "model-a".into(),
            )
            .expect("provisioning");
            Connector::new(temp_root.join("state"))
                .plan(ApplyInput {
                    manifest: &manifest,
                    provisioning: &provisioning,
                    bearer: &Secret::new("secret").expect("secret"),
                    selected_models: Default::default(),
                    installs: vec![AgentInstall {
                        agent: AgentId::Codex,
                        root,
                        detected: true,
                    }],
                    synchronized_skills: Default::default(),
                })
                .expect("plan")
        }
    }
}
