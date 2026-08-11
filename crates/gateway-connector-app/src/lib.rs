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
        preview: Option<Box<Plan>>,
        verification: Option<Verification>,
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

impl AppState {
    pub fn connected(result: ConnectionResult) -> Self {
        Self::Connected {
            connection: Box::new(result),
            installs: QueryStatus::Unknown,
            managed_agents: QueryStatus::Unknown,
            preview: None,
            verification: None,
        }
    }

    pub fn update_protocol(&mut self, agent: AgentId, protocol: Protocol) {
        if let Self::Connected {
            connection,
            preview,
            verification,
            ..
        } = self
            && let Some(selection) = connection.profile.agents.get_mut(&agent)
        {
            selection.protocol = protocol;
            *preview = None;
            *verification = None;
        }
    }

    pub fn update_model(&mut self, agent: AgentId, model: String) {
        if let Self::Connected {
            connection,
            preview,
            verification,
            ..
        } = self
            && let Some(selection) = connection.profile.agents.get_mut(&agent)
        {
            selection.default_model = Some(model);
            *preview = None;
            *verification = None;
        }
    }

    /// Applies an explicit picker choice, including the confirmation required for an
    /// unknown-capability model in direct mode.
    pub fn select_model(&mut self, agent: AgentId, model_id: String) -> Result<(), String> {
        let Self::Connected {
            connection,
            preview,
            verification,
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
        *preview = None;
        *verification = None;
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
            ..
        } = self
        {
            *current_installs = installs;
            *current_managed = managed_agents;
        }
    }

    pub fn set_preview(&mut self, plan: Plan) {
        if let Self::Connected {
            preview,
            verification,
            ..
        } = self
        {
            *preview = Some(Box::new(plan));
            *verification = None;
        }
    }

    pub fn clear_preview(&mut self) {
        if let Self::Connected {
            preview,
            verification,
            ..
        } = self
        {
            *preview = None;
            *verification = None;
        }
    }

    pub fn set_verification(&mut self, value: Verification) {
        if let Self::Connected { verification, .. } = self {
            *verification = Some(value);
        }
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
        let AppState::Connected { preview, .. } = state else {
            panic!("connected state")
        };
        assert!(preview.is_none());
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
