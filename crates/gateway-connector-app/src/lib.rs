//! Testable application state kept independent from GPUI rendering.

use std::collections::BTreeSet;

use gateway_connector_backend::ConnectionResult;
use gateway_connector_core::{AgentId, AgentInstall, Plan, Protocol, Verification};

#[derive(Debug, Default)]
pub enum AppState {
    #[default]
    Loading,
    FirstRun,
    Connecting,
    Connected {
        connection: Box<ConnectionResult>,
        installs: Vec<AgentInstall>,
        managed_agents: BTreeSet<AgentId>,
        preview: Option<Box<Plan>>,
        verification: Option<Verification>,
    },
    Failed(String),
}

impl AppState {
    pub fn connected(result: ConnectionResult) -> Self {
        Self::Connected {
            connection: Box::new(result),
            installs: Vec::new(),
            managed_agents: BTreeSet::new(),
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

    pub fn set_projection_status(
        &mut self,
        installs: Vec<AgentInstall>,
        managed_agents: BTreeSet<AgentId>,
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

    struct PlanFixture;

    impl PlanFixture {
        fn plan() -> Plan {
            use gateway_connector_core::{
                AgentInstall, ApplyInput, ConnectionManifest, Connector, Gateway, Model, Platform,
                Provisioning, Secret,
            };
            let temp = tempfile::tempdir().expect("temp");
            let root = temp.path().join("codex");
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
            Connector::new(temp.path().join("state"))
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
