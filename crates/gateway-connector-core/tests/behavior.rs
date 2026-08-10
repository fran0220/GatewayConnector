#![allow(clippy::unwrap_used)]

use gateway_connector_core::{
    AgentId, AgentInstall, ApplyInput, ConnectionManifest, Connector, Gateway, Platform,
    Provisioning, Secret,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Write, path::Path};
use tempfile::tempdir;

fn contracts() -> (ConnectionManifest, Provisioning) {
    let manifest=ConnectionManifest::parse(br#"{"success":true,"data":{"schema_version":2,"platform":{"id":"platform-a","name":"Platform A"},"authentication":{"type":"browser_pkce","authorize_url":"https://id.example/auth","token_url":"https://id.example/token"},"gateway":{"base_url":"https://gw.example","protocols":["openai"]},"provisioning_url":"https://gw.example/provision","connection_bearer_origins":["https://gw.example"],"supported_agents":["claude","codex","gemini","grokbuild","opencode"]}}"#).unwrap();
    let provisioning=Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"alpha","chat_capable":true},{"id":"beta","chat_capable":true}],"default_model":"alpha","mcp_servers":[{"id":"docs","name":"Docs","url":"https://gw.example/mcp/docs","authorization":"connection_bearer","description":"docs"}],"skills":[{"id":"deploy","name":"Deploy","version":"1.0.0","archive":{"url":"https://gw.example/skills/deploy.zip","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size_bytes":1,"format":"zip","authorization":"none"}}]}}"#).unwrap();
    (manifest, provisioning)
}

#[test]
fn authentication_is_optional_and_direct_manifests_use_the_exact_gateway_origin() {
    let manifest = ConnectionManifest::direct(
        Platform {
            id: "direct".into(),
            name: "Direct".into(),
        },
        Gateway {
            base_url: "https://gateway.example/nested".parse().unwrap(),
            protocols: vec!["openai".into()],
        },
        "https://gateway.example/provision".parse().unwrap(),
        vec![AgentId::Codex],
    )
    .unwrap();
    assert!(manifest.authentication.is_none());
    assert_eq!(
        manifest.connection_bearer_origins[0].as_str(),
        "https://gateway.example/"
    );

    let missing_gateway_origin = br#"{"success":true,"data":{"schema_version":2,"platform":{"id":"direct","name":"Direct"},"gateway":{"base_url":"https://gateway.example","protocols":[]},"provisioning_url":"https://gateway.example/provision","connection_bearer_origins":["https://other.example"],"supported_agents":["codex"]}}"#;
    assert!(ConnectionManifest::parse(missing_gateway_origin).is_err());
}
fn managed(platform: &str, kind: &str, id: &str) -> String {
    let mut hash = Sha256::new();
    for value in [platform, kind, id] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    format!("connector-{kind}-{:x}", hash.finalize())
}

#[test]
fn parses_full_additive_provisioning_contract() {
    let value = Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"account":{"id":7,"username":"user","display_name":"User","email":"user@example.test","group":"pro"},"usage":{"wallet_quota_remaining":75,"lifetime_quota_used":25,"lifetime_request_count":9},"billing":{"portal_url":"https://billing.example/portal","wallet_fallback_allowed":true,"subscriptions":[{"id":11,"plan_id":3,"status":"active","unlimited":false,"quota_total":100,"quota_used_current_period":25,"current_period_start":1,"end_time":3,"next_reset_time":2,"wallet_fallback":true}]},"model_plaza":{"portal_url":"https://models.example/","models":[{"id":"embed","chat_capable":false,"description":"Embeddings","icon":"spark","tags":["embedding"],"vendor":{"id":42,"name":"Vendor","icon":"example"}},{"id":"chat","chat_capable":true,"tags":[]}]},"models":[{"id":"chat","chat_capable":true,"tags":[]}],"default_model":"chat","mcp_servers":[],"skills":[]}}"#).unwrap();
    assert_eq!(value.account.as_ref().unwrap().group, "pro");
    assert_eq!(value.usage.as_ref().unwrap().wallet_quota_remaining, 75);
    let plaza = value.model_plaza.as_ref().unwrap();
    assert!(!plaza.models[0].chat_capable);
    assert_eq!(plaza.models[0].vendor.as_ref().unwrap().name, "Vendor");
    assert_eq!(plaza.models[0].vendor.as_ref().unwrap().id, 42);
    assert_eq!(value.models.len(), 1);
}

#[test]
fn non_chat_models_are_catalogued_but_never_defaulted_or_projected() {
    let non_chat_only = Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"model_plaza":{"portal_url":"https://models.example/","models":[{"id":"embed","chat_capable":false}]},"models":[],"default_model":"","mcp_servers":[],"skills":[]}}"#).unwrap();
    assert!(Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"model_plaza":{"portal_url":"https://models.example/","models":[{"id":"embed","chat_capable":false}]},"models":[{"id":"embed","chat_capable":false}],"default_model":"embed","mcp_servers":[],"skills":[]}}"#).is_err());
    assert!(Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"model_plaza":{"portal_url":"https://models.example/","models":[]},"models":[{"id":"chat","chat_capable":true}],"default_model":"chat","mcp_servers":[],"skills":[]}}"#).is_err());

    let (manifest, _) = contracts();
    let t = tempdir().unwrap();
    let root = t.path().join("codex");
    fs::create_dir_all(&root).unwrap();
    let error = Connector::new(t.path().join("state"))
        .plan(ApplyInput {
            manifest: &manifest,
            provisioning: &non_chat_only,
            bearer: &Secret::new("secret").unwrap(),
            selected_models: BTreeMap::from([(AgentId::Codex, "embed".into())]),
            installs: vec![AgentInstall {
                agent: AgentId::Codex,
                root,
                detected: true,
            }],
            synchronized_skills: BTreeMap::new(),
        })
        .unwrap_err()
        .to_string();
    assert!(error.contains("no chat-capable model"), "{error}");
}
fn setup(root: &Path) -> (Connector, gateway_connector_core::Plan) {
    let (m, p) = contracts();
    let skill = root.join("source-skill");
    fs::create_dir_all(&skill).unwrap();
    fs::write(skill.join("SKILL.md"), "verified").unwrap();
    let agents = [
        AgentId::Claude,
        AgentId::Codex,
        AgentId::Gemini,
        AgentId::Grokbuild,
        AgentId::Opencode,
    ];
    let installs = agents
        .into_iter()
        .map(|agent| {
            let dir = root.join(agent.as_str());
            fs::create_dir_all(&dir).unwrap();
            AgentInstall {
                agent,
                root: dir,
                detected: true,
            }
        })
        .collect();
    fs::write(
        root.join("claude/settings.json"),
        r#"{"theme":"dark","env":{"KEEP":"yes"}}"#,
    )
    .unwrap();
    fs::write(
        root.join("claude/.claude.json"),
        r#"{"other":1,"mcpServers":{"mine":{"command":"x"}}}"#,
    )
    .unwrap();
    fs::write(
        root.join("codex/config.toml"),
        "# keep-comment\nsandbox = \"workspace-write\"\n",
    )
    .unwrap();
    fs::write(root.join("gemini/.env"), "# keep\nOTHER=yes\n").unwrap();
    fs::write(
        root.join("gemini/settings.json"),
        r#"{"theme":"x","mcpServers":{"mine":{"command":"x"}}}"#,
    )
    .unwrap();
    fs::write(
        root.join("grokbuild/config.toml"),
        "# grok-comment\nkeep = true\n",
    )
    .unwrap();
    fs::write(
        root.join("opencode/opencode.json"),
        "{// comment\n\"theme\":\"dark\",\"provider\":{\"mine\":{}},\"mcp\":{\"mine\":{}}}",
    )
    .unwrap();
    for a in ["claude", "codex", "gemini", "grokbuild", "opencode"] {
        let d = root.join(a).join("skills/unmanaged");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("x"), "keep").unwrap();
    }
    let connector = Connector::new(root.join("state"));
    let mut skills = BTreeMap::new();
    skills.insert("deploy".into(), skill);
    let plan = connector
        .plan(ApplyInput {
            manifest: &m,
            provisioning: &p,
            bearer: &Secret::new("super-secret").unwrap(),
            selected_models: BTreeMap::from([(AgentId::Codex, "beta".into())]),
            installs,
            synchronized_skills: skills,
        })
        .unwrap();
    (connector, plan)
}

#[test]
fn projects_all_clients_preserves_and_disconnects_owned_entries() {
    let t = tempdir().unwrap();
    let (c, p) = setup(t.path());
    let provider = managed("platform-a", "provider", "default");
    let mcp = managed("platform-a", "mcp", "docs");
    let skill = "deploy";
    // One SSOT staging operation plus one target per Agent (not one SSOT copy
    // per Agent), in addition to the seven configuration projections.
    assert_eq!(p.changes.len(), 13);
    assert!(!format!("{p:?}").contains("super-secret"));
    c.apply(&p).unwrap();
    assert!(c.verify(&p).unwrap().ok);
    let claude: Value =
        serde_json::from_slice(&fs::read(t.path().join("claude/settings.json")).unwrap()).unwrap();
    assert_eq!(claude["theme"], "dark");
    assert_eq!(claude["env"]["ANTHROPIC_MODEL"], "alpha");
    let cm: Value =
        serde_json::from_slice(&fs::read(t.path().join("claude/.claude.json")).unwrap()).unwrap();
    assert!(
        cm["mcpServers"][&mcp]["headers"]["Authorization"]
            .as_str()
            .unwrap()
            .starts_with("Bearer ")
    );
    assert!(cm["mcpServers"]["mine"].is_object());
    let codex = fs::read_to_string(t.path().join("codex/config.toml")).unwrap();
    assert!(
        codex.contains("# keep-comment")
            && codex.contains("wire_api = \"responses\"")
            && codex.contains("model = \"beta\"")
            && codex.contains("http_headers"),
        "{codex}"
    );
    let env = fs::read_to_string(t.path().join("gemini/.env")).unwrap();
    assert!(
        env.contains("# keep")
            && env.contains("OTHER=yes")
            && env.contains("GEMINI_MODEL=\"alpha\"")
    );
    let gem: Value =
        serde_json::from_slice(&fs::read(t.path().join("gemini/settings.json")).unwrap()).unwrap();
    assert_eq!(gem["security"]["auth"]["selectedType"], "gemini-api-key");
    assert_eq!(gem["model"]["name"], "alpha");
    assert!(gem["mcpServers"][&mcp]["httpUrl"].is_string());
    let grok = fs::read_to_string(t.path().join("grokbuild/config.toml")).unwrap();
    assert!(
        grok.contains("# grok-comment")
            && grok.contains(&format!("default = \"{provider}\""))
            && grok.contains(&format!("[model.{provider}]"))
            && grok.contains("api_backend = \"responses\"")
            && grok.contains("headers")
    );
    let oc: Value =
        serde_json::from_slice(&fs::read(t.path().join("opencode/opencode.json")).unwrap())
            .unwrap();
    assert_eq!(oc["theme"], "dark");
    assert_eq!(oc["model"], format!("{provider}/alpha"));
    assert!(oc["provider"][&provider]["models"]["beta"].is_object());
    assert_eq!(oc["mcp"][&mcp]["type"], "remote");
    for a in ["claude", "codex", "gemini", "grokbuild", "opencode"] {
        assert!(
            t.path()
                .join(a)
                .join("skills")
                .join(skill)
                .join("SKILL.md")
                .exists()
        );
        assert!(t.path().join(a).join("skills/unmanaged/x").exists());
    }
    let bearer = Secret::new("super-secret").unwrap();
    c.disconnect("platform-a", &bearer).unwrap();
    c.disconnect("platform-a", &bearer).unwrap();
    assert!(t.path().join("claude/skills/unmanaged/x").exists());
    assert!(!t.path().join("state/skills/platform-a/deploy").exists());
    assert!(!t.path().join("claude/skills").join(skill).exists());
    assert!(!t.path().join("state/receipts/platform-a.json").exists());
    assert_eq!(
        fs::read_to_string(t.path().join("opencode/opencode.json")).unwrap(),
        "{// comment\n\"theme\":\"dark\",\"provider\":{\"mine\":{}},\"mcp\":{\"mine\":{}}}"
    );
}

#[test]
fn rejects_schema_and_security_errors() {
    let bad = |s: &str| ConnectionManifest::parse(s.as_bytes());
    let base = r#"{"success":true,"data":{"schema_version":VERSION,"platform":{"id":"x","name":"X"},"authentication":{"type":"browser_pkce","authorize_url":"https://x/a","token_url":"https://x/t"},"gateway":{"base_url":"URL","protocols":[]},"provisioning_url":"https://x/p","connection_bearer_origins":["https://x"],"supported_agents":["codex"]}}"#;
    assert!(bad(&base.replace("VERSION", "3").replace("URL", "https://x")).is_err());
    assert!(
        bad(&base
            .replace("VERSION", "2")
            .replace("URL", "http://evil.example"))
        .is_err()
    );
    assert!(Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"x","chat_capable":true}],"default_model":"missing","mcp_servers":[],"skills":[]}}"#).is_err());
    assert!(Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"x","chat_capable":true}],"default_model":"x","mcp_servers":[{"id":"m","name":"m","url":"http://localhost/m","authorization":"connection_bearer"}],"skills":[]}}"#).is_err());
    assert!(Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"openai/gpt-5:latest","chat_capable":true}],"default_model":"openai/gpt-5:latest","mcp_servers":[],"skills":[]}}"#).is_ok());
    assert!(Provisioning::parse(b"{\"success\":true,\"data\":{\"schema_version\":2,\"models\":[{\"id\":\"bad\\nmodel\",\"chat_capable\":true}],\"default_model\":\"bad\\nmodel\",\"mcp_servers\":[],\"skills\":[]}}").is_err());
    let (manifest, mut provisioning) = contracts();
    provisioning.mcp_servers[0].url = "https://attacker.example/mcp".parse().unwrap();
    assert!(provisioning.validate_for(&manifest).is_err());
    provisioning.skills.clear();
    let temp = tempdir().unwrap();
    assert!(
        Connector::new(temp.path().join("state"))
            .plan(ApplyInput {
                manifest: &manifest,
                provisioning: &provisioning,
                bearer: &Secret::new("secret").unwrap(),
                selected_models: BTreeMap::new(),
                installs: vec![],
                synchronized_skills: BTreeMap::new(),
            })
            .is_err()
    );
    assert!(Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"x","chat_capable":true}],"default_model":"x","mcp_servers":[],"skills":[{"id":"large","name":"Large","version":"1.0.0","archive":{"url":"https://gw.example/large.zip","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size_bytes":67108865,"format":"zip","authorization":"none"}}]}}"#).is_err());
    assert!(Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"x","chat_capable":true}],"default_model":"x","mcp_servers":[],"skills":[{"id":"con.tools","name":"Reserved","version":"1.0.0","archive":{"url":"https://gw.example/con.zip","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size_bytes":1,"format":"zip","authorization":"none"}}]}}"#).is_err());
    assert!(
        bad(&base
            .replace("VERSION", "2")
            .replace("URL", "https://x")
            .replace("\"id\":\"x\"", "\"id\":\"con\""))
        .is_err()
    );
    assert!(!format!("{:?}", Secret::new("needle").unwrap()).contains("needle"));
}

#[test]
fn provisioning_enforces_catalog_and_description_bounds() {
    let (_, base) = contracts();
    let mcp = base.mcp_servers[0].clone();
    let mut provisioning = base.clone();
    provisioning.mcp_servers = (0..256)
        .map(|index| {
            let mut item = mcp.clone();
            item.id = format!("mcp-{index}");
            item
        })
        .collect();
    assert!(provisioning.validate().is_ok());
    let mut extra = mcp.clone();
    extra.id = "mcp-256".into();
    provisioning.mcp_servers.push(extra);
    assert!(
        provisioning
            .validate()
            .unwrap_err()
            .to_string()
            .contains("exceeds 256 entries")
    );

    let skill = base.skills[0].clone();
    provisioning = base.clone();
    provisioning.skills = (0..256)
        .map(|index| {
            let mut item = skill.clone();
            item.id = format!("skill-{index}");
            item
        })
        .collect();
    assert!(provisioning.validate().is_ok());
    let mut extra = skill;
    extra.id = "skill-256".into();
    provisioning.skills.push(extra);
    assert!(
        provisioning
            .validate()
            .unwrap_err()
            .to_string()
            .contains("exceeds 256 entries")
    );

    provisioning = base;
    provisioning.mcp_servers[0].description = Some("x".repeat(1024));
    assert!(provisioning.validate().is_ok());
    provisioning.mcp_servers[0].description = Some("x".repeat(1025));
    assert!(provisioning.validate().is_err());
    provisioning.mcp_servers[0].description = Some("bad\ndescription".into());
    assert!(provisioning.validate().is_err());
}

#[test]
fn empty_catalog_is_honest_but_cannot_be_projected_and_duplicates_fail() {
    let empty = Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[],"default_model":"","mcp_servers":[],"skills":[]}}"#).unwrap();
    let (manifest, _) = contracts();
    let t = tempdir().unwrap();
    let error = Connector::new(t.path().join("state"))
        .plan(ApplyInput {
            manifest: &manifest,
            provisioning: &empty,
            bearer: &Secret::new("x").unwrap(),
            selected_models: BTreeMap::new(),
            installs: vec![],
            synchronized_skills: BTreeMap::new(),
        })
        .unwrap_err()
        .to_string();
    assert!(error.contains("no chat-capable model"), "{error}");
    assert!(Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"x","chat_capable":true},{"id":"x","chat_capable":true}],"default_model":"x","mcp_servers":[],"skills":[]}}"#).is_err());
}

#[test]
fn discovery_honors_override_then_environment_without_creating_paths() {
    use gateway_connector_core::Discovery;
    let t = tempdir().unwrap();
    let home = t.path().join("home");
    let override_path = t.path().join("override");
    let codex_env = t.path().join("codex-env");
    let grok_env = t.path().join("grok-env");
    let xdg = t.path().join("xdg");
    let discovery = Discovery {
        overrides: BTreeMap::from([(AgentId::Codex, override_path.clone())]),
    };
    let found = discovery.discover_with(&home, |key| match key {
        "CODEX_HOME" => Some(codex_env.clone()),
        "GROK_HOME" => Some(grok_env.clone()),
        "XDG_CONFIG_HOME" => Some(xdg.clone()),
        _ => None,
    });
    let root = |agent| {
        found
            .iter()
            .find(|x| x.agent == agent)
            .unwrap()
            .root
            .clone()
    };
    assert_eq!(root(AgentId::Codex), override_path);
    assert_eq!(root(AgentId::Grokbuild), grok_env);
    assert_eq!(root(AgentId::Opencode), xdg.join("opencode"));
    assert!(found.iter().all(|x| !x.detected));
    assert!(!home.exists() && !codex_env.exists() && !xdg.exists());
}

#[test]
fn duplicate_projection_paths_and_unknown_managed_entries_are_rejected() {
    let t = tempdir().unwrap();
    let (manifest, _) = contracts();
    let provisioning = Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"alpha","chat_capable":true}],"default_model":"alpha","mcp_servers":[],"skills":[]}}"#).unwrap();
    let shared = t.path().join("shared");
    fs::create_dir_all(&shared).unwrap();
    let connector = Connector::new(t.path().join("state"));
    let error = connector
        .plan(ApplyInput {
            manifest: &manifest,
            provisioning: &provisioning,
            bearer: &Secret::new("secret").unwrap(),
            selected_models: BTreeMap::new(),
            installs: vec![
                AgentInstall {
                    agent: AgentId::Codex,
                    root: shared.clone(),
                    detected: true,
                },
                AgentInstall {
                    agent: AgentId::Grokbuild,
                    root: shared,
                    detected: true,
                },
            ],
            synchronized_skills: BTreeMap::new(),
        })
        .unwrap_err()
        .to_string();
    assert!(error.contains("same path"), "{error}");

    let opencode = t.path().join("opencode");
    fs::create_dir_all(&opencode).unwrap();
    let provider = managed("platform-a", "provider", "default");
    fs::write(
        opencode.join("opencode.json"),
        serde_json::to_vec(&serde_json::json!({"provider":{provider:{"user":true}}})).unwrap(),
    )
    .unwrap();
    let error = connector
        .plan(ApplyInput {
            manifest: &manifest,
            provisioning: &provisioning,
            bearer: &Secret::new("secret").unwrap(),
            selected_models: BTreeMap::new(),
            installs: vec![AgentInstall {
                agent: AgentId::Opencode,
                root: opencode,
                detected: true,
            }],
            synchronized_skills: BTreeMap::new(),
        })
        .unwrap_err()
        .to_string();
    assert!(error.contains("collides with unknown"), "{error}");
}

#[test]
fn independently_branded_connectors_share_agent_ownership_leases() {
    let t = tempdir().unwrap();
    let (first_manifest, _) = contracts();
    let provisioning = Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"alpha","chat_capable":true}],"default_model":"alpha","mcp_servers":[],"skills":[]}}"#).unwrap();
    let codex = t.path().join("codex");
    fs::create_dir_all(&codex).unwrap();
    let install = AgentInstall {
        agent: AgentId::Codex,
        root: codex,
        detected: true,
    };
    let alias_parent = t.path().join("alias-parent");
    fs::create_dir_all(&alias_parent).unwrap();
    let coordinator = t.path().join("shared-coordinator");
    let first_connector = Connector::with_coordinator(t.path().join("first-state"), &coordinator);
    let first_plan = first_connector
        .plan(ApplyInput {
            manifest: &first_manifest,
            provisioning: &provisioning,
            bearer: &Secret::new("first-secret").unwrap(),
            selected_models: BTreeMap::new(),
            installs: vec![install.clone()],
            synchronized_skills: BTreeMap::new(),
        })
        .unwrap();
    first_connector.apply(&first_plan).unwrap();

    let mut second_manifest = first_manifest.clone();
    second_manifest.platform.id = "platform-b".into();
    second_manifest.platform.name = "Platform B".into();
    let second_connector = Connector::with_coordinator(t.path().join("second-state"), &coordinator);
    let error = second_connector
        .plan(ApplyInput {
            manifest: &second_manifest,
            provisioning: &provisioning,
            bearer: &Secret::new("second-secret").unwrap(),
            selected_models: BTreeMap::new(),
            installs: vec![AgentInstall {
                root: alias_parent.join("../codex"),
                ..install.clone()
            }],
            synchronized_skills: BTreeMap::new(),
        })
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("already managed by platform platform-a"),
        "{error}"
    );

    #[cfg(unix)]
    {
        let symlink = t.path().join("codex-link");
        std::os::unix::fs::symlink(&install.root, &symlink).unwrap();
        let error = second_connector
            .plan(ApplyInput {
                manifest: &second_manifest,
                provisioning: &provisioning,
                bearer: &Secret::new("second-secret").unwrap(),
                selected_models: BTreeMap::new(),
                installs: vec![AgentInstall {
                    root: symlink,
                    ..install.clone()
                }],
                synchronized_skills: BTreeMap::new(),
            })
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("already managed by platform platform-a"),
            "{error}"
        );
    }

    first_connector
        .disconnect("platform-a", &Secret::new("first-secret").unwrap())
        .unwrap();
    let second_plan = second_connector
        .plan(ApplyInput {
            manifest: &second_manifest,
            provisioning: &provisioning,
            bearer: &Secret::new("second-secret").unwrap(),
            selected_models: BTreeMap::new(),
            installs: vec![install],
            synchronized_skills: BTreeMap::new(),
        })
        .unwrap();
    second_connector.apply(&second_plan).unwrap();
}

#[cfg(unix)]
#[test]
fn configuration_symlinks_are_rejected_without_replacing_them() {
    let t = tempdir().unwrap();
    let (manifest, _) = contracts();
    let provisioning = Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"alpha","chat_capable":true}],"default_model":"alpha","mcp_servers":[],"skills":[]}}"#).unwrap();
    let codex = t.path().join("codex");
    fs::create_dir_all(&codex).unwrap();
    let target = t.path().join("dotfiles-codex.toml");
    fs::write(&target, "keep = true\n").unwrap();
    std::os::unix::fs::symlink(&target, codex.join("config.toml")).unwrap();

    let error = Connector::new(t.path().join("state"))
        .plan(ApplyInput {
            manifest: &manifest,
            provisioning: &provisioning,
            bearer: &Secret::new("secret").unwrap(),
            selected_models: BTreeMap::new(),
            installs: vec![AgentInstall {
                agent: AgentId::Codex,
                root: codex.clone(),
                detected: true,
            }],
            synchronized_skills: BTreeMap::new(),
        })
        .unwrap_err()
        .to_string();
    assert!(error.contains("symlinks are not supported"), "{error}");
    assert!(
        fs::symlink_metadata(codex.join("config.toml"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(target).unwrap(), "keep = true\n");
}

#[test]
fn skill_replacement_requires_both_owner_marker_and_framed_tree_hash() {
    let t = tempdir().unwrap();
    let (manifest, _) = contracts();
    let provisioning = Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"alpha","chat_capable":true}],"default_model":"alpha","mcp_servers":[],"skills":[{"id":"deploy","name":"Deploy","version":"1.0.0","archive":{"url":"https://gw.example/skills/deploy.zip","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size_bytes":1,"format":"zip","authorization":"none"}}]}}"#).unwrap();
    let source = t.path().join("source");
    let claude = t.path().join("claude");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&claude).unwrap();
    fs::write(source.join("a"), "bc").unwrap();
    let connector = Connector::new(t.path().join("state"));
    let plan = connector
        .plan(ApplyInput {
            manifest: &manifest,
            provisioning: &provisioning,
            bearer: &Secret::new("secret").unwrap(),
            selected_models: BTreeMap::new(),
            installs: vec![AgentInstall {
                agent: AgentId::Claude,
                root: claude.clone(),
                detected: true,
            }],
            synchronized_skills: BTreeMap::from([("deploy".into(), source)]),
        })
        .unwrap();
    connector.apply(&plan).unwrap();
    let target = claude.join("skills/deploy");
    let marker = fs::read(target.join(".gateway-connector-owner")).unwrap();
    fs::remove_dir_all(&target).unwrap();
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("ab"), "c").unwrap();
    fs::write(target.join(".gateway-connector-owner"), marker).unwrap();

    let error = connector
        .disconnect("platform-a", &Secret::new("secret").unwrap())
        .unwrap_err()
        .to_string();
    assert!(error.contains("local changes"), "{error}");
    assert!(target.join("ab").exists());
    assert!(t.path().join("state/receipts/platform-a.json").exists());
}

#[test]
fn reapply_keeps_first_original_and_drift_disconnect_is_semantic() {
    let t = tempdir().unwrap();
    let original = fs::read(t.path().join("nothing")).ok();
    assert!(original.is_none());
    let (c, first) = setup(t.path());
    let original_codex = fs::read(t.path().join("codex/config.toml")).unwrap();
    c.apply(&first).unwrap();
    let (_, second) = setup(t.path());
    c.apply(&second).unwrap();
    let opencode = t.path().join("opencode/opencode.json");
    let mut drift: Value = serde_json::from_slice(&fs::read(&opencode).unwrap()).unwrap();
    drift["user_after"] = Value::Bool(true);
    fs::write(&opencode, serde_json::to_vec_pretty(&drift).unwrap()).unwrap();
    c.disconnect("platform-a", &Secret::new("super-secret").unwrap())
        .unwrap();
    assert_eq!(
        fs::read(t.path().join("codex/config.toml")).unwrap(),
        original_codex
    );
    let after: Value = serde_json::from_slice(&fs::read(opencode).unwrap()).unwrap();
    assert_eq!(after["user_after"], true);
    assert!(after["provider"][managed("platform-a", "provider", "default")].is_null());
}

#[test]
fn reapply_removes_stale_mcp_and_skill_ownership() {
    let t = tempdir().unwrap();
    let mcp = managed("platform-a", "mcp", "docs");
    let skill = "deploy";
    let (connector, first) = setup(t.path());
    connector.apply(&first).unwrap();
    let (manifest, _) = contracts();
    let provisioning = Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"alpha","chat_capable":true}],"default_model":"alpha","mcp_servers":[],"skills":[]}}"#).unwrap();
    let installs = [
        AgentId::Claude,
        AgentId::Codex,
        AgentId::Gemini,
        AgentId::Grokbuild,
        AgentId::Opencode,
    ]
    .into_iter()
    .map(|agent| AgentInstall {
        agent,
        root: t.path().join(agent.as_str()),
        detected: true,
    })
    .collect();
    let second = connector
        .plan(ApplyInput {
            manifest: &manifest,
            provisioning: &provisioning,
            bearer: &Secret::new("super-secret").unwrap(),
            selected_models: BTreeMap::new(),
            installs,
            synchronized_skills: BTreeMap::new(),
        })
        .unwrap();
    assert!(second.changes.iter().any(|change| change.kind
        == gateway_connector_core::ChangeKind::Remove
        && change.path.ends_with("skills/deploy")));
    connector.apply(&second).unwrap();
    assert!(connector.verify(&second).unwrap().ok);

    let claude: Value =
        serde_json::from_slice(&fs::read(t.path().join("claude/.claude.json")).unwrap()).unwrap();
    assert!(claude["mcpServers"]["mine"].is_object());
    assert!(claude["mcpServers"][&mcp].is_null());
    assert!(
        !fs::read_to_string(t.path().join("codex/config.toml"))
            .unwrap()
            .contains(&mcp)
    );
    assert!(!t.path().join("state/skills/platform-a/deploy").exists());
    assert!(!t.path().join("opencode/skills").join(skill).exists());
}

#[test]
fn drifted_text_projection_blocks_disconnect_and_keeps_ownership() {
    let t = tempdir().unwrap();
    let (connector, plan) = setup(t.path());
    connector.apply(&plan).unwrap();
    let codex = t.path().join("codex/config.toml");
    fs::OpenOptions::new()
        .append(true)
        .open(&codex)
        .unwrap()
        .write_all(b"\nuser_after = true\n")
        .unwrap();

    let error = connector
        .disconnect("platform-a", &Secret::new("super-secret").unwrap())
        .unwrap_err()
        .to_string();
    assert!(error.contains("local changes"), "{error}");
    assert!(fs::read_to_string(codex).unwrap().contains("super-secret"));
    assert!(t.path().join("state/receipts/platform-a.json").exists());
}

#[test]
fn malformed_receipt_nonce_is_rejected_without_panicking() {
    let t = tempdir().unwrap();
    let (connector, plan) = setup(t.path());
    connector.apply(&plan).unwrap();
    let path = t.path().join("state/receipts/platform-a.json");
    let mut receipt: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    receipt["nonce"] = serde_json::json!([]);
    fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();

    let error = connector
        .disconnect("platform-a", &Secret::new("super-secret").unwrap())
        .unwrap_err()
        .to_string();
    assert!(error.contains("invalid receipt nonce"), "{error}");
}

#[test]
fn rolls_back_an_earlier_write_when_later_write_fails() {
    let t = tempdir().unwrap();
    let (c, p) = setup(t.path());
    let original = fs::read(t.path().join("claude/settings.json")).unwrap();
    fs::remove_file(t.path().join("claude/.claude.json")).unwrap();
    fs::create_dir(t.path().join("claude/.claude.json")).unwrap();
    assert!(c.apply(&p).is_err());
    assert_eq!(
        fs::read(t.path().join("claude/settings.json")).unwrap(),
        original
    );
    assert!(
        !t.path()
            .join("state/backups/platform-a")
            .read_dir()
            .is_ok_and(|mut entries| entries.next().is_some())
    );
}

#[test]
fn receipt_failure_rolls_back_every_projection() {
    let t = tempdir().unwrap();
    let (c, p) = setup(t.path());
    let original = fs::read(t.path().join("codex/config.toml")).unwrap();
    fs::create_dir_all(t.path().join("state")).unwrap();
    fs::write(t.path().join("state/receipts"), "blocks receipt directory").unwrap();

    assert!(c.apply(&p).is_err());
    assert_eq!(
        fs::read(t.path().join("codex/config.toml")).unwrap(),
        original
    );
    assert!(!t.path().join("state/skills/platform-a/deploy").exists());
}

#[test]
fn receipt_is_authenticated_ciphertext_and_verification_rejects_two_missing_directories() {
    let t = tempdir().unwrap();
    let (connector, plan) = setup(t.path());
    connector.apply(&plan).unwrap();
    let receipt = fs::read(t.path().join("state/receipts/platform-a.json")).unwrap();
    assert!(
        !receipt
            .windows(b"super-secret".len())
            .any(|w| w == b"super-secret")
    );
    assert!(
        !receipt
            .windows(b"ANTHROPIC_AUTH_TOKEN".len())
            .any(|w| w == b"ANTHROPIC_AUTH_TOKEN")
    );

    fs::remove_dir_all(t.path().join("source-skill")).unwrap();
    fs::remove_dir_all(t.path().join("state/skills/platform-a/deploy")).unwrap();
    let verification = connector.verify(&plan).unwrap();
    assert!(!verification.ok);
    assert!(
        verification
            .mismatches
            .iter()
            .any(|path| path.ends_with("deploy"))
    );
}

#[cfg(unix)]
#[test]
fn verification_treats_two_skill_hash_errors_as_a_mismatch() {
    use std::os::unix::fs::PermissionsExt;

    let t = tempdir().unwrap();
    let (connector, plan) = setup(t.path());
    connector.apply(&plan).unwrap();
    for path in [
        t.path().join("source-skill/SKILL.md"),
        t.path().join("claude/skills/deploy/SKILL.md"),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o000)).unwrap();
    }
    let verification = connector.verify(&plan).unwrap();
    assert!(!verification.ok);
    assert!(
        verification
            .mismatches
            .iter()
            .any(|path| path.ends_with("skills/deploy"))
    );
}

#[test]
fn claude_legacy_settings_and_opencode_jsonc_are_respected() {
    let t = tempdir().unwrap();
    let (manifest, provisioning) = contracts();
    let claude = t.path().join("custom-claude");
    let opencode = t.path().join("opencode");
    fs::create_dir_all(&claude).unwrap();
    fs::create_dir_all(&opencode).unwrap();
    fs::write(claude.join("claude.json"), r#"{"keep":true}"#).unwrap();
    fs::write(opencode.join("opencode.jsonc"), r#"{"keep":true}"#).unwrap();
    let connector = Connector::new(t.path().join("state"));
    let plan = connector
        .plan(ApplyInput {
            manifest: &manifest,
            provisioning: &provisioning,
            bearer: &Secret::new("secret").unwrap(),
            selected_models: BTreeMap::new(),
            installs: vec![
                AgentInstall {
                    agent: AgentId::Claude,
                    root: claude.clone(),
                    detected: true,
                },
                AgentInstall {
                    agent: AgentId::Opencode,
                    root: opencode.clone(),
                    detected: true,
                },
            ],
            synchronized_skills: BTreeMap::new(),
        })
        .unwrap_err();
    assert!(
        plan.to_string()
            .contains("missing verified synchronized source")
    );

    let provisioning = Provisioning::parse(br#"{"success":true,"data":{"schema_version":2,"models":[{"id":"alpha","chat_capable":true}],"default_model":"alpha","mcp_servers":[],"skills":[]}}"#).unwrap();
    let plan = connector
        .plan(ApplyInput {
            manifest: &manifest,
            provisioning: &provisioning,
            bearer: &Secret::new("secret").unwrap(),
            selected_models: BTreeMap::new(),
            installs: vec![
                AgentInstall {
                    agent: AgentId::Claude,
                    root: claude.clone(),
                    detected: true,
                },
                AgentInstall {
                    agent: AgentId::Opencode,
                    root: opencode.clone(),
                    detected: true,
                },
            ],
            synchronized_skills: BTreeMap::new(),
        })
        .unwrap();
    connector.apply(&plan).unwrap();
    assert!(claude.join("claude.json").exists());
    assert!(!claude.join("settings.json").exists());
    assert!(claude.join(".claude.json").exists());
    assert!(opencode.join("opencode.jsonc").exists());
    assert!(!opencode.join("opencode.json").exists());
}
