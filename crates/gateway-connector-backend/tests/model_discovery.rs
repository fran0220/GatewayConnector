use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read, Write},
    net::{Ipv4Addr, TcpStream},
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use gateway_connector_backend::{
    ApiKey, BackendError, Browser, ConnectRequest, ConnectorBackend, CredentialStore,
    DiscoveryError, Distribution, GatewayClient, InMemoryCredentialStore, InMemoryProfileStore,
    ManifestLocation, PkceError, ProfileStore, StoreError, SystemBrowser, VaultError,
};
use gateway_connector_core::{
    CanonicalBaseUrl, ConnectionManifest, ConnectionMode, ConnectionProfile, CredentialKind,
    CredentialRef, ProfileId, Protocol,
};
use sha2::{Digest, Sha256};
use tiny_http::{Header, Response, Server, StatusCode};
use url::Url;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

#[derive(Debug, Default)]
struct RequestCapture {
    path: String,
    authorization: Option<String>,
}

fn spawn_response(
    status: u16,
    body: &'static str,
) -> (String, Arc<Mutex<RequestCapture>>, thread::JoinHandle<()>) {
    let server = Server::http("127.0.0.1:0").expect("start mock server");
    let address = format!("http://{}", server.server_addr());
    let capture = Arc::new(Mutex::new(RequestCapture::default()));
    let thread_capture = Arc::clone(&capture);
    let handle = thread::spawn(move || {
        let mut request = server.recv().expect("receive request");
        let authorization = request
            .headers()
            .iter()
            .find(|header| header.field.equiv("authorization"))
            .map(|header| header.value.as_str().to_owned());
        let mut ignored_body = String::new();
        request
            .as_reader()
            .read_to_string(&mut ignored_body)
            .expect("read request");
        *thread_capture.lock().expect("capture lock") = RequestCapture {
            path: request.url().to_owned(),
            authorization,
        };
        request
            .respond(Response::from_string(body).with_status_code(StatusCode(status)))
            .expect("send response");
    });
    (address, capture, handle)
}

fn spawn_direct(body: &'static str, requests: usize) -> (String, thread::JoinHandle<()>) {
    let server = Server::http("127.0.0.1:0").expect("start mock server");
    let address = format!("http://{}", server.server_addr());
    let handle = thread::spawn(move || {
        for index in 0..requests {
            let request = server.recv().expect("receive request");
            let response = if index == 0 {
                Response::from_string("").with_status_code(StatusCode(404))
            } else {
                Response::from_string(body).with_status_code(StatusCode(200))
            };
            request.respond(response).expect("send response");
        }
    });
    (address, handle)
}

fn manifest_body(
    platform: &str,
    gateway: &str,
    provisioning_url: &str,
    bearer_origins: &[&str],
) -> String {
    serde_json::json!({
        "success": true,
        "data": {
            "schema_version": 2,
            "platform": {"id": platform, "name": "Test Platform"},
            "gateway": {"base_url": gateway, "protocols": ["openai_chat"]},
            "provisioning_url": provisioning_url,
            "connection_bearer_origins": bearer_origins,
            "supported_agents": ["claude", "codex", "gemini", "grokbuild", "opencode"]
        }
    })
    .to_string()
}

fn provisioning_body() -> String {
    serde_json::json!({
        "success": true,
        "data": {
            "schema_version": 2,
            "models": [{"id": "agent-model", "chat_capable": true}],
            "default_model": "agent-model",
            "model_plaza": {
                "portal_url": "https://platform.example/models",
                "models": [
                    {"id": "agent-model", "chat_capable": true},
                    {"id": "embedding-only", "chat_capable": false}
                ]
            },
            "mcp_servers": [],
            "skills": []
        }
    })
    .to_string()
}

fn skill_zip(contents: &[u8]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "SKILL.md",
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .expect("Skill entry");
    writer.write_all(contents).expect("Skill body");
    writer.finish().expect("finish ZIP").into_inner()
}

fn provisioning_with_skill_body(origin: &str, archive: &[u8]) -> String {
    let mut value: serde_json::Value =
        serde_json::from_str(&provisioning_body()).expect("provisioning JSON");
    value["data"]["skills"] = serde_json::json!([{
        "id":"online-skill",
        "name":"Online Skill",
        "version":"1.0.0",
        "archive":{
            "url":format!("{origin}/skill.zip"),
            "sha256":format!("{:x}", Sha256::digest(archive)),
            "size_bytes":archive.len(),
            "format":"zip",
            "authorization":"connection_bearer"
        }
    }]);
    value.to_string()
}

fn browser_manifest_body(platform: &str, origin: &str) -> String {
    serde_json::json!({
        "success": true,
        "data": {
            "schema_version": 2,
            "platform": {"id": platform, "name": "Test Platform"},
            "authentication": {
                "type": "browser_pkce",
                "authorize_url": format!("{origin}/authorize"),
                "token_url": format!("{origin}/token")
            },
            "gateway": {"base_url": origin, "protocols": ["openai_chat"]},
            "provisioning_url": format!("{origin}/api/connector/provisioning"),
            "connection_bearer_origins": [origin],
            "supported_agents": ["claude", "codex", "gemini", "grokbuild", "opencode"]
        }
    })
    .to_string()
}

#[derive(Debug, Default)]
struct AutoCallbackBrowser;

impl Browser for AutoCallbackBrowser {
    fn open(&self, url: &Url) -> Result<(), PkceError> {
        let query: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        let redirect = Url::parse(
            query
                .get("redirect_uri")
                .ok_or(PkceError::InvalidCallback)?,
        )
        .map_err(|_| PkceError::InvalidCallback)?;
        let state = query
            .get("state")
            .cloned()
            .ok_or(PkceError::InvalidCallback)?;
        thread::spawn(move || {
            let mut stream =
                TcpStream::connect((Ipv4Addr::LOCALHOST, redirect.port().expect("callback port")))
                    .expect("connect callback");
            write!(
                stream,
                "GET /callback?code=test-code&state={state} HTTP/1.1\r\n"
            )
            .expect("write callback");
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .expect("read callback response");
        });
        Ok(())
    }
}

#[derive(Debug, Default)]
struct FailOnceCredentialStore {
    attempts: AtomicUsize,
    inner: InMemoryCredentialStore,
}

#[derive(Debug, Default)]
struct CommitThenErrorCredentialStore {
    inner: InMemoryCredentialStore,
    last_profile: Mutex<Option<ConnectionProfile>>,
}

impl CredentialStore for CommitThenErrorCredentialStore {
    fn get(&self, profile: &ConnectionProfile) -> Result<Option<ApiKey>, VaultError> {
        self.inner.get(profile)
    }

    fn set(&self, profile: &ConnectionProfile, api_key: &ApiKey) -> Result<(), VaultError> {
        self.inner.set(profile, api_key)?;
        *self.last_profile.lock().map_err(|_| VaultError::Poisoned)? = Some(profile.clone());
        Err(VaultError::Unavailable(
            "injected error after commit".to_owned(),
        ))
    }

    fn delete(&self, credential: &CredentialRef) -> Result<(), VaultError> {
        self.inner.delete(credential)
    }
}

#[derive(Debug)]
struct FailingCreateProfileStore;

impl ProfileStore for FailingCreateProfileStore {
    fn load(&self) -> Result<Vec<ConnectionProfile>, StoreError> {
        Ok(Vec::new())
    }

    fn create(&self, _profile: &ConnectionProfile) -> Result<(), StoreError> {
        Err(StoreError::Io(std::io::Error::other(
            "injected create failure",
        )))
    }

    fn save(&self, _profile: &ConnectionProfile) -> Result<(), StoreError> {
        Err(StoreError::Io(std::io::Error::other(
            "injected save failure",
        )))
    }

    fn delete(&self, _profile_id: ProfileId) -> Result<(), StoreError> {
        Ok(())
    }
}

impl CredentialStore for FailOnceCredentialStore {
    fn get(&self, profile: &ConnectionProfile) -> Result<Option<ApiKey>, VaultError> {
        self.inner.get(profile)
    }

    fn set(&self, profile: &ConnectionProfile, api_key: &ApiKey) -> Result<(), VaultError> {
        if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(VaultError::Unavailable("injected first failure".to_owned()))
        } else {
            self.inner.set(profile, api_key)
        }
    }

    fn delete(&self, credential: &CredentialRef) -> Result<(), VaultError> {
        self.inner.delete(credential)
    }
}

const PINNED_DISTRIBUTION: Distribution = Distribution {
    product_id: "test-connector",
    product_name: "Test Connector",
    expected_platform_id: Some("pinned-platform"),
    default_gateway_url: None,
    manifest_url: None,
    allow_custom_urls: true,
    qualifier: "dev",
    organization: "test-connector",
    application: "test-connector",
    keyring_service: "test-connector",
    bundle_id: "dev.test-connector",
    supported_locales: &["en"],
    asset_identity: None,
    release_metadata: None,
    pkce_client_id: "test-connector",
    device_name: "Test Connector",
};

const LOCKED_DISTRIBUTION: Distribution = Distribution {
    product_id: "locked-connector",
    product_name: "Locked Connector",
    expected_platform_id: Some("locked-platform"),
    default_gateway_url: Some("https://gateway.example/v1"),
    manifest_url: Some("https://gateway.example/connector-manifest.json"),
    allow_custom_urls: false,
    qualifier: "dev",
    organization: "locked-connector",
    application: "locked-connector",
    keyring_service: "locked-connector",
    bundle_id: "dev.locked-connector",
    supported_locales: &["en"],
    asset_identity: None,
    release_metadata: None,
    pkce_client_id: "locked-connector",
    device_name: "Locked Connector",
};

#[test]
fn sends_bearer_to_models_endpoint_and_normalizes_catalog() {
    let (base, capture, handle) = spawn_response(
        200,
        r#"{"data":[
            {"id":" zeta ","owned_by":"vendor-a","context_window":32000},
            {"id":"alpha","created":42,"object":"model"},
            {"id":"zeta","created":7}
        ]}"#,
    );
    let client = GatewayClient::new().expect("client");
    let key = ApiKey::new("test-key").expect("key");
    let models = client
        .discover_models(&CanonicalBaseUrl::parse(&base).expect("base URL"), &key)
        .expect("discover models");
    handle.join().expect("mock server");

    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "zeta"]
    );
    assert_eq!(models[1].owned_by.as_deref(), Some("vendor-a"));
    assert_eq!(models[1].created, Some(7));
    assert_eq!(models[1].metadata["context_window"], 32000);
    let capture = capture.lock().expect("capture lock");
    assert_eq!(capture.path, "/v1/models");
    assert_eq!(capture.authorization.as_deref(), Some("Bearer test-key"));
}

#[test]
fn requests_exact_model_paths_for_supported_gateway_url_forms() {
    let client = GatewayClient::new().expect("client");
    let key = ApiKey::new("path-test-key").expect("key");

    for (suffix, expected_path) in [
        ("", "/v1/models"),
        ("/v1", "/v1/models"),
        ("/v1/models", "/v1/models"),
        ("/proxy", "/proxy/v1/models"),
        ("/proxy/v1", "/proxy/v1/models"),
    ] {
        let (origin, capture, handle) = spawn_response(200, r#"{"data":[]}"#);
        let base_url = CanonicalBaseUrl::parse(&format!("{origin}{suffix}"))
            .expect("supported Gateway URL form");
        client
            .discover_models(&base_url, &key)
            .expect("discover models");
        handle.join().expect("mock server");

        let capture = capture.lock().expect("capture lock");
        assert_eq!(capture.path, expected_path, "Gateway URL suffix {suffix:?}");
        assert_eq!(
            capture.authorization.as_deref(),
            Some("Bearer path-test-key")
        );
    }
}

#[test]
fn reports_unauthorized_and_malformed_responses() {
    let (base, _, handle) = spawn_response(401, r#"{"error":"invalid key"}"#);
    let client = GatewayClient::new().expect("client");
    let key = ApiKey::new("wrong").expect("key");
    let error = client
        .discover_models(&CanonicalBaseUrl::parse(&base).expect("base URL"), &key)
        .expect_err("401 must fail");
    handle.join().expect("mock server");
    assert!(matches!(error, DiscoveryError::Unauthorized));

    let (base, _, handle) = spawn_response(200, r#"{"models":[]}"#);
    let error = client
        .discover_models(&CanonicalBaseUrl::parse(&base).expect("base URL"), &key)
        .expect_err("malformed response must fail");
    handle.join().expect("mock server");
    assert!(matches!(error, DiscoveryError::InvalidSchema { .. }));
}

#[test]
fn refuses_cross_origin_redirect_without_contacting_target() {
    let target = Server::http("127.0.0.1:0").expect("start target");
    let target_url = format!("http://{}/leak", target.server_addr());
    let source = Server::http("127.0.0.1:0").expect("start source");
    let source_url = format!("http://{}", source.server_addr());
    let source_handle =
        thread::spawn(move || {
            let request = source.recv().expect("source request");
            request
                .respond(Response::empty(StatusCode(302)).with_header(
                    Header::from_bytes("Location", target_url).expect("location header"),
                ))
                .expect("source response");
        });

    let client = GatewayClient::new().expect("client");
    let error = client
        .discover_models(
            &CanonicalBaseUrl::parse(&source_url).expect("source URL"),
            &ApiKey::new("must-not-leak").expect("key"),
        )
        .expect_err("cross-origin redirect must fail");
    source_handle.join().expect("source server");
    assert!(matches!(error, DiscoveryError::CrossOriginRedirect { .. }));
    assert!(
        target
            .recv_timeout(Duration::from_millis(250))
            .is_ok_and(|request| request.is_none())
    );
}

#[test]
fn manifest_discovery_is_exact_origin_and_unauthenticated() {
    let (base, capture, handle) = spawn_response(
        200,
        r#"{"success":true,"data":{"schema_version":2,"platform":{"id":"test","name":"Test"},"gateway":{"base_url":"http://127.0.0.1","protocols":["openai"]},"provisioning_url":"http://127.0.0.1/provision","connection_bearer_origins":["http://127.0.0.1"],"supported_agents":["codex"]}}"#,
    );
    let client = GatewayClient::new().expect("client");
    let base_url = CanonicalBaseUrl::parse(&base).expect("base URL");
    let manifest = client
        .discover_manifest(&base_url, ManifestLocation::WellKnown)
        .expect("discover manifest")
        .expect("manifest");
    handle.join().expect("mock server");
    assert_eq!(manifest.document.schema_version, 2);
    let capture = capture.lock().expect("capture lock");
    assert_eq!(capture.path, "/.well-known/gateway-connector");
    assert!(capture.authorization.is_none());

    let credentialed =
        Url::parse(&base.replace("http://", "http://user:password@")).expect("credentialed URL");
    let error = client
        .discover_manifest(&base_url, ManifestLocation::Explicit(credentialed))
        .expect_err("URL credentials must be rejected");
    assert!(matches!(error, DiscoveryError::ManifestUrlCredentials));
}

#[test]
fn explicit_manifest_404_does_not_fall_back_to_direct_mode() {
    let (base, capture, handle) = spawn_response(404, "not found");
    let client = GatewayClient::new().expect("client");
    let base_url = CanonicalBaseUrl::parse(&base).expect("base URL");
    let explicit =
        Url::parse(&format!("{base}/connector-manifest.json")).expect("explicit manifest URL");
    let error = client
        .discover_manifest(&base_url, ManifestLocation::Explicit(explicit))
        .expect_err("an explicit manifest is a required contract");
    handle.join().expect("mock server");
    assert!(matches!(error, DiscoveryError::ExplicitManifestNotFound));
    assert_eq!(
        capture.lock().expect("capture lock").path,
        "/connector-manifest.json"
    );
}

#[test]
fn provisioned_connection_uses_manifest_catalog_and_bearer_boundary() {
    let server = Server::http("127.0.0.1:0").expect("enhanced server");
    let origin = format!("http://{}", server.server_addr());
    let manifest = manifest_body(
        "test-platform",
        &origin,
        &format!("{origin}/api/connector/provisioning"),
        &[&origin],
    );
    let archive = skill_zip(b"online Skill");
    let provisioning = provisioning_with_skill_body(&origin, &archive);
    let archive_response = archive.clone();
    let handle = thread::spawn(move || {
        let mut captures = Vec::new();
        for expected_path in [
            "/.well-known/gateway-connector",
            "/api/connector/provisioning",
            "/skill.zip",
        ] {
            let request = server.recv().expect("enhanced request");
            let authorization = request
                .headers()
                .iter()
                .find(|header| header.field.equiv("authorization"))
                .map(|header| header.value.as_str().to_owned());
            assert_eq!(request.url(), expected_path);
            let response = if expected_path == "/skill.zip" {
                Response::from_data(archive_response.clone()).with_status_code(StatusCode(200))
            } else if expected_path.ends_with("provisioning") {
                Response::from_string(provisioning.clone()).with_status_code(StatusCode(200))
            } else {
                Response::from_string(manifest.clone()).with_status_code(StatusCode(200))
            };
            captures.push(authorization);
            request.respond(response).expect("enhanced response");
        }
        captures
    });
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let profiles = Arc::new(InMemoryProfileStore::default());
    let state = tempfile::tempdir().expect("catalog state");
    let backend = ConnectorBackend::new(credentials, profiles)
        .and_then(|backend| backend.with_state_directory(state.path()))
        .expect("backend");
    let connected = backend
        .connect(ConnectRequest {
            display_name: "Enhanced".to_owned(),
            base_url: origin,
            api_key: ApiKey::new("enhanced-key").expect("key"),
            protocol: Protocol::Auto,
        })
        .expect("provisioned connection");
    let captures = handle.join().expect("enhanced server");

    assert_eq!(
        captures,
        [
            None,
            Some("Bearer enhanced-key".to_owned()),
            Some("Bearer enhanced-key".to_owned())
        ]
    );
    assert_eq!(connected.profile.mode, ConnectionMode::Provisioned);
    assert_eq!(connected.profile.platform_id, "test-platform");
    assert_eq!(
        connected
            .models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        ["agent-model"]
    );
    assert!(connected.provisioning.is_some());
    assert!(connected.manifest.is_some());
    assert_eq!(
        fs::read(connected.synchronized_skills["online-skill"].join("SKILL.md"))
            .expect("synchronized Skill"),
        b"online Skill"
    );
}

#[test]
fn platform_pin_is_enforced_during_probe() {
    let server = Server::http("127.0.0.1:0").expect("manifest server");
    let origin = format!("http://{}", server.server_addr());
    let body = manifest_body(
        "other-platform",
        &origin,
        &format!("{origin}/provisioning"),
        &[&origin],
    );
    let handle = thread::spawn(move || {
        let request = server.recv().expect("manifest request");
        request
            .respond(Response::from_string(body).with_status_code(StatusCode(200)))
            .expect("manifest response");
    });
    let backend = ConnectorBackend::with_dependencies(
        Arc::new(InMemoryCredentialStore::default()),
        Arc::new(InMemoryProfileStore::default()),
        &PINNED_DISTRIBUTION,
        Arc::new(SystemBrowser),
    )
    .expect("backend");
    let error = backend.probe(&origin).expect_err("platform pin mismatch");
    handle.join().expect("manifest server");
    assert!(matches!(
        error,
        BackendError::PlatformMismatch { expected, actual }
            if expected == "pinned-platform" && actual == "other-platform"
    ));
}

#[test]
fn locked_distribution_rejects_a_custom_gateway_before_network_access() {
    let backend = ConnectorBackend::with_dependencies(
        Arc::new(InMemoryCredentialStore::default()),
        Arc::new(InMemoryProfileStore::default()),
        &LOCKED_DISTRIBUTION,
        Arc::new(SystemBrowser),
    )
    .expect("backend");
    let error = backend
        .probe("https://other.example/v1")
        .expect_err("custom URL must be rejected");
    assert!(matches!(error, BackendError::CustomGatewayUrlNotAllowed));
}

#[test]
fn cross_origin_provisioning_requires_allowlist_and_never_forwards_redirects() {
    let gateway = Server::http("127.0.0.1:0").expect("gateway server");
    let gateway_origin = format!("http://{}", gateway.server_addr());
    let provisioning = Server::http("127.0.0.1:0").expect("provisioning server");
    let provisioning_origin = format!("http://{}", provisioning.server_addr());
    let manifest = ConnectionManifest::parse(
        manifest_body(
            "test-platform",
            &gateway_origin,
            &format!("{provisioning_origin}/provisioning"),
            &[&gateway_origin, &provisioning_origin],
        )
        .as_bytes(),
    )
    .expect("allowlisted cross-origin provisioning");
    let provisioning_body = provisioning_body();
    let handle = thread::spawn(move || {
        let request = provisioning.recv().expect("provisioning request");
        let authorization = request
            .headers()
            .iter()
            .find(|header| header.field.equiv("authorization"))
            .map(|header| header.value.as_str().to_owned());
        request
            .respond(Response::from_string(provisioning_body).with_status_code(StatusCode(200)))
            .expect("provisioning response");
        authorization
    });
    GatewayClient::new()
        .expect("client")
        .fetch_provisioning(&manifest, &ApiKey::new("cross-origin-key").expect("key"))
        .expect("allowlisted provisioning");
    assert_eq!(
        handle.join().expect("provisioning server").as_deref(),
        Some("Bearer cross-origin-key")
    );

    let redirect_source = Server::http("127.0.0.1:0").expect("redirect source");
    let redirect_origin = format!("http://{}", redirect_source.server_addr());
    let redirect_target = Server::http("127.0.0.1:0").expect("redirect target");
    let target_url = format!("http://{}/must-not-receive", redirect_target.server_addr());
    let redirect_manifest = ConnectionManifest::parse(
        manifest_body(
            "test-platform",
            &gateway_origin,
            &format!("{redirect_origin}/provisioning"),
            &[&gateway_origin, &redirect_origin],
        )
        .as_bytes(),
    )
    .expect("redirect manifest");
    let redirect_handle =
        thread::spawn(move || {
            let request = redirect_source.recv().expect("redirect request");
            request
                .respond(Response::empty(StatusCode(302)).with_header(
                    Header::from_bytes("Location", target_url).expect("location header"),
                ))
                .expect("redirect response");
        });
    let error = GatewayClient::new()
        .expect("client")
        .fetch_provisioning(
            &redirect_manifest,
            &ApiKey::new("must-not-leak").expect("key"),
        )
        .expect_err("cross-origin redirect");
    redirect_handle.join().expect("redirect server");
    assert!(matches!(error, DiscoveryError::CrossOriginRedirect { .. }));
    assert!(
        redirect_target
            .recv_timeout(Duration::from_millis(250))
            .is_ok_and(|request| request.is_none())
    );
}

#[test]
fn resume_rechecks_saved_platform_identity() {
    let server = Server::http("127.0.0.1:0").expect("manifest server");
    let origin = format!("http://{}", server.server_addr());
    let body = manifest_body(
        "changed-platform",
        &origin,
        &format!("{origin}/provisioning"),
        &[&origin],
    );
    let handle = thread::spawn(move || {
        let request = server.recv().expect("manifest request");
        request
            .respond(Response::from_string(body).with_status_code(StatusCode(200)))
            .expect("manifest response");
    });
    let profile = ConnectionProfile::new_connection(
        "Saved platform",
        CanonicalBaseUrl::parse(&origin).expect("base URL"),
        Protocol::Auto,
        ConnectionMode::Provisioned,
        CredentialKind::AccessToken,
        "saved-platform",
        None,
    )
    .expect("profile");
    let credentials = Arc::new(InMemoryCredentialStore::default());
    credentials
        .set(&profile, &ApiKey::new("saved-token").expect("token"))
        .expect("store token");
    let profiles = Arc::new(InMemoryProfileStore::default());
    profiles.save(&profile).expect("save profile");
    let backend = ConnectorBackend::new(credentials, profiles).expect("backend");
    let error = backend.resume(profile).expect_err("platform changed");
    handle.join().expect("manifest server");
    assert!(matches!(
        error,
        BackendError::PlatformMismatch { expected, actual }
            if expected == "saved-platform" && actual == "changed-platform"
    ));
}

#[test]
fn vault_binding_rejects_tampered_profile_destination_before_network_access() {
    let (base, handle) = spawn_direct(r#"{"data":[{"id":"model-a"}]}"#, 2);
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let profiles = Arc::new(InMemoryProfileStore::default());
    let backend = ConnectorBackend::new(credentials, profiles).expect("backend");
    let connected = backend
        .connect(ConnectRequest {
            display_name: "Bound".to_owned(),
            base_url: base,
            api_key: ApiKey::new("bound-secret").expect("key"),
            protocol: Protocol::Auto,
        })
        .expect("connect");
    handle.join().expect("gateway server");

    let attacker = Server::http("127.0.0.1:0").expect("attacker server");
    let attacker_url = format!("http://{}", attacker.server_addr());
    let tampered = ConnectionProfile::reconfigured(
        connected.profile.clone(),
        connected.profile.display_name,
        CanonicalBaseUrl::parse(&attacker_url).expect("attacker URL"),
        Protocol::Auto,
    )
    .expect("otherwise valid tampered profile");
    assert_eq!(tampered.id, connected.profile.id);
    assert_eq!(tampered.credential, connected.profile.credential);
    let error = backend
        .resume(tampered)
        .expect_err("vault binding must reject destination tampering");
    assert!(matches!(
        error,
        BackendError::Vault(VaultError::BindingMismatch)
    ));
    assert!(
        attacker
            .recv_timeout(Duration::from_millis(250))
            .is_ok_and(|request| request.is_none())
    );
}

#[test]
fn browser_login_keeps_failed_vault_credentials_retryable() {
    let server = Server::http("127.0.0.1:0").expect("enhanced server");
    let origin = format!("http://{}", server.server_addr());
    let manifest = browser_manifest_body("pinned-platform", &origin);
    let provisioning = provisioning_body();
    let handle = thread::spawn(move || {
        let mut captures = Vec::new();
        for expected_path in [
            "/.well-known/gateway-connector",
            "/token",
            "/api/connector/provisioning",
        ] {
            let mut request = server.recv().expect("enhanced request");
            let authorization = request
                .headers()
                .iter()
                .find(|header| header.field.equiv("authorization"))
                .map(|header| header.value.as_str().to_owned());
            assert_eq!(request.url(), expected_path);
            let body = match expected_path {
                "/token" => {
                    let mut request_body = String::new();
                    request
                        .as_reader()
                        .read_to_string(&mut request_body)
                        .expect("token request");
                    let json: serde_json::Value =
                        serde_json::from_str(&request_body).expect("token JSON");
                    assert_eq!(json["code"], "test-code");
                    assert_eq!(json.as_object().expect("token object").len(), 3);
                    r#"{"access_token":"browser-access","token_type":"Bearer","refresh_token":"ignored"}"#.to_owned()
                }
                "/api/connector/provisioning" => provisioning.clone(),
                _ => manifest.clone(),
            };
            captures.push(authorization);
            request
                .respond(Response::from_string(body).with_status_code(StatusCode(200)))
                .expect("enhanced response");
        }
        captures
    });
    let credentials = Arc::new(FailOnceCredentialStore::default());
    let profiles = Arc::new(InMemoryProfileStore::default());
    let backend = ConnectorBackend::with_dependencies(
        credentials.clone(),
        profiles,
        &PINNED_DISTRIBUTION,
        Arc::new(AutoCallbackBrowser),
    )
    .expect("backend");
    let offer = match backend
        .connect(ConnectRequest {
            display_name: "Browser login".to_owned(),
            base_url: origin,
            api_key: ApiKey::new("unused-form-key").expect("key"),
            protocol: Protocol::Auto,
        })
        .expect_err("browser login offer")
    {
        BackendError::BrowserLoginRequired(offer) => *offer,
        error => panic!("unexpected error: {error}"),
    };
    assert!(matches!(
        backend.browser_login(offer),
        Err(BackendError::Vault(VaultError::Unavailable(_)))
    ));
    assert!(backend.has_pending_credential().expect("pending state"));
    assert_eq!(backend.profiles().expect("recoverable profile").len(), 1);

    let connected = backend
        .retry_pending_credential()
        .expect("retry pending credential");
    let captures = handle.join().expect("enhanced server");
    assert_eq!(
        captures,
        [None, None, Some("Bearer browser-access".to_owned())]
    );
    assert!(!backend.has_pending_credential().expect("pending state"));
    assert_eq!(
        connected.profile.credential_kind,
        CredentialKind::AccessToken
    );
    assert_eq!(connected.models[0].id, "agent-model");
    assert_eq!(
        credentials
            .get(&connected.profile)
            .expect("vault")
            .expect("saved access token")
            .expose_secret(),
        "browser-access"
    );
}

#[test]
fn browser_token_is_pending_when_profile_creation_fails_after_redemption() {
    let server = Server::http("127.0.0.1:0").expect("enhanced server");
    let origin = format!("http://{}", server.server_addr());
    let manifest = browser_manifest_body("pinned-platform", &origin);
    let handle = thread::spawn(move || {
        for expected_path in ["/.well-known/gateway-connector", "/token"] {
            let request = server.recv().expect("enhanced request");
            assert_eq!(request.url(), expected_path);
            let body = if expected_path == "/token" {
                r#"{"access_token":"pending-after-create","token_type":"Bearer"}"#
            } else {
                manifest.as_str()
            };
            request
                .respond(Response::from_string(body).with_status_code(StatusCode(200)))
                .expect("enhanced response");
        }
    });
    let backend = ConnectorBackend::with_dependencies(
        Arc::new(InMemoryCredentialStore::default()),
        Arc::new(FailingCreateProfileStore),
        &PINNED_DISTRIBUTION,
        Arc::new(AutoCallbackBrowser),
    )
    .expect("backend");
    let offer = match backend
        .connect(ConnectRequest {
            display_name: "Browser login".to_owned(),
            base_url: origin,
            api_key: ApiKey::new("unused-form-key").expect("key"),
            protocol: Protocol::Auto,
        })
        .expect_err("browser login offer")
    {
        BackendError::BrowserLoginRequired(offer) => *offer,
        error => panic!("unexpected error: {error}"),
    };
    assert!(matches!(
        backend.browser_login(offer),
        Err(BackendError::Store(StoreError::Io(_)))
    ));
    handle.join().expect("enhanced server");
    assert!(backend.has_pending_credential().expect("pending state"));
}

#[test]
fn browser_offer_is_fully_validated_before_redeeming_a_code() {
    let server = Server::http("127.0.0.1:0").expect("enhanced server");
    let origin = format!("http://{}", server.server_addr());
    let manifest = browser_manifest_body("pinned-platform", &origin);
    let handle = thread::spawn(move || {
        let request = server.recv().expect("manifest request");
        request
            .respond(Response::from_string(manifest).with_status_code(StatusCode(200)))
            .expect("manifest response");
        server
            .recv_timeout(Duration::from_millis(250))
            .expect("token timeout")
            .is_none()
    });
    let backend = ConnectorBackend::with_dependencies(
        Arc::new(InMemoryCredentialStore::default()),
        Arc::new(InMemoryProfileStore::default()),
        &PINNED_DISTRIBUTION,
        Arc::new(AutoCallbackBrowser),
    )
    .expect("backend");
    let mut offer = match backend
        .connect(ConnectRequest {
            display_name: "Initially valid".to_owned(),
            base_url: origin,
            api_key: ApiKey::new("unused-form-key").expect("key"),
            protocol: Protocol::Auto,
        })
        .expect_err("browser login offer")
    {
        BackendError::BrowserLoginRequired(offer) => *offer,
        error => panic!("unexpected error: {error}"),
    };
    offer.request.display_name.clear();
    assert!(matches!(
        backend.browser_login(offer),
        Err(BackendError::Profile(_))
    ));
    assert!(handle.join().expect("enhanced server"));
    assert!(!backend.has_pending_credential().expect("pending state"));
}

#[test]
fn failed_browser_credential_can_be_remotely_revoked_and_discarded() {
    let server = Server::http("127.0.0.1:0").expect("enhanced server");
    let origin = format!("http://{}", server.server_addr());
    let manifest = browser_manifest_body("pinned-platform", &origin);
    let handle = thread::spawn(move || {
        let mut captures = Vec::new();
        for expected_path in [
            "/.well-known/gateway-connector",
            "/token",
            "/api/connector/revoke",
        ] {
            let request = server.recv().expect("enhanced request");
            let authorization = request
                .headers()
                .iter()
                .find(|header| header.field.equiv("authorization"))
                .map(|header| header.value.as_str().to_owned());
            assert_eq!(request.url(), expected_path);
            let (status, body) = if expected_path == "/token" {
                (
                    200,
                    r#"{"access_token":"pending-access","token_type":"Bearer"}"#,
                )
            } else if expected_path.ends_with("revoke") {
                (204, "")
            } else {
                (200, manifest.as_str())
            };
            captures.push(authorization);
            request
                .respond(Response::from_string(body).with_status_code(StatusCode(status)))
                .expect("enhanced response");
        }
        captures
    });
    let backend = ConnectorBackend::with_dependencies(
        Arc::new(FailingCredentialStore),
        Arc::new(InMemoryProfileStore::default()),
        &PINNED_DISTRIBUTION,
        Arc::new(AutoCallbackBrowser),
    )
    .expect("backend");
    let offer = match backend
        .connect(ConnectRequest {
            display_name: "Browser login".to_owned(),
            base_url: origin,
            api_key: ApiKey::new("unused-form-key").expect("key"),
            protocol: Protocol::Auto,
        })
        .expect_err("browser login offer")
    {
        BackendError::BrowserLoginRequired(offer) => *offer,
        error => panic!("unexpected error: {error}"),
    };
    assert!(matches!(
        backend.browser_login(offer),
        Err(BackendError::Vault(VaultError::Unavailable(_)))
    ));
    assert!(backend.has_pending_credential().expect("pending state"));
    backend
        .revoke_pending_credential()
        .expect("confirmed remote revocation");
    let captures = handle.join().expect("enhanced server");
    assert_eq!(
        captures,
        [None, None, Some("Bearer pending-access".to_owned())]
    );
    assert!(!backend.has_pending_credential().expect("pending state"));
    assert!(backend.profiles().expect("profiles").is_empty());
}

#[test]
fn backend_uses_in_memory_vault_and_persists_reference_only() {
    let (base, handle) = spawn_direct(r#"{"data":[{"id":"model-a"}]}"#, 2);
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let profiles = Arc::new(InMemoryProfileStore::default());
    let backend = ConnectorBackend::new(credentials, profiles).expect("backend");
    let connected = backend
        .connect(ConnectRequest {
            display_name: "Local test".to_owned(),
            base_url: base,
            api_key: ApiKey::new("not-persisted").expect("key"),
            protocol: Protocol::Auto,
        })
        .expect("connect");
    handle.join().expect("mock server");
    assert_eq!(connected.models[0].id, "model-a");
    assert!(connected.synchronized_skills.is_empty());
    let json = serde_json::to_string(&backend.profiles().expect("profiles")).expect("profile JSON");
    assert!(!json.contains("not-persisted"));
    assert!(json.contains("profile:"));
}

#[test]
fn saved_connection_resumes_with_the_same_profile_id() {
    let (base, handle) = spawn_direct(r#"{"data":[{"id":"model-a"}]}"#, 3);
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let profiles = Arc::new(InMemoryProfileStore::default());
    let backend = ConnectorBackend::new(credentials, profiles).expect("backend");
    let connected = backend
        .connect(ConnectRequest {
            display_name: "Resume test".to_owned(),
            base_url: base,
            api_key: ApiKey::new("resume-key").expect("key"),
            protocol: Protocol::Auto,
        })
        .expect("connect");
    let resumed = backend
        .resume_saved()
        .expect("resume request")
        .expect("saved profile");
    handle.join().expect("mock server");
    assert_eq!(resumed.profile.id, connected.profile.id);
    assert_eq!(resumed.models[0].id, "model-a");
}

#[test]
fn connect_never_silently_overwrites_an_active_profile() {
    let (base, handle) = spawn_direct(r#"{"data":[{"id":"model-a"}]}"#, 2);
    let credentials = Arc::new(InMemoryCredentialStore::default());
    let profiles = Arc::new(InMemoryProfileStore::default());
    let backend = ConnectorBackend::new(credentials, profiles).expect("backend");
    let first = backend
        .connect(ConnectRequest {
            display_name: "First".to_owned(),
            base_url: base.clone(),
            api_key: ApiKey::new("first-key").expect("key"),
            protocol: Protocol::Auto,
        })
        .expect("first connection");
    handle.join().expect("mock server");
    let error = backend
        .connect(ConnectRequest {
            display_name: "Replacement".to_owned(),
            base_url: base,
            api_key: ApiKey::new("replacement-key").expect("key"),
            protocol: Protocol::Anthropic,
        })
        .expect_err("active connection must not be overwritten");
    assert!(matches!(error, BackendError::AlreadyConnected));
    let saved = backend.profiles().expect("profiles");
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].id, first.profile.id);
    assert_eq!(saved[0].display_name, "First");
}

#[derive(Debug)]
struct FailingCredentialStore;

impl CredentialStore for FailingCredentialStore {
    fn get(&self, _profile: &ConnectionProfile) -> Result<Option<ApiKey>, VaultError> {
        Ok(None)
    }

    fn set(&self, _profile: &ConnectionProfile, _api_key: &ApiKey) -> Result<(), VaultError> {
        Err(VaultError::Unavailable("injected failure".to_owned()))
    }

    fn delete(&self, _credential: &CredentialRef) -> Result<(), VaultError> {
        Ok(())
    }
}

#[test]
fn failed_credential_commit_rolls_back_new_profile() {
    let (base, handle) = spawn_direct(r#"{"data":[{"id":"model-a"}]}"#, 2);
    let backend = ConnectorBackend::new(
        Arc::new(FailingCredentialStore),
        Arc::new(InMemoryProfileStore::default()),
    )
    .expect("backend");
    backend
        .connect(ConnectRequest {
            display_name: "Rollback test".to_owned(),
            base_url: base,
            api_key: ApiKey::new("cannot-store").expect("key"),
            protocol: Protocol::Auto,
        })
        .expect_err("credential storage must fail");
    handle.join().expect("mock server");
    assert!(backend.profiles().expect("profiles").is_empty());
}

#[test]
fn ambiguous_credential_commit_is_deleted_before_profile_rollback() {
    let (base, handle) = spawn_direct(r#"{"data":[{"id":"model-a"}]}"#, 2);
    let credentials = Arc::new(CommitThenErrorCredentialStore::default());
    let backend = ConnectorBackend::new(
        credentials.clone(),
        Arc::new(InMemoryProfileStore::default()),
    )
    .expect("backend");
    assert!(matches!(
        backend.connect(ConnectRequest {
            display_name: "Ambiguous commit".to_owned(),
            base_url: base,
            api_key: ApiKey::new("ambiguous-secret").expect("key"),
            protocol: Protocol::Auto,
        }),
        Err(BackendError::Vault(VaultError::Unavailable(_)))
    ));
    handle.join().expect("mock server");
    let profile = credentials
        .last_profile
        .lock()
        .expect("last profile")
        .clone()
        .expect("committed profile");
    assert!(credentials.get(&profile).expect("vault").is_none());
    assert!(backend.profiles().expect("profiles").is_empty());
}
