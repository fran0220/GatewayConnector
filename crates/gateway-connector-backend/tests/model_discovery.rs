use std::{
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use gateway_connector_backend::{
    ApiKey, ConnectRequest, ConnectorBackend, CredentialStore, DiscoveryError, GatewayClient,
    InMemoryCredentialStore, InMemoryProfileStore, ManifestLocation, VaultError,
};
use gateway_connector_core::{CanonicalBaseUrl, CredentialRef, Protocol};
use tiny_http::{Header, Response, Server, StatusCode};
use url::Url;

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
    let (base, capture, handle) = spawn_response(200, r#"{"schema_version":2}"#);
    let client = GatewayClient::new().expect("client");
    let base_url = CanonicalBaseUrl::parse(&base).expect("base URL");
    let manifest = client
        .discover_manifest(&base_url, ManifestLocation::WellKnown)
        .expect("discover manifest");
    handle.join().expect("mock server");
    assert_eq!(manifest.document["schema_version"], 2);
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
fn backend_uses_in_memory_vault_and_persists_reference_only() {
    let (base, _, handle) = spawn_response(200, r#"{"data":[{"id":"model-a"}]}"#);
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
    let json = serde_json::to_string(&backend.profiles().expect("profiles")).expect("profile JSON");
    assert!(!json.contains("not-persisted"));
    assert!(json.contains("profile:"));
}

#[test]
fn saved_connection_resumes_with_the_same_profile_id() {
    let server = Server::http("127.0.0.1:0").expect("start mock server");
    let base = format!("http://{}", server.server_addr());
    let handle = thread::spawn(move || {
        for _ in 0..2 {
            server
                .recv()
                .expect("request")
                .respond(Response::from_string(r#"{"data":[{"id":"model-a"}]}"#))
                .expect("response");
        }
    });
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

#[derive(Debug)]
struct FailingCredentialStore;

impl CredentialStore for FailingCredentialStore {
    fn get(&self, _credential: &CredentialRef) -> Result<Option<ApiKey>, VaultError> {
        Ok(None)
    }

    fn set(&self, _credential: &CredentialRef, _api_key: &ApiKey) -> Result<(), VaultError> {
        Err(VaultError::Unavailable("injected failure".to_owned()))
    }

    fn delete(&self, _credential: &CredentialRef) -> Result<(), VaultError> {
        Ok(())
    }
}

#[test]
fn failed_credential_commit_rolls_back_new_profile() {
    let (base, _, handle) = spawn_response(200, r#"{"data":[{"id":"model-a"}]}"#);
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
