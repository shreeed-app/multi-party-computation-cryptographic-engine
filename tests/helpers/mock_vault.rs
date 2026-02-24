use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
};

use axum::{
    Json,
    Router,
    extract::{Path, State},
    response::IntoResponse,
    routing::post,
    serve,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{net::TcpListener, spawn};

type Storage = Arc<Mutex<HashMap<String, String>>>;

const SHARE_FIELD: &str = "share";
const VAULT_PATH_PREFIX: &str = "/{*key}";

/// A simple in-memory mock Vault server for testing purposes. It supports
/// basic read and write operations on secrets.
#[derive(Deserialize)]
struct VaultWriteRequest {
    /// The "data" field in the Vault write request, containing the secret
    /// data to be stored.
    data: HashMap<String, String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

/// The VaultReadResponse struct represents the structure of the response
/// returned by the mock Vault server when a secret is read. It contains a
/// nested "data" field that holds the actual secret data.
#[derive(Serialize)]
struct VaultReadInner {
    /// The "data" field in the Vault read response, containing the secret
    /// data that was stored.
    data: HashMap<String, String>,
}

/// The VaultReadResponse struct represents the structure of the response
/// returned by the mock Vault server when a secret is read. It contains a
/// nested "data" field that holds the actual secret data.
#[derive(Serialize)]
struct VaultReadResponse {
    /// The "data" field in the Vault read response, containing the secret
    /// data that was stored.
    data: VaultReadInner,
}

/// Handle POST requests to write a secret to the mock Vault. The secret is
/// stored in an in-memory HashMap, and the response mimics the structure of a
/// real Vault write response.
///
/// # Arguments
/// * `State(storage)` (`State<Storage>`) - The shared in-memory storage for
///   secrets, wrapped in an Arc and Mutex for thread safety.
/// * `Path(key)` `(Path<String>)` - The key under which the secret should be
///   stored, extracted from the request path.
/// * `Json(payload)` (`Json<VaultWriteRequest>`) - The JSON payload of the
///   request, containing the secret data to be stored.
///
/// # Returns
/// A JSON response mimicking the structure of a real Vault write response,
/// indicating that the secret was successfully stored.

async fn write_secret(
    State(storage): State<Storage>,
    Path(path): Path<String>,
    Json(payload): Json<VaultWriteRequest>,
) -> impl IntoResponse {
    let key = path
        .strip_prefix("secret/data/mpc/shares/")
        .unwrap_or(&path)
        .to_string();

    let mut map = storage.lock().unwrap();

    if let Some(value) = payload.data.get(SHARE_FIELD) {
        map.insert(key, value.clone());
    }

    // Return empty JSON object with proper content-type
    (StatusCode::OK, Json(serde_json::json!({})))
}

/// Handle GET requests to read a secret from the mock Vault. The secret is
/// retrieved from an in-memory HashMap, and the response mimics the structure
/// of a real Vault read response.
///
/// # Arguments
/// * `State(storage)` (`State<Storage>`) - The shared in-memory storage for
///   secrets, wrapped in an Arc and Mutex for thread safety.
/// * `Path(key)` `(Path<String>)` - The key of the secret to be retrieved,
///   extracted from the request path.
///
/// # Returns
/// A JSON response mimicking the structure of a real Vault read response,
/// containing the secret data if it exists, or an empty value if the key is
/// not found.
async fn read_secret(
    State(storage): State<Storage>,
    Path(key): Path<String>,
) -> Json<VaultReadResponse> {
    let map: MutexGuard<'_, HashMap<String, String>> = storage.lock().unwrap();

    let value: String = map.get(&key).cloned().unwrap_or_default();

    let mut inner: HashMap<String, String> = HashMap::new();
    inner.insert(SHARE_FIELD.to_string(), value);

    Json(VaultReadResponse { data: VaultReadInner { data: inner } })
}

/// Spawn the mock Vault server on the specified port. The server will listen
/// for incoming requests and handle them using the defined routes for reading
/// and writing secrets.
///
/// # Arguments
/// * `port` `(u16)` - The port number on which the mock Vault server should
///   listen for incoming requests.
pub async fn spawn_fake_vault(port: u16) {
    let storage: Storage = Arc::new(Mutex::new(HashMap::new()));

    let app: Router = Router::new()
        .route(VAULT_PATH_PREFIX, post(write_secret).get(read_secret))
        .with_state(storage);

    let address: SocketAddr = SocketAddr::from(([127, 0, 0, 1], port));

    let listener: TcpListener = TcpListener::bind(&address)
        .await
        .expect("Failed to bind to address for Fake Vault server.");

    spawn(async move {
        serve(listener, app).await.expect("Fake Vault server failed.");
    });
}
