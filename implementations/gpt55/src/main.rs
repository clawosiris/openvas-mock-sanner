use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone)]
struct Config {
    result_count: usize,
    findings_delay_polls: usize,
    scan_complete_polls: usize,
    host_count: usize,
    seed: String,
}

#[derive(Clone)]
struct AppState {
    config: Config,
    inner: Arc<Mutex<InnerState>>,
}

struct InnerState {
    next_id: u64,
    scans: HashMap<String, Scan>,
}

struct Scan {
    id: String,
    status: ScanStatus,
    #[allow(dead_code)]
    create_payload: Value,
    status_polls_after_start: usize,
    result_polls_after_start: usize,
    cached_results: Option<Vec<Finding>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanStatus {
    Created,
    Running,
    Stopped,
    Succeeded,
}

impl ScanStatus {
    fn as_str(self) -> &'static str {
        match self {
            ScanStatus::Created => "created",
            ScanStatus::Running => "running",
            ScanStatus::Stopped => "stopped",
            ScanStatus::Succeeded => "succeeded",
        }
    }
}

#[derive(Serialize, Clone)]
struct Finding {
    id: usize,
    #[serde(rename = "type")]
    finding_type: String,
    ip_address: String,
    hostname: String,
    oid: String,
    port: u16,
    protocol: String,
    message: String,
}

#[derive(Deserialize)]
struct ActionRequest {
    action: String,
}

#[derive(Serialize)]
struct StateResponse {
    id: String,
    status: String,
}

#[tokio::main]
async fn main() {
    let config = match load_config() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(2);
        }
    };

    let port = match parse_port() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(2);
        }
    };

    let state = AppState {
        config,
        inner: Arc::new(Mutex::new(InnerState {
            next_id: 1,
            scans: HashMap::new(),
        })),
    };

    let app = Router::new()
        .route("/scans", post(create_scan))
        .route("/scans/{scan_id}", post(scan_action).delete(delete_scan))
        .route("/scans/{scan_id}/status", get(scan_status))
        .route("/scans/{scan_id}/results", get(scan_results))
        .fallback(not_found)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("failed to bind {addr}: {err}");
            std::process::exit(1);
        }
    };

    if let Err(err) = axum::serve(listener, app).await {
        eprintln!("server error: {err}");
        std::process::exit(1);
    }
}

fn parse_port() -> Result<u16, String> {
    let raw = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    raw.parse::<u16>()
        .map_err(|_| format!("PORT must be an integer TCP port, got {raw:?}"))
}

fn load_config() -> Result<Config, String> {
    Ok(Config {
        result_count: parse_usize_env("MOCK_RESULT_COUNT", "100")?,
        findings_delay_polls: parse_usize_env("MOCK_FINDINGS_DELAY_POLLS", "0")?,
        scan_complete_polls: parse_usize_env("MOCK_SCAN_COMPLETE_POLLS", "1")?,
        host_count: parse_positive_usize_env("MOCK_HOST_COUNT", "10")?,
        seed: env::var("MOCK_SEED").unwrap_or_else(|_| "openvas-mock-sanner".to_string()),
    })
}

fn parse_usize_env(name: &str, default: &str) -> Result<usize, String> {
    let raw = env::var(name).unwrap_or_else(|_| default.to_string());
    raw.parse::<usize>()
        .map_err(|_| format!("{name} must be a non-negative integer, got {raw:?}"))
}

fn parse_positive_usize_env(name: &str, default: &str) -> Result<usize, String> {
    let parsed = parse_usize_env(name, default)?;
    if parsed == 0 {
        Err(format!("{name} must be greater than zero"))
    } else {
        Ok(parsed)
    }
}

async fn create_scan(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> Result<impl IntoResponse, ApiError> {
    if !payload.is_object() {
        return Err(ApiError::bad_request("scan payload must be a JSON object"));
    }

    let mut inner = state.inner.lock().await;
    let id = format!("scan-{:04}", inner.next_id);
    inner.next_id += 1;
    inner.scans.insert(
        id.clone(),
        Scan {
            id: id.clone(),
            status: ScanStatus::Created,
            create_payload: payload,
            status_polls_after_start: 0,
            result_polls_after_start: 0,
            cached_results: None,
        },
    );

    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

async fn scan_action(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
    Json(action): Json<ActionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mut inner = state.inner.lock().await;
    let scan = inner
        .scans
        .get_mut(&scan_id)
        .ok_or_else(ApiError::not_found)?;

    match action.action.as_str() {
        "start" => {
            if scan.status == ScanStatus::Created || scan.status == ScanStatus::Stopped {
                scan.status = ScanStatus::Running;
                scan.status_polls_after_start = 0;
                scan.result_polls_after_start = 0;
                scan.cached_results = None;
            } else if scan.status == ScanStatus::Succeeded {
                // Treat restarting a completed mock scan as a fresh run.
                scan.status = ScanStatus::Running;
                scan.status_polls_after_start = 0;
                scan.result_polls_after_start = 0;
                scan.cached_results = None;
            }
        }
        "stop" => {
            if scan.status == ScanStatus::Running {
                scan.status = ScanStatus::Stopped;
            }
        }
        _ => return Err(ApiError::bad_request("unknown scan action")),
    }

    Ok(Json(StateResponse {
        id: scan.id.clone(),
        status: scan.status.as_str().to_string(),
    }))
}

async fn scan_status(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let mut inner = state.inner.lock().await;
    let scan = inner
        .scans
        .get_mut(&scan_id)
        .ok_or_else(ApiError::not_found)?;

    if scan.status == ScanStatus::Running {
        scan.status_polls_after_start += 1;
        if scan.status_polls_after_start >= state.config.scan_complete_polls {
            scan.status = ScanStatus::Succeeded;
        }
    }

    Ok(Json(StateResponse {
        id: scan.id.clone(),
        status: scan.status.as_str().to_string(),
    }))
}

async fn scan_results(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let mut inner = state.inner.lock().await;
    let scan = inner
        .scans
        .get_mut(&scan_id)
        .ok_or_else(ApiError::not_found)?;

    let visible = match scan.status {
        ScanStatus::Created | ScanStatus::Stopped => false,
        ScanStatus::Running | ScanStatus::Succeeded => {
            let visible = scan.result_polls_after_start >= state.config.findings_delay_polls;
            scan.result_polls_after_start += 1;
            visible
        }
    };

    let results = if visible {
        if scan.cached_results.is_none() {
            scan.cached_results = Some(generate_results(&state.config, &scan.id));
        }
        scan.cached_results.clone().unwrap_or_default()
    } else {
        Vec::new()
    };

    Ok(Json(json!({ "scan_id": scan.id, "results": results })))
}

async fn delete_scan(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let mut inner = state.inner.lock().await;
    if inner.scans.remove(&scan_id).is_some() {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found())
    }
}

async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })))
}

fn generate_results(config: &Config, scan_id: &str) -> Vec<Finding> {
    let oids = [
        "1.3.6.1.4.1.25623.1.0.147696",
        "1.3.6.1.4.1.25623.1.0.103674",
        "1.3.6.1.4.1.25623.1.0.108239",
        "1.3.6.1.4.1.25623.1.0.90022",
        "1.3.6.1.4.1.25623.1.0.11219",
    ];
    let ports = [22_u16, 80, 443, 25, 53, 3389, 8080, 5432];
    let messages = [
        "Synthetic scanner finding: service version disclosure detected",
        "Synthetic scanner finding: weak configuration observed",
        "Synthetic scanner finding: patch level appears outdated",
        "Synthetic scanner log: host responded to probe",
        "Synthetic scanner finding: TLS policy should be reviewed",
    ];
    let base = stable_hash(&format!(
        "{}:{}:{}:{}",
        config.seed, scan_id, config.host_count, config.result_count
    ));

    (0..config.result_count)
        .map(|idx| {
            let host_idx = idx % config.host_count;
            let mixed = stable_mix(base, idx as u64);
            let finding_type = if mixed % 5 == 0 { "log" } else { "alarm" };
            let protocol = if ports[idx % ports.len()] == 53 && mixed % 2 == 0 {
                "udp"
            } else {
                "tcp"
            };
            Finding {
                id: idx + 1,
                finding_type: finding_type.to_string(),
                ip_address: format!("10.42.{}.{}", host_idx / 254, (host_idx % 254) + 1),
                hostname: format!("synthetic-host-{:04}.lab", host_idx + 1),
                oid: oids[idx % oids.len()].to_string(),
                port: ports[((mixed as usize) + idx) % ports.len()],
                protocol: protocol.to_string(),
                message: format!("{} on {}", messages[idx % messages.len()], scan_id),
            }
        })
        .collect()
}

fn stable_hash(input: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn stable_mix(seed: u64, value: u64) -> u64 {
    let mut x = seed ^ value.wrapping_mul(0x9e3779b97f4a7c15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: "not found",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}
