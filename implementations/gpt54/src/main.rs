use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<ServerState>>,
    config: Config,
}

struct ServerState {
    next_scan_id: u64,
    scans: HashMap<String, ScanRecord>,
}

struct ScanRecord {
    create_payload: Value,
    lifecycle: LifecycleStatus,
    status_polls_since_start: u32,
    result_polls_since_start: u32,
    cached_results: Option<Vec<Finding>>,
}

#[derive(Clone)]
struct Config {
    result_count: usize,
    findings_delay_polls: u32,
    scan_complete_polls: u32,
    host_count: usize,
    seed: String,
    port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LifecycleStatus {
    Created,
    Running,
    Stopped,
    Succeeded,
}

impl LifecycleStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Succeeded => "succeeded",
        }
    }
}

#[derive(Deserialize)]
struct ScanActionRequest {
    action: String,
}

#[derive(Serialize)]
struct CreateScanResponse {
    id: String,
}

#[derive(Serialize)]
struct ScanStatusResponse {
    id: String,
    status: String,
}

#[derive(Serialize, Clone)]
struct ResultsResponse {
    scan_id: String,
    results: Vec<Finding>,
}

#[derive(Serialize, Clone)]
struct Finding {
    id: usize,
    r#type: String,
    ip_address: String,
    hostname: String,
    oid: String,
    port: u16,
    protocol: String,
    message: String,
}

#[tokio::main]
async fn main() {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(1);
        }
    };

    let state = AppState {
        inner: Arc::new(Mutex::new(ServerState {
            next_scan_id: 1,
            scans: HashMap::new(),
        })),
        config: config.clone(),
    };

    let app = Router::new()
        .route("/scans", post(create_scan))
        .route("/scans/:scan_id", post(scan_action).delete(delete_scan))
        .route("/scans/:scan_id/status", get(scan_status))
        .route("/scans/:scan_id/results", get(scan_results))
        .with_state(state);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|err| panic!("failed to bind {addr}: {err}"));

    axum::serve(listener, app)
        .await
        .unwrap_or_else(|err| panic!("server error: {err}"));
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let port = parse_env::<u16>("PORT", None)?.ok_or_else(|| "PORT is required".to_string())?;
        let result_count = parse_env::<usize>("MOCK_RESULT_COUNT", Some(100))?.unwrap();
        let findings_delay_polls = parse_env::<u32>("MOCK_FINDINGS_DELAY_POLLS", Some(0))?.unwrap();
        let scan_complete_polls = parse_env::<u32>("MOCK_SCAN_COMPLETE_POLLS", Some(1))?.unwrap();
        let host_count = parse_env::<usize>("MOCK_HOST_COUNT", Some(10))?.unwrap();
        let seed = env::var("MOCK_SEED").unwrap_or_else(|_| "openvas-mock-sanner".to_string());

        if host_count == 0 {
            return Err("MOCK_HOST_COUNT must be greater than 0".to_string());
        }

        Ok(Self {
            result_count,
            findings_delay_polls,
            scan_complete_polls,
            host_count,
            seed,
            port,
        })
    }
}

fn parse_env<T>(key: &str, default: Option<T>) -> Result<Option<T>, String>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    match env::var(key) {
        Ok(value) => value
            .parse::<T>()
            .map(Some)
            .map_err(|err| format!("{key} must be a valid value: {err}")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(format!("failed reading {key}: {err}")),
    }
}

async fn create_scan(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    if !payload.is_object() {
        return (StatusCode::BAD_REQUEST, Json(json_error("request body must be a JSON object"))).into_response();
    }

    let mut inner = state.inner.lock().expect("state poisoned");
    let scan_id = format!("scan-{next:04}", next = inner.next_scan_id);
    inner.next_scan_id += 1;
    inner.scans.insert(
        scan_id.clone(),
        ScanRecord {
            create_payload: payload,
            lifecycle: LifecycleStatus::Created,
            status_polls_since_start: 0,
            result_polls_since_start: 0,
            cached_results: None,
        },
    );

    (StatusCode::CREATED, Json(CreateScanResponse { id: scan_id })).into_response()
}

async fn scan_action(
    Path(scan_id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<ScanActionRequest>,
) -> impl IntoResponse {
    let mut inner = state.inner.lock().expect("state poisoned");
    let Some(scan) = inner.scans.get_mut(&scan_id) else {
        return not_found();
    };

    match payload.action.as_str() {
        "start" => {
            if matches!(scan.lifecycle, LifecycleStatus::Created | LifecycleStatus::Stopped) {
                scan.lifecycle = LifecycleStatus::Running;
                scan.status_polls_since_start = 0;
                scan.result_polls_since_start = 0;
            }
            ok_status(scan_id, scan.lifecycle)
        }
        "stop" => {
            if scan.lifecycle == LifecycleStatus::Running {
                scan.lifecycle = LifecycleStatus::Stopped;
            }
            ok_status(scan_id, scan.lifecycle)
        }
        _ => (StatusCode::BAD_REQUEST, Json(json_error("unknown action"))).into_response(),
    }
}

async fn scan_status(
    Path(scan_id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let mut inner = state.inner.lock().expect("state poisoned");
    let Some(scan) = inner.scans.get_mut(&scan_id) else {
        return not_found();
    };

    if scan.lifecycle == LifecycleStatus::Running {
        scan.status_polls_since_start = scan.status_polls_since_start.saturating_add(1);
        if scan.status_polls_since_start >= state.config.scan_complete_polls {
            scan.lifecycle = LifecycleStatus::Succeeded;
        }
    }

    ok_status(scan_id, scan.lifecycle)
}

async fn scan_results(
    Path(scan_id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let mut inner = state.inner.lock().expect("state poisoned");
    let Some(scan) = inner.scans.get_mut(&scan_id) else {
        return not_found();
    };

    let results = match scan.lifecycle {
        LifecycleStatus::Created | LifecycleStatus::Stopped => Vec::new(),
        LifecycleStatus::Running => {
            scan.result_polls_since_start = scan.result_polls_since_start.saturating_add(1);
            if scan.result_polls_since_start <= state.config.findings_delay_polls {
                Vec::new()
            } else {
                ensure_results(scan, &scan_id, &state.config)
            }
        }
        LifecycleStatus::Succeeded => ensure_results(scan, &scan_id, &state.config),
    };

    (StatusCode::OK, Json(ResultsResponse { scan_id, results })).into_response()
}

async fn delete_scan(
    Path(scan_id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let mut inner = state.inner.lock().expect("state poisoned");
    if inner.scans.remove(&scan_id).is_some() {
        StatusCode::NO_CONTENT.into_response()
    } else {
        not_found()
    }
}

fn ensure_results(scan: &mut ScanRecord, scan_id: &str, config: &Config) -> Vec<Finding> {
    if let Some(results) = &scan.cached_results {
        return results.clone();
    }

    let generated = generate_findings(scan_id, &scan.create_payload, config);
    scan.cached_results = Some(generated.clone());
    generated
}

fn generate_findings(scan_id: &str, payload: &Value, config: &Config) -> Vec<Finding> {
    const OIDS: [&str; 5] = [
        "1.3.6.1.4.1.25623.1.0.100001",
        "1.3.6.1.4.1.25623.1.0.100002",
        "1.3.6.1.4.1.25623.1.0.100003",
        "1.3.6.1.4.1.25623.1.0.100004",
        "1.3.6.1.4.1.25623.1.0.100005",
    ];
    const PORTS: [u16; 6] = [22, 80, 111, 443, 3306, 8080];
    const PROTOCOLS: [&str; 2] = ["tcp", "udp"];
    const TYPES: [&str; 2] = ["alarm", "log"];

    let host_span = config.host_count.min(config.result_count.max(1));
    let payload_hint = payload
        .get("target")
        .and_then(|target| target.get("hosts"))
        .and_then(Value::as_str)
        .unwrap_or("synthetic-target");

    (0..config.result_count)
        .map(|index| {
            let id = index + 1;
            let host_index = index % host_span;
            let oid = OIDS[index % OIDS.len()].to_string();
            let port = PORTS[mix_u64(&config.seed, scan_id, index as u64) as usize % PORTS.len()];
            let protocol = PROTOCOLS[(index + scan_id.len()) % PROTOCOLS.len()].to_string();
            let kind = TYPES[index % TYPES.len()].to_string();
            let ip_octet_3 = ((host_index / 250) % 250) + 1;
            let ip_octet_4 = (host_index % 250) + 1;
            let hostname = format!("synthetic-host-{host_index:04}.lab");
            let message = format!(
                "Synthetic {} finding {} on {}:{} for {} ({})",
                kind, id, hostname, port, payload_hint, oid
            );

            Finding {
                id,
                r#type: kind,
                ip_address: format!("10.42.{ip_octet_3}.{ip_octet_4}"),
                hostname,
                oid,
                port,
                protocol,
                message,
            }
        })
        .collect()
}

fn mix_u64(seed: &str, scan_id: &str, n: u64) -> u64 {
    let mut value: u64 = 0xcbf29ce484222325;
    for byte in seed.as_bytes().iter().chain(scan_id.as_bytes()).chain(n.to_string().as_bytes()) {
        value ^= u64::from(*byte);
        value = value.wrapping_mul(0x100000001b3);
    }
    value
}

fn ok_status(scan_id: String, lifecycle: LifecycleStatus) -> axum::response::Response {
    (StatusCode::OK, Json(ScanStatusResponse {
        id: scan_id,
        status: lifecycle.as_str().to_string(),
    }))
        .into_response()
}

fn not_found() -> axum::response::Response {
    (StatusCode::NOT_FOUND, Json(json_error("scan not found"))).into_response()
}

fn json_error(message: &str) -> Value {
    serde_json::json!({ "error": message })
}
