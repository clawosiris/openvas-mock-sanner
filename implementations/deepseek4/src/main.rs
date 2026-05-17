use actix_web::{web, App, HttpServer, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::collections::hash_map::DefaultHasher;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Config {
    result_count: usize,
    findings_delay_polls: usize,
    scan_complete_polls: usize,
    host_count: usize,
    seed: u64,
}

fn load_config() -> Result<Config, String> {
    let result_count = parse_env::<usize>("MOCK_RESULT_COUNT", Some(100))?;
    let findings_delay_polls = parse_env::<usize>("MOCK_FINDINGS_DELAY_POLLS", Some(0))?;
    let scan_complete_polls = parse_env::<usize>("MOCK_SCAN_COMPLETE_POLLS", Some(1))?;
    let host_count = parse_env::<usize>("MOCK_HOST_COUNT", Some(10))?;

    let seed_raw = std::env::var("MOCK_SEED").unwrap_or_else(|_| "openvas-mock-sanner".into());
    let seed = hash_str(&seed_raw);

    if result_count == 0 {
        // Zero is allowed, results endpoint returns empty array
    }

    Ok(Config {
        result_count,
        findings_delay_polls,
        scan_complete_polls,
        host_count,
        seed,
    })
}

fn parse_env<T: std::str::FromStr>(name: &str, default: Option<T>) -> Result<T, String> {
    match std::env::var(name) {
        Ok(val) => {
            val.trim().parse::<T>().map_err(|_| {
                format!("Invalid value for {}: {}. Expected an integer.", name, val)
            })
        }
        Err(std::env::VarError::NotPresent) => {
            match default {
                Some(d) => Ok(d),
                None => Err(format!("Missing required environment variable: {}", name)),
            }
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("Environment variable {} is not valid UTF-8.", name))
        }
    }
}

fn hash_str(s: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

// ---------------------------------------------------------------------------
// Scan state / model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct ResultItem {
    id: usize,
    #[serde(rename = "type")]
    type_: String,
    ip_address: String,
    hostname: String,
    oid: String,
    port: u16,
    protocol: String,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanStatus {
    Created,
    Running,
    Stopped,
    Succeeded,
}

impl ScanStatus {
    fn as_str(&self) -> &'static str {
        match self {
            ScanStatus::Created => "created",
            ScanStatus::Running => "running",
            ScanStatus::Stopped => "stopped",
            ScanStatus::Succeeded => "succeeded",
        }
    }
}

struct ScanState {
    status: ScanStatus,
    status_polls_since_start: usize,
    result_polls_since_start: usize,
}

struct AppState {
    config: Config,
    scans: Mutex<HashMap<String, ScanState>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CreateScanRequest {
    #[serde(default)]
    target: serde_json::Value,
    #[serde(default)]
    vts: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ScanActionRequest {
    action: String,
}

#[derive(Debug, Serialize)]
struct ScanIdResponse {
    id: String,
}

#[derive(Debug, Serialize)]
struct ScanStatusResponse {
    id: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct ResultsResponse {
    scan_id: String,
    results: Vec<ResultItem>,
}

// ---------------------------------------------------------------------------
// Deterministic result generation
// ---------------------------------------------------------------------------

fn generate_results(config: &Config, scan_id: &str) -> Vec<ResultItem> {
    if config.result_count == 0 {
        return Vec::new();
    }

    let oids = [
        "1.3.6.1.4.1.25623.1.0.147696",
        "1.3.6.1.4.1.25623.1.0.100061",
        "1.3.6.1.4.1.25623.1.0.147697",
        "1.3.6.1.4.1.25623.1.0.147698",
        "1.3.6.1.4.1.25623.1.0.147699",
    ];

    let protocols = ["tcp", "udp"];
    let type_options = ["alarm", "log"];

    let seed_base = config.seed.wrapping_add(hash_str(scan_id));

    let host_count_actual = if config.result_count < config.host_count {
        config.result_count.max(1)
    } else {
        config.host_count
    };

    let mut results = Vec::with_capacity(config.result_count);

    for i in 0..config.result_count {
        let seed_i = seed_base.wrapping_mul(31).wrapping_add(i as u64);
        let host_idx = i % host_count_actual;

        let ip_third = ((seed_i >> 8) & 0xFF) as u8;
        let ip_fourth = ((seed_i >> 16) & 0xFE) as u8 | 1; // ensure odd, non-zero

        let id = i + 1;
        let ip_address = format!("10.42.{}.{}", ip_third, ip_fourth);
        let hostname = format!("synthetic-host-{:04}.lab", host_idx + 1);
        let oid = oids[seed_i as usize % oids.len()];
        let port = ((seed_i % 65525) + 10) as u16; // 10-65534
        let protocol = protocols[seed_i as usize % protocols.len()];
        let type_ = type_options[seed_i as usize % type_options.len()];

        let message_seed = seed_i.wrapping_mul(7);
        let message = format!(
            "Synthetic finding #{}: detected potential issue ({})",
            id,
            match message_seed % 6 {
                0 => "low severity",
                1 => "medium severity",
                2 => "high severity",
                3 => "informational",
                4 => "best practice violation",
                _ => "configuration issue",
            }
        );

        results.push(ResultItem {
            id,
            type_: type_.to_string(),
            ip_address,
            hostname,
            oid: oid.to_string(),
            port,
            protocol: protocol.to_string(),
            message,
        });
    }

    results
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn create_scan(
    state: web::Data<AppState>,
    _body: web::Json<CreateScanRequest>,
) -> HttpResponse {
    let scan_id = uuid::Uuid::new_v4().to_string();

    let mut scans = state.scans.lock().unwrap();
    scans.insert(
        scan_id.clone(),
        ScanState {
            status: ScanStatus::Created,
            status_polls_since_start: 0,
            result_polls_since_start: 0,
        },
    );

    HttpResponse::Created()
        .content_type("application/json")
        .json(ScanIdResponse { id: scan_id })
}

async fn scan_action(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ScanActionRequest>,
) -> HttpResponse {
    let scan_id = path.into_inner();

    let mut scans = state.scans.lock().unwrap();
    let scan = match scans.get_mut(&scan_id) {
        Some(s) => s,
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "scan not found"})),
    };

    match body.action.as_str() {
        "start" => {
            match scan.status {
                ScanStatus::Created | ScanStatus::Stopped => {
                    scan.status = ScanStatus::Running;
                    scan.status_polls_since_start = 0;
                    scan.result_polls_since_start = 0;
                }
                // Running -> Running is idempotent
                _ => {} // succeeded can't be restarted; idempotent
            }
            HttpResponse::Ok().json(ScanStatusResponse {
                id: scan_id.clone(),
                status: scan.status.as_str().to_string(),
            })
        }
        "stop" => {
            if scan.status == ScanStatus::Running {
                scan.status = ScanStatus::Stopped;
            }
            HttpResponse::Ok().json(ScanStatusResponse {
                id: scan_id.clone(),
                status: scan.status.as_str().to_string(),
            })
        }
        _ => {
            HttpResponse::BadRequest().json(serde_json::json!({"error": "unknown action"}))
        }
    }
}

async fn get_status(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let config = &state.config;

    let mut scans = state.scans.lock().unwrap();
    let scan = match scans.get_mut(&scan_id) {
        Some(s) => s,
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "scan not found"})),
    };

    // Advance state: if running and enough polls, transition to succeeded
    if scan.status == ScanStatus::Running {
        scan.status_polls_since_start += 1;
        if scan.status_polls_since_start >= config.scan_complete_polls {
            scan.status = ScanStatus::Succeeded;
        }
    }

    HttpResponse::Ok().json(ScanStatusResponse {
        id: scan_id.clone(),
        status: scan.status.as_str().to_string(),
    })
}

async fn get_results(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let config = &state.config;

    let mut scans = state.scans.lock().unwrap();
    let scan = match scans.get_mut(&scan_id) {
        Some(s) => s,
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "scan not found"}));
        }
    };

    // Before scan is started, return empty results (preferred behavior per spec)
    if scan.status == ScanStatus::Created || scan.status == ScanStatus::Stopped {
        return HttpResponse::Ok().json(ResultsResponse {
            scan_id: scan_id.clone(),
            results: Vec::new(),
        });
    }

    // Count result polls for delay behavior
    scan.result_polls_since_start += 1;

    if scan.result_polls_since_start <= config.findings_delay_polls {
        // Still in delay window — return empty results
        return HttpResponse::Ok().json(ResultsResponse {
            scan_id: scan_id.clone(),
            results: Vec::new(),
        });
    }

    // Generate deterministic results
    let results = generate_results(config, &scan_id);

    HttpResponse::Ok().json(ResultsResponse {
        scan_id: scan_id.clone(),
        results,
    })
}

async fn delete_scan(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let scan_id = path.into_inner();

    let mut scans = state.scans.lock().unwrap();
    match scans.remove(&scan_id) {
        Some(_) => HttpResponse::NoContent().finish(),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "scan not found"})),
    }
}

async fn not_found() -> HttpResponse {
    HttpResponse::NotFound().json(serde_json::json!({"error": "not found"}))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load config — fails fast on invalid values with stderr message and non-zero exit
    let config = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    let port: u16 = match std::env::var("PORT") {
        Ok(p) => p.trim().parse().unwrap_or_else(|_| {
            eprintln!("Invalid PORT value");
            std::process::exit(1);
        }),
        Err(_) => {
            eprintln!("PORT environment variable not set");
            std::process::exit(1);
        }
    };

    let app_state = web::Data::new(AppState {
        config,
        scans: Mutex::new(HashMap::new()),
    });

    eprintln!(
        "Starting OpenVAS mock server on 127.0.0.1:{}",
        port
    );

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .route("/scans", web::post().to(create_scan))
            .route("/scans/{scan_id}", web::post().to(scan_action))
            .route("/scans/{scan_id}/status", web::get().to(get_status))
            .route("/scans/{scan_id}/results", web::get().to(get_results))
            .route("/scans/{scan_id}", web::delete().to(delete_scan))
            .default_service(web::route().to(not_found))
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}
