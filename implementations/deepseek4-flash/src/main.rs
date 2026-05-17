use rand::RngCore;
use rand_chacha::ChaChaRng;
use rand_chacha::rand_core::SeedableRng;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Config {
    port: u16,
    result_count: usize,
    findings_delay_polls: usize,
    scan_complete_polls: usize,
    host_count: usize,
    seed: Vec<u8>,
}

fn load_config() -> Result<Config, String> {
    let port = parse_env_u16("PORT", 8000)?;
    let result_count = parse_env_usize("MOCK_RESULT_COUNT", 100)?;
    let findings_delay = parse_env_usize("MOCK_FINDINGS_DELAY_POLLS", 0)?;
    let complete_polls = parse_env_usize("MOCK_SCAN_COMPLETE_POLLS", 1)?;
    let host_count = parse_env_usize("MOCK_HOST_COUNT", 10)?;
    let seed_raw =
        env::var("MOCK_SEED").unwrap_or_else(|_| "openvas-mock-sanner".to_string());

    // Sanity validation
    if result_count > 1_000_000 {
        return Err("MOCK_RESULT_COUNT too large (max 1_000_000)".into());
    }
    if host_count < 1 || host_count > 100_000 {
        return Err("MOCK_HOST_COUNT must be >= 1 and <= 100_000".into());
    }

    Ok(Config {
        port,
        result_count,
        findings_delay_polls: findings_delay,
        scan_complete_polls: complete_polls,
        host_count,
        seed: seed_raw.into_bytes(),
    })
}

fn parse_env_usize(name: &str, default: usize) -> Result<usize, String> {
    let raw = env::var(name).unwrap_or_else(|_| default.to_string());
    raw.parse::<usize>()
        .map_err(|_| format!("{} must be a non-negative integer, got {:?}", name, raw))
}

fn parse_env_u16(name: &str, default: u16) -> Result<u16, String> {
    let raw = env::var(name).unwrap_or_else(|_| default.to_string());
    raw.parse::<u16>()
        .map_err(|_| format!("{} must be an integer 0–65535, got {:?}", name, raw))
}

// ---------------------------------------------------------------------------
// Deterministic data generation with ChaCha
// ---------------------------------------------------------------------------

static TEMPLATES: &[(&str, &str, u16, &str, &str)] = &[
    ("alarm", "1.3.6.1.4.1.25623.1.0.147696", 22, "tcp", "Synthetic SSH finding"),
    ("alarm", "1.3.6.1.4.1.25623.1.0.50282", 80, "tcp", "Synthetic HTTP service finding"),
    ("alarm", "1.3.6.1.4.1.25623.1.0.10330", 445, "tcp", "Synthetic SMB fingerprint"),
    ("log", "1.3.6.1.4.1.25623.1.0.117628", 21, "tcp", "Synthetic FTP observation"),
    ("alarm", "1.3.6.1.4.1.25623.1.0.100315", 443, "tcp", "Synthetic HTTPS service finding"),
    ("log", "1.3.6.1.4.1.25623.1.0.104002", 161, "udp", "Synthetic SNMP discovery log"),
];

#[derive(Clone, Serialize)]
struct ResultItem {
    id: usize,
    #[serde(rename = "type")]
    kind: String,
    ip_address: String,
    hostname: String,
    oid: String,
    port: u16,
    protocol: String,
    message: String,
}

fn seed_bytes_for(seed: &[u8], scan_id: &str) -> [u8; 32] {
    let mut buf = Vec::with_capacity(seed.len() + scan_id.len());
    buf.extend_from_slice(seed);
    buf.extend_from_slice(scan_id.as_bytes());
    while buf.len() < 32 {
        buf.push(0);
    }
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&buf[..32]);
    fixed
}

fn generate_results(config: &Config, scan_id: &str) -> Vec<ResultItem> {
    if config.result_count == 0 {
        return Vec::new();
    }

    let fixed = seed_bytes_for(&config.seed, scan_id);
    let mut rng = ChaChaRng::from_seed(fixed);
    let n = config.result_count;
    let host_count = config.host_count.min(n);
    let mut results = Vec::with_capacity(n);

    for id in 1..=n {
        let template_idx = (rng.next_u64() as usize) % TEMPLATES.len();
        let host_idx = (id - 1) % host_count;

        let (kind, oid, port, protocol, msg) = TEMPLATES[template_idx];

        let ip_block = host_idx / 250;
        let ip_host = (host_idx % 250) + 1;
        let ip_address = format!("10.42.{}.{}", ip_block, ip_host);
        let hostname = format!("synthetic-host-{:04}.lab", host_idx + 1);
        let message = format!(
            "{} — target {} ({}); scan {}, slot {}",
            msg, hostname, ip_address, scan_id, id
        );

        results.push(ResultItem {
            id,
            kind: kind.to_string(),
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
// Scan state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Scan {
    scan_id: String,
    payload: Value,
    status: String,
    started: bool,
    status_polls_after_start: usize,
    results_polls_after_start: usize,
    /// memoized generated results
    cached_results: Option<Vec<ResultItem>>,
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn json_response(status: u16, value: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(value).unwrap();
    Response::from_data(body)
        .with_status_code(StatusCode(status))
        .with_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        )
}

fn read_json_body(request: &mut Request) -> Result<Value, String> {
    let mut body = String::new();
    request
        .as_reader()
        .read_to_string(&mut body)
        .map_err(|e| format!("failed to read body: {}", e))?;
    if body.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_str(&body).map_err(|_| "invalid JSON in request body".to_string())
}

// ---------------------------------------------------------------------------
// Request router — uses AppState to avoid double-borrow of "app"
// ---------------------------------------------------------------------------

struct AppState {
    config: Config,
    next_scan_id: usize,
    scans: HashMap<String, Scan>,
}

fn route(mut request: Request, state: Arc<Mutex<AppState>>) {
    let method = request.method().clone();
    let url = request.url().to_string();
    let segments: Vec<&str> = url.trim_start_matches('/').split('/').collect();

    // Extract values we'll need while holding the lock
    // We clone/derive config outside the lock to avoid borrow conflicts
    match (method, segments.as_slice()) {
        // POST /scans — create scan
        (Method::Post, ["scans"]) => {
            let payload = match read_json_body(&mut request) {
                Ok(v) => v,
                Err(msg) => {
                    let _ = request.respond(json_response(400, &json!({"error": msg})));
                    return;
                }
            };
            let mut state = state.lock().unwrap();
            let scan_id = format!("scan-{:04}", state.next_scan_id);
            state.next_scan_id += 1;
            let scan = Scan {
                scan_id: scan_id.clone(),
                payload,
                status: "created".to_string(),
                started: false,
                status_polls_after_start: 0,
                results_polls_after_start: 0,
                cached_results: None,
            };
            state.scans.insert(scan_id.clone(), scan);
            let _ = request.respond(json_response(201, &json!({"id": scan_id})));
        }

        // POST /scans/{scan_id} — action (start/stop)
        (Method::Post, ["scans", scan_id]) => {
            let payload = match read_json_body(&mut request) {
                Ok(v) => v,
                Err(msg) => {
                    let _ = request.respond(json_response(400, &json!({"error": msg})));
                    return;
                }
            };
            let action = payload
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let mut state = state.lock().unwrap();
            let Some(scan) = state.scans.get_mut(*scan_id) else {
                let _ = request.respond(json_response(404, &json!({"error": "scan not found"})));
                return;
            };

            match action {
                "start" => {
                    if scan.status == "created" || scan.status == "stopped" {
                        scan.status = "running".to_string();
                        scan.started = true;
                    }
                    let _ = request.respond(json_response(
                        200,
                        &json!({"id": scan.scan_id, "status": scan.status}),
                    ));
                }
                "stop" => {
                    if scan.status == "running" {
                        scan.status = "stopped".to_string();
                    }
                    let _ = request.respond(json_response(
                        200,
                        &json!({"id": scan.scan_id, "status": scan.status}),
                    ));
                }
                _ => {
                    let _ = request.respond(json_response(400, &json!({"error": "unknown action"})));
                }
            }
        }

        // GET /scans/{scan_id}/status
        (Method::Get, ["scans", scan_id, "status"]) => {
            let mut state = state.lock().unwrap();
            let complete_polls = state.config.scan_complete_polls;
            let Some(scan) = state.scans.get_mut(*scan_id) else {
                let _ = request.respond(json_response(404, &json!({"error": "scan not found"})));
                return;
            };

            if scan.status == "running" {
                scan.status_polls_after_start += 1;
                if scan.status_polls_after_start >= complete_polls {
                    scan.status = "succeeded".to_string();
                }
            }

            let _ = request.respond(json_response(
                200,
                &json!({"id": scan.scan_id, "status": scan.status}),
            ));
        }

        // GET /scans/{scan_id}/results
        (Method::Get, ["scans", scan_id, "results"]) => {
            // Step 1: check scan under lock, clone config early
            let scan_id_owned = scan_id.to_string();
            let (config, needs_generation) = {
                let mut state = state.lock().unwrap();
                let cfg = state.config.clone();

                let Some(scan) = state.scans.get_mut(&scan_id_owned) else {
                    let _ = request.respond(json_response(404, &json!({"error": "scan not found"})));
                    return;
                };

                if !scan.started {
                    let _ = request.respond(json_response(
                        200,
                        &json!({"scan_id": scan.scan_id, "results": []}),
                    ));
                    return;
                }

                // Respect findings delay
                scan.results_polls_after_start += 1;
                if scan.results_polls_after_start <= cfg.findings_delay_polls {
                    let _ = request.respond(json_response(
                        200,
                        &json!({"scan_id": scan.scan_id, "results": []}),
                    ));
                    return;
                }

                // If already cached, serve directly
                if let Some(ref cached) = scan.cached_results {
                    let _ = request.respond(json_response(
                        200,
                        &json!({"scan_id": scan.scan_id, "results": cached}),
                    ));
                    return;
                }

                // Need to generate
                (cfg, true)
            };

            if !needs_generation {
                return;
            }

            // Generate results without the lock held
            let results = generate_results(&config, &scan_id_owned);

            // Store in cache and respond
            let mut state = state.lock().unwrap();
            if let Some(scan) = state.scans.get_mut(&scan_id_owned) {
                scan.cached_results = Some(results.clone());
                let _ = request.respond(json_response(
                    200,
                    &json!({"scan_id": scan.scan_id, "results": results}),
                ));
            } else {
                let _ = request.respond(json_response(404, &json!({"error": "scan not found"})));
            }
        }

        // DELETE /scans/{scan_id}
        (Method::Delete, ["scans", scan_id]) => {
            let mut state = state.lock().unwrap();
            if state.scans.remove(*scan_id).is_some() {
                let _ = request.respond(json_response(200, &json!({"status": "deleted"})));
            } else {
                let _ = request.respond(json_response(404, &json!({"error": "scan not found"})));
            }
        }

        // Everything else → 404
        _ => {
            let _ = request.respond(json_response(404, &json!({"error": "not found"})));
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let config = match load_config() {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("CONFIG ERROR: {}", msg);
            std::process::exit(2);
        }
    };

    let addr = format!("127.0.0.1:{}", config.port);
    let server = match Server::http(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SERVER ERROR: cannot bind {} — {}", addr, e);
            std::process::exit(3);
        }
    };

    eprintln!("deepseek4-flash mock server listening on http://{}", addr);

    let state = Arc::new(Mutex::new(AppState {
        config,
        next_scan_id: 1,
        scans: HashMap::new(),
    }));

    for request in server.incoming_requests() {
        route(request, Arc::clone(&state));
    }
}
