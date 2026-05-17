use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::env;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

#[derive(Clone)]
struct Config {
    host: String,
    port: u16,
    result_count: usize,
    findings_delay_polls: usize,
    scan_complete_polls: usize,
    host_count: usize,
    seed: String,
}

#[derive(Clone)]
struct Template {
    finding_type: &'static str,
    oid: &'static str,
    port: u16,
    protocol: &'static str,
    message: &'static str,
}

#[derive(Clone)]
struct Scan {
    scan_id: String,
    payload: Value,
    status: String,
    started: bool,
    status_polls_after_start: usize,
    results_polls_after_start: usize,
    cached_results: Vec<ResultItem>,
}

#[derive(Clone, Serialize)]
struct ResultItem {
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

struct AppState {
    config: Config,
    next_id: usize,
    scans: HashMap<String, Scan>,
}

fn templates() -> [Template; 4] {
    [
        Template {
            finding_type: "alarm",
            oid: "1.3.6.1.4.1.25623.1.0.147696",
            port: 22,
            protocol: "tcp",
            message: "Synthetic SSH finding with a plausible version banner.",
        },
        Template {
            finding_type: "alarm",
            oid: "1.3.6.1.4.1.25623.1.0.50282",
            port: 80,
            protocol: "tcp",
            message: "Synthetic HTTP service finding for deterministic benchmark use.",
        },
        Template {
            finding_type: "alarm",
            oid: "1.3.6.1.4.1.25623.1.0.10330",
            port: 445,
            protocol: "tcp",
            message: "Synthetic SMB fingerprint result for mock scanner testing.",
        },
        Template {
            finding_type: "log",
            oid: "1.3.6.1.4.1.25623.1.0.117628",
            port: 21,
            protocol: "tcp",
            message: "Synthetic FTP observation emitted by the mock server.",
        },
    ]
}

fn parse_usize_env(name: &str, default_value: usize, minimum: usize) -> Result<usize, String> {
    let raw = env::var(name).unwrap_or_else(|_| default_value.to_string());
    let value = raw
        .parse::<usize>()
        .map_err(|_| format!("{} must be an integer, got {:?}", name, raw))?;
    if value < minimum {
        return Err(format!("{} must be >= {}, got {}", name, minimum, value));
    }
    Ok(value)
}

fn parse_u16_env(name: &str, default_value: u16) -> Result<u16, String> {
    let raw = env::var(name).unwrap_or_else(|_| default_value.to_string());
    raw.parse::<u16>().map_err(|_| {
        format!(
            "{} must be an integer between 0 and 65535, got {:?}",
            name, raw
        )
    })
}

fn load_config() -> Result<Config, String> {
    Ok(Config {
        host: "127.0.0.1".to_string(),
        port: parse_u16_env("PORT", 8000)?,
        result_count: parse_usize_env("MOCK_RESULT_COUNT", 100, 0)?,
        findings_delay_polls: parse_usize_env("MOCK_FINDINGS_DELAY_POLLS", 0, 0)?,
        scan_complete_polls: parse_usize_env("MOCK_SCAN_COMPLETE_POLLS", 1, 1)?,
        host_count: parse_usize_env("MOCK_HOST_COUNT", 10, 1)?,
        seed: env::var("MOCK_SEED").unwrap_or_else(|_| "openvas-mock-sanner".to_string()),
    })
}

fn ip_for(host_index: usize) -> String {
    let block = host_index / 250;
    let host = host_index % 250 + 1;
    format!("10.42.{}.{}", block, host)
}

fn stable_offset(seed: &str, scan_id: &str) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut hasher);
    scan_id.hash(&mut hasher);
    hasher.finish() as usize
}

fn generate_results(scan_id: &str, config: &Config) -> Vec<ResultItem> {
    if config.result_count == 0 {
        return Vec::new();
    }
    let template_set = templates();
    let active_host_count = config.host_count.min(config.result_count);
    let offset = stable_offset(&config.seed, scan_id);
    let mut results = Vec::with_capacity(config.result_count);

    for result_id in 1..=config.result_count {
        let host_index = (result_id - 1) % active_host_count;
        let template = &template_set[(offset + result_id - 1) % template_set.len()];
        let ip_address = ip_for(host_index);
        let hostname = format!("synthetic-host-{:04}.lab", host_index + 1);
        results.push(ResultItem {
            id: result_id,
            finding_type: template.finding_type.to_string(),
            ip_address: ip_address.clone(),
            hostname: hostname.clone(),
            oid: template.oid.to_string(),
            port: template.port,
            protocol: template.protocol.to_string(),
            message: format!(
                "{} Synthetic target: {} ({}). Scan: {}. Slot: {}.",
                template.message, hostname, ip_address, scan_id, result_id
            ),
        });
    }

    results
}

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()
}

fn respond_json(request: Request, status: u16, payload: Value) {
    let body = serde_json::to_string(&payload).unwrap();
    let response = Response::from_string(body)
        .with_status_code(StatusCode(status))
        .with_header(json_header());
    let _ = request.respond(response);
}

fn respond_empty(request: Request, status: u16) {
    let response = Response::empty(StatusCode(status)).with_header(json_header());
    let _ = request.respond(response);
}

fn parse_json_body(request: &mut Request) -> Result<Value, String> {
    let mut body = String::new();
    request
        .as_reader()
        .read_to_string(&mut body)
        .map_err(|err| format!("failed to read request body: {}", err))?;
    if body.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let value: Value = serde_json::from_str(&body).map_err(|_| "invalid json".to_string())?;
    match value {
        Value::Object(_) => Ok(value),
        _ => Err("request body must be a json object".to_string()),
    }
}

fn not_found(request: Request) {
    respond_json(request, 404, json!({"error": "not found"}));
}

fn scan_not_found(request: Request) {
    respond_json(request, 404, json!({"error": "scan not found"}));
}

fn handle_request(mut request: Request, state: &Arc<Mutex<AppState>>) {
    let method = request.method().clone();
    let path = request.url().to_string();
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match (method, segments.as_slice()) {
        (Method::Post, ["scans"]) => match parse_json_body(&mut request) {
            Ok(payload) => {
                let mut state = state.lock().unwrap();
                let scan_id = format!("scan-{:04}", state.next_id);
                state.next_id += 1;
                state.scans.insert(
                    scan_id.clone(),
                    Scan {
                        scan_id: scan_id.clone(),
                        payload,
                        status: "created".to_string(),
                        started: false,
                        status_polls_after_start: 0,
                        results_polls_after_start: 0,
                        cached_results: Vec::new(),
                    },
                );
                respond_json(request, 201, json!({"id": scan_id}));
            }
            Err(message) => respond_json(request, 400, json!({"error": message})),
        },
        (Method::Post, ["scans", scan_id]) => match parse_json_body(&mut request) {
            Ok(payload) => {
                let action = payload.get("action").and_then(Value::as_str);
                let mut state = state.lock().unwrap();
                let Some(scan) = state.scans.get_mut(*scan_id) else {
                    scan_not_found(request);
                    return;
                };

                match action {
                    Some("start") => {
                        if scan.status == "created" || scan.status == "stopped" {
                            scan.status = "running".to_string();
                            scan.started = true;
                        }
                        respond_json(
                            request,
                            200,
                            json!({"id": scan.scan_id, "status": scan.status}),
                        );
                    }
                    Some("stop") => {
                        if scan.status == "running" {
                            scan.status = "stopped".to_string();
                        }
                        respond_json(
                            request,
                            200,
                            json!({"id": scan.scan_id, "status": scan.status}),
                        );
                    }
                    _ => respond_json(request, 400, json!({"error": "unknown action"})),
                }
            }
            Err(message) => respond_json(request, 400, json!({"error": message})),
        },
        (Method::Get, ["scans", scan_id, "status"]) => {
            let mut state = state.lock().unwrap();
            let complete_polls = state.config.scan_complete_polls;
            let Some(scan) = state.scans.get_mut(*scan_id) else {
                scan_not_found(request);
                return;
            };
            if scan.status == "running" {
                scan.status_polls_after_start += 1;
                if scan.status_polls_after_start >= complete_polls {
                    scan.status = "succeeded".to_string();
                }
            }
            respond_json(
                request,
                200,
                json!({"id": scan.scan_id, "status": scan.status}),
            );
        }
        (Method::Get, ["scans", scan_id, "results"]) => {
            let mut state = state.lock().unwrap();
            let config = state.config.clone();
            let Some(scan) = state.scans.get_mut(*scan_id) else {
                scan_not_found(request);
                return;
            };
            if !scan.started {
                respond_json(
                    request,
                    200,
                    json!({"scan_id": scan.scan_id, "results": []}),
                );
                return;
            }
            scan.results_polls_after_start += 1;
            if scan.results_polls_after_start <= config.findings_delay_polls {
                respond_json(
                    request,
                    200,
                    json!({"scan_id": scan.scan_id, "results": []}),
                );
                return;
            }
            if scan.cached_results.is_empty() {
                scan.cached_results = generate_results(&scan.scan_id, &config);
            }
            respond_json(
                request,
                200,
                json!({"scan_id": scan.scan_id, "results": scan.cached_results}),
            );
        }
        (Method::Delete, ["scans", scan_id]) => {
            let mut state = state.lock().unwrap();
            if state.scans.remove(*scan_id).is_some() {
                respond_json(request, 200, json!({"status": "deleted"}));
            } else {
                scan_not_found(request);
            }
        }
        _ => not_found(request),
    }
}

fn main() {
    let config = match load_config() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("configuration error: {}", message);
            std::process::exit(2);
        }
    };

    let address = format!("{}:{}", config.host, config.port);
    let server = match Server::http(&address) {
        Ok(server) => server,
        Err(err) => {
            eprintln!("server error: {}", err);
            std::process::exit(3);
        }
    };

    println!("listening on http://{}", address);
    let state = Arc::new(Mutex::new(AppState {
        config,
        next_id: 1,
        scans: HashMap::new(),
    }));

    for request in server.incoming_requests() {
        handle_request(request, &state);
    }
}
