use actix_web::{web, App, HttpResponse, HttpServer, middleware::Logger, Result, HttpRequest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use rand::{Rng, SeedableRng};
use rand_core::SeedableRng as _;

// Scan status enum
#[derive(Serialize, Clone, Debug)]
enum ScanStatus {
    #[serde(rename = "created")]
    Created,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "stopped")]
    Stopped,
    #[serde(rename = "succeeded")]
    Succeeded,
    #[serde(rename = "deleted")]
    Deleted,
}

// Scan struct
#[derive(Serialize, Clone, Debug)]
struct Scan {
    id: String,
    status: ScanStatus,
    payload: serde_json::Value,
    result_poll_count: usize,
}

// Create scan request
#[derive(Deserialize)]
struct CreateScanRequest {
    #[serde(default)]
    target: serde_json::Value,
    #[serde(default)]
    vts: Vec<serde_json::Value>,
}

// Scan action request
#[derive(Deserialize)]
struct ScanActionRequest {
    action: String,
}

// Create scan response
#[derive(Serialize)]
struct CreateScanResponse {
    id: String,
}

// Scan status response
#[derive(Serialize)]
struct ScanStatusResponse {
    id: String,
    status: ScanStatus,
}

// Scan action response
#[derive(Serialize)]
struct ScanActionResponse {
    id: String,
    status: ScanStatus,
}

// Result item
#[derive(Serialize, Clone, Debug)]
struct ResultItem {
    id: usize,
    #[serde(rename = "type")]
    result_type: String,
    ip_address: String,
    hostname: String,
    oid: String,
    port: u16,
    protocol: String,
    message: String,
}

// Results response
#[derive(Serialize)]
struct ResultsResponse {
    scan_id: String,
    results: Vec<ResultItem>,
}

// Application state
struct AppState {
    scans: Mutex<HashMap<String, Scan>>,
    result_count: usize,
    findings_delay_polls: usize,
    scan_complete_polls: usize,
    host_count: usize,
    seed: String,
}

impl AppState {
    fn new() -> Self {
        let result_count = env::var("MOCK_RESULT_COUNT")
            .unwrap_or_else(|_| "100".to_string())
            .parse()
            .expect("MOCK_RESULT_COUNT must be a valid integer");
        
        let findings_delay_polls = env::var("MOCK_FINDINGS_DELAY_POLLS")
            .unwrap_or_else(|_| "0".to_string())
            .parse()
            .expect("MOCK_FINDINGS_DELAY_POLLS must be a valid integer");
        
        let scan_complete_polls = env::var("MOCK_SCAN_COMPLETE_POLLS")
            .unwrap_or_else(|_| "1".to_string())
            .parse()
            .expect("MOCK_SCAN_COMPLETE_POLLS must be a valid integer");
        
        let host_count = env::var("MOCK_HOST_COUNT")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .expect("MOCK_HOST_COUNT must be a valid integer");
        
        let seed = env::var("MOCK_SEED")
            .unwrap_or_else(|_| "openvas-mock-sanner".to_string());

        Self {
            scans: Mutex::new(HashMap::new()),
            result_count,
            findings_delay_polls,
            scan_complete_polls,
            host_count,
            seed,
        }
    }

    fn generate_results(&self, scan_id: &str) -> Vec<ResultItem> {
        let mut results = Vec::with_capacity(self.result_count);
        
        // Create a deterministic seed based on scan_id and the configured seed
        let mut seed_data = self.seed.clone();
        seed_data.push_str(scan_id);
        let seed_bytes = seed_data.as_bytes();
        
        // Create a hash of the seed data to use as a numeric seed
        let mut hash: u64 = 0;
        for &byte in seed_bytes {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        
        let mut rng = rand::rngs::StdRng::seed_from_u64(hash);
        
        let oids = [
            "1.3.6.1.4.1.25623.1.0.147696",
            "1.3.6.1.4.1.25623.1.0.103696",
            "1.3.6.1.4.1.25623.1.0.112196",
        ];
        
        let protocols = ["tcp", "udp"];
        let result_types = ["alarm", "log"];
        
        for i in 1..=self.result_count {
            let host_index = (i - 1) % self.host_count;
            let oid_index = (i - 1) % oids.len();
            
            let result = ResultItem {
                id: i,
                result_type: result_types[rng.gen_range(0..result_types.len())].to_string(),
                ip_address: format!("10.42.{}.{}", (host_index / 256) % 256, host_index % 256),
                hostname: format!("synthetic-host-{:04}.lab", host_index),
                oid: oids[oid_index].to_string(),
                port: rng.gen_range(1..65535),
                protocol: protocols[rng.gen_range(0..protocols.len())].to_string(),
                message: format!("Synthetic finding text #{}", i),
            };
            
            results.push(result);
        }
        
        results
    }
}

// Create a new scan
async fn create_scan(
    data: web::Data<Arc<AppState>>,
    payload: web::Json<CreateScanRequest>,
) -> Result<HttpResponse> {
    let mut scans = data.scans.lock().unwrap();
    
    // Generate a unique scan ID
    let scan_id = format!("scan-{:04}", scans.len() + 1);
    
    let scan = Scan {
        id: scan_id.clone(),
        status: ScanStatus::Created,
        payload: serde_json::json!({
            "target": payload.target,
            "vts": payload.vts
        }),
        result_poll_count: 0,
    };
    
    scans.insert(scan_id.clone(), scan);
    
    let response = CreateScanResponse { id: scan_id };
    Ok(HttpResponse::Created().json(response))
}

// Perform scan action
async fn scan_action(
    data: web::Data<Arc<AppState>>,
    path: web::Path<String>,
    payload: web::Json<ScanActionRequest>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();
    
    let mut scans = data.scans.lock().unwrap();
    
    if let Some(scan) = scans.get_mut(&scan_id) {
        match payload.action.as_str() {
            "start" => {
                scan.status = ScanStatus::Running;
            },
            "stop" => {
                scan.status = ScanStatus::Stopped;
            },
            _ => {
                return Ok(HttpResponse::BadRequest().json("Invalid action"));
            }
        }
        
        let response = ScanActionResponse {
            id: scan.id.clone(),
            status: scan.status.clone(),
        };
        
        Ok(HttpResponse::Ok().json(response))
    } else {
        Ok(HttpResponse::NotFound().json("Scan not found"))
    }
}

// Get scan status
async fn get_scan_status(
    data: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();
    
    let mut scans = data.scans.lock().unwrap();
    
    if let Some(scan) = scans.get_mut(&scan_id) {
        // Check if we should transition to succeeded
        if matches!(scan.status, ScanStatus::Running) && scan.result_poll_count >= data.scan_complete_polls {
            scan.status = ScanStatus::Succeeded;
        }
        
        let response = ScanStatusResponse {
            id: scan.id.clone(),
            status: scan.status.clone(),
        };
        
        Ok(HttpResponse::Ok().json(response))
    } else {
        Ok(HttpResponse::NotFound().json("Scan not found"))
    }
}

// Get scan results
async fn get_scan_results(
    data: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();
    
    let mut scans = data.scans.lock().unwrap();
    
    if let Some(scan) = scans.get_mut(&scan_id) {
        // Increment result poll count
        scan.result_poll_count += 1;
        
        // Check if we should transition to succeeded
        if matches!(scan.status, ScanStatus::Running) && scan.result_poll_count >= data.scan_complete_polls {
            scan.status = ScanStatus::Succeeded;
        }
        
        let results = if scan.result_poll_count <= data.findings_delay_polls {
            // Return empty results until delay threshold is crossed
            vec![]
        } else {
            // Return generated results
            data.generate_results(&scan_id)
        };
        
        let response = ResultsResponse {
            scan_id: scan.id.clone(),
            results,
        };
        
        Ok(HttpResponse::Ok().json(response))
    } else {
        Ok(HttpResponse::NotFound().json("Scan not found"))
    }
}

// Delete a scan
async fn delete_scan(
    data: web::Data<Arc<AppState>>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();
    
    let mut scans = data.scans.lock().unwrap();
    
    if scans.contains_key(&scan_id) {
        scans.remove(&scan_id);
        Ok(HttpResponse::Ok().finish())
    } else {
        Ok(HttpResponse::NotFound().json("Scan not found"))
    }
}

// 404 handler
async fn not_found(_req: HttpRequest) -> Result<HttpResponse> {
    Ok(HttpResponse::NotFound().json("Not found"))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Check for required PORT environment variable
    let port = env::var("PORT")
        .expect("PORT environment variable is required");
    
    // Validate configuration at startup
    if let Err(e) = env::var("MOCK_RESULT_COUNT") {
        eprintln!("Error: MOCK_RESULT_COUNT not set or invalid: {}", e);
        std::process::exit(1);
    }
    
    if let Err(e) = env::var("MOCK_FINDINGS_DELAY_POLLS") {
        eprintln!("Error: MOCK_FINDINGS_DELAY_POLLS not set or invalid: {}", e);
        std::process::exit(1);
    }
    
    if let Err(e) = env::var("MOCK_SCAN_COMPLETE_POLLS") {
        eprintln!("Error: MOCK_SCAN_COMPLETE_POLLS not set or invalid: {}", e);
        std::process::exit(1);
    }
    
    if let Err(e) = env::var("MOCK_HOST_COUNT") {
        eprintln!("Error: MOCK_HOST_COUNT not set or invalid: {}", e);
        std::process::exit(1);
    }
    
    let app_state = Arc::new(AppState::new());
    
    println!("Starting server on port {}", port);
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(Logger::default())
            .service(
                web::scope("/scans")
                    .route("", web::post().to(create_scan))
                    .route("/{scan_id}", web::post().to(scan_action))
                    .route("/{scan_id}/status", web::get().to(get_scan_status))
                    .route("/{scan_id}/results", web::get().to(get_scan_results))
                    .route("/{scan_id}", web::delete().to(delete_scan))
            )
            .default_service(web::route().to(not_found))
    })
    .bind(format!("127.0.0.1:{}", port))?
    .run()
    .await
}