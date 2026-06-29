use anyhow::{Result, Context};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio::process::Command;
use serde::Deserialize;
use crate::qihse::QihseClient;

#[derive(Deserialize, Debug)]
struct MispSearchResponse {
    response: MispResponseData,
}

#[derive(Deserialize, Debug)]
struct MispResponseData {
    #[serde(default, rename = "Attribute")]
    attributes: Vec<MispAttribute>,
}

#[derive(Deserialize, Debug)]
struct MispAttribute {
    #[serde(rename = "type")]
    attr_type: String,
    value: String,
}

pub async fn run_misp_sidecar(tx: mpsc::Sender<u32>) -> Result<()> {
    println!("[MISP] Sidecar activated. Connecting to live MISP instance at https://localhost:8443...");
    
    let db = QihseClient::new("qihse://localhost:9090");
    
    let misp_url = "https://localhost:8443";
    let misp_auth_key = "DEMO_AUTH_KEY_REPLACE_ME";

    // Wait for EDR to fully initialize
    sleep(Duration::from_secs(2)).await;
    
    loop {
        let payload = serde_json::json!({
            "returnFormat": "json",
            "type": ["ip-dst", "yara"],
            "published": true
        });
        
        let payload_str = serde_json::to_string(&payload).unwrap_or_default();

        let output = Command::new("curl")
            .arg("-k") // Accept invalid certs
            .arg("-s") // Silent
            .arg("-X")
            .arg("POST")
            .arg("-H")
            .arg(format!("Authorization: {}", misp_auth_key))
            .arg("-H")
            .arg("Accept: application/json")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(&payload_str)
            .arg(format!("{}/attributes/restSearch", misp_url))
            .output()
            .await;

        if let Ok(out) = output {
            if out.status.success() {
                let json_str = String::from_utf8_lossy(&out.stdout);
                if let Ok(misp_data) = serde_json::from_str::<MispSearchResponse>(&json_str) {
                    for attr in misp_data.response.attributes {
                        if attr.attr_type == "ip-dst" {
                            if let Ok(ip) = attr.value.parse::<Ipv4Addr>() {
                                let ip_u32 = u32::from(ip).to_be();
                                if tx.send(ip_u32).await.is_err() {
                                    eprintln!("[MISP] Connection to XDP engine lost. Shutting down sidecar.");
                                    return Ok(());
                                }
                                db.insert_threat_intel("IP_DST", &attr.value, "MISP_LIVE").unwrap_or_default();
                                println!("[MISP] Live Intel Synced: Blocked IP {} via XDP.", attr.value);
                            }
                        } else if attr.attr_type == "yara" {
                            db.insert_threat_intel("YARA_RULE", &attr.value, "MISP_LIVE").unwrap_or_default();
                            println!("[MISP] Live Intel Synced: Downloaded YARA Rule. Queued for scanner.");
                        }
                    }
                }
            } else {
                eprintln!("[MISP] Failed to fetch from MISP. Curl exited with: {}", out.status);
            }
        }
        
        // Sleep for standard polling interval (e.g., 5 minutes)
        sleep(Duration::from_secs(300)).await;
    }
}
