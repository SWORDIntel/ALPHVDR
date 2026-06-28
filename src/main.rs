use anyhow::{Result, Context};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use std::mem::MaybeUninit;
use std::time::Duration;
use tokio::time::sleep;
use tokio::sync::mpsc;

mod qihse;
use qihse::QihseClient;

mod misp;
mod rollback;
use rollback::ZfsManager;

mod yara;
use yara::YaraEngine;

mod memory_carver;
use memory_carver::MemoryCarver;

mod proxmox_bridge;
use proxmox_bridge::ProxmoxBridge;

mod kp14_suite;
use kp14_suite::Kp14Client;

mod sensor {
    include!(concat!(env!("OUT_DIR"), "/sensor.skel.rs"));
}
use sensor::*;

use libbpf_rs::{MapFlags, MapCore};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[repr(C)]
#[derive(Debug)]
struct Event {
    pub pid: i32,
    pub ppid: i32,
    pub uid: i32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

#[repr(C)]
#[derive(Debug)]
struct TlsHelloEvent {
    pub saddr: u32,
    pub daddr: u32,
    pub dport: u16,
    pub payload_len: u16,
    pub payload: [u8; 128],
}

fn handle_tls_event(data: &[u8]) -> i32 {
    if data.len() != std::mem::size_of::<TlsHelloEvent>() {
        return 0;
    }
    let event = unsafe { &*(data.as_ptr() as *const TlsHelloEvent) };
    
    // In production: Rust would parse the extensions and MD5 hash the cipher suites to create the JA3
    println!("[TLS JA3] Intercepted Client Hello to {}.{}.{}.{} | Payload size: {} bytes",
             event.daddr & 0xFF, (event.daddr >> 8) & 0xFF, (event.daddr >> 16) & 0xFF, (event.daddr >> 24) & 0xFF,
             event.payload_len);
    
    // Log to QIHSE
    let db = QihseClient::new("qihse://localhost:9090");
    if let Err(e) = db.insert_tls_telemetry(event.saddr, event.daddr, event.dport, event.payload_len) {
        eprintln!("[QIHSE] Failed to log TLS telemetry: {}", e);
    }
    
    0
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        if args[1] == "--kp14-daemon" {
            println!("Starting KP14-SUITE local daemon mode...");
            let kp14 = kp14_suite::Kp14Client::new();
            let _ = kp14.run_daemon_pipeline(3600)?;
            return Ok(());
        } else if args[1] == "--kp14-remote" && args.len() > 2 {
            println!("Starting KP14-SUITE remote SSH mode...");
            let kp14 = kp14_suite::Kp14Client::with_ssh_host(&args[2]);
            // Just test connectivity by listing block devices
            let _ = kp14.watch_for_hotplugged_device(1)?;
            return Ok(());
        } else if args[1] == "--yara-raw" && args.len() > 2 {
            println!("Running raw YARA scan on {}...", args[2]);
            let yara = yara::YaraEngine::new();
            if let Ok(data) = std::fs::read(&args[2]) {
                let _ = yara.scan_raw_buffer(&data)?;
            }
            return Ok(());
        }
    }

    println!("[ALPHVDR] Initializing Advanced Threat Detection Engine...");

    // Setup the Async Responder Engine channel
    let (tx, mut rx) = mpsc::channel::<i32>(1000);

    // Spawn the detached Responder task
    tokio::spawn(async move {
        println!("[RESPONDER] Async freeze engine active and listening for anomalies...");
        while let Some(pid) = rx.recv().await {
            println!("[RESPONDER] ⚡ CRITICAL THREAT DETECTED ⚡ -> Freezing PID {}", pid);
            unsafe {
                if libc::kill(pid, libc::SIGSTOP) == 0 {
                    println!("[RESPONDER] ✅ Successfully froze PID {}. Initiating memory carving pipeline...", pid);

                    // Phase 2 & 3: Carve memory and package into core dump blob
                    let carver = MemoryCarver::new(pid);
                    match carver.carve_and_package() {
                        Ok(blob_path) => {
                            println!("[RESPONDER] Core dump blob ready: {}", blob_path.display());

                            // Phase 4: Route to KP14-SUITE via Proxmox bridge
                            let bridge = ProxmoxBridge::default_kp14();
                            match bridge.route_to_kp14(&blob_path) {
                                Ok((volume_id, scsi_slot)) => {
                                    println!("[RESPONDER] Routed to KP14-SUITE (volume: {}, scsi{})", volume_id, scsi_slot);

                                    // Phase 5: Trigger KP14-SUITE analysis (remote SSH mode)
                                    let kp14 = Kp14Client::new();
                                    let blob_str = blob_path.to_string_lossy().to_string();
                                    tokio::task::spawn_blocking(move || {
                                        match kp14.run_remote_analysis(&blob_str) {
                                            Ok(iocs) => {
                                                println!("[RESPONDER] KP14-SUITE analysis complete. {} IOCs extracted.", iocs.len());
                                                for ioc in &iocs {
                                                    println!("[RESPONDER]   IOC [{:?}] {} (confidence: {:.2}, source: {})",
                                                             ioc.ioc_type, ioc.value, ioc.confidence, ioc.source);
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!("[RESPONDER] KP14-SUITE analysis failed: {}", e);
                                            }
                                        }
                                    });

                                    // Cleanup volume after analysis (async, delayed)
                                    let bridge_clone = bridge;
                                    tokio::spawn(async move {
                                        sleep(Duration::from_secs(300)).await; // 5min for analysis
                                        if let Err(e) = bridge_clone.cleanup_volume(&volume_id, scsi_slot) {
                                            eprintln!("[RESPONDER] Volume cleanup failed: {}", e);
                                        }
                                    });
                                }
                                Err(e) => {
                                    eprintln!("[RESPONDER] Proxmox routing failed: {}. Falling back to direct SSH transfer.", e);

                                    // Fallback: direct SSH to KP14-SUITE
                                    let kp14 = Kp14Client::new();
                                    let blob_str = blob_path.to_string_lossy().to_string();
                                    tokio::task::spawn_blocking(move || {
                                        if let Err(e) = kp14.run_remote_analysis(&blob_str) {
                                            eprintln!("[RESPONDER] Direct SSH analysis also failed: {}", e);
                                        }
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[RESPONDER] Memory carving failed for PID {}: {}", pid, e);
                        }
                    }
                } else {
                    eprintln!("[RESPONDER] ❌ Failed to freeze PID {}. It may have already exited.", pid);
                }
            }
        }
    });

    // Setup MISP Threat Intel Sidecar
    let (tx_misp, mut rx_misp) = mpsc::channel::<u32>(100);
    tokio::spawn(async move {
        let _ = misp::run_misp_sidecar(tx_misp).await;
    });

    let skel_builder = SensorSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object).context("Failed to open BPF program")?;
    let mut skel = open_skel.load().context("Failed to load BPF program")?;
    
    skel.attach().context("Failed to attach BPF program")?;
    println!("eBPF probes successfully attached to the kernel.");
    
    // --- Register Agent Self-Defense PID ---
    let my_pid: u32 = std::process::id();
    let zero_key = 0u32.to_ne_bytes();
    let pid_value = my_pid.to_ne_bytes();
    skel.maps.agent_pid.update(&zero_key, &pid_value, MapFlags::ANY).context("Failed to register self-defense PID")?;
    println!("[SELF-DEFENSE] EDR Kernel shield active for PID: {}", my_pid);
    // ---------------------------------------

    // --- Setup AWS Deception Honeytoken ---
    let aws_dir = "/home/john/.aws";
    let aws_cred_path = "/home/john/.aws/credentials";
    fs::create_dir_all(aws_dir).context("Failed to create .aws directory")?;
    
    let fake_aws_creds = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
    fs::write(aws_cred_path, fake_aws_creds).context("Failed to write AWS honeytoken")?;
    
    let metadata = fs::metadata(aws_cred_path).context("Failed to read honeytoken metadata")?;
    let inode: u64 = metadata.ino();
    
    let key = inode.to_ne_bytes();
    let value = 1u8.to_ne_bytes();
    skel.maps.honeytokens.update(&key, &value, MapFlags::ANY).context("Failed to register honeytoken in eBPF map")?;
    println!("[DECEPTION] AWS Credential Honeytoken deployed. Guarding inode: {}", inode);
    
    // --- Setup Kubernetes Deception Honeytoken ---
    let kube_dir = "/home/john/.kube";
    let kube_cred_path = "/home/john/.kube/config";
    fs::create_dir_all(kube_dir).context("Failed to create .kube directory")?;
    
    let fake_kube_creds = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://10.99.0.1:6443\n  name: k8s-admin\ncontexts:\n- context:\n    cluster: k8s-admin\n    user: kubernetes-admin\n  name: default\ncurrent-context: default\nkind: Config\npreferences: {}\nusers:\n- name: kubernetes-admin\n  user:\n    client-certificate-data: LS0tLS1C\n    client-key-data: LS0tLS1C\n";
    fs::write(kube_cred_path, fake_kube_creds).context("Failed to write Kubernetes honeytoken")?;
    
    let kube_metadata = fs::metadata(kube_cred_path).context("Failed to read kube honeytoken metadata")?;
    let kube_inode: u64 = kube_metadata.ino();
    
    let kube_key = kube_inode.to_ne_bytes();
    skel.maps.honeytokens.update(&kube_key, &value, MapFlags::ANY).context("Failed to register K8s honeytoken in eBPF map")?;
    println!("[DECEPTION] Kubernetes Kubeconfig Honeytoken deployed. Guarding inode: {}", kube_inode);
    
    // --- Setup SSH Authorized Keys Persistence Trap ---
    let ssh_dir = "/home/john/.ssh";
    let ssh_keys_path = "/home/john/.ssh/authorized_keys";
    fs::create_dir_all(ssh_dir).unwrap_or_default();
    if !std::path::Path::new(ssh_keys_path).exists() {
        fs::write(ssh_keys_path, "").unwrap_or_default();
    }
    if let Ok(ssh_metadata) = fs::metadata(ssh_keys_path) {
        let ssh_inode: u64 = ssh_metadata.ino();
        let ssh_key = ssh_inode.to_ne_bytes();
        let ssh_value = 2u8.to_ne_bytes(); // 2 = Write-only trap
        skel.maps.honeytokens.update(&ssh_key, &ssh_value, MapFlags::ANY).unwrap_or_default();
        println!("[DECEPTION] SSH authorized_keys Write-Trap deployed. Guarding inode: {}", ssh_inode);
    }
    // --------------------------------------------------
    
    // --- Setup Firmware / ME Hardware Locks ---
    let hw_devices = ["/dev/mei0", "/dev/mem", "/dev/kmem", "/dev/port"];
    for dev in hw_devices.iter() {
        if let Ok(hw_metadata) = fs::metadata(dev) {
            let hw_inode: u64 = hw_metadata.ino();
            let hw_key = hw_inode.to_ne_bytes();
            let hw_value = 2u8.to_ne_bytes(); // 2 = Write-only trap
            skel.maps.honeytokens.update(&hw_key, &hw_value, MapFlags::ANY).unwrap_or_default();
            println!("[HARDWARE-LOCK] Firmware Write-Trap deployed on {}. Guarding inode: {}", dev, hw_inode);
        } else {
            println!("[HARDWARE-LOCK] Device {} not present on host architecture. Skipping.", dev);
        }
    }
    // ------------------------------------------
    
    // --- Setup Ghost Process Decoys ---
    let decoys = ["keepassxc", "mongod", "mysqld"];
    fs::create_dir_all("/tmp/alphvdr_decoys").unwrap_or_default();
    
    for decoy in decoys.iter() {
        let decoy_path = format!("/tmp/alphvdr_decoys/{}", decoy);
        if let Ok(_) = std::fs::copy("/usr/bin/sleep", &decoy_path) {
            if let Ok(child) = std::process::Command::new(&decoy_path).arg("infinity").spawn() {
                let pid: u32 = child.id();
                let key = pid.to_ne_bytes();
                let value = 1u8.to_ne_bytes();
                skel.maps.ghost_pids.update(&key, &value, MapFlags::ANY).unwrap_or_default();
                println!("[DECEPTION] Spun up High-Value Decoy: '{}' (PID: {}). Monitoring for memory scraping.", decoy, pid);
                std::mem::forget(child);
            }
        }
    }
    // ----------------------------------

    let db = QihseClient::new("qihse://localhost:9090");
    let zfs = ZfsManager::new("rpool/home");
    let yara_engine = YaraEngine::new();
    let tx_exec = tx.clone();
    
    // Start automated daily backups
    let zfs_daily = zfs.clone();
    tokio::spawn(async move {
        println!("[ZFS-BACKUP] Automated snapshot scheduler active (24h cycle).");
        loop {
            // Take the snapshot first, then sleep 24 hours
            if let Err(e) = zfs_daily.take_daily_snapshot() {
                eprintln!("[ZFS-BACKUP] Scheduled task failed: {}", e);
            }
            sleep(Duration::from_secs(86400)).await;
        }
    });

    // --- Setup Authorized Research Mode Monitor ---
    let research_mode = Arc::new(AtomicBool::new(false));
    let rm_monitor = research_mode.clone();
    tokio::spawn(async move {
        let lock_path = std::path::Path::new("/tmp/ALPHVDR_RESEARCH_MODE");
        let mut was_active = false;
        loop {
            let is_active = lock_path.exists();
            rm_monitor.store(is_active, Ordering::Relaxed);
            
            if is_active && !was_active {
                println!("[MAINTENANCE] ⚠️ AUTHORIZED RESEARCH SESSION INITIATED. SHIELDS DROPPED. ⚠️");
            } else if !is_active && was_active {
                println!("[MAINTENANCE] 🛡️ RESEARCH SESSION TERMINATED. SHIELDS RAISED. 🛡️");
            }
            was_active = is_active;
            
            sleep(Duration::from_secs(2)).await;
        }
    });
    // ----------------------------------------------

    let mut builder = RingBufferBuilder::new();
    let rm_event_check = research_mode.clone();
    builder.add(
        &skel.maps.events,
        move |data: &[u8]| -> i32 {
            // Instant zero-overhead bypass if research mode is active
            if rm_event_check.load(Ordering::Relaxed) {
                return 0;
            }
            
            if data.len() != std::mem::size_of::<Event>() {
                eprintln!("Invalid event size from kernel");
                return 0;
            }
            
            let event = unsafe { &*(data.as_ptr() as *const Event) };
            let comm = String::from_utf8_lossy(&event.comm).trim_end_matches('\0').to_string();
            let filename = String::from_utf8_lossy(&event.filename).trim_end_matches('\0').to_string();
            
            println!("[EXEC] PID: {} | PPID: {} | UID: {} | COMM: {} | FILE: {}", 
                     event.pid, event.ppid, event.uid, comm, filename);
                     
            if let Err(e) = db.insert_event(event.pid, event.ppid, event.uid, &comm, &filename) {
                eprintln!("Failed to log to QIHSE WAL: {}", e);
            }
            
            // Deception Trigger: General Honeytoken
            if filename == "HONEYTOKEN_TRIGGERED" {
                println!("[DECEPTION] 🚨 HONEYTOKEN BREACH DETECTED! Process '{}' (PID: {}) attempted to steal or modify a restricted trap file!", comm, event.pid);
                let _ = db.insert_edr_action("FREEZE", &format!("PID:{}", event.pid), "HONEYTOKEN_TRIGGERED");
                if let Err(e) = tx_exec.try_send(event.pid) {
                    eprintln!("[RESPONDER] Failed to dispatch freeze order for PID {}: {}", event.pid, e);
                }
            }
            
            // Deception Trigger: Ghost Process Scraping
            if filename == "GHOST_PROCESS_TRAP" {
                println!("[DECEPTION] 🚨 MEMORY DUMP DETECTED! Process '{}' (PID: {}) attempted to ptrace/scrape memory of a Ghost Decoy!", comm, event.pid);
                let _ = db.insert_edr_action("FREEZE", &format!("PID:{}", event.pid), "GHOST_PROCESS_TRAP");
                if let Err(e) = tx_exec.try_send(event.pid) {
                    eprintln!("[RESPONDER] Failed to dispatch freeze order for PID {}: {}", event.pid, e);
                }
            }
            
            // Deception Trigger: Behavioral Privilege Escalation
            if filename == "PRIVILEGE_ESCALATION_TRAP" {
                println!("[BEHAVIORAL] 🚨 EXPLOIT DETECTED! Unprivileged App '{}' (PID: {}) escaped sandbox and spawned root process! Kernel auto-froze it.", comm, event.pid);
                let _ = db.insert_edr_action("SIGSTOP", &format!("PID:{}", event.pid), "PRIVILEGE_ESCALATION_TRAP");
                // eBPF already froze it, but we can queue it for carving
                if let Err(e) = tx_exec.try_send(event.pid) {
                    eprintln!("[RESPONDER] Failed to dispatch carve order for PID {}: {}", event.pid, e);
                }
            }
            
            // Deception Trigger: Unauthorized Execution
            if filename == "UNAUTHORIZED_EXEC_TRAP" {
                println!("[BEHAVIORAL] 🚨 UNAUTHORIZED TOOL DETECTED! Process '{}' (PID: {}) attempted to run a banned tool! Kernel auto-froze it.", comm, event.pid);
                let _ = db.insert_edr_action("SIGSTOP", &format!("PID:{}", event.pid), "UNAUTHORIZED_EXEC_TRAP");
                if let Err(e) = tx_exec.try_send(event.pid) {
                    eprintln!("[RESPONDER] Failed to dispatch carve order for PID {}: {}", event.pid, e);
                }
            }
            
            // Deception Trigger: Agent Self Defense
            if filename == "SELF_DEFENSE_TRAP" {
                println!("[SELF-DEFENSE] 🚨 ASSASSINATION ATTEMPT DETECTED! Process '{}' (PID: {}) attempted to kill the EDR! Kernel auto-froze it.", comm, event.pid);
                let _ = db.insert_edr_action("SIGSTOP", &format!("PID:{}", event.pid), "SELF_DEFENSE_TRAP");
                // eBPF already froze it, but we can queue it for carving
                if let Err(e) = tx_exec.try_send(event.pid) {
                    eprintln!("[RESPONDER] Failed to dispatch carve order for PID {}: {}", event.pid, e);
                }
            }
            
            // YARA Memory Scanning Trigger
            if let Ok(Some((sig_name, region))) = yara_engine.scan_process_memory(event.pid) {
                println!("[YARA] 🚨 IN-MEMORY SIGNATURE MATCH ({})! Freezing PID {}", sig_name, event.pid);
                let _ = db.insert_yara_match(event.pid, &sig_name, &region);
                let _ = db.insert_edr_action("FREEZE", &format!("PID:{}", event.pid), &format!("YARA_MATCH:{}", sig_name));
                if let Err(e) = tx_exec.try_send(event.pid) {
                    eprintln!("[RESPONDER] Failed to dispatch freeze order for PID {}: {}", event.pid, e);
                }
            }
            
            // Heuristic trigger: Mock threat signature
            if comm == "malware" || filename.contains("/tmp/pwn") {
                let _ = db.insert_edr_action("FREEZE", &format!("PID:{}", event.pid), "HEURISTIC_MOCK_THREAT");
                if let Err(e) = tx_exec.try_send(event.pid) {
                    eprintln!("[RESPONDER] Failed to dispatch freeze order for PID {}: {}", event.pid, e);
                }
            }
            
            // Ransomware trigger: Mock rapid encryption signature
            if comm == "ransomware" || filename.ends_with(".enc") {
                let _ = db.insert_edr_action("FREEZE", &format!("PID:{}", event.pid), "RANSOMWARE_ENCRYPTION_BURST");
                let _ = db.insert_edr_action("ZFS_ROLLBACK", "rpool/home", "RANSOMWARE_ENCRYPTION_BURST");
                if let Err(e) = tx_exec.try_send(event.pid) {
                    eprintln!("[RESPONDER] Failed to dispatch freeze order for PID {}: {}", event.pid, e);
                }
                if let Err(e) = zfs.trigger_rollback() {
                    eprintln!("[ZFS-ROLLBACK] Error: {}", e);
                }
            }
            
            0
        },
    ).context("Failed to register ring buffer callback")?;

    builder.add(
        &skel.maps.tls_events,
        handle_tls_event,
    ).context("Failed to register TLS ring buffer callback")?;
    
    let ringbuf = builder.build().context("Failed to build ringbuf")?;

    println!("Entering continuous off-tick event loop...");
    loop {
        ringbuf.poll(Duration::from_millis(100)).context("Failed to poll ring buffer")?;
        
        // Drain new MISP IOCs and push them into the eBPF XDP map
        while let Ok(c2_ip) = rx_misp.try_recv() {
            let key = c2_ip.to_ne_bytes();
            let value = 1u8.to_ne_bytes(); // 1 = Blocked
            
            if let Err(e) = skel.maps.c2_blocklist.update(&key, &value, MapFlags::ANY) {
                eprintln!("[XDP-SYNC] Failed to inject C2 block into kernel: {}", e);
            } else {
                println!("[XDP-SYNC] Hardware firewall updated. Instantly dropping traffic to IP signature.");
            }
        }
        sleep(Duration::from_millis(10)).await;
    }
}
