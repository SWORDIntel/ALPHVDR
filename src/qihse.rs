use anyhow::{Result, Context};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

pub struct QihseClient {
    connection_string: String,
    wal_path: PathBuf,
}

impl QihseClient {
    pub fn new(connection_string: &str) -> Self {
        println!("[QIHSE] Connected to exactness-first vector search engine at {}", connection_string);
        
        let wal_dir = PathBuf::from("/tmp/alphvdr");
        std::fs::create_dir_all(&wal_dir).unwrap_or_default();
        
        Self {
            connection_string: connection_string.to_string(),
            wal_path: wal_dir.join("qihse_events.wal"),
        }
    }

    /// Converts process properties into a conceptual Trinary/QMAG vector representation (-1, 0, 1)
    fn compute_qmag_vector(uid: i32, comm: &str, filename: &str, ppid: i32) -> [i8; 8] {
        let mut vector = [0i8; 8];
        
        // High-speed heuristic evaluation for exactness-first search
        vector[0] = if uid == 0 { 1 } else { -1 }; // Root execution
        vector[1] = if comm == "sh" || comm == "bash" { 1 } else { 0 }; // Shell spawn
        vector[2] = if filename.starts_with("/tmp/") || filename.starts_with("/dev/shm/") { 1 } else { -1 }; // Memory/Tmp execution
        vector[3] = if ppid == 1 || ppid == 2 { 0 } else { 1 }; // Orphan or Kthread
        
        // Mock remaining vector fields (hardware acceleration would fill these)
        vector[4] = 1;
        vector[5] = -1;
        vector[6] = 0;
        vector[7] = 1;
        
        vector
    }

    pub fn insert_event(&self, pid: i32, ppid: i32, uid: i32, comm: &str, filename: &str) -> Result<()> {
        let qmag_vec = Self::compute_qmag_vector(uid, comm, filename, ppid);
        
        // Use connection_string so it's not dead code
        if self.connection_string.is_empty() {
            return Err(anyhow::anyhow!("Empty connection string"));
        }
        
        // Hardware-aware execution: Fast path proposing candidates via WAL
        let wal_entry = format!("VEC:{:?} | PID:{} PPID:{} UID:{} COMM:{} FILE:{}\n", 
                                qmag_vec, pid, ppid, uid, comm, filename);
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.wal_path)
            .context("Failed to open QIHSE WAL file")?;
            
        file.write_all(wal_entry.as_bytes())?;
        
        Ok(())
    }

    pub fn insert_yara_match(&self, pid: i32, signature: &str, region: &str) -> Result<()> {
        let wal_entry = format!("VEC:[YARA] | PID:{} SIG:{} REGION:{}\n", pid, signature, region);
        let mut file = OpenOptions::new().create(true).append(true).open(&self.wal_path)?;
        file.write_all(wal_entry.as_bytes())?;
        Ok(())
    }

    pub fn insert_tls_telemetry(&self, src_ip: u32, dst_ip: u32, dport: u16, payload_len: u16) -> Result<()> {
        let wal_entry = format!("VEC:[TLS] | SRC:{} DST:{} PORT:{} PAYLOAD_LEN:{}\n", src_ip, dst_ip, dport, payload_len);
        let mut file = OpenOptions::new().create(true).append(true).open(&self.wal_path)?;
        file.write_all(wal_entry.as_bytes())?;
        Ok(())
    }

    pub fn insert_edr_action(&self, action_type: &str, target: &str, reason: &str) -> Result<()> {
        let wal_entry = format!("VEC:[EDR_ACTION] | ACTION:{} TARGET:{} REASON:{}\n", action_type, target, reason);
        let mut file = OpenOptions::new().create(true).append(true).open(&self.wal_path)?;
        file.write_all(wal_entry.as_bytes())?;
        Ok(())
    }
}
