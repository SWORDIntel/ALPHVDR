use std::process::Command;
use anyhow::{Result, bail, Context};
use std::time::SystemTime;

#[derive(Clone)]
pub struct ZfsManager {
    dataset: String,
}

impl ZfsManager {
    pub fn new(dataset: &str) -> Self {
        println!("[ZFS] Initialized Automated Rollback Engine for dataset: {}", dataset);
        Self {
            dataset: dataset.to_string(),
        }
    }
    
    pub fn trigger_rollback(&self) -> Result<()> {
        println!("[ZFS-ROLLBACK] ⚡ MASS ENCRYPTION HEURISTIC DETECTED. INITIATING ZFS ROLLBACK ⚡");
        
        // Rolling back to the known-good baseline snapshot we took earlier
        let snapshot_name = format!("{}@edr_pre_dev_snapshot", self.dataset);
        
        // The rollback command dynamically restores the filesystem blocks 
        // to instantly revert all encrypted files to their pristine state.
        // -r flag destroys any newer snapshots or bookmarks created by the malware.
        let status = Command::new("sudo")
            .arg("zfs")
            .arg("rollback")
            .arg("-r") 
            .arg(&snapshot_name)
            .status()
            .context("Failed to execute zfs rollback. Is ZFS installed and sudo configured?")?;
            
        if status.success() {
            println!("[ZFS-ROLLBACK] ✅ Successfully rolled back dataset '{}'. Ransomware damage neutralized.", self.dataset);
            Ok(())
        } else {
            bail!("ZFS rollback failed! Manual forensic intervention required.");
        }
    }
    
    pub fn take_daily_snapshot(&self) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(std::time::UNIX_EPOCH).context("Time went backwards")?.as_secs();
        let snapshot_name = format!("{}@edr_daily_{}", self.dataset, timestamp);
        
        println!("[ZFS-BACKUP] Taking scheduled daily snapshot: {}", snapshot_name);
        
        let status = Command::new("sudo")
            .arg("zfs")
            .arg("snapshot")
            .arg(&snapshot_name)
            .status()
            .context("Failed to execute zfs snapshot")?;
            
        if !status.success() {
            bail!("Daily ZFS snapshot creation failed.");
        }
        
        println!("[ZFS-BACKUP] Exporting and compressing snapshot with zstd level 20...");
        
        let backup_path = format!("/tmp/alphvdr_backup_{}.zst", timestamp);
        // We use maximum compression via zstd -20. -T0 utilizes all CPU cores.
        let shell_cmd = format!("sudo zfs send {} | zstd -20 -T0 > {}", snapshot_name, backup_path);
        
        let export_status = Command::new("sh")
            .arg("-c")
            .arg(&shell_cmd)
            .status()
            .context("Failed to run export shell command")?;
            
        if !export_status.success() {
            bail!("Snapshot zstd-20 compression failed.");
        }
        
        println!("[ZFS-BACKUP] ✅ Snapshot perfectly compressed (zstd-20) and saved to: {}", backup_path);
        Ok(())
    }
}
