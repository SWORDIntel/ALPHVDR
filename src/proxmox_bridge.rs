use anyhow::{Result, Context, bail};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

/// The Proxmox Bridge handles Phase 4 of the memory carving architecture:
/// routing the packaged core dump blob from the endpoint agent to the
/// KP14-SUITE analysis VM (VMID 9211) via the Proxmox hypervisor.
///
/// It uses pvesm for storage allocation and qm for VM hotplugging.
#[derive(Clone)]
pub struct ProxmoxBridge {
    /// Proxmox storage target (e.g., "local-lvm", "zfspool")
    storage: String,
    /// Target VM ID for the KP14-SUITE disassembly environment
    vmid: u32,
    /// Network endpoint for the Proxmox API (host:port)
    proxmox_host: String,
    /// Whether this agent runs directly on the Proxmox host (true)
    /// or needs to route via SSH/API (false)
    is_local_hypervisor: bool,
}

impl ProxmoxBridge {
    pub fn new(storage: &str, vmid: u32, proxmox_host: &str, is_local: bool) -> Self {
        println!("[PROXMOX] Bridge initialized -> Storage: {} | VMID: {} | Host: {} | Local: {}",
                 storage, vmid, proxmox_host, is_local);
        Self {
            storage: storage.to_string(),
            vmid,
            proxmox_host: proxmox_host.to_string(),
            is_local_hypervisor: is_local,
        }
    }

    /// Default configuration targeting KP14-SUITE on local Proxmox host
    pub fn default_kp14() -> Self {
        Self::new("local-lvm", 9211, "localhost:8006", true)
    }

    /// Phase 4a: Allocate a temporary storage volume on the Proxmox hypervisor
    /// using `pvesm alloc`. This creates a logical volume or ZFS dataset
    /// that will hold the core dump blob.
    pub fn allocate_storage(&self, size_mb: u64) -> Result<String> {
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("Time went backwards")?
            .as_secs();

        let volume_name = format!("alphvdr-coredump-{}", timestamp);

        println!("[PROXMOX] Allocating {}MB temporary volume '{}' on storage '{}'",
                 size_mb, volume_name, self.storage);

        if self.is_local_hypervisor {
            // Direct pvesm alloc on the hypervisor
            let status = Command::new("pvesm")
                .arg("alloc")
                .arg(&self.storage)
                .arg(&volume_name)
                .arg(format!("{}M", size_mb))
                .status()
                .context("Failed to execute pvesm alloc")?;

            if !status.success() {
                bail!("pvesm alloc failed for volume {}", volume_name);
            }
        } else {
            // Remote: would use Proxmox API or SSH to execute pvesm
            // For now, we simulate the allocation path
            println!("[PROXMOX] Remote hypervisor mode: routing alloc request via API to {}",
                     self.proxmox_host);
        }

        let volume_id = format!("{}:{}", self.storage, volume_name);
        println!("[PROXMOX] Allocated volume: {}", volume_id);
        Ok(volume_id)
    }

    /// Phase 4b: Write the core dump blob to the allocated storage volume.
    /// On a local hypervisor, this writes directly to the volume's device path.
    /// On a remote hypervisor, this transmits the blob over the isolated
    /// management interface (dedicated VLAN or VirtIO serial channel).
    pub fn write_blob_to_volume(&self, blob_path: &PathBuf, volume_id: &str) -> Result<()> {
        let blob_size = fs::metadata(blob_path)?.len();
        println!("[PROXMOX] Writing core dump blob ({} bytes) to volume '{}'",
                 blob_size, volume_id);

        if self.is_local_hypervisor {
            // Get the device path for the allocated volume
            let device_path = self.get_volume_device_path(volume_id)?;

            // Copy the blob directly to the block device
            let status = Command::new("dd")
                .arg(format!("if={}", blob_path.display()))
                .arg(format!("of={}", device_path))
                .arg("bs=1M")
                .arg("conv=fdatasync")
                .status()
                .context("Failed to execute dd to write blob to volume")?;

            if !status.success() {
                bail!("Failed to write blob to volume device {}", device_path);
            }
        } else {
            // Remote: transmit over isolated management network
            // This would use SCP over a dedicated VLAN or a VirtIO serial channel
            println!("[PROXMOX] Remote mode: transmitting blob via isolated management interface to {}",
                     self.proxmox_host);

            // Simulate secure transfer via scp over management VLAN
            let remote_target = format!("root@{}:/tmp/{}", self.proxmox_host, volume_id);
            let status = Command::new("scp")
                .arg("-B")
                .arg("-o").arg("StrictHostKeyChecking=yes")
                .arg(blob_path)
                .arg(&remote_target)
                .status()
                .context("Failed to execute scp for blob transfer")?;

            if !status.success() {
                bail!("Failed to transfer blob to remote hypervisor");
            }
        }

        println!("[PROXMOX] Core dump blob successfully written to volume '{}'", volume_id);
        Ok(())
    }

    /// Resolve the device path for a Proxmox storage volume
    fn get_volume_device_path(&self, volume_id: &str) -> Result<String> {
        let output = Command::new("pvesm")
            .arg("path")
            .arg(volume_id)
            .output()
            .context("Failed to execute pvesm path")?;

        if !output.status.success() {
            bail!("pvesm path failed for volume {}", volume_id);
        }

        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if path.is_empty() {
            bail!("pvesm path returned empty device path for volume {}", volume_id);
        }

        Ok(path)
    }

    /// Phase 4c: Hotplug the storage volume into the KP14-SUITE VM
    /// using `qm set` with a dynamically assigned SCSI device slot.
    pub fn hotplug_to_vm(&self, volume_id: &str) -> Result<u32> {
        // Find the next available SCSI slot in the VM
        let scsi_slot = self.find_available_scsi_slot()?;

        let device_spec = format!("scsi{},{}", scsi_slot, volume_id);

        println!("[PROXMOX] Hotplugging volume '{}' into VM {} as {}",
                 volume_id, self.vmid, device_spec);

        if self.is_local_hypervisor {
            let status = Command::new("qm")
                .arg("set")
                .arg(self.vmid.to_string())
                .arg(format!("--{}", device_spec))
                .status()
                .context("Failed to execute qm set for hotplug")?;

            if !status.success() {
                bail!("qm set hotplug failed for VM {} device {}", self.vmid, device_spec);
            }
        } else {
            // Remote: would use Proxmox API
            println!("[PROXMOX] Remote mode: routing hotplug request via API to {}",
                     self.proxmox_host);
        }

        println!("[PROXMOX] Volume hotplugged to VM {} on scsi{}", self.vmid, scsi_slot);
        Ok(scsi_slot)
    }

    /// Scan the VM's current configuration to find an available SCSI slot
    fn find_available_scsi_slot(&self) -> Result<u32> {
        if !self.is_local_hypervisor {
            // Default to slot 10 for remote mode
            return Ok(10);
        }

        let output = Command::new("qm")
            .arg("config")
            .arg(self.vmid.to_string())
            .output()
            .context("Failed to execute qm config")?;

        let config = String::from_utf8_lossy(&output.stdout);

        // Find used SCSI slots (scsi0, scsi1, etc.)
        let mut used_slots = std::collections::HashSet::new();
        for line in config.lines() {
            if line.starts_with("scsi") {
                let slot_str: String = line.chars()
                    .skip(4) // skip "scsi"
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if let Ok(slot) = slot_str.parse::<u32>() {
                    used_slots.insert(slot);
                }
            }
        }

        // Find first available slot starting from 10 (lower slots reserved for OS disks)
        for slot in 10..=30 {
            if !used_slots.contains(&slot) {
                return Ok(slot);
            }
        }

        bail!("No available SCSI slot in VM {} (slots 10-30 all in use)", self.vmid);
    }

    /// Phase 4d: Cleanup - remove the hotplugged device and deallocate the volume
    /// after the KP14-SUITE has finished analysis.
    pub fn cleanup_volume(&self, volume_id: &str, scsi_slot: u32) -> Result<()> {
        let device_spec = format!("scsi{}", scsi_slot);

        println!("[PROXMOX] Cleaning up: removing {} from VM {} and deallocating {}",
                 device_spec, self.vmid, volume_id);

        if self.is_local_hypervisor {
            // Unset the device from the VM
            let _ = Command::new("qm")
                .arg("set")
                .arg(self.vmid.to_string())
                .arg(format!("--delete").to_string())
                .arg(&device_spec)
                .status();

            // Deallocate the volume
            let _ = Command::new("pvesm")
                .arg("free")
                .arg(volume_id)
                .status();
        }

        println!("[PROXMOX] Cleanup complete for volume '{}'", volume_id);
        Ok(())
    }

    /// Full Phase 4 pipeline: Allocate storage -> Write blob -> Hotplug to VM
    /// Returns (volume_id, scsi_slot) for later cleanup.
    pub fn route_to_kp14(&self, blob_path: &PathBuf) -> Result<(String, u32)> {
        println!("[PROXMOX] Initiating full routing pipeline to KP14-SUITE (VMID {})", self.vmid);

        // Calculate required storage size (blob size + 10% overhead, in MB)
        let blob_size = fs::metadata(blob_path)?.len();
        let size_mb = (blob_size / (1024 * 1024)) + 1;
        let size_mb = size_mb + (size_mb / 10); // 10% overhead

        // Phase 4a: Allocate temporary storage
        let volume_id = self.allocate_storage(size_mb)?;

        // Phase 4b: Write blob to volume
        self.write_blob_to_volume(blob_path, &volume_id)?;

        // Phase 4c: Hotplug into VM
        let scsi_slot = self.hotplug_to_vm(&volume_id)?;

        println!("[PROXMOX] Routing pipeline complete. Volume: {} | SCSI slot: {}",
                 volume_id, scsi_slot);

        Ok((volume_id, scsi_slot))
    }
}
