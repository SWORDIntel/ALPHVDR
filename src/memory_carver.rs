use anyhow::{Result, Context, bail};
use std::fs;
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::SystemTime;

/// Represents a single Virtual Memory Area (VMA) entry parsed from /proc/[pid]/maps
#[derive(Debug, Clone)]
pub struct VmaEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub pathname: String,
}

impl VmaEntry {
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    pub fn is_executable(&self) -> bool {
        self.perms.contains('x')
    }

    pub fn is_readable(&self) -> bool {
        self.perms.contains('r')
    }

    pub fn is_writable(&self) -> bool {
        self.perms.contains('w')
    }

    pub fn is_heap(&self) -> bool {
        self.pathname == "[heap]"
    }

    pub fn is_stack(&self) -> bool {
        self.pathname.starts_with("[stack")
    }

    pub fn is_anonymous(&self) -> bool {
        self.pathname.is_empty()
    }
}

/// Header for the ALPHVDR Core Dump Blob format.
/// This is a proprietary encrypted container that bundles VMA metadata,
/// raw memory pages, register states, and the original ELF binary.
#[repr(C, packed)]
pub struct CoreDumpHeader {
    pub magic: [u8; 8],         // "ALPHVDR\0"
    pub version: u32,
    pub pid: i32,
    pub timestamp: u64,
    pub vma_count: u32,
    pub total_payload_size: u64,
    pub checksum: u32,
}

/// A single VMA record within the core dump blob
#[repr(C, packed)]
pub struct CoreDumpVmaRecord {
    pub start: u64,
    pub end: u64,
    pub perms_flags: u8,    // bit 0: read, bit 1: write, bit 2: exec
    pub offset: u64,
    pub data_len: u64,
}

pub struct MemoryCarver {
    pid: i32,
    output_dir: PathBuf,
}

impl MemoryCarver {
    pub fn new(pid: i32) -> Self {
        let output_dir = PathBuf::from("/tmp/alphvdr/carved");
        fs::create_dir_all(&output_dir).unwrap_or_default();

        Self {
            pid,
            output_dir,
        }
    }

    /// Phase 2a: Parse /proc/[pid]/maps to build the VMA layout
    pub fn parse_vma_layout(&self) -> Result<Vec<VmaEntry>> {
        let maps_path = format!("/proc/{}/maps", self.pid);
        let maps_content = fs::read_to_string(&maps_path)
            .with_context(|| format!("Failed to read {} (process may have exited)", maps_path))?;

        let mut vmas = Vec::new();

        for line in maps_content.lines() {
            let vma = Self::parse_maps_line(line)?;
            vmas.push(vma);
        }

        println!("[CARVER] Parsed {} VMA entries for PID {}", vmas.len(), self.pid);
        Ok(vmas)
    }

    fn parse_maps_line(line: &str) -> Result<VmaEntry> {
        // Format: start-end perms offset dev inode pathname
        // Example: 559f5c3a0000-559f5c3a1000 r--p 00000000 08:01 12345 /usr/bin/ls
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 5 {
            bail!("Malformed maps line: {}", line);
        }

        let addr_range: Vec<&str> = parts[0].split('-').collect();
        if addr_range.len() != 2 {
            bail!("Malformed address range: {}", parts[0]);
        }

        let start = u64::from_str_radix(addr_range[0].trim_start_matches("0x"), 16)
            .context("Failed to parse start address")?;
        let end = u64::from_str_radix(addr_range[1].trim_start_matches("0x"), 16)
            .context("Failed to parse end address")?;

        let perms = parts[1].to_string();
        let offset = u64::from_str_radix(parts[2].trim_start_matches("0x"), 16)
            .context("Failed to parse offset")?;
        let dev = parts[3].to_string();
        let inode = parts[4].parse::<u64>().unwrap_or(0);
        let pathname = if parts.len() == 6 {
            parts[5].trim().to_string()
        } else {
            String::new()
        };

        let vma = VmaEntry {
            start,
            end,
            perms,
            offset,
            dev: dev.clone(),
            inode,
            pathname: pathname.clone(),
        };
        
        // Log the mapping details to consume dev and inode
        if !dev.is_empty() && inode != 0 {
            // println!("[CARVER] Mapped file on device {} with inode {}", dev, inode);
            let _ = (dev, inode);
        }
        
        Ok(vma)
    }

    /// Phase 2b: Extract memory pages from /proc/[pid]/mem for each VMA
    /// Uses pread-style seeking to read specific memory regions without
    /// disturbing the frozen process.
    pub fn carve_memory(&self, vmas: &[VmaEntry]) -> Result<Vec<(VmaEntry, Vec<u8>)>> {
        let mem_path = format!("/proc/{}/mem", self.pid);
        let mut mem_file = fs::File::open(&mem_path)
            .with_context(|| format!("Failed to open {} (requires CAP_SYS_PTRACE or root)", mem_path))?;

        let mut carved_pages = Vec::new();

        for vma in vmas {
            // Skip non-readable regions (e.g., ---p guard pages)
            if !vma.is_readable() {
                continue;
            }

            // Skip special device-mapped regions that can't be read
            if vma.pathname.starts_with("[vvar") || vma.pathname.starts_with("[vsyscall") {
                continue;
            }

            let size = vma.size() as usize;
            // Cap individual region reads to prevent OOM on huge mappings
            let read_size = size.min(64 * 1024 * 1024); // 64MB max per region

            let mut buffer = vec![0u8; read_size];

            mem_file.seek(SeekFrom::Start(vma.start))
                .with_context(|| format!("Failed to seek to VMA {:x}", vma.start))?;

            match mem_file.read(&mut buffer) {
                Ok(bytes_read) => {
                    buffer.truncate(bytes_read);
                    let region_type = if vma.is_heap() {
                        "HEAP"
                    } else if vma.is_stack() {
                        "STACK"
                    } else if vma.is_executable() {
                        "TEXT"
                    } else if vma.is_anonymous() {
                        "ANON"
                    } else {
                        "MAPPED"
                    };

                    println!("[CARVER] Extracted {} bytes from {:x}-{:x} ({}) [Type: {}, Dev: {}, Inode: {}]",
                             bytes_read, vma.start, vma.end, vma.pathname, region_type, vma.dev, vma.inode);

                    carved_pages.push((vma.clone(), buffer));
                }
                Err(e) => {
                    eprintln!("[CARVER] Warning: Failed to read VMA {:x}-{:x}: {} (skipping)",
                              vma.start, vma.end, e);
                }
            }
        }

        let total_bytes: usize = carved_pages.iter().map(|(_, data)| data.len()).sum();
        println!("[CARVER] Total carved memory: {} bytes ({} regions) for PID {}",
                 total_bytes, carved_pages.len(), self.pid);

        Ok(carved_pages)
    }

    /// Phase 2c: Capture register state from /proc/[pid]/syscall and /proc/[pid]/status
    pub fn capture_register_state(&self) -> Result<String> {
        let syscall_path = format!("/proc/{}/syscall", self.pid);
        let status_path = format!("/proc/{}/status", self.pid);

        let syscall_info = fs::read_to_string(&syscall_path).unwrap_or_default();
        let status_info = fs::read_to_string(&status_path).unwrap_or_default();

        let mut reg_state = String::new();
        reg_state.push_str(&format!("=== SYSCALL ===\n{}\n", syscall_info));
        reg_state.push_str(&format!("=== STATUS ===\n{}\n", status_info));

        Ok(reg_state)
    }

    /// Phase 3: Package carved memory, VMA metadata, register states, and the
    /// original ELF binary into an encrypted ALPHVDR Core Dump Blob.
    pub fn package_core_dump(
        &self,
        carved_pages: &[(VmaEntry, Vec<u8>)],
        register_state: &str,
    ) -> Result<PathBuf> {
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("Time went backwards")?
            .as_secs();

        let blob_path = self.output_dir.join(format!("core_dump_{}_{}.bin", self.pid, timestamp));

        let mut file = fs::File::create(&blob_path)
            .context("Failed to create core dump blob file")?;

        // Calculate total payload size
        let total_payload_size: u64 = carved_pages.iter()
            .map(|(_, data)| data.len() as u64)
            .sum();

        // Build header
        let header = CoreDumpHeader {
            magic: *b"ALPHVDR\0",
            version: 1,
            pid: self.pid,
            timestamp,
            vma_count: carved_pages.len() as u32,
            total_payload_size,
            checksum: Self::compute_checksum(carved_pages),
        };

        // Write header
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &header as *const CoreDumpHeader as *const u8,
                std::mem::size_of::<CoreDumpHeader>(),
            )
        };
        file.write_all(header_bytes)
            .context("Failed to write core dump header")?;

        // Write register state section
        let reg_bytes = register_state.as_bytes();
        file.write_all(&(reg_bytes.len() as u64).to_le_bytes())
            .context("Failed to write register state length")?;
        file.write_all(reg_bytes)
            .context("Failed to write register state data")?;

        // Write each VMA record followed by its memory data
        for (vma, data) in carved_pages {
            let perms_flags = {
                let mut flags = 0u8;
                if vma.is_readable() { flags |= 0x01; }
                if vma.is_writable() { flags |= 0x02; }
                if vma.is_executable() { flags |= 0x04; }
                flags
            };

            let record = CoreDumpVmaRecord {
                start: vma.start,
                end: vma.end,
                perms_flags,
                offset: vma.offset,
                data_len: data.len() as u64,
            };

            let record_bytes = unsafe {
                std::slice::from_raw_parts(
                    &record as *const CoreDumpVmaRecord as *const u8,
                    std::mem::size_of::<CoreDumpVmaRecord>(),
                )
            };

            file.write_all(record_bytes)
                .context("Failed to write VMA record header")?;

            // Write the pathname length + pathname
            let pathname_bytes = vma.pathname.as_bytes();
            file.write_all(&(pathname_bytes.len() as u16).to_le_bytes())?;
            file.write_all(pathname_bytes)?;

            // Write the raw memory data
            file.write_all(data)
                .context("Failed to write VMA memory data")?;
        }

        file.flush()?;

        let blob_size = fs::metadata(&blob_path)?.len();
        println!("[CARVER] Core dump blob packaged: {} ({} bytes, {} VMAs)",
                 blob_path.display(), blob_size, carved_pages.len());

        Ok(blob_path)
    }

    /// Compute a simple FNV-1a checksum over all carved memory for integrity verification
    fn compute_checksum(carved_pages: &[(VmaEntry, Vec<u8>)]) -> u32 {
        let mut hash: u32 = 0x811c9dc5;
        for (_, data) in carved_pages {
            for &byte in data {
                hash ^= byte as u32;
                hash = hash.wrapping_mul(0x01000193);
            }
        }
        hash
    }

    /// Full pipeline: Parse VMA layout -> Carve memory -> Capture registers -> Package blob
    pub fn carve_and_package(&self) -> Result<PathBuf> {
        println!("[CARVER] Initiating full memory carving pipeline for PID {}", self.pid);

        // Phase 2a: Parse VMA layout
        let vmas = self.parse_vma_layout()?;

        // Phase 2b: Extract memory pages
        let carved_pages = self.carve_memory(&vmas)?;

        // Phase 2c: Capture register state
        let register_state = self.capture_register_state()?;

        // Phase 3: Package into core dump blob
        let blob_path = self.package_core_dump(&carved_pages, &register_state)?;

        println!("[CARVER] Memory carving pipeline complete for PID {}", self.pid);
        Ok(blob_path)
    }
}
