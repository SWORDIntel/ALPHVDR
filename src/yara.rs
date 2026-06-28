use anyhow::Result;
use crate::memory_carver::MemoryCarver;

#[derive(Clone)]
pub struct YaraEngine {
    // In a production environment, this struct would hold a compiled `yara::Rules` object
    // loaded from standard YARA rule files and MISP signature feeds.
    // For now, we use built-in heuristic signatures for in-memory scanning.
}

impl YaraEngine {
    pub fn new() -> Self {
        println!("[YARA] Initializing YARA Rules Engine (In-Memory Scanner)...");
        Self {}
    }

    /// Scans the live memory of a running process for malware signatures.
    /// Uses the MemoryCarver to extract VMA regions from /proc/[pid]/mem,
    /// then applies heuristic signature matching across all readable regions.
    /// Returns Some((signature_name, region_name)) if a match is found.
    pub fn scan_process_memory(&self, pid: i32) -> Result<Option<(String, String)>> {
        let carver = MemoryCarver::new(pid);

        // Parse VMA layout
        let vmas = match carver.parse_vma_layout() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[YARA] Failed to parse VMA layout for PID {}: {}", pid, e);
                return Ok(None);
            }
        };

        // Carve memory pages
        let carved_pages = match carver.carve_memory(&vmas) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[YARA] Failed to carve memory for PID {}: {}", pid, e);
                return Ok(None);
            }
        };

        // Run heuristic signature scans across all carved memory regions
        for (vma, data) in &carved_pages {
            if let Some(match_info) = self.scan_region_for_signatures(data, vma.pathname.as_str())? {
                return Ok(Some(match_info));
            }
        }

        Ok(None)
    }

    /// Apply heuristic byte-pattern signatures to a memory region.
    /// In production, this would use the `yara-rust` crate with compiled rules.
    fn scan_region_for_signatures(&self, data: &[u8], region_name: &str) -> Result<Option<(String, String)>> {
        let signatures: &[(&str, &[u8])] = &[
            ("x86_nop_sled", &[0x90; 8]),
            ("x86_syscall_execve", &[0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00, 0x0f, 0x05]),
            ("http_post_beacon", b"POST /beacon"),
            ("http_get_checkin", b"GET /checkin"),
            ("http_c2_gate", b"GET /gate.php"),
            ("aes_sbox_partial", &[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]),
            ("rc4_init_pattern", b"RC4 Key"),
            ("apt41_keyplug_rc4_stage", &[0x0d, 0x20, 0x61, 0x0a]),
            ("apt41_keyplug_xor_auth", &[0xdd, 0x79, 0x19, 0xae]),
            ("apt41_keyplug_sled", &[0xeb, 0xfe, 0xeb, 0xfe, 0xeb, 0xfe, 0xeb, 0xfe]),
            ("reverse_shell_sh", b"/bin/sh"),
            ("reverse_shell_bash", b"/bin/bash -i"),
            ("ransomware_extension", b".encrypted"),
            ("ransomware_note", b"YOUR FILES ARE ENCRYPTED"),
            ("cryptominer_pool", b"stratum+tcp://"),
            ("cryptominer_xmr", b"monero"),
            ("tmp_exec_path", b"/tmp/.X11"),
            ("dev_shm_exec", b"/dev/shm/."),
            ("io_uring_setup", b"io_uring_setup"),
            ("io_uring_enter", b"io_uring_enter"),
            ("liburing_init", b"io_uring_queue_init"),
        ];

        for (name, pattern) in signatures {
            if data.len() >= pattern.len() {
                if let Some(pos) = find_subslice(data, pattern) {
                    let ctx_start = pos.saturating_sub(16);
                    let ctx_end = (pos + pattern.len() + 16).min(data.len());
                    let context = &data[ctx_start..ctx_end];
                    println!("[YARA] SIGNATURE MATCH: '{}' in region '{}' at offset {} (context: {:02x?})",
                             name, region_name, pos, context);
                    return Ok(Some((name.to_string(), region_name.to_string())));
                }
            }
        }

        // Entropy-based detection for packed/encrypted regions
        if data.len() > 1024 {
            let entropy = calculate_shannon_entropy(data);
            if entropy > 7.5 {
                println!("[YARA] High entropy ({:.2}) in region '{}' (possible packed/encrypted payload)",
                         entropy, region_name);
                return Ok(Some(("high_entropy_packed".to_string(), region_name.to_string())));
            }
        }

        Ok(None)
    }

    /// Scan a raw byte buffer (e.g., from a core dump) for signatures
    pub fn scan_raw_buffer(&self, data: &[u8]) -> Result<Option<(String, String)>> {
        self.scan_region_for_signatures(data, "raw_buffer")
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}
