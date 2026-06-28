# ALPHVDR EDR - Current Status & Roadmap

## 1. Accomplished & Implemented

### Kernel Space (eBPF / C)
* **Process Tracking (`sys_enter_execve`)**: Successfully implemented a high-speed eBPF tracepoint to monitor process creation, capturing PID, PPID, UID, and executing file paths.
* **Network Interception (XDP DPI)**: Deployed an XDP program directly at the NIC level to parse Ethernet and IPv4 headers. It drops packets matching high-confidence C2 IPs before they reach the OS TCP stack.
* **TLS Fingerprinting (JA3 / JA3S)**: Added advanced TCP payload inspection to the XDP pipeline to identify `0x16 0x03` TLS Client Hello packets. Extracts up to 128 bytes of raw cipher suites for user-space JA3 hashing to defeat domain fronting.
* **Ring Buffers**: Implemented dual ultra-low-latency eBPF Ring Buffers (`events` and `tls_events`) for zero-copy IPC between the kernel and the Rust agent.

### User Space (Rust / Tokio)
* **Event-Driven Architecture**: Abandoned timer-based polling. The engine is fully off-tick and asynchronous.
* **QIHSE Integration**: Built the exactness-first vector search stub. Calculates a structural `[i8; 8]` Trinary/QMAG vector representation from incoming events (e.g., checking for root execution, memory/tmp binaries) and persists it to a hardware-aware Write-Ahead Log (WAL) at `/tmp/alphvdr/qihse_events.wal`.
* **Async Responder Engine**: Deployed a detached Tokio Multi-Producer Single-Consumer (mpsc) channel that constantly listens for threat alerts. 
* **Process Freezing (SIGSTOP)**: When a malicious signature is matched, the engine instantly issues a raw `libc::kill(pid, libc::SIGSTOP)` to perfectly freeze the execution state of the process in RAM, preventing evasion or data destruction.
* **Memory Carving & VMA Extraction**: Full implementation of Phase 2 — parses `/proc/[pid]/maps` for VMA layout, extracts memory pages via `/proc/[pid]/mem` with seek-based reads, captures register state from `/proc/[pid]/syscall` and `/proc/[pid]/status`.
* **Core Dump Blob Packaging**: Phase 3 — packages carved memory regions, VMA metadata, register states, and FNV-1a checksums into a proprietary `ALPHVDR` core dump blob format with structured headers.
* **Proxmox Bridge (Phase 4)**: Routes core dump blobs to the KP14-SUITE VM (VMID 9211) via `pvesm alloc` (storage allocation), `dd` (blob write), and `qm set` (SCSI hotplug). Supports both local hypervisor and remote SSH modes with automatic SCSI slot discovery and post-analysis cleanup.
* **KP14-SUITE Disassembly Integration (Phase 5)**: Full integration with the real KP14 platform on `kp14-suite` (192.168.1.252). Parses ALPHVDR core dump blobs, extracts executable memory regions, runs the `disasm_pipeline.py` v3.0 pipeline (7-phase: triage → decompile → annotate → reconstruct → validate → steganography → packaging), performs radare2 quick triage, extracts IOCs (IPs, URLs, domains, file paths, MITRE ATT&CK techniques), and pushes them to the MISP sidecar. Supports daemon mode (block device watch + mount) and remote SSH trigger mode.
* **YARA In-Memory Scanning**: Replaced the stub scanner with real memory carving integration. Extracts VMA regions via `MemoryCarver`, then applies heuristic byte-pattern signatures (shellcode, C2 beacons, ransomware markers, cryptominer indicators, io_uring evasion patterns) and Shannon entropy analysis (>7.5 bits/byte triggers packed/encrypted payload detection).

---

## 2. Pending Implementation (To Do)

### Phase 1: Advanced Isolation & Analysis
* **Sigma Rule Engine**: Integrate Sigma behavioral rules for complex event correlations on top of the existing YARA byte-pattern scanner.
* **Ransomware Rollback**: Hook deep VFS functions (`vfs_write`) to detect high-entropy rapid encryption. Trigger automated Btrfs/ZFS filesystem snapshots for instant rollback.

### Phase 2: Threat Intelligence & Telemetry
* **MISP Sidecar Deployment**: Spin up the MISP Docker sidecar to automatically ingest and curate feeds from Abuse.ch, ThreatFox, and AlienVault OTX, dynamically updating the eBPF `c2_blocklist` hash map.
* **KEYSTONE Query Engine**: Build out the structured event parsing for KEYSTONE to allow real-time IOC hunting across the telemetry.
* **Hardware Acceleration (ASIC-SOC)**: Offload the QIHSE vector processing and entropy math from the CPU to dedicated hardware security silicon to ensure zero-latency detection for APT-grade runtimes (e.g., legacy Lua 5.0 VMs).

### Phase 3: Active Defense
* **Deception / Honeytokens**: Seed the host with monitored, fake credentials and files, setting up instantaneous trigger alerts if any unauthorized process touches them.
* **Advanced Evasion Mitigation**: Hook `io_uring` and `mprotect` to catch advanced, fileless malware attempting to bypass standard syscall tracepoints.
