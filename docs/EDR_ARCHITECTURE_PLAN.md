# EDR Architecture & Development Plan

## 1. Core Architecture Overview
The EDR is split into two primary domains to balance absolute performance with modern memory safety and maintainability:
- **Kernel Space (C / eBPF):** Responsible for high-performance, low-overhead event collection. Uses eBPF tracepoints, kprobes, and LSM hooks to gather system activity safely.
- **User Space (Rust):** A robust, memory-safe, highly concurrent event processing engine. It reads from eBPF ring buffers, filters benign noise, applies complex behavioral detection logic, and orchestrates automated responses.
- **IPC (Inter-Process Communication):** eBPF Ring Buffers / Perf Buffers to stream data from Kernel to User space with zero-copy overhead.

## 2. Component Roadmap

### Phase 1: The Sensor Core (Visibility)
*   **eBPF Probes (C):**
    *   `sys_enter_execve` / `sys_exit_execve`: Complete process creation and termination tracking.
    *   LSM Hooks (`security_file_open`): Granular file access monitoring.
    *   Network Hooks (`tcp_v4_connect` / `inet_csk_accept`): Outbound and inbound network connection tracking.
    *   **Container & Kubernetes Awareness:** Enrich eBPF events directly in the kernel by reading `cgroup` and `namespace` IDs, mapping raw PIDs to specific Docker/k8s pods.
    *   **Deep Packet Inspection (XDP):** Inject eBPF XDP programs directly into the network driver to capture, dissect, and match Command & Control (C2) traffic signatures in absolute real-time before they even hit the OS networking stack.
    *   **Advanced Evasion Tracking:** Hooks into `io_uring_setup` and deep VFS functions (`vfs_read`, `vfs_write`) to counter tools like GentlemenKiller.
*   **eBPF Framework (PerFeBPF):** Leverage **PerFeBPF** for our eBPF foundation to ensure ultra-low latency event capture.
*   **eBPF Loader (Rust):** Uses `libbpf-rs` or `aya` to load compiled eBPF ELF objects dynamically.

### Phase 2: The Agent (Processing & Detection)
*   **Continuous "Off-Tick" Architecture:** To defeat timer-based evasion, the agent abandons the traditional polling "tick." All processing is continuous and purely event-driven via asynchronous Rust (Tokio).
*   **Context & State Management:** Maintain an in-memory graph of process trees to contextualize isolated events.
*   **Rules Engine & Triggered Scans:**
    *   **Execution-Triggered Analysis (IMPLEMENTED):** Deep YARA scans are triggered instantly by high-risk kernel events (`mprotect`, `io_uring`), rather than timers. Uses `MemoryCarver` to extract VMA regions and applies 18 heuristic byte-pattern signatures plus Shannon entropy detection.
    *   **Legacy & Esoteric VM Detection (APT-Grade):** Heuristic memory entropy analysis to hunt for embedded, legacy runtimes (like Lua 5.0) via structural footprints (opcode tables) rather than modern bytecode hashes.
    *   **DNS & DGA Detection:** Intercept port 53 traffic via eBPF to calculate entropy on DNS queries. Block Domain Generation Algorithm (DGA) lookups instantly.
    *   **Active Deception (Honeytokens):** Inject fake, highly-monitored credentials into memory/files. Trigger instant freeze alerts if any process touches them.
    *   **Sigma Rule Application:** Parse and apply Sigma behavioral detection rules.

### Phase 3: The Responder (Action)
*   **eBPF Anti-Tampering (Self-Defense):** LSM hooks explicitly block any process (including root) from sending `SIGKILL` to the agent, modifying its binaries, or unloading its eBPF probes.
*   **Enforcement (Freeze & Carve):** Rather than killing a process, the EDR sends `SIGSTOP` (or uses `cgroup` freezer) to suspend execution and preserve state.
*   **Memory Carving & Disassembly (IMPLEMENTED):** Dumps the frozen process memory directly from RAM via `/proc/[pid]/maps` + `/proc/[pid]/mem` VMA carving, packages into ALPHVDR core dump blobs, routes via Proxmox `pvesm`/`qm set` hotplug to the **KP14-SUITE** VM (VMID 9211), and runs automated headless disassembly via `disasm_pipeline.py` v3.0 (Ghidra + radare2). Extracted IOCs are pushed to the MISP sidecar. See `MEMORY_CARVING_ARCHITECTURE.md` for full details.
*   **Automated Ransomware Rollback:** If high-entropy, rapid VFS writes are detected (indicating ransomware), freeze the process and trigger a filesystem snapshot rollback (via Btrfs/ZFS).
*   **Isolation:** Dynamically inject eBPF `tc` programs to drop host network packets (except EDR management comms).

### Phase 4: Telemetry & Backend (QIHSE, KEYSTONE & ASIC-SOC)
*   **Hardware Acceleration (ASIC-SOC):** Integrate **ASIC-SOC** to offload intense data processing and complex anomaly detection to dedicated, GPU-agnostic security silicon.
*   **Datastore (QIHSE):** Forward structured events to QIHSE for hardware-aware, WAL-backed persistence and high-speed vector search for anomaly detection.
*   **Query Engine (KEYSTONE):** Use KEYSTONE's adaptive search and CPU acceleration over sorted int64_t datasets to perform lightning-fast Threat Hunting lookups and IOC indexing across the telemetry.

### Phase 5: Threat Intelligence Integration
*   **Dynamic YARA/Sigma Sync:** The user-space agent dynamically pulls rules from community and commercial sources.
    *   *Recommended:* **Florian Roth (Neo23x0)** signatures and **SigmaHQ** for behavioral rules.
*   **Live IOC Feeds (Hashes, IPs, Domains):** The rules engine caches high-priority Indicators of Compromise locally for instantaneous matching.
    *   *Recommended:* **Abuse.ch (MalwareBazaar/ThreatFox)** for high-fidelity hashes/C2 IPs, and **AlienVault OTX** for broad pulse tracking.
    *   *Management:* Use a local **MISP (Malware Information Sharing Platform)** instance as a middleware to aggregate, clean, and curate external feeds before pushing them down to your EDR agents.

## 3. Directory Structure
```text
defensive/
├── Cargo.toml            # Rust project configuration
├── build.rs              # Rust build script to compile the eBPF code automatically before building the Rust binary
├── src/                  # Rust user-space agent source
│   ├── main.rs           # Agent entry point, event loop, responder engine (SIGSTOP + carve pipeline)
│   ├── qihse.rs          # QIHSE vector search client (Trinary/QMAG WAL persistence)
│   ├── misp.rs           # MISP threat intel sidecar (C2 IOC feed -> eBPF XDP blocklist)
│   ├── yara.rs           # YARA in-memory scanner (MemoryCarver + heuristic signatures + entropy)
│   ├── rollback.rs       # ZFS snapshot manager (ransomware rollback + daily backups)
│   ├── memory_carver.rs  # Phase 2-3: VMA parsing, /proc/[pid]/mem extraction, core dump blob packaging
│   ├── proxmox_bridge.rs # Phase 4: pvesm alloc, dd write, qm set hotplug to VM 9211, cleanup
│   └── kp14_suite.rs     # Phase 5: blob parsing, executable extraction, disasm_pipeline.py, IOC extraction, MISP push
├── src-bpf/              # C eBPF source code
│   ├── vmlinux.h         # Generated kernel headers for CO-RE support
│   ├── sensor.bpf.c      # Main eBPF probes (execve, vfs_open honeytoken, XDP DPI, TLS JA3)
│   └── common.h          # Shared data structs between C and Rust
├── MEMORY_CARVING_ARCHITECTURE.md  # Full architecture doc for the 5-phase memory carving pipeline
├── EDR_ARCHITECTURE.md             # This file — overall EDR architecture & development plan
└── CURRENT_STATUS.md               # Accomplished vs pending implementation tracker
```
