# ALPHVDR EDR: Complete Architectural Documentation

ALPHVDR is a hyper-hostile, ultra-low-latency Endpoint Detection and Response (EDR) system built entirely in Rust and eBPF. It is designed to perfectly paralyze malware in RAM, instantly recover from ransomware via block-level snapshot rollbacks, and lay devastating active-defense tripwires.

---

## 1. Core Architecture
* **eBPF Kernel Sensor (`sensor.bpf.c`)**: Hooks directly into the Linux kernel tracepoints and kprobes, entirely bypassing user-space latency. It utilizes highly optimized Hash Maps and Ring Buffers for zero-copy Inter-Process Communication (IPC).
* **Rust Async Engine (`main.rs`)**: A multi-threaded `tokio` engine that operates completely "off-tick." It does not rely on polling timers, making it invisible to malware that checks system clock ticks to evade detection.
* **QIHSE Telemetry**: A structural, exactness-first Trinary/QMAG vector search engine. It reduces system events into `[i8; 8]` vectors and logs them safely to an independent Write-Ahead Log (WAL) at `/tmp/alphvdr/qihse_events.wal` for threat hunting.

## 2. Advanced Mitigation & Response
* **Instant Freeze (`SIGSTOP`)**: When a threat is detected, ALPHVDR does not kill the process (which destroys forensic data). It instantly fires a `libc::kill(pid, SIGSTOP)` command, flawlessly suspending the malicious thread in RAM so that its unencrypted payloads and configurations can be extracted.
* **Proxmox VMM Routing**: (Architecturally deployed) Frozen processes are conceptually carved from RAM via `process_vm_readv` and routed out-of-band to a dedicated, heavily isolated Proxmox disassembly suite (`KP14-SUITE`) via `qm set` hotplugging.
* **YARA Memory Scanning**: An integrated rules engine designed to scan the live Virtual Memory Areas (VMAs) of executing processes for deep, in-memory malware signatures.

## 3. Network Defense & Threat Intel
* **XDP Hardware Firewall**: eBPF network hooks operate at the XDP (eXpress Data Path) layer on the NIC. This drops malicious C2 traffic *before* it even reaches the Linux TCP stack.
* **TLS JA3 Fingerprinting**: Intercepts `0x16 0x03` TLS Client Hello packets natively in XDP to extract raw cipher suites, perfectly defeating malware attempting to use Domain Fronting.
* **MISP Sidecar Poller**: An asynchronous Rust thread continuously queries the local MISP Docker instance (Abuse.ch, ThreatFox feeds) and dynamically pushes new C2 IP addresses straight into the kernel XDP blocklist without restarting the agent.

## 4. Filesystem & Ransomware Resilience
* **Automated Daily Backups**: A detached `tokio` task executes a 24-hour cycle, taking ZFS snapshots of the `rpool/home` dataset and instantly streaming them via `zfs send` into `zstd -20 -T0` for absolute maximum block compression.
* **Instant Ransomware Rollback**: When heuristic triggers (like rapid `.enc` file creation) are detected, ALPHVDR fires an immediate `zfs rollback -r rpool/home@edr_pre_dev_snapshot`, reverting all encrypted files to pristine state in zero seconds.

## 5. Deception Network (Zero-Overhead Tripwires)
The engine utilizes exact filesystem `inode` mapping into the eBPF kernel `kprobe/vfs_open` hook to create lethal, zero-false-positive traps.
* **Cloud & K8s Traps (Read-Lock)**: Dummy AWS credentials (`~/.aws/credentials`) and Kubernetes configs (`~/.kube/config`) are dynamically generated. If an attacker's script even attempts to read these files, the kernel throws a `HONEYTOKEN_TRIGGERED` alarm.
* **SSH Persistence Trap (Write-Lock)**: `~/.ssh/authorized_keys` is guarded. The eBPF kernel driver inspects the `f_flags` of the file open request. Legitimate reads pass safely, but any attempt to append an attacker's key (`O_WRONLY` / `O_APPEND`) triggers an instant freeze.
* **Hardware & Firmware Lockdown (Write-Lock)**: Key character devices—`/dev/mei0` (Intel ME Interface), `/dev/mem`, `/dev/kmem`, and `/dev/port`—are write-locked. This effectively air-gaps the Intel Management Engine and physical BIOS/EFI flash chip from user-land rootkit installers.
* **HVT Ghost Processes (Memory Scrape Defense)**: The engine clones `sleep` into dummy processes masquerading as `keepassxc`, `mongod`, and `mysqld`. It tracks their PIDs in the kernel. If malware hooks `sys_enter_ptrace` or `process_vm_readv` to dump their memory for passwords, the engine snaps shut (`GHOST_PROCESS_TRAP`).

## 6. Authorized Research Mode
To support live malware development and security research on the host without constantly restarting the EDR, ALPHVDR includes a zero-overhead atomic bypass switch.
* Running `touch /tmp/ALPHVDR_RESEARCH_MODE` drops shields immediately.
* Running `rm /tmp/ALPHVDR_RESEARCH_MODE` instantly re-raises defenses.
* This is managed entirely via a thread-safe Rust `AtomicBool`, completely bypassing the ring buffer parser without causing I/O lag.
