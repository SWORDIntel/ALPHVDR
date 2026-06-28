# ALPHVDR Defensive Node

ALPHVDR is a next-generation, kernel-level Endpoint Detection and Response (EDR) agent for Linux environments. Written entirely in memory-safe Rust and leveraging low-overhead eBPF probes, it provides autonomous threat detection, dynamic memory carving, and instant ransomware remediation.

## Core Features

- **eBPF Kernel Telemetry & Behavioral Tripwires**:
  - Monitors `execve`, `ptrace`, and `process_vm_readv` syscalls directly in the kernel ring buffer.
  - Automatically freezes (`SIGSTOP`) malicious processes that attempt privilege escalation or container escapes (e.g., unauthorized `podman` execution).
  - Deception traps (Honeytokens) deployed in `~/.aws/`, `~/.kube/`, and `/dev/mei0` to catch credential scrapers and firmware flashers.
- **Dynamic Memory Carving & KP14-SUITE**:
  - Hooks memory regions via `/proc/[pid]/maps` and extracts raw Virtual Memory Areas (VMAs) upon detecting a threat.
  - Formats extractions into a proprietary `.bin` core dump structure for remote analysis.
  - Bridges with **Proxmox Virtual Environment** to automatically provision isolated VM storage and route core dumps for headless Ghidra and Radare2 triage via the KP14 daemon.
- **In-Memory YARA Engine**:
  - Directly scans process memory for known malware signatures and extracts the matching byte regions without dumping to disk.
- **Autonomous Ransomware Reversion**:
  - Detects rapid encryption bursts heuristically.
  - Instantly neuters the ransomware and triggers a fully automated `zfs rollback -r` to restore the compromised dataset to its pristine state.
- **Network Threat Intelligence**:
  - Native XDP (eXpress Data Path) kernel packet dropping for identified C2 IPs.
  - Extracts and analyzes TLS Client Hello handshakes to generate JA3 fingerprints for evasive malware tracking.
- **QIHSE Telemetry Logging**:
  - Emits all EDR actions, YARA matches, and network telemetry to a high-performance WAL (Write-Ahead Log) for SOC ingestion.

## Installation & Compilation

```bash
cargo build --release
```

## Usage

ALPHVDR requires root privileges to attach eBPF probes and utilize kernel features.

```bash
sudo cargo run
```

### Advanced Modes

- `--kp14-daemon`: Boots ALPHVDR into the headless KP14 VM Daemon mode, automatically mounting hotplugged storage, parsing proprietary core dump blobs, and orchestrating reverse-engineering triage.
- `--kp14-remote <host>`: Connects to a remote KP14 analysis instance over SSH.
- `--yara-raw <file>`: Runs the raw YARA byte scanner against a static file on disk rather than active memory.

## Architecture

Please see the `docs/` folder for detailed architecture blueprints, memory carving structures, and full implementation details.

---
*Note: This software is intended for defensive research and enterprise threat mitigation.*
