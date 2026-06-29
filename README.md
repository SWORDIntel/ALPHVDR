# ALPHVDR Defensive Node

ALPHVDR is a next-generation, kernel-level Endpoint Detection and Response (EDR) agent for Linux environments. Written entirely in memory-safe Rust and leveraging low-overhead eBPF probes, it provides autonomous threat detection, dynamic memory carving, and instant ransomware remediation.

## Core Features

- **eBPF Kernel Telemetry & Behavioral Tripwires**:
  - Monitors `execve`, `ptrace`, `openat`, and `sendto` syscalls directly in the kernel ring buffer.
  - Automatically freezes (`SIGSTOP`) malicious processes that attempt privilege escalation, container escapes (e.g., unauthorized `podman` execution), or Denial of Service attacks.
  - **Anti-DoS**: Aggressive LRU hash map tracking stops Inode Exhaustion (rapid file creation spam) and Journald Exhaustion (syslog/UNIX socket datagram spam) in their tracks.
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

## 🌐 Online Threat Intelligence & MISP Sync

ALPHVDR includes a native `misp.rs` sidecar daemon that runs continuously to ensure your defenses are armed with the latest open-source threat intelligence.

1. **Live MISP Telemetry**: It queries your local MISP node (`https://localhost:8443`) for high-confidence `ip-dst` records and blocklists them immediately at the kernel XDP layer.
2. **Open-Source YARA Feeds**: The sidecar actively pulls public bulk YARA datasets from GitHub (`Yara-Rules`) and logs them into the QIHSE engine, updating the memory scanner signatures on the fly.

## 📊 AMOLED Command & Control Dashboard

To visually monitor and control your endpoint telemetry, ALPHVDR ships with a dynamic, dependency-free Python web dashboard accessible over your local area network (LAN).

- **Stealth Port**: Listens on `http://0.0.0.0:31337`.
- **Aesthetic UI**: Deep AMOLED black (`#000000`) background with glowing blood-red accents and glassmorphism.
- **Live QIHSE WAL Stream**: Automatically tails the `/tmp/alphvdr/qihse_events.wal` file to instantly display system traps, eBPF telemetry, and downloaded YARA rules.
- **Active Controls**: Includes a Command & Control (C2) panel to directly issue `EDR_ACTION` commands:
  - `Flush XDP Blocklist`
  - `Reload YARA Rules`
  - `Toggle KP14 Sandbox`
  - `Emergency Network Isolate`

To spin up the dashboard:
```bash
cd dashboard
python3 dashboard.py
```

---

## 🏗 Installation & Deployment

ALPHVDR requires root privileges to attach eBPF probes and utilize kernel features.

We provide a covert installer that compiles the agent and deploys it as a stealthy, unassuming systemd service (`sys-thermald.service`) to hide in plain sight from attackers.

```bash
sudo ./install.sh
```

### Advanced Modes

- **Advanced KP14 Daemon**: Runs seamlessly in the background by default to automatically mount hotplugged storage, parse proprietary core dump blobs, and orchestrate reverse-engineering triage.
- `--kp14-remote <host>`: Connects to a remote KP14 analysis instance over SSH.
- `--yara-raw <file>`: Runs the raw YARA byte scanner against a static file on disk rather than active memory.

## Architecture

Please see the `docs/` folder for detailed architecture blueprints, memory carving structures, and full implementation details.

---
*Note: This software is intended for defensive research and enterprise threat mitigation.*
