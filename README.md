<div align="center">

<p align="center">
<img src="https://cdn.jsdelivr.net/gh/boylegu/TyrShield/assets/images/TyrShield.png">
</p>

[![go](https://img.shields.io/badge/Go-1.24+-66C9D6)]()
[![ver](https://img.shields.io/badge/version-1.0.0-0F80C2)]()
[![eBPF](https://img.shields.io/badge/support-eBPF-F1E05A)]()
[![XDP](https://img.shields.io/badge/support-XDP-F1E05A)]()
[![linux](https://img.shields.io/badge/support-Linux5.10+-4CC81E)]()
[![license](https://img.shields.io/badge/license-MIT-0F80C2)]()

</div>


# **High-performance XDP/eBPF SSH Brute Force Protection Tool — TyrShield**

- **Line-speed Filtering**: Discards excessive SYN packets directly at the network card driver layer using XDP, with nearly zero latency and no consumption of regular network stack resources.
- **Low-overhead Event Notification**: Uses perf events to asynchronously push "IP ban" events to user space, with minimal system call overhead.
- **Asynchronous Zero-blocking Logging**: Integrates io_uring + Zap for structured log asynchronous writing, preventing log writes from blocking the main process in high-concurrency scenarios.
- **Scalable**: Can be deployed on multi-core machines or containers, with XDP programs consuming very little CPU, enabling linear performance scalability.

---

## 🚀 Features

- **XDP/eBPF Packet Filtering**  
  - Discards SSH SYN packets at the forefront of the network card (XDP), with performance almost equal to kernel drivers, and typical latency < 1µs.

- **Real-time Event Reporting**  
  - Uses the perf ring buffer to asynchronously pass ban events, with user-space consumption requiring minimal memory copying.

- **Asynchronous Structured Logging**  
  - Uses **giouring** (io_uring binding) + **Uber Zap**, enabling non-blocking log writing under high concurrency, capable of handling tens of thousands of log entries per second.

- **Flexible Policy Configuration**  
  - One-click adjustments for maximum attempts, statistical time window, ban duration, XDP mode, perf buffer size (`perf-pages`), and more.

## Prerequisites

- Linux kernel ≥ 5.10 with XDP and eBPF support (enable CONFIG_BPF, CONFIG_XDP_SOCKETS, etc.)

- Go ≥ 1.24

- Root or sufficient capabilities to load eBPF and attach XDP

## Installation



## Usage

```shell

sudo ./tyrshield \
  -interface eth0 \
  -port 22 \
  -max-attempts 5 \
  -time-window 60 \
  -block-time 300 \
  -mode generic \
  -perf-pages 8

```

- -interface : Network interface to attach XDP (e.g. eth0)

- -port : SSH port to protect (default 22)

- -max-attempts: Max SYN retries in window before ban (default 5)

- -time-window: Window in seconds to count attempts (default 60)

- -block-time : Ban duration in seconds (default 300)

- -mode : XDP attach mode:

- generic : software/compat mode (default)

  - native : driver (offload) mode

  - hw : hardware offload mode

  - perf-pages: Perf buffer size in pages (default 8)

Press Ctrl+C to stop and unload XDP.

<p align="center">
<img src="https://cdn.jsdelivr.net/gh/boylegu/TyrShield/assets/images/tyrshield_show.gif">
</p>

## Alternatives 🆚 Comparison

| Tool               | Blocking Layer            | Latency Overhead | CPU Overhead       | Logging Model                          | Configuration        | Language       |
|--------------------|---------------------------|------------------|--------------------|----------------------------------------|----------------------|----------------|
| **TyrShield**      | XDP (driver/software)      | < 1 µs           | Negligible         | Async via io_uring + structured (Zap)  | CLI flags           | Go + eBPF      |
| **fail2ban**       | netfilter (iptables)       | ~ 100–500 µs     | Moderate (Python)  | Synchronous file I/O + log parsing     | INI + regex         | Python         |
| **CrowdSec**       | netfilter (iptables)       | ~ 100–300 µs     | Moderate (Go)      | Synchronous + agent mode               | YAML + regex        | Go             |
| **sshguard**       | netfilter (iptables)       | ~ 50–200 µs      | Low (C)            | Synchronous file I/O                   | Simple conf file    | C              |
| **iptables/ipset** | netfilter rule sets         | Variable (chain length) | Variable           | No native logging (manual rules)       | CLI / scripts       | C (kernel)     |
| **nftables**       | netfilter v2 (nf_tables)   | Variable         | Variable           | No native logging (manual rules)       | CLI / scripts       | C (kernel)     |

**Why TyrShield ssh‑protector stands out:**
1. **Wire‑speed defense**: XDP drops bad SYNs before the kernel TCP stack, achieving sub‑microsecond decision time.
2. **Ultra‑low CPU**: BPF bytecode in the driver layer uses minimal cycles even under flood conditions.
3. **Non‑blocking logs**: io_uring + Zap offloads every log write to the kernel, eliminating write(2) stalls on bursts.
4. **Lightweight Go binary**: single static executable with zero runtime dependencies beyond a modern Linux kernel.
5. **Dynamic tuning**: adjust perf buffer depth, XDP mode, ban windows, etc. in real time via CLI flags.

If your environment requires the absolute lowest per‑packet overhead and the ability to handle thousands of simultaneous SSH attempts with minimal user‑space cost, **TyrShield** is the ideal choice.

## Contributing

- Fork the repository

- Create a feature branch (git checkout -b feature/foo)

- Commit your changes (git commit -m "feat: add foo")

- Push to your branch (git push origin feature/foo)

- Open a Pull Request