<div align="center">

<p align="center">
<img src="https://cdn.jsdelivr.net/gh/boylegu/TyrShield/assets/image/TyrShield.png">
</p>

[![go](https://img.shields.io/badge/Go-1.24+-66C9D6)]()
[![ver](https://img.shields.io/badge/version-1.0.0-0F80C2)]()
[![eBPF](https://img.shields.io/badge/support-eBPF-F1E05A)]()
[![XDP](https://img.shields.io/badge/support-XDP-F1E05A)]()
[![linux](https://img.shields.io/badge/support-Linux5.10+-4CC81E)]()
[![license](https://img.shields.io/badge/license-MIT-0F80C2)]()

</div>


## Features
- XDP/eBPF packet filtering
  -  Drops SYN packets after configurable threshold to thwart SSH brute‑force.

- Perf events
  - Emits “ban” events to userspace when an IP exceeds retry limits.

- Asynchronous, high‑performance logging
  - Uses io_uring (via giouring) + Uber’s Zap for nonblocking, structured logs.

- Flexible CLI
  - Configure interface, port, max attempts, time window, ban duration, XDP mode, perf buffer size.

## Prerequisites

- Linux kernel ≥ 5.10 with XDP and eBPF support (enable CONFIG_BPF, CONFIG_XDP_SOCKETS, etc.)

- Go ≥ 1.24

- Root or sufficient capabilities to load eBPF and attach XDP