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

[English](https://github.com/boylegu/TyrShield) | [简体中文]


# **高性能 XDP/eBPF SSH 暴力破解防护工具 — TyrShield**

- **线速过滤**：使用 XDP 直接在网卡驱动层丢弃过量的 SYN 包，几乎零延迟，不消耗常规网络栈资源。
- **低开销事件通知**：通过 perf 事件将“IP 封禁”事件异步推送到用户空间，几乎没有系统调用开销。
- **异步零阻塞日志**：集成 io_uring + Zap 进行结构化日志的异步写入，在高并发场景下防止日志写入阻塞主进程。
- **可扩展性**：可部署在多核机器或容器中，XDP 程序几乎不消耗 CPU，支持线性性能扩展。

---

## 🚀 特性

- **XDP/eBPF 包过滤**
    - 在网络卡前端使用 XDP 丢弃 SSH SYN 包，性能几乎与内核驱动相当，典型延迟 < 1µs。

- **实时事件报告**
    - 使用 perf 环形缓冲区异步传递封禁事件，用户空间的消耗需要最小的内存复制。

- **高性能异步结构化日志**
    - 使用 **giouring** (io_uring 绑定) + **Uber Zap**，在高并发情况下实现非阻塞日志写入，能够每秒处理成千上万条日志条目。

- **灵活的策略配置**
    - 支持一键调整最大尝试次数、统计时间窗口、封禁时长、XDP 模式、perf 缓冲区大小（`perf-pages`）等。

## 先决条件

- Linux 内核 ≥ 5.10，支持 XDP 和 eBPF（启用 CONFIG_BPF, CONFIG_XDP_SOCKETS 等配置）

- Go ≥ 1.24

- 具有足够权限的 root 用户或能够加载 eBPF 并附加 XDP 的能力

## 安装

```shell

go install github.com/boylegu/TyrShield@latest

```


## Usage

```shell

sudo ./tyrshield \
  --iface eth0 \
  --port 22 \
  --max-attempts 5 \
  --time-window 60 \
  --block-time 300 \
  --mode generic \
  --perf-pages 8

```

- `--iface` : 要附加 XDP 的网络接口（例如 eth0）

- `--port` : 要保护的 SSH 端口（默认 22）

- `--max-attempts` : 在窗口内的最大 SYN 重试次数，超过后进行封禁（默认 5）

- `--time-window` : 统计尝试的时间窗口（单位：秒，默认 60）

- `--block-time` : 封禁时长（单位：秒，默认 300）

- `--mode` : XDP 附加模式：

    - `--generic` : 软件/兼容模式（默认，多数云厂商都采用虚拟网卡，并默认使用generic）

    - `--native` : 驱动（卸载）模式

    - `--hw` : 硬件卸载模式

- `--perf-pages` : perf 缓冲区大小（默认 8）

按下 Ctrl+C 停止并卸载 XDP。

<p align="center">
<img src="https://cdn.jsdelivr.net/gh/boylegu/TyrShield/assets/images/tyrshield_show.gif">
</p>

## 竞品 🆚 对比

| Tool               | Blocking Layer            | Latency Overhead | CPU Overhead       | Logging Model                          | Configuration        | Language       |
|--------------------|---------------------------|------------------|--------------------|----------------------------------------|----------------------|----------------|
| **TyrShield**      | XDP (driver/software)      | < 1 µs           | Negligible         | Async via io_uring + structured (Zap)  | CLI flags           | Go + eBPF      |
| **fail2ban**       | netfilter (iptables)       | ~ 100–500 µs     | Moderate (Python)  | Synchronous file I/O + log parsing     | INI + regex         | Python         |
| **CrowdSec**       | netfilter (iptables)       | ~ 100–300 µs     | Moderate (Go)      | Synchronous + agent mode               | YAML + regex        | Go             |
| **sshguard**       | netfilter (iptables)       | ~ 50–200 µs      | Low (C)            | Synchronous file I/O                   | Simple conf file    | C              |
| **iptables/ipset** | netfilter rule sets         | Variable (chain length) | Variable           | No native logging (manual rules)       | CLI / scripts       | C (kernel)     |
| **nftables**       | netfilter v2 (nf_tables)   | Variable         | Variable           | No native logging (manual rules)       | CLI / scripts       | C (kernel)     |

**为什么 TyrShield ssh‑protector 性能更优：**
1. **线速防御**: XDP drops bad SYNs before the kernel TCP stack, achieving sub‑microsecond decision time.
2. **超低 CPU 使用率**: BPF bytecode in the driver layer uses minimal cycles even under flood conditions.
3. **高性能日志**: io_uring + Zap 将每条日志写入卸载到内核，消除了在日志爆发时的写入阻塞，通常主流的日志库(epoll实现)很难接得住eBPF数据量.
4. **轻量级 Go 二进制文件**: 单一静态可执行文件，除了Linux 内核外没有任何运行时依赖.
5. **丰富的性能策略**: 通过 CLI 参数实时调整 perf 缓冲区深度、XDP 模式、封禁窗口等.

如果您的环境要求最低的每包开销，并能够处理成千上万次并发的 SSH 尝试，同时保持最小的用户空间成本，TyrShield 是理想的选择。

## Contributing

- Fork the repository

- Create a feature branch (git checkout -b feature/foo)

- Commit your changes (git commit -m "feat: add foo")

- Push to your branch (git push origin feature/foo)

- Open a Pull Request