#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>


#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define TCPHDR_SYN 0x0020

#define SSH_PORT 22
#define MAX_ATTEMPTS 5
#define TIME_WINDOW_NS (60 * 1000000000ULL) // 60秒
#define BLOCK_TIME_NS (300 * 1000000000ULL) // 300秒封禁

struct config {
    __u32 ssh_port;
    __u32 max_attempts;
    __u64 time_window_ns;
    __u64 block_time_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

struct attempt_info {
    __u32 count;
    __u64 first_attempt_time;
    __u64 last_attempt_time;
    __u64 block_until;
};

struct event {
    __u32 ip;
    __u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct attempt_info);
} ssh_attempts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("xdp")
int xdp_ssh_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 默认配置（硬编码）
    struct config default_cfg = {
        .ssh_port = SSH_PORT,
        .max_attempts = MAX_ATTEMPTS,
        .time_window_ns = TIME_WINDOW_NS,
        .block_time_ns = BLOCK_TIME_NS
    };

    // 尝试从 config_map 获取配置
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg) {
        cfg = &default_cfg; // 使用默认配置
    }

    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 只处理 IPv4 数据包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 解析 IP 头
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 只处理 TCP 流量
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // 计算 IP 头部长度并检查边界
    __u8 ip_header_len = ip->ihl * 4;
    if ((void *)ip + ip_header_len + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    // 解析 TCP 头
    struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip_header_len);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // 检查是否是目标端口的 SYN 包（SSH）
    if (tcp->dest == bpf_htons(cfg->ssh_port) && tcp->syn) {
        __u32 src_ip = ip->saddr;
        __u64 now = bpf_ktime_get_ns();

        // 查找或初始化尝试记录
        struct attempt_info *info = bpf_map_lookup_elem(&ssh_attempts, &src_ip);

        // 检查是否在封禁期内
        if (info && now < info->block_until) {
            return XDP_DROP;
        }

        struct attempt_info new_info = {0};
        if (info) {
            // 检查是否在时间窗口内
            if (now - info->first_attempt_time <= cfg->time_window_ns) {
                new_info.count = info->count + 1;
                new_info.first_attempt_time = info->first_attempt_time;
                new_info.last_attempt_time = now;

                // 如果超过最大尝试次数，触发事件并丢弃包
                if (new_info.count >= cfg->max_attempts) {
                    new_info.block_until = now + cfg->block_time_ns;
                    struct event evt = {
                        .ip = src_ip,
                        .count = new_info.count
                    };
                    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
                    bpf_map_update_elem(&ssh_attempts, &src_ip, &new_info, BPF_ANY);
                    return XDP_DROP;
                }
            } else {
                // 时间窗口过期，重置计数器
                new_info.count = 1;
                new_info.first_attempt_time = now;
                new_info.last_attempt_time = now;
                new_info.block_until = 0;
            }
        } else {
            // 第一次尝试
            new_info.count = 1;
            new_info.first_attempt_time = now;
            new_info.last_attempt_time = now;
            new_info.block_until = 0;
        }

        // 更新记录
        bpf_map_update_elem(&ssh_attempts, &src_ip, &new_info, BPF_ANY);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";