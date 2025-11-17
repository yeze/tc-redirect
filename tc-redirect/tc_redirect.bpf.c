// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "tc_redirect.h"

#define TC_ACT_OK           0
#define TC_ACT_STOLEN		4
#define ETH_P_IP            0x0800 /* Internet Protocol packet	*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} filter_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} redirect_ringbuf SEC(".maps");

SEC("tc")
int tc_redirect(struct __sk_buff *ctx) {
    void *data = (void *)(__u64)ctx->data;
    void *data_end = (void *)(__u64)ctx->data_end;

    if (ctx->protocol != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct ethhdr *l2 = data;
    if ((void *)(l2 + 1) > data_end) {
        return TC_ACT_OK;
    }

    struct iphdr *l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end) {
        return TC_ACT_OK;
    }
    if (l3->protocol != IPPROTO_UDP) {
        return TC_ACT_OK;
    }

    struct udphdr *l4 = (struct udphdr *)(l3 + 1);
    if ((void *)(l4 + 1) > data_end) {
        return TC_ACT_OK;
    }

    char *payload = (char *)(l4 + 1);
    if ((void *)(payload + 4) > data_end) {
        return TC_ACT_OK;
    }
    // RTPS报文
    if (payload[0] != 'R' || payload[1] != 'T' || payload[2] != 'P' || payload[3] != 'S') {
        return TC_ACT_OK;
    }

    // 检查发包pid是否在map中
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int tgid = BPF_CORE_READ(task, tgid);
    __u32 *pid_entry = bpf_map_lookup_elem(&filter_pid_map, &tgid);
    if (!pid_entry) {
        return TC_ACT_OK;
    }

    struct data_event *event = bpf_ringbuf_reserve(&redirect_ringbuf, sizeof(struct data_event), 0);
    if (!event) {
        return TC_ACT_OK;
    }
    int len = ctx->len - sizeof(struct ethhdr);
    if (len > sizeof(event->data)) {
        len = sizeof(event->data);
    }
    event->len = len;
    bpf_probe_read_kernel(event->data, len, l3);
    bpf_ringbuf_submit(event, 0);
    return TC_ACT_STOLEN;
}

char __license[] SEC("license") = "GPL";
