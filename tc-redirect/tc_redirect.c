// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> // Ethernet header
#include <netinet/ip.h>   // IP header
#include <netinet/udp.h>  // UDP header
#include <netinet/in.h>   // IPPROTO constants
#include <arpa/inet.h>
#include <net/if.h>
#include "tc_redirect.h"
#include "tc_redirect.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo) {
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    static char buffer[MAX_PAYLOAD];

    int sockfd = *(int *)ctx;
    const struct data_event *event = data;
    memcpy(buffer, event->data, event->len);

    struct iphdr *iph = (struct iphdr *)buffer;
    struct udphdr *udph = (struct udphdr *)(buffer + iph->ihl * 4);
    char *payload = (char *)(buffer + iph->ihl * 4 + sizeof(struct udphdr));
    int payload_size = event->len - (iph->ihl * 4 + sizeof(struct udphdr));

    // checksum需要清零, 即使不修改payload, 原有checksum也需要清零, 否则会被协议栈以InCsumErrors丢包
    udph->check = 0;
    payload[0] = 'X';
    printf("Original payload: %.*s\n", payload_size, (char *)(event->data + iph->ihl * 4 + sizeof(struct udphdr)));
    printf("Modified payload: %.*s\n", payload_size, payload);

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = iph->daddr;
    dest_addr.sin_port = udph->dest;
    ssize_t send_result = sendto(sockfd, buffer, event->len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (send_result < 0) {
        perror("Failed to send modified packet");
    } else {
        printf("Modified packet sent successfully!\n");
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
        return 1;
    }
    int target_pid = (int)atoi(argv[1]);

    libbpf_set_print(libbpf_print_fn);
    struct tc_redirect_bpf *skel = tc_redirect_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* The hook (i.e. qdisc) may already exists because:
     *   1. it is created by other processes or users
     *   2. or since we are attaching to the TC ingress ONLY,
     *      bpf_tc_hook_destroy does NOT really remove the qdisc,
     *      there may be an egress filter on the qdisc
     */
    bool hook_created = false;
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = LO_IFINDEX,
                        .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
    int err = bpf_tc_hook_create(&tc_hook);
    if (!err) {
        hook_created = true;
    }
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        goto cleanup;
    }

    tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_redirect);
    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC: %d\n", err);
        goto cleanup;
    }

    int filter_pid_map_fd = bpf_map__fd(skel->maps.filter_pid_map);
    if (filter_pid_map_fd < 0) {
        fprintf(stderr, "Failed to locate filter_pid_map in BPF object\n");
        goto cleanup_dattach;
    }
    int pid_value = 1;
    if (bpf_map_update_elem(filter_pid_map_fd, &target_pid, &pid_value, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update PID map with PID %u\n", target_pid);
        goto cleanup_dattach;
    }
    printf("Set PID %u in PID map\n", target_pid);

    int raw_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_sockfd < 0) {
        fprintf(stderr, "Failed to creation raw socket\n");
        goto cleanup_dattach;
    }
    int hdrincl = 1;
    if (setsockopt(raw_sockfd, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl)) < 0) {
        fprintf(stderr, "Failed to set hdrincl\n");
        goto cleanup_dattach;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.redirect_ringbuf), handle_event, &raw_sockfd, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup_dattach;
    }

    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF program.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout in milliseconds */);
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll() failed: %d\n", err);
            continue;
        }
    }

cleanup_dattach:
    if (raw_sockfd > 0) {
        close(raw_sockfd);
    }
    tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
    err = bpf_tc_detach(&tc_hook, &tc_opts);
    if (err) {
        fprintf(stderr, "Failed to detach TC: %d\n", err);
        goto cleanup;
    }

cleanup:
    if (hook_created) {
        bpf_tc_hook_destroy(&tc_hook);
    }
    tc_redirect_bpf__destroy(skel);
    return -err;
}
