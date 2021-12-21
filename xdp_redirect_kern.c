/* Copyright (c) 2016 John Fastabend <john.r.fastabend@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "bpf_helpers.h"

#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})


struct ip_entry {
    __be32 dst_ip;
};
//
//
//struct bpf_map_def SEC("maps") lpm_map = {
//        .type = BPF_MAP_TYPE_LPM_TRIE,
//        .key_size = sizeof(int),
//        .value_size = sizeof(struct ip_entry),
//        .max_entries = 1,
//};

struct bpf_map_def SEC("maps") tx_port = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = 1,
};

/* Count RX packets, as XDP bpf_prog doesn't get direct TX-success
 * feedback.  Redirect TX errors can be caught via a tracepoint.
 */
struct bpf_map_def SEC("maps") rxcnt = {
        .type = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(long),
        .max_entries = 1,
};

static void swap_src_dst_mac(void *data)
{
    unsigned short *p = data;
    unsigned short dst[3];

    dst[0] = p[0];
    dst[1] = p[1];
    dst[2] = p[2];
    p[0] = p[3];
    p[1] = p[4];
    p[2] = p[5];
    p[3] = dst[0];
    p[4] = dst[1];
    p[5] = dst[2];
}


static  int parse_ipv4(void *data, u64 nh_off, void *data_end,struct ip_entry *ipEntry)
{
    struct iphdr *iph = data + nh_off;

    if (iph + 1 > data_end)
        return 0;


//    int key=0;
//    ifindex = bpf_map_lookup_elem(&tx_port, &key);
//    if (!ifindex)
//        return rc;

//    struct iphdr *iph = data + nh_off;
//    if (iph + 1 > data_end)
//        return -1;
    ipEntry->dst_ip = iph->daddr;
    bpf_printk("src ip addr1: %d.%d.%d\n",(ipEntry->dst_ip) & 0xFF,(ipEntry->dst_ip >> 8) & 0xFF,(ipEntry->dst_ip >> 16) & 0xFF);
    bpf_printk("src ip addr2:.%d\n",(ipEntry->dst_ip >> 24) & 0xFF);
    return iph->protocol;
}

SEC("xdp_redirect")
int xdp_redirect_prog(struct xdp_md *ctx)
{

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int rc = XDP_DROP;
    int *ifindex, port = 0;
    struct ip_entry ipe={};
    long *value;
    u32 key = 0;
    u64 nh_off;
    u32 h_proto;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return rc;


    h_proto = eth->h_proto;
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return rc;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return rc;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }



    ifindex = bpf_map_lookup_elem(&tx_port, &port);
    if (!ifindex)
        return rc;

    value = bpf_map_lookup_elem(&rxcnt, &key);
    if (value)
        *value += 1;


    if (h_proto == htons(ETH_P_IP)) {
        bpf_printk("func parse_ipv4 exec.\n");
        parse_ipv4(data,nh_off, data_end,&ipe);
    }

    bpf_printk("begin to swap mac.\n");
    swap_src_dst_mac(data);
    return bpf_redirect(*ifindex, 0);
}

/* Redirect require an XDP bpf_prog loaded on the TX device */
SEC("xdp_redirect_dummy")
int xdp_redirect_dummy_prog(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
