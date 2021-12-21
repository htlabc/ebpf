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
//#include <linux/icmp.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") tx_port = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = 1,
};


struct bpf_map_def SEC("maps") rxcnt = {
        .type = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(long),
        .max_entries = 1,
};


//struct redirect_info{
//    _u32 saddr;
//    _u32 daddr;
//
//};

/* Count RX packets, as XDP bpf_prog doesn't get direct TX-success
 * feedback.  Redirect TX errors can be caught via a tracepoint.
 */


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

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end,
                             __be32 *src, __be32 *dest)
{
    struct iphdr *iph = data + nh_off;
    if (iph + 1 > data_end)
        return -1;
    *src = iph->saddr;
    *dest = iph->daddr;
    return 0;
}


//static __always_inline int parse_icmphdr(void *data, u64 nh_off, void *data_end)
//{
//    struct icmphdr_common *h = data+nh_off;
//
//    if (h + 1 > data_end)
//        return -1;
//
//    return h->type;
//}

SEC("xdp_redirect_htl")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int rc = XDP_DROP;
    int *ifindex, port = 0;
    long *value;
    u32 key = 0;
    u16 h_proto;
    u64 nh_off;
    u64 iph_off=sizeof(struct iphdr);
    //__u16 echo_reply;
    nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return rc;

  //new
    h_proto = eth->h_proto;
    __be32 src_ip = 0, dest_ip = 0;
    if (h_proto == htons(ETH_P_IP)){
        iph_off=parse_ipv4(data,nh_off, data_end, &src_ip, &dest_ip);
        if iph_off <=-1{
            return rc;
        }
    }


    bpf_trace_printk("src ip addr1: %d.%d.%d\n",(src_ip) & 0xFF,(src_ip >> 8) & 0xFF,(src_ip >> 16) & 0xFF);
    bpf_trace_printk("src ip addr2:.%d\n",(src_ip >> 24) & 0xFF);

    bpf_trace_printk("dest ip addr1: %d.%d.%d\n",(dest_ip) & 0xFF,(dest_ip >> 8) & 0xFF,(dest_ip >> 16) & 0xFF);
    bpf_trace_printk("dest ip addr2: .%d\n",(dest_ip >> 24) & 0xFF);

    //parse_icmphdr(data,iph_off,data_end);

//    if (eth_type == bpf_htons(ETH_P_IP) && icmp_type == ICMP_ECHO) {
//        /* Swap IP source and destination */
//        swap_src_dst_ipv4(iphdr);
//        echo_reply = ICMP_ECHOREPLY;
//    }


    ifindex = bpf_map_lookup_elem(&tx_port, &port);
    if (!ifindex)
        return rc;



    bpf_trace_printk("1.redirect mac %d %d %d", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
    bpf_trace_printk("2.redirect mac %d %d %d", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
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
