//
// Created by Lenovo on 2021/12/3.
//

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <libgen.h>

char buf[8192];

int main(){
    get_route_table(AF_INET);
}


 int get_route_table(int rtm_family)
{
    //发送给内核的sock结构体
    struct sockaddr_nl sa;
    //发送给内核的sock结构体，用于请求内核通信，这是一个消息头
    struct nlmsghdr *nh;
    int sock, seq = 0;
    struct msghdr msg;
    struct iovec iov;
    int ret = 0;
    int nll;
    struct {
        struct nlmsghdr nl;
        struct rtmsg rt;
        char buf[8192];
    } req;
    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        printf("open netlink socket: %s\n", strerror(errno));
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        printf("bind to netlink: %s\n", strerror(errno));
        ret = -1;
        goto cleanup;
    }
    memset(&req, 0, sizeof(req));
    req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nl.nlmsg_type = RTM_GETROUTE;
    req.rt.rtm_family = rtm_family;
    req.rt.rtm_table = RT_TABLE_MAIN;
    req.nl.nlmsg_pid = 0;
    req.nl.nlmsg_seq = ++seq;
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = (void *)&req.nl;
    iov.iov_len = req.nl.nlmsg_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    ret = sendmsg(sock, &msg, 0);
    if (ret < 0) {
        printf("send to netlink: %s\n", strerror(errno));
        ret = -1;
        goto cleanup;
    }
    memset(buf, 0, sizeof(buf));
    nll = recv_msg(sa, sock);
    if (nll < 0) {
        printf("recv from netlink: %s\n", strerror(nll));
        ret = -1;
        goto cleanup;
    }
    nh = (struct nlmsghdr *)buf;
    read_route(nh, nll);
    cleanup:
    close(sock);
    return ret;
}


//解析从内核返回的消息
 int recv_msg(struct sockaddr_nl sock_addr, int sock)
{
    struct nlmsghdr *nh;
    int len, nll = 0;
    char *buf_ptr;
    buf_ptr = buf;
    while (1) {
        len = recv(sock, buf_ptr, sizeof(buf) - nll, 0);
        if (len < 0)
            return len;
        nh = (struct nlmsghdr *)buf_ptr;
        if (nh->nlmsg_type == NLMSG_DONE)
            break;
        buf_ptr += len;
        nll += len;
        if ((sock_addr.nl_groups & RTMGRP_NEIGH) == RTMGRP_NEIGH)
            break;
        if ((sock_addr.nl_groups & RTMGRP_IPV4_ROUTE) == RTMGRP_IPV4_ROUTE)
            break;
    }
    return nll;
}


 void read_route(struct nlmsghdr *nh, int nll)
{
    char dsts[24], gws[24], ifs[16], dsts_len[24], metrics[24];
    struct bpf_lpm_trie_key *prefix_key;
    struct rtattr *rt_attr;
    struct rtmsg *rt_msg;
    int rtm_family;
    int rtl;
    int i;
    struct route_table {
        int  dst_len, iface, metric;
        char *iface_name;
        __be32 dst, gw;
        __be64 mac;
    } route;
    struct arp_table {
        __be64 mac;
        __be32 dst;
    };
    struct direct_map {
        struct arp_table arp;
        int ifindex;
        __be64 mac;
    } direct_entry;
    if (nh->nlmsg_type == RTM_DELROUTE)
        printf("DELETING Route entry\n");
    else if (nh->nlmsg_type == RTM_GETROUTE)
        printf("READING Route entry\n");
    else if (nh->nlmsg_type == RTM_NEWROUTE)
        printf("NEW Route entry\n");
    else
        printf("%d\n", nh->nlmsg_type);
    memset(&route, 0, sizeof(route));
    printf("Destination\t\tGateway\t\tGenmask\t\tMetric\t\tIface\n");
    for (; NLMSG_OK(nh, nll); nh = NLMSG_NEXT(nh, nll)) {
        rt_msg = (struct rtmsg *)NLMSG_DATA(nh);
        rtm_family = rt_msg->rtm_family;
        if (rtm_family == AF_INET)
            if (rt_msg->rtm_table != RT_TABLE_MAIN)
                continue;
        rt_attr = (struct rtattr *)RTM_RTA(rt_msg);
        rtl = RTM_PAYLOAD(nh);
        for (; RTA_OK(rt_attr, rtl); rt_attr = RTA_NEXT(rt_attr, rtl)) {
            switch (rt_attr->rta_type) {
                case NDA_DST:
                    sprintf(dsts, "%u",
                            (*((__be32 *)RTA_DATA(rt_attr))));
                    break;
                case RTA_GATEWAY:
                    sprintf(gws, "%u",
                            *((__be32 *)RTA_DATA(rt_attr)));
                    break;
                case RTA_OIF:
                    sprintf(ifs, "%u",
                            *((int *)RTA_DATA(rt_attr)));
                    break;
                case RTA_METRICS:
                    sprintf(metrics, "%u",
                            *((int *)RTA_DATA(rt_attr)));
                default:
                    break;
            }
        }
        sprintf(dsts_len, "%d", rt_msg->rtm_dst_len);
        route.dst = atoi(dsts);
        route.dst_len = atoi(dsts_len);
        route.gw = atoi(gws);
        route.iface = atoi(ifs);
        route.metric = atoi(metrics);
        route.iface_name = alloca(sizeof(char *) * IFNAMSIZ);
        route.iface_name = if_indextoname(route.iface, route.iface_name);
        route.mac = getmac(route.iface_name);
        if (route.mac == -1)
            int_exit(0);
//        assert(bpf_map_update_elem(tx_port_map_fd,
//                                   &route.iface, &route.iface, 0) == 0);
        if (rtm_family == AF_INET) {
            struct trie_value {
                __u8 prefix[4];
                __be64 value;
                int ifindex;
                int metric;
                __be32 gw;
            } *prefix_value;
            prefix_key = alloca(sizeof(*prefix_key) + 3);
            prefix_value = alloca(sizeof(*prefix_value));
            prefix_key->prefixlen = 32;
            prefix_key->prefixlen = route.dst_len;
            direct_entry.mac = route.mac & 0xffffffffffff;
            direct_entry.ifindex = route.iface;
            direct_entry.arp.mac = 0;
            direct_entry.arp.dst = 0;
            if (route.dst_len == 32) {
                if (nh->nlmsg_type == RTM_DELROUTE) {
//                    assert(bpf_map_delete_elem(exact_match_map_fd,
//                                               &route.dst) == 0);
                } else {
                    printf("update route table.");
//                    if (bpf_map_lookup_elem(arp_table_map_fd,
//                                            &route.dst,
//                                            &direct_entry.arp.mac) == 0)
//                        direct_entry.arp.dst = route.dst;
//                    assert(bpf_map_update_elem(exact_match_map_fd,
//                                               &route.dst,
//                                               &direct_entry, 0) == 0);
                }
            }
            for (i = 0; i < 4; i++)
                //获取ip地址
                prefix_key->data[i] = (route.dst >> i * 8) & 0xff;
            printf("%3d.%d.%d.%d\t\t%3x\t\t%d\t\t%d\t\t%s\n",
                   (int)prefix_key->data[0],
                   (int)prefix_key->data[1],
                   (int)prefix_key->data[2],
                   (int)prefix_key->data[3],
                   route.gw, route.dst_len,
                   route.metric,
                   route.iface_name);
//            if (bpf_map_lookup_elem(lpm_map_fd, prefix_key,
//                                    prefix_value) < 0) {
//                for (i = 0; i < 4; i++)
//                    prefix_value->prefix[i] = prefix_key->data[i];
//                prefix_value->value = route.mac & 0xffffffffffff;
//                prefix_value->ifindex = route.iface;
//                prefix_value->gw = route.gw;
//                prefix_value->metric = route.metric;
//                assert(bpf_map_update_elem(lpm_map_fd,
//                                           prefix_key,
//                                           prefix_value, 0
//                ) == 0);
//            } else {
                if (nh->nlmsg_type == RTM_DELROUTE) {
                    printf("deleting entry\n");
                    printf("prefix key=%d.%d.%d.%d/%d",
                           prefix_key->data[0],
                           prefix_key->data[1],
                           prefix_key->data[2],
                           prefix_key->data[3],
                           prefix_key->prefixlen);
                    assert(bpf_map_delete_elem(lpm_map_fd,
                                               prefix_key
                    ) == 0);
                    /* Rereading the route table to check if
                     * there is an entry with the same
                     * prefix but a different metric as the
                     * deleted enty.
                     */
                    get_route_table(AF_INET);
                } else if (prefix_key->data[0] ==
                           prefix_value->prefix[0] &&
                           prefix_key->data[1] ==
                           prefix_value->prefix[1] &&
                           prefix_key->data[2] ==
                           prefix_value->prefix[2] &&
                           prefix_key->data[3] ==
                           prefix_value->prefix[3] &&
                           route.metric >= prefix_value->metric) {
                    continue;
                } else {
                    for (i = 0; i < 4; i++)
                        prefix_value->prefix[i] =
                                prefix_key->data[i];
                    prefix_value->value =
                            route.mac & 0xffffffffffff;
                    prefix_value->ifindex = route.iface;
                    prefix_value->gw = route.gw;
                    prefix_value->metric = route.metric;
                    assert(bpf_map_update_elem(lpm_map_fd,
                                               prefix_key,
                                               prefix_value,
                                               0) == 0);
                }
            //}
        }
        memset(&route, 0, sizeof(route));
        memset(dsts, 0, sizeof(dsts));
        memset(dsts_len, 0, sizeof(dsts_len));
        memset(gws, 0, sizeof(gws));
        memset(ifs, 0, sizeof(ifs));
        memset(&route, 0, sizeof(route));
    }
}

