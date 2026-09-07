#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");


SEC("xdp")
int xdp_pass_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // --- Ethernet header ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Check for IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // --- IP header ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Check for UDP
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // --- UDP header ---
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u32 index = ctx->rx_queue_index;

    bpf_printk("UDP src port: %d, dst port: %d", __constant_ntohs(udp->source), __constant_ntohs(udp->dest));

    // --- Check if destination port is 53 (DNS) ---
    if (udp->dest == __constant_htons(53)) {
        return bpf_redirect_map(&xsks_map, index, XDP_ABORTED);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
