//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/string.h>

// Define the process name to match
#define PROCESS_NAME "myprocess"
#define PROCESS_NAME_LEN 9  // Length of the process name

// Define the TCP port constant
#define TCP_PORT 4040

// Define the section name for the eBPF program
__attribute__((section("xdp"), used))
int filter_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_DROP;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_DROP;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_DROP;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_DROP;

    struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return XDP_DROP;

    if (tcph->dest != __constant_htons(TCP_PORT))
        return XDP_DROP;

    char *comm = (char *)((unsigned char *)tcph + sizeof(*tcph) + 32); // Assuming process name is at this offset
    if ((void *)comm + PROCESS_NAME_LEN > data_end)
        return XDP_DROP;

    // Custom strncmp function
    int i;
    for (i = 0; i < PROCESS_NAME_LEN; i++) {
        if (comm[i] != PROCESS_NAME[i])
            return XDP_DROP;
        if (comm[i] == '\0')
            break;
    }

    return XDP_PASS; // Allow the packet
}

// License declaration with a semicolon at the end and char type specifier
char _license[] __attribute__((section("license"))) = "GPL";
