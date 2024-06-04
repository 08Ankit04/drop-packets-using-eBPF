//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/xdp.h>

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u16);
} block_port SEC(".maps");

SEC("xdp")
XDP_ACTION drop_tcp_port(struct xdp_md *ctx) {
  void *data = (void *)(long)xdp_access(ctx);
  void *data_end = (void *)(long)(xdp_len(ctx));

  // Skip non-IP packets
  if (!bpf_skb_is_ip(ctx)) {
    return XDP_PASS;
  }

  // Access the Ethernet header
  struct ethhdr *eth = data;
  if (data + sizeof(*eth) > data_end) {
    return XDP_PASS;
  }
  struct iphdr *ip = data + sizeof(*eth);
  if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
    return XDP_PASS;
  }
  if (ip->protocol != IPPROTO_TCP) {
    return XDP_PASS;
  }

  // Access the TCP header
  struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
  if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end) {
    return XDP_PASS;
  }

  // Get the configured port from map (optional)
  __u16 *port = bpf_map_lookup_elem(&block_port, &0);
  int configured_port = port ? *port : 4040; // Default port (replace with your desired port)

  // Drop TCP packets on the configured port
  if (tcp->dest == __constant_htons(configured_port)) {
    return XDP_DROP;
  }

  return XDP_PASS;
}

char __license[] SEC("license") = "GPL";