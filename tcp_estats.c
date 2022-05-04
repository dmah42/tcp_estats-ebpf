// +build ignore

#include "tcp_estats.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/types.h>

#define AF_INET 2
#define AF_INET6 10

#define ESTATS_INF32 0xffffffff
#define TCP_INFINITE_SSTHRESH 0x7fffffff

char __license[] SEC("license") = "MIT";

/**
 * preseve_access_index preserves the offset of the fields in the original
 * kernel struct so we only need to declare the struct and the fields the
 * program requires.
 **/

/**
 * struct sock_common is the minimal network layer representation of sockets.
 **/
struct sock_common {
  union {
    struct {
      __be32 skc_daddr;
      __be32 skc_rcv_saddr;
    };
  };
  union {
    struct {
      __be16 skc_dport;
      __u16 skc_num;
    };
  };
  short unsigned int skc_family;
} __attribute__((preserve_access_index));

/**
 * struct sock is the network layer representation of sockets.
 **/
struct sock {
  struct sock_common __sk_common;
} __attribute__((preserve_access_index));

/**
 * struct sk_buff is the network layer socket buffer representation.
 */
struct sk_buff {
  char cb[48];  // TODO: aligned(8)
  unsigned int len;

  __u16 transport_header;
  __u16 network_header;

  unsigned char *head;

} __attribute__((preserve_access_index));

// used by the send packet queuing engine to pass TCP per-packet
// control information to the transmission code.
struct tcp_skb_cb {
  __u32 ack_seq;
} __attribute__((preserve_access_index));

#define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))

struct tcphdr {
  // note: assuming little-endian.
  __u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1,
      urg : 1, ece : 1, cwr : 1;
} __attribute__((preserve_access_index));

#define SKB_TO_TCP_HDR(__skb) \
  (struct tcphdr *)(__skb->head + __skb->transport_header)

struct iphdr {
  __u8 tos;
  __u8 ttl;
} __attribute__((preserve_access_index));

#define SKB_TO_IP_HDR(__skb) (struct iphdr *)(skb->head + skb->network_header)

/**
 * struct tcp_sock is the kernel representation of a TCP socket.
 **/
struct tcp_sock {
  // RFC 793
  __u32 segs_in;
  __u32 rcv_nxt;
  __u32 snd_nxt;
  __u32 segs_out;
  __u32 snd_una;
  __u32 mss_cache;

  // RTT measurement
  __u32 srtt_us;
  __u32 packets_out;
  __u32 retrans_out;

  // slow start and cong control
  __u32 snd_ssthresh;
  __u32 snd_cwnd;
  __u32 lost_out;
  __u32 sacked_out;

  __u32 total_retrans;
} __attribute__((preserve_access_index));

// Packets sent one on trans queue /minus/
// Packets left network, but not acked /plus/
// Packets fast retransmitted
static inline unsigned int tcp_packets_in_flight(const struct tcp_sock *tp) {
  return tp->packets_out - (tp->sacked_out + tp->lost_out) + tp->retrans_out;
}

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} global_table SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} connection_table SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} perf_table SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} path_table SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} stack_table SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} app_table SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} extras_table SEC(".maps");

int _submit_entry(void *table, const struct key key,
                  enum tcp_estats_operation op, __u32 var, __u32 val) {
  struct entry *entry = bpf_ringbuf_reserve(table, sizeof(struct entry), 0);
  if (!entry) return 0;

  entry->key = key;
  entry->op = op;
  entry->var = var;
  entry->val = val;

  bpf_ringbuf_submit(entry, 0);

  return 0;
}

#define FUNC_NAME(TABLE) submit_##TABLE##_table_entry
#define VAR_TYPE(TABLE) tcp_estats_##TABLE##_table
#define TABLE_NAME(TABLE) TABLE##_table

#define SUBMIT_FUNC(TABLE)                                                  \
  int FUNC_NAME(TABLE)(const struct key *key, enum tcp_estats_operation op, \
                       enum VAR_TYPE(TABLE) var, __u32 val) {               \
    void *table = &TABLE_NAME(TABLE);                                       \
    return _submit_entry(table, *key, op, (__u32)var, val);                 \
  }

SUBMIT_FUNC(global)
SUBMIT_FUNC(connection)
SUBMIT_FUNC(perf)
SUBMIT_FUNC(path)
SUBMIT_FUNC(stack)
SUBMIT_FUNC(app)
SUBMIT_FUNC(extras)

static int tcp_estats_create(const struct key *key, const struct tcp_sock *ts,
                             int addr_family, int active) {
  if (!ts) return 0;

  enum tcp_estats_addrtype addr_type;

  if (addr_family == AF_INET) {
    addr_type = TCP_ESTATS_ADDRTYPE_IPV4;
  } else if (addr_family == AF_INET6) {
    addr_type = TCP_ESTATS_ADDRTYPE_IPV6;
  } else {
    // Invalid address family
    return 0;
  }

  submit_connection_table_entry(key, TCP_ESTATS_OPERATION_SET,
                                TCP_ESTATS_CONNECTION_TABLE_ADDRESS_TYPE,
                                addr_type);

  submit_global_table_entry(key, TCP_ESTATS_OPERATION_SET,
                            TCP_ESTATS_GLOBAL_TABLE_LIMSTATE,
                            TCP_ESTATS_SNDLIM_STARTUP);

  __u32 timestamp = (__u32)(bpf_ktime_get_ns() / 1000000000);
  submit_global_table_entry(key, TCP_ESTATS_OPERATION_SET,
                            TCP_ESTATS_GLOBAL_TABLE_LIMSTATE_TS, timestamp);
  submit_global_table_entry(key, TCP_ESTATS_OPERATION_SET,
                            TCP_ESTATS_GLOBAL_TABLE_START_TS, timestamp);
  submit_global_table_entry(key, TCP_ESTATS_OPERATION_SET,
                            TCP_ESTATS_GLOBAL_TABLE_CURRENT_TS, timestamp);
  submit_global_table_entry(key, TCP_ESTATS_OPERATION_SET,
                            TCP_ESTATS_GLOBAL_TABLE_START_TV, timestamp);

  submit_stack_table_entry(key, TCP_ESTATS_OPERATION_SET,
                           TCP_ESTATS_STACK_TABLE_ACTIVEOPEN, active);

  submit_app_table_entry(key, TCP_ESTATS_OPERATION_SET,
                         TCP_ESTATS_APP_TABLE_SNDMAX, ts->snd_nxt);
  submit_stack_table_entry(key, TCP_ESTATS_OPERATION_SET,
                           TCP_ESTATS_STACK_TABLE_SNDINITIAL, ts->snd_nxt);

  submit_path_table_entry(key, TCP_ESTATS_OPERATION_SET,
                          TCP_ESTATS_PATH_TABLE_MINRTT, ESTATS_INF32);
  submit_path_table_entry(key, TCP_ESTATS_OPERATION_SET,
                          TCP_ESTATS_PATH_TABLE_MINRTO, ESTATS_INF32);
  submit_stack_table_entry(key, TCP_ESTATS_OPERATION_SET,
                           TCP_ESTATS_STACK_TABLE_MINMSS, ESTATS_INF32);
  submit_stack_table_entry(key, TCP_ESTATS_OPERATION_SET,
                           TCP_ESTATS_STACK_TABLE_MINSSTHRESH, ESTATS_INF32);

  return 0;
}

SEC("fexit/tcp_create_openreq_child")
int BPF_PROG(tcp_estats_create_inactive, struct sock *sk) {
  if (!sk) return 0;
  struct sock_common *sk_comm = &(sk->__sk_common);

  struct key key;
  __builtin_memset(&key, 0, sizeof(key));

  key.pid_tgid = bpf_get_current_pid_tgid();
  key.saddr = sk_comm->skc_rcv_saddr;
  key.daddr = sk_comm->skc_daddr;
  key.sport = sk_comm->skc_num;
  key.dport = bpf_ntohs(sk_comm->skc_dport);

  // TODO: support tcp6_sock if family is AF_INET6.
  struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
  if (!ts) return 0;
  return tcp_estats_create(&key, ts, AF_INET, TCP_ESTATS_INACTIVE);
}

SEC("fexit/tcp_init_sock")
int BPF_PROG(tcp_estats_create_active, struct sock *sk) {
  if (!sk) return 0;
  struct sock_common *sk_comm = &(sk->__sk_common);

  struct key key;
  __builtin_memset(&key, 0, sizeof(key));

  key.pid_tgid = bpf_get_current_pid_tgid();
  key.saddr = sk_comm->skc_rcv_saddr;
  key.daddr = sk_comm->skc_daddr;
  key.sport = sk_comm->skc_num;
  key.dport = bpf_ntohs(sk_comm->skc_dport);

  // TODO: support tcp6_sock if family is AF_INET6.
  struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
  if (!ts) return 0;
  return tcp_estats_create(&key, ts, AF_INET, TCP_ESTATS_ACTIVE);
}

SEC("fentry/tcp_v4_do_rcv")
int BPF_PROG(tcp_estats_update_segrecv, struct sock *sk, struct sk_buff *skb) {
  if (!sk) return 0;
  if (!skb) return 0;

  struct sock_common *sk_comm = &(sk->__sk_common);

  struct key key;
  __builtin_memset(&key, 0, sizeof(key));

  key.pid_tgid = bpf_get_current_pid_tgid();
  key.saddr = sk_comm->skc_rcv_saddr;
  key.daddr = sk_comm->skc_daddr;
  key.sport = sk_comm->skc_num;
  key.dport = bpf_ntohs(sk_comm->skc_dport);

  submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                          TCP_ESTATS_PERF_TABLE_SEGSIN, 1);

  struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
  if (!ts) return 0;

  struct tcphdr *th = SKB_TO_TCP_HDR(skb);
  if (!th) return 0;
  // struct tcphdr th;
  // bpf_probe_read(&th, sizeof(th), (void *)SKB_TO_TCP_HDR(skb));

  if (skb->len == th->doff * 4) {
    if (TCP_SKB_CB(skb)->ack_seq == ts->snd_una) {
      submit_stack_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                               TCP_ESTATS_STACK_TABLE_DUPACKSIN, 1);
    }
  } else {
    submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                            TCP_ESTATS_PERF_TABLE_DATASEGSIN, 1);
    submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                            TCP_ESTATS_PERF_TABLE_DATAOCTETSIN,
                            skb->len - th->doff * 4);
  }

  struct iphdr *iph = SKB_TO_IP_HDR(skb);
  if (!iph) return 0;
  // struct iphdr iph;
  // bpf_probe_read(&iph, sizeof(iph), (void *)SKB_TO_IP_HDR(skb));

  submit_path_table_entry(&key, TCP_ESTATS_OPERATION_SET,
                          TCP_ESTATS_PATH_TABLE_IPTTL, iph->ttl);
  submit_path_table_entry(&key, TCP_ESTATS_OPERATION_SET,
                          TCP_ESTATS_PATH_TABLE_IPTOSIN, iph->tos);

  return 0;
}

SEC("fexit/tcp_v4_do_rcv")
int BPF_PROG(tcp_estats_update_finish_segrecv, struct sock *sk,
             struct sk_buff *skb) {
  if (!sk) return 0;
  if (!skb) return 0;

  struct sock_common *sk_comm = &(sk->__sk_common);

  struct key key;
  __builtin_memset(&key, 0, sizeof(key));

  key.pid_tgid = bpf_get_current_pid_tgid();
  key.saddr = sk_comm->skc_rcv_saddr;
  key.daddr = sk_comm->skc_daddr;
  key.sport = sk_comm->skc_num;
  key.dport = bpf_ntohs(sk_comm->skc_dport);

  struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
  if (!ts) return 0;

  __u32 mss = ts->mss_cache;
  __u32 cwnd = ts->snd_cwnd * mss;
  if (ts->snd_cwnd <= ts->snd_ssthresh) {
    submit_stack_table_entry(&key, TCP_ESTATS_OPERATION_MAX,
                             TCP_ESTATS_STACK_TABLE_MAXSSCWND, cwnd);
  } else {
    submit_stack_table_entry(&key, TCP_ESTATS_OPERATION_MAX,
                             TCP_ESTATS_STACK_TABLE_MAXCACWND, cwnd);
  }

  submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_MAX,
                          TCP_ESTATS_PERF_TABLE_MAXPIPESIZE,
                          tcp_packets_in_flight(ts) * mss);

  if (ts->snd_ssthresh < TCP_INFINITE_SSTHRESH) {
    __u32 ssthresh = ts->snd_ssthresh * mss;
    submit_stack_table_entry(&key, TCP_ESTATS_OPERATION_MAX,
                             TCP_ESTATS_STACK_TABLE_MAXSSTHRESH, ssthresh);
    submit_stack_table_entry(&key, TCP_ESTATS_OPERATION_MIN,
                             TCP_ESTATS_STACK_TABLE_MAXSSTHRESH, ssthresh);
  }
  return 0;
}
