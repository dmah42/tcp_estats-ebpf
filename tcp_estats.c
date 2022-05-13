// +build ignore

#include "tcp_estats.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/const.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <unistd.h>

#include "tcp_sock.h"

#define AF_INET 2
#define AF_INET6 10

#define ESTATS_INF32 0xffffffff
#define TCP_INFINITE_SSTHRESH 0x7fffffff

// TODO: figure out how to get these from /include/net/tcp.h
#define TCP_ECN_OK 1
#define TCP_ECN_QUEUE_CWR 2
#define TCP_ECN_DEMAND_CWR 4
#define TCP_ECN_SEEN 8

#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_PSH 0x08
#define TCPHDR_ACK 0x10
#define TCPHDR_URG 0x20
#define TCPHDR_ECE 0x40
#define TCPHDR_CWR 0x80

#define TCPHDR_SYN_ECN (TCPHDR_SYN | TCPHDR_ECE | TCPHDR_CWR)

// TODO: get this from /include/net/inet_ecn.h
enum {
  INET_ECN_NOT_ECT = 0,
  INET_ECN_ECT_1 = 1,
  INET_ECN_ECT_0 = 2,
  INET_ECN_CE = 3,
  INET_ECN_MASK = 3,
};

// dual-license GPL so i can use useful functions like bpf_probe_read
// and bpf_printk. you know, the ones you need rarely. :|
char __license[] SEC("license") = "GPL";

// struct sock_common is the minimal network layer representation of sockets.
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

// struct sock is the network layer representation of sockets.
struct sock {
  struct sock_common __sk_common;
} __attribute__((preserve_access_index));

// used by the send packet queuing engine to pass TCP per-packet
// control information to the transmission code.
struct tcp_skb_cb {
  __u32 seq;
  __u32 end_seq;

  union {
    __u32 tcp_tw_isn;
    struct {
      __u16 tcp_gso_segs;
      __u16 tcp_gso_size;
    };
  };
  __u8 tcp_flags;
  __u8 sacked;
  __u8 ip_dsfield;

  __u32 ack_seq;
} __attribute__((preserve_access_index));

#define TCP_SKB_CB(__skb) ((struct tcp_skb_cb *)&((__skb)->cb[0]))

struct tcp_sacktag_state {
  int reord;
  int fack_count;
  int flag;
} __attribute__((preserve_access_index));

// define a ringbuf per table
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

static struct key create_key(const struct sock_common *sk_comm) {
  struct key key;
  __builtin_memset(&key, 0, sizeof(key));

  key.pid_tgid = bpf_get_current_pid_tgid();
  key.saddr = sk_comm->skc_rcv_saddr;
  key.daddr = sk_comm->skc_daddr;
  key.sport = sk_comm->skc_num;
  key.dport = bpf_ntohs(sk_comm->skc_dport);

  return key;
}

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

  struct key key = create_key(sk_comm);

  // TODO: support tcp6_sock if family is AF_INET6.
  struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
  if (!ts) return 0;
  return tcp_estats_create(&key, ts, AF_INET, TCP_ESTATS_INACTIVE);
}

SEC("fexit/tcp_init_sock")
int BPF_PROG(tcp_estats_create_active, struct sock *sk) {
  return 0;
  if (!sk) return 0;
  struct sock_common *sk_comm = &(sk->__sk_common);

  struct key key = create_key(sk_comm);

  // TODO: support tcp6_sock if family is AF_INET6.
  struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
  if (!ts) return 0;
  return tcp_estats_create(&key, ts, AF_INET, TCP_ESTATS_ACTIVE);
}

SEC("fentry/tcp_v4_do_rcv")
int BPF_PROG(tcp_estats_update_segrecv, struct sock *sk,
             struct __sk_buff *skb) {
  if (!sk) return 0;
  if (!skb) return 0;

  const struct sock_common *sk_comm = &(sk->__sk_common);

  struct key key = create_key(sk_comm);

  submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                          TCP_ESTATS_PERF_TABLE_SEGSIN, 1);

  struct __sk_buff skbuff;
  __builtin_memset(&skbuff, 0, sizeof(struct __sk_buff));
  bpf_probe_read(&skbuff, sizeof(struct __sk_buff), skb);

  const void *data = (void *)(long)skbuff.data;

  struct tcphdr th;
  __builtin_memset(&th, 0, sizeof(struct tcphdr));
  bpf_probe_read(&th, sizeof(struct tcphdr), data + sizeof(struct iphdr));

  if (skbuff.len == th.doff * 4) {
    const struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
    if (!ts) return 0;

    if (TCP_SKB_CB(skb)->ack_seq == ts->snd_una) {
      submit_stack_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                               TCP_ESTATS_STACK_TABLE_DUPACKSIN, 1);
    }
  } else {
    submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                            TCP_ESTATS_PERF_TABLE_DATASEGSIN, 1);
    submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                            TCP_ESTATS_PERF_TABLE_DATAOCTETSIN,
                            skbuff.len - th.doff * 4);
  }

  struct iphdr iph;
  __builtin_memset(&iph, 0, sizeof(struct iphdr));
  bpf_probe_read(&iph, sizeof(struct iphdr), data + sizeof(struct ethhdr));

  submit_path_table_entry(&key, TCP_ESTATS_OPERATION_SET,
                          TCP_ESTATS_PATH_TABLE_IPTTL, iph.ttl);
  submit_path_table_entry(&key, TCP_ESTATS_OPERATION_SET,
                          TCP_ESTATS_PATH_TABLE_IPTOSIN, iph.tos);

  return 0;
}

SEC("fexit/__tcp_transmit_skb")
int BPF_PROG(tcp_estats_update_segsend, struct sock *sk, struct __sk_buff *skb,
             int clone_it, unsigned int gfp_mask, __u32 rcv_nxt) {
  if (!sk) return 0;

  struct sock_common *sk_comm = &(sk->__sk_common);
  struct key key = create_key(sk_comm);

  __u32 timestamp = (__u32)(bpf_ktime_get_ns() / 1000000000);

  submit_global_table_entry(&key, TCP_ESTATS_OPERATION_SET,
                            TCP_ESTATS_GLOBAL_TABLE_CURRENT_TS, timestamp);

  const int pcount = TCP_SKB_CB(skb)->tcp_gso_segs;
  const __u32 seq = TCP_SKB_CB(skb)->seq;
  const __u32 end_seq = TCP_SKB_CB(skb)->end_seq;

  submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                          TCP_ESTATS_PERF_TABLE_SEGSOUT, pcount);

  const int data_len = end_seq - seq;
  if (data_len > 0) {
    submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                            TCP_ESTATS_PERF_TABLE_DATASEGSOUT, pcount);
    submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                            TCP_ESTATS_PERF_TABLE_DATAOCTETSOUT, data_len);
  }

  // TODO: possible retransmission
  /*
        const int tcp_flags = TCP_SKB_CB(skb)->tcp_flags;
  if (tcp_flags & TCPHDR_SYN) {
          if (((struct inet_connection_sock *)sk)->icsk_retransmits)
                  submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                                  TCP_ESTATS_PERF_TABLE_SEGSRETRANS, 1);
  } else if (seq < snd_max) {
          submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                          TCP_ESTATS_PERF_TABLE_SEGSRETRANS, pcount);
          submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                          TCP_ESTATS_PERF_TABLE_OCTETSRETRANS, data_len);
  }
  */

  return 0;
}

// Packets sent one on trans queue /minus/
// Packets left network, but not acked /plus/
// Packets fast retransmitted
#define TCP_PACKETS_IN_FLIGHT(tp) \
  tp->packets_out - (tp->sacked_out + tp->lost_out) + tp->retrans_out

SEC("fexit/tcp_v4_do_rcv")
int BPF_PROG(tcp_estats_update_finish_segrecv, struct sock *sk,
             struct __sk_buff *skb) {
  if (!sk) return 0;
  if (!skb) return 0;

  struct sock_common *sk_comm = &(sk->__sk_common);
  struct key key = create_key(sk_comm);

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
                          TCP_PACKETS_IN_FLIGHT(ts) * mss);

  if (ts->snd_ssthresh < TCP_INFINITE_SSTHRESH) {
    __u32 ssthresh = ts->snd_ssthresh * mss;
    submit_stack_table_entry(&key, TCP_ESTATS_OPERATION_MAX,
                             TCP_ESTATS_STACK_TABLE_MAXSSTHRESH, ssthresh);
    submit_stack_table_entry(&key, TCP_ESTATS_OPERATION_MIN,
                             TCP_ESTATS_STACK_TABLE_MAXSSTHRESH, ssthresh);
  }
  return 0;
}

static void TCP_ECN_check_ce(struct key key, const struct tcp_sock *ts,
                             const struct __sk_buff *skb) {
  if (!(ts->ecn_flags & TCP_ECN_OK)) return;

  switch (TCP_SKB_CB(skb)->ip_dsfield & INET_ECN_MASK) {
    case INET_ECN_CE:
      submit_path_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                              TCP_ESTATS_PATH_TABLE_CERCVD, 1);
      if (ts->ecn_flags & TCP_ECN_DEMAND_CWR) {
        submit_path_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                                TCP_ESTATS_PATH_TABLE_ECESENT, 1);
      }
  }
}

SEC("fexit/tcp_event_data_recv")
int BPF_PROG(tcp_event_data_recv, struct sock *sk, struct __sk_buff *skb) {
  if (!sk) return 0;
  if (!skb) return 0;

  struct sock_common *sk_comm = &(sk->__sk_common);

  struct key key = create_key(sk_comm);

  struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
  if (!ts) return 0;

  TCP_ECN_check_ce(key, ts, skb);

  return 0;
}

SEC("fentry/tcp_data_queue_ofo")
int BPF_PROG(tcp_data_queue_ofo, struct sock *sk, struct __sk_buff *skb) {
  if (!sk) return 0;
  if (!skb) return 0;

  struct sock_common *sk_comm = &(sk->__sk_common);

  struct key key = create_key(sk_comm);

  struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
  if (!ts) return 0;

  TCP_ECN_check_ce(key, ts, skb);

  return 0;
}

SEC("fentry/tcp_rtt_estimator")
int BPF_PROG(tcp_rtt_estimator, struct sock *sk, long mrtt_us) {
  if (!sk) return 0;

  struct sock_common *sk_comm = &(sk->__sk_common);
  struct key key = create_key(sk_comm);

  struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
  if (!ts) return 0;

  // TODO: read sysctl from kernel
  static int sysctl_tcp_link_latency = 0;
  if (sysctl_tcp_link_latency > 0) {
    if (mrtt_us > sysctl_tcp_link_latency) {
      submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                              TCP_ESTATS_PERF_TABLE_HIGHRTTM, 1);
    } else {
      submit_perf_table_entry(&key, TCP_ESTATS_OPERATION_ADD,
                              TCP_ESTATS_PERF_TABLE_NORMALRTTM, 1);
    }
  }

  return 0;
}
