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
 * struct tcp_sock is the kernel representation of a TCP socket.
 **/
struct tcp_sock {
  __u32 snd_nxt;
  __u32 srtt_us;
  __u32 total_retrans;
} __attribute__((preserve_access_index));

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

int _submit_entry(void *table, struct key key,  // struct sock_common *sk_comm,
                  enum tcp_estats_operation op, __u32 var, __u32 val) {
  struct entry *entry = bpf_ringbuf_reserve(table, sizeof(struct entry), 0);
  if (!entry) return 0;

  // entry->key.saddr = sk_comm->skc_rcv_saddr;
  // entry->key.daddr = sk_comm->skc_daddr;
  // entry->key.sport = sk_comm->skc_num;
  // entry->key.dport = bpf_ntohs(sk_comm->skc_dport);
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

#define SUBMIT_FUNC(TABLE)                                           \
  int FUNC_NAME(TABLE)(struct key key, enum tcp_estats_operation op, \
                       enum VAR_TYPE(TABLE) var, __u32 val) {        \
    void *table = &TABLE_NAME(TABLE);                                \
    return _submit_entry(table, key, op, (__u32)var, val);           \
  }

SUBMIT_FUNC(global)
SUBMIT_FUNC(connection)
SUBMIT_FUNC(perf)
SUBMIT_FUNC(path)
SUBMIT_FUNC(stack)
SUBMIT_FUNC(app)
SUBMIT_FUNC(extras)

static int tcp_estats_create(struct key *key, struct tcp_sock *ts,
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

  submit_connection_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                                TCP_ESTATS_CONNECTION_TABLE_ADDRESS_TYPE,
                                addr_type);

  submit_global_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                            TCP_ESTATS_GLOBAL_TABLE_LIMSTATE,
                            TCP_ESTATS_SNDLIM_STARTUP);

  __u32 timestamp = (__u32)(bpf_ktime_get_ns() / 1000000000);
  submit_global_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                            TCP_ESTATS_GLOBAL_TABLE_LIMSTATE_TS, timestamp);
  submit_global_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                            TCP_ESTATS_GLOBAL_TABLE_START_TS, timestamp);
  submit_global_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                            TCP_ESTATS_GLOBAL_TABLE_CURRENT_TS, timestamp);
  submit_global_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                            TCP_ESTATS_GLOBAL_TABLE_START_TV, timestamp);

  submit_stack_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                           TCP_ESTATS_STACK_TABLE_ACTIVEOPEN, active);

  submit_app_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                         TCP_ESTATS_APP_TABLE_SNDMAX, ts->snd_nxt);
  submit_stack_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                           TCP_ESTATS_STACK_TABLE_SNDINITIAL, ts->snd_nxt);

  submit_path_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                          TCP_ESTATS_PATH_TABLE_MINRTT, ESTATS_INF32);
  submit_path_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                          TCP_ESTATS_PATH_TABLE_MINRTO, ESTATS_INF32);
  submit_stack_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                           TCP_ESTATS_STACK_TABLE_MINMSS, ESTATS_INF32);
  submit_stack_table_entry(*key, TCP_ESTATS_OPERATION_SET,
                           TCP_ESTATS_STACK_TABLE_MINSSTHRESH, ESTATS_INF32);

  return 0;
}

SEC("fexit/tcp_create_openreq_child")
int BPF_PROG(tcp_create_openreq_child, struct sock *sk) {
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
int BPF_PROG(tcp_init_sock, struct sock *sk) {
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