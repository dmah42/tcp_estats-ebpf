// +build ignore
//go:generate main

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2

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
	__u32 srtt_us;
	__u32 total_retrans;
} __attribute__((preserve_access_index));

/**
 * this maps a fixed size ring buf we'll use to read samples.
 **/
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} samples SEC(".maps");

/**
 * A sample submitted to the ring buffer for use in userspace
 **/
struct sample {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 srtt;
	__u32 total_retrans;
};

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk) {
	// only support IPv4
	if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}

	struct tcp_sock *ts = bpf_skc_to_tcp_sock(sk);
	if (!ts) return 0;

	struct sample *tcp_info =
		bpf_ringbuf_reserve(&samples, sizeof(struct sample), 0);
	if (!tcp_info) return 0;

	tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
	tcp_info->daddr = sk->__sk_common.skc_daddr;
	tcp_info->sport = sk->__sk_common.skc_num;
	tcp_info->dport = bpf_ntohs(sk->__sk_common.skc_dport);

	tcp_info->srtt = (ts->srtt_us >> 3) / 1000;
	tcp_info->total_retrans = ts->total_retrans;

	bpf_ringbuf_submit(tcp_info, 0);

	return 0;
}
