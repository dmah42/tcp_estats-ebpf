#ifndef TCP_SOCK_H
#define TCP_SOCK_H

// struct tcp_sock is the kernel representation of a TCP socket.
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

  __u8 ecn_flags;

  // slow start and cong control
  __u32 snd_ssthresh;
  __u32 snd_cwnd;
  __u32 lost_out;
  __u32 sacked_out;

  __u32 total_retrans;
} __attribute__((preserve_access_index));

#endif // TCP_SOCK_H
