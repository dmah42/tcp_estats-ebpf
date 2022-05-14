#ifndef TCP_ESTATS_TCP_H
#define TCP_ESTATS_TCP_H

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

#endif  // TCP_ESTATS_TCP_H
