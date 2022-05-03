//go:build linux
// +build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --strip llvm-strip-12 --cflags "-Wall -Werror" tcpestats tcp_estats.c

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"tcp_estats-ebpf/endian"
	"tcp_estats-ebpf/tcp_estats"
)

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("locking memory: %v", err)
	}

	// load pre-compiled programs into the kernel
	objs := tcpestatsObjects{}
	if err := loadTcpestatsObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// TODO: how to attach to multiple points
	link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.tcpestatsPrograms.TcpInitSock,
	})
	if err != nil {
		log.Fatalf("attaching tracing: %v", err)
	}
	defer link.Close()

	rd, err := ringbuf.NewReader(objs.tcpestatsMaps.Entries)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	estats := tcp_estats.Estats{}

	formatStr := "%-15s %-6s -> %-15s %-6s [%-6s %-8s]"
	log.Printf(formatStr, "src", "sport", "dest", "dport", "rtt", "retrans")

	go readLoop(rd, &estats)

	<-stopper
}

// Mirror of `entry` in tcp_estats.c
type key struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

type entry struct {
	Key key
	Op  tcp_estats.Operation
	Var tcp_estats.Variable
	Val uint32
}

func readLoop(rd *ringbuf.Reader, t *tcp_estats.Estats) {
	var entry entry
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from ringbuf: %v", err)
			continue
		}

		// parse to structure
		if err := binary.Read(bytes.NewBuffer(record.RawSample), endian.Native, &entry); err != nil {
			log.Printf("parsing sample: %v", err)
			continue
		}

		formatStr := "%-15s %-6d -> %-15s %-6d [%-6d %-6d]"
		log.Printf(formatStr, intToIP(entry.Key.Saddr), entry.Key.Sport, intToIP(entry.Key.Daddr), entry.Key.Dport)
		log.Printf("%+v", entry)
	}
}

func intToIP(num uint32) net.IP {
	ip := make(net.IP, 4)
	endian.Native.PutUint32(ip, num)
	return ip
}
