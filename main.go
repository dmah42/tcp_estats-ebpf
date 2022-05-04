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

	initSockLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.tcpestatsPrograms.TcpInitSock,
	})
	if err != nil {
		log.Fatalf("attaching init sock tracing: %v", err)
	}
	defer initSockLink.Close()

	createOpenreqChildLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TcpCreateOpenreqChild,
	})
	if err != nil {
		log.Fatalf("attaching create openreq child tracing: %v", err)
	}
	defer createOpenreqChildLink.Close()

	global_rd, err := ringbuf.NewReader(objs.tcpestatsMaps.GlobalTable)
	if err != nil {
		log.Fatalf("opening global table reader: %v", err)
	}
	defer global_rd.Close()

	conn_rd, err := ringbuf.NewReader(objs.tcpestatsMaps.ConnectionTable)
	if err != nil {
		log.Fatalf("opening connection table reader: %v", err)
	}
	defer conn_rd.Close()

	estats := tcp_estats.New()

	//	go readLoop[tcp_estats.GlobalVar](global_rd, &estats.Tables.GlobalTable)
	//	go readLoop[tcp_estats.ConnectionVar](conn_rd, &estats.Tables.ConnectionTable)
	go readLoop(global_rd, estats.Tables.GlobalTable)
	go readLoop(conn_rd, estats.Tables.ConnectionTable)

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
	Var uint32
	Val uint32
}

type Vars interface {
	tcp_estats.GlobalVar | tcp_estats.ConnectionVar
}

func readLoop[V Vars](rd *ringbuf.Reader, m map[V]uint32) {
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
			log.Printf("parsing entry: %v", err)
			continue
		}

		log.Printf("read %+v", entry)

		v := V(entry.Var)

		switch entry.Op {
		case tcp_estats.OPERATION_SET:
			m[v] = entry.Val
		case tcp_estats.OPERATION_ADD:
			m[v] += entry.Val
		case tcp_estats.OPERATION_SUB:
			m[v] -= entry.Val
		case tcp_estats.OPERATION_INC:
			m[v] += 1
		case tcp_estats.OPERATION_DEC:
			m[v] -= 1
		}
	}
}

func intToIP(num uint32) net.IP {
	ip := make(net.IP, 4)
	endian.Native.PutUint32(ip, num)
	return ip
}
