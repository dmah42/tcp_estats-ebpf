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

	// Create program links
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

	// Create ring buffers
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

	perf_rd, err := ringbuf.NewReader(objs.tcpestatsMaps.PerfTable)
	if err != nil {
		log.Fatalf("opening perf table reader: %v", err)
	}
	defer perf_rd.Close()

	path_rd, err := ringbuf.NewReader(objs.tcpestatsMaps.PathTable)
	if err != nil {
		log.Fatalf("opening path table reader: %v", err)
	}
	defer path_rd.Close()

	stack_rd, err := ringbuf.NewReader(objs.tcpestatsMaps.StackTable)
	if err != nil {
		log.Fatalf("opening stack table reader: %v", err)
	}
	defer stack_rd.Close()

	app_rd, err := ringbuf.NewReader(objs.tcpestatsMaps.AppTable)
	if err != nil {
		log.Fatalf("opening app table reader: %v", err)
	}
	defer app_rd.Close()

	extras_rd, err := ringbuf.NewReader(objs.tcpestatsMaps.ExtrasTable)
	if err != nil {
		log.Fatalf("opening extras table reader: %v", err)
	}
	defer extras_rd.Close()

	estats := tcp_estats.New()

	// Start your engines
	go readLoop(global_rd, estats.Tables.GlobalTable)
	go readLoop(conn_rd, estats.Tables.ConnectionTable)
	go readLoop(perf_rd, estats.Tables.PerfTable)
	go readLoop(path_rd, estats.Tables.PathTable)
	go readLoop(stack_rd, estats.Tables.StackTable)
	go readLoop(app_rd, estats.Tables.AppTable)
	go readLoop(extras_rd, estats.Tables.ExtrasTable)

	<-stopper
}

type Vars interface {
	tcp_estats.GlobalVar | tcp_estats.ConnectionVar | tcp_estats.PerfVar |
		tcp_estats.PathVar | tcp_estats.StackVar | tcp_estats.AppVar |
		tcp_estats.ExtrasVar
}

func readLoop[V Vars](rd *ringbuf.Reader, m map[V]uint32) {
	var entry tcp_estats.Entry
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
			log.Printf(" . setting %v to %d", v, entry.Val)
			m[v] = entry.Val
		case tcp_estats.OPERATION_ADD:
			log.Printf(" . adding %v to %d", v, entry.Val)
			m[v] += entry.Val
		case tcp_estats.OPERATION_SUB:
			log.Printf(" . subtracting %d from %v", entry.Val, v)
			m[v] -= entry.Val
		case tcp_estats.OPERATION_INC:
			log.Printf(" . incrementing %v", v)
			m[v] += 1
		case tcp_estats.OPERATION_DEC:
			log.Printf(" . decrementing %v", v)
			m[v] -= 1
		}
	}
}

func intToIP(num uint32) net.IP {
	ip := make(net.IP, 4)
	endian.Native.PutUint32(ip, num)
	return ip
}
