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

var (
	estats_db *db
)

func init() {
	estats_db = NewDB()
}

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

	// Start your engines
	go readLoop[tcp_estats.GlobalVar](global_rd)
	go readLoop[tcp_estats.ConnectionVar](conn_rd)
	go readLoop[tcp_estats.PerfVar](perf_rd)
	go readLoop[tcp_estats.PathVar](path_rd)
	go readLoop[tcp_estats.StackVar](stack_rd)
	go readLoop[tcp_estats.AppVar](app_rd)
	go readLoop[tcp_estats.ExtrasVar](extras_rd)

	<-stopper

	log.Printf("%s", estats_db)
}

func readLoop[V tcp_estats.Vars](rd *ringbuf.Reader) {
	var entry tcp_estats.Entry
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			continue
		}

		// parse to structure
		if err := binary.Read(bytes.NewBuffer(record.RawSample), endian.Native, &entry); err != nil {
			log.Printf("parsing entry: %v", err)
			continue
		}

		// log.Printf("read %+v", entry)

		v := V(entry.Var)

		// There might be a way to get away with a RLock here followed
		// by a Lock in the unlikely case we need to insert, but just taking
		// the more expensive lock is easier.
		estats_db.Lock()

		e, ok := estats_db.m[entry.Key]
		if !ok {
			e = tcp_estats.New()
			estats_db.m[entry.Key] = e
		}
		estats_db.Unlock()

		// FIXME: this is really ugly. we shouldn't need to cast here.
		t := e.GetTableForVar(v).(*tcp_estats.Table[V])
		t.RLock()
		defer t.RUnlock()

		switch entry.Op {
		case tcp_estats.OPERATION_SET:
			log.Printf(" . setting %v to %d", v, entry.Val)
			t.M[v] = entry.Val
		case tcp_estats.OPERATION_ADD:
			log.Printf(" . adding %v to %d", v, entry.Val)
			t.M[v] += entry.Val
		case tcp_estats.OPERATION_SUB:
			log.Printf(" . subtracting %d from %v", entry.Val, v)
			t.M[v] -= entry.Val
		case tcp_estats.OPERATION_INC:
			log.Printf(" . incrementing %v", v)
			t.M[v] += 1
		case tcp_estats.OPERATION_DEC:
			log.Printf(" . decrementing %v", v)
			t.M[v] -= 1
		}
	}
}

func intToIP(num uint32) net.IP {
	ip := make(net.IP, 4)
	endian.Native.PutUint32(ip, num)
	return ip
}
