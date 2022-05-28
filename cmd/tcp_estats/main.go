//go:build linux
// +build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --strip llvm-strip-12 --cflags "-Wall -Werror -O1 -I../.." tcp_estats ../../probe/tcp_estats.c

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var (
	estats_db *db
)

func init() {
	estats_db = NewDB()
}

func main() {
	flag.Parse()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("locking memory: %v", err)
	}

	// load pre-compiled programs into the kernel
	objs := tcp_estatsObjects{}
	if err := loadTcp_estatsObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Create program links
	tcpEstatsCreateActive, err := link.AttachTracing(link.TracingOptions{
		Program: objs.tcp_estatsPrograms.TcpEstatsCreateActive,
	})
	if err != nil {
		log.Fatalf("attaching tracing: %v", err)
	}
	defer tcpEstatsCreateActive.Close()

	tcpEstatsCreateInactive, err := link.AttachTracing(link.TracingOptions{
		Program: objs.tcp_estatsPrograms.TcpEstatsCreateInactive,
	})
	if err != nil {
		log.Fatalf("attaching tracing: %v", err)
	}
	defer tcpEstatsCreateInactive.Close()

	tcpEstatsUpdateSegrecv, err := link.AttachTracing(link.TracingOptions{
		Program: objs.tcp_estatsPrograms.TcpEstatsUpdateSegrecv,
	})
	if err != nil {
		log.Fatalf("attaching tracing: %v", err)
	}
	defer tcpEstatsUpdateSegrecv.Close()

	tcpEstatsUpdateFinishSegrecv, err := link.AttachTracing(link.TracingOptions{
		Program: objs.tcp_estatsPrograms.TcpEstatsUpdateFinishSegrecv,
	})
	if err != nil {
		log.Fatalf("attaching tracing: %v", err)
	}
	defer tcpEstatsUpdateFinishSegrecv.Close()

	// Create ring buffers
	global_rd, err := ringbuf.NewReader(objs.tcp_estatsMaps.GlobalTable)
	if err != nil {
		log.Fatalf("opening global table reader: %v", err)
	}
	defer global_rd.Close()

	conn_rd, err := ringbuf.NewReader(objs.tcp_estatsMaps.ConnectionTable)
	if err != nil {
		log.Fatalf("opening connection table reader: %v", err)
	}
	defer conn_rd.Close()

	perf_rd, err := ringbuf.NewReader(objs.tcp_estatsMaps.PerfTable)
	if err != nil {
		log.Fatalf("opening perf table reader: %v", err)
	}
	defer perf_rd.Close()

	path_rd, err := ringbuf.NewReader(objs.tcp_estatsMaps.PathTable)
	if err != nil {
		log.Fatalf("opening path table reader: %v", err)
	}
	defer path_rd.Close()

	stack_rd, err := ringbuf.NewReader(objs.tcp_estatsMaps.StackTable)
	if err != nil {
		log.Fatalf("opening stack table reader: %v", err)
	}
	defer stack_rd.Close()

	app_rd, err := ringbuf.NewReader(objs.tcp_estatsMaps.AppTable)
	if err != nil {
		log.Fatalf("opening app table reader: %v", err)
	}
	defer app_rd.Close()

	extras_rd, err := ringbuf.NewReader(objs.tcp_estatsMaps.ExtrasTable)
	if err != nil {
		log.Fatalf("opening extras table reader: %v", err)
	}
	defer extras_rd.Close()

	// Start your engines
	log.Println("starting read loops..")
	go readLoop[GlobalVar](global_rd)
	go readLoop[ConnectionVar](conn_rd)
	go readLoop[PerfVar](perf_rd)
	go readLoop[PathVar](path_rd)
	go readLoop[StackVar](stack_rd)
	go readLoop[AppVar](app_rd)
	go readLoop[ExtrasVar](extras_rd)

	<-stopper

	log.Println(".. stopped read loops")
	fmt.Printf("%s", estats_db)
}

func readLoop[V Vars](rd *ringbuf.Reader) {
	var record Record
	for {
		item, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				// log.Println("received signal, exiting loop..")
				return
			}
			continue
		}

		// parse to structure
		if err := binary.Read(bytes.NewBuffer(item.RawSample), Native, &record); err != nil {
			//log.Printf("parsing entry: %v", err)
			continue
		}

		// There might be a way to get away with a RLock here followed
		// by a Lock in the unlikely case we need to insert, but just taking
		// the more expensive lock is easier.
		estats_db.Lock()

		k := key{
			PidTgid: record.PidTgid,
			Saddr:   record.Saddr,
			Daddr:   record.Daddr,
			Sport:   record.Sport,
			Dport:   record.Dport,
		}

		e, ok := estats_db.m[k]
		if !ok {
			e = NewEstats()
			estats_db.m[k] = e
		}
		estats_db.Unlock()

		DoOp[V](e, record.Op, V(record.Var), record.Val)
	}
}
