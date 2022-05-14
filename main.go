//go:build linux
// +build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --strip llvm-strip-12 --cflags "-Wall -Werror -O1 -I." tcpestats probe/tcp_estats.c

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
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
	tcpEstatsCreateActive, err := link.AttachTracing(link.TracingOptions{
		Program: objs.tcpestatsPrograms.TcpEstatsCreateActive,
	})
	if err != nil {
		log.Fatalf("attaching tracing: %v", err)
	}
	defer tcpEstatsCreateActive.Close()

	tcpEstatsCreateInactive, err := link.AttachTracing(link.TracingOptions{
		Program: objs.tcpestatsPrograms.TcpEstatsCreateInactive,
	})
	if err != nil {
		log.Fatalf("attaching tracing: %v", err)
	}
	defer tcpEstatsCreateInactive.Close()

	tcpEstatsUpdateSegrecv, err := link.AttachTracing(link.TracingOptions{
		Program: objs.tcpestatsPrograms.TcpEstatsUpdateSegrecv,
	})
	if err != nil {
		log.Fatalf("attaching tracing: %v", err)
	}
	defer tcpEstatsUpdateSegrecv.Close()

	tcpEstatsUpdateFinishSegrecv, err := link.AttachTracing(link.TracingOptions{
		Program: objs.tcpestatsPrograms.TcpEstatsUpdateFinishSegrecv,
	})
	if err != nil {
		log.Fatalf("attaching tracing: %v", err)
	}
	defer tcpEstatsUpdateFinishSegrecv.Close()

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
	log.Println("starting read loops..")
	go readLoop[tcp_estats.GlobalVar](global_rd)
	go readLoop[tcp_estats.ConnectionVar](conn_rd)
	go readLoop[tcp_estats.PerfVar](perf_rd)
	go readLoop[tcp_estats.PathVar](path_rd)
	go readLoop[tcp_estats.StackVar](stack_rd)
	go readLoop[tcp_estats.AppVar](app_rd)
	go readLoop[tcp_estats.ExtrasVar](extras_rd)

	<-stopper

	log.Println(".. stopped read loops")
	fmt.Printf("%s", estats_db)
}

func readLoop[V tcp_estats.Vars](rd *ringbuf.Reader) {
	var entry tcp_estats.Entry
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting loop..")
				return
			}
			continue
		}

		// parse to structure
		if err := binary.Read(bytes.NewBuffer(record.RawSample), endian.Native, &entry); err != nil {
			//log.Printf("parsing entry: %v", err)
			continue
		}

		//log.Printf("read %+v", entry)

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

		tcp_estats.DoOp[V](e, entry)
	}
}
