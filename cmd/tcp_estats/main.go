//go:build linux
// +build linux

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"tcp_estats-ebpf/internal/tcp_estats"
	"time"
)

var (
	runDuration = flag.Duration("runFor", time.Second*30, "the time for which to run the probe")
)

func main() {
	flag.Parse()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	tcpEstats, err := tcp_estats.New()
	if err != nil {
		log.Fatal(err)
	}

	go tcpEstats.Run()

	timeout := make(chan bool)
	go func() {
		<-time.After(*runDuration)
		timeout <- true
	}()

	select {
	case <-timeout:
	case <-stopper:
		if err := tcpEstats.Close(); err != nil {
			log.Fatal(err)
		}
		dump, err := tcpEstats.Dump()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", dump)
	}
}
