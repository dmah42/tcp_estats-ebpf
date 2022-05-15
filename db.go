package main

import (
	"fmt"
	"net"
	"sync"

	"tcp_estats-ebpf/endian"
	"tcp_estats-ebpf/tcp_estats"
)

// Extracted from tcp_estats.Record
type key struct {
	PidTgid uint64
	Saddr   uint32
	Daddr   uint32
	Sport   uint16
	Dport   uint16
}

func (k key) String() string {
	return fmt.Sprintf("[P: %d, S: %s:%d, D: %s:%d]", k.PidTgid, intToIP(k.Saddr), k.Sport, intToIP(k.Daddr), k.Dport)
}

func intToIP(num uint32) net.IP {
	ip := make(net.IP, 4)
	endian.Native.PutUint32(ip, num)
	return ip
}

type db struct {
	sync.RWMutex
	m map[key]*tcp_estats.Estats
}

func NewDB() *db {
	db := new(db)
	db.Lock()
	db.m = make(map[key]*tcp_estats.Estats)
	db.Unlock()
	return db
}

func (db *db) String() string {
	db.RLock()
	defer db.RUnlock()

	s := "-+= DB =+-\n"

	for key, stats := range db.m {
		s += fmt.Sprintf("%s\n%s\n", key, stats)
	}

	return s
}
