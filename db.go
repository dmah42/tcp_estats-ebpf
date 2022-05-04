package main

import (
	"fmt"
	"sync"
	"tcp_estats-ebpf/tcp_estats"
)

type db struct {
	sync.RWMutex
	m map[tcp_estats.Key]*tcp_estats.Estats
}

func NewDB() *db {
	db := new(db)
	db.Lock()
	db.m = make(map[tcp_estats.Key]*tcp_estats.Estats)
	db.Unlock()
	return db
}

func (db *db) String() string {
	db.RLock()
	defer db.RUnlock()
	return fmt.Sprintf("%+v", db.m)
}