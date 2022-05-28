package main

import (
	"fmt"
	"sync"
)

// Extracted from Record
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

type db struct {
	sync.RWMutex
	m map[key]*Estats
}

func NewDB() *db {
	db := new(db)
	db.Lock()
	db.m = make(map[key]*Estats)
	db.Unlock()
	return db
}

// TODO: json export something like this:
/*
	[
		{
			"saddrport": "",
			"daddrport": "",
			"tables": {
				"global": {
					"var": x,
					"var2": x,
					...
				},
				...
			}
		}
	]
*/

func (db *db) String() string {
	db.RLock()
	defer db.RUnlock()

	s := "-+= DB =+-\n"

	for key, stats := range db.m {
		s += fmt.Sprintf("%s\n%s\n", key, stats)
	}

	return s
}
