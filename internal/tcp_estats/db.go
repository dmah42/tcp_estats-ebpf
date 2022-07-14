package tcp_estats

import (
	"encoding/json"
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

type DB struct {
	sync.RWMutex
	m map[key]*Estats
}

func newDB() *DB {
	db := DB{}
	db.Lock()
	db.m = make(map[key]*Estats)
	db.Unlock()
	return &db
}

type export struct {
	Saddr  string `json:"saddr"`
	Daddr  string `json:"daddr"`
	Tables Estats `json:"tables"`
}

func (d *DB) MarshalJSON() ([]byte, error) {
	d.Lock()
	defer d.Unlock()

	var ex []export

	for k, estats := range d.m {
		ex = append(ex, export{
			Saddr:  fmt.Sprintf("%s:%d", intToIP(k.Saddr), k.Sport),
			Daddr:  fmt.Sprintf("%s:%d", intToIP(k.Daddr), k.Dport),
			Tables: *estats,
		})
	}
	return json.Marshal(ex)
}
