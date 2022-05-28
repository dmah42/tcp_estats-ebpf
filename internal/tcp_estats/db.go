package tcp_estats

import (
	"encoding/json"
	"fmt"
	"sync"
)

// Extracted from Record
type Key struct {
	PidTgid uint64
	Saddr   uint32
	Daddr   uint32
	Sport   uint16
	Dport   uint16
}

func (k Key) String() string {
	return fmt.Sprintf("[P: %d, S: %s:%d, D: %s:%d]", k.PidTgid, intToIP(k.Saddr), k.Sport, intToIP(k.Daddr), k.Dport)
}

type DB struct {
	sync.RWMutex
	M map[Key]*Estats
}

func NewDB() *DB {
	db := new(DB)
	db.Lock()
	db.M = make(map[Key]*Estats)
	db.Unlock()
	return db
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

	for k, estats := range d.M {
		ex = append(ex, export{
			Saddr:  fmt.Sprintf("%s:%d", intToIP(k.Saddr), k.Sport),
			Daddr:  fmt.Sprintf("%s:%d", intToIP(k.Daddr), k.Dport),
			Tables: *estats,
		})
	}
	return json.Marshal(ex)
}
