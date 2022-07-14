package tcp_estats

import "fmt"

// Mirror of `retord` in tcp_estats.h
type Record struct {
	PidTgid uint64
	Saddr   uint32
	Daddr   uint32
	Sport   uint16
	Dport   uint16
	Op      Operation
	Var     uint32
	Val     uint32
}

func (rec Record) String() string {
	return fmt.Sprintf("%s: %s on %d with %d",
		key{PidTgid: rec.PidTgid, Saddr: rec.Saddr, Sport: rec.Sport, Daddr: rec.Daddr, Dport: rec.Dport},
		rec.Op, rec.Var, rec.Val)
}
