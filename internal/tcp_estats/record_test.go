package tcp_estats

import (
	"net"
	"testing"
)

func TestString(t *testing.T) {
	got := Record{
		PidTgid: 12345,
		Saddr:   ipToInt(net.IPv4(127, 0, 0, 1).To4()),
		Daddr:   ipToInt(net.IPv4(239, 192, 0, 1).To4()),
		Sport:   8080,
		Dport:   1248,
		Op:      OPERATION_MIN,
		Var:     uint32(PERF_TABLE_DATAOCTETSIN),
		Val:     42,
	}.String()

	want := "[P: 12345, S: 127.0.0.1:8080, D: 239.192.0.1:1248]: OPERATION_MIN on 7 with 42"

	if got != want {
		t.Errorf("want %q got %q", want, got)
	}
}
