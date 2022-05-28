package tcp_estats

import (
	"net"
	"testing"
)

func TestIntToIP(t *testing.T) {
	got := intToIP(16777343)
	want := net.IPv4(127, 0, 0, 1).To4()

	if !net.IP.Equal(got, want) {
		t.Errorf("want %q got %q", want, got)
	}
}

func TestIPToInt(t *testing.T) {
	got := ipToInt(net.IPv4(127, 0, 0, 1))
	want := uint32(16777343)

	if got != want {
		t.Errorf("want %d got %d", want, got)
	}
}
