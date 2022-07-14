package tcp_estats

import (
	"encoding/binary"
	"unsafe"
)

var native binary.ByteOrder

func init() {
	if isBigEndian() {
		native = binary.BigEndian
	} else {
		native = binary.LittleEndian
	}
}

func isBigEndian() (ret bool) {
	i := int(0x1)
	bs := (*[int(unsafe.Sizeof(i))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0
}
