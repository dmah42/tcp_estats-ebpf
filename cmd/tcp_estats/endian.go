package main

import (
	"encoding/binary"
	"unsafe"
)

var Native binary.ByteOrder

func init() {
	if isBigEndian() {
		Native = binary.BigEndian
	} else {
		Native = binary.LittleEndian
	}
}

func isBigEndian() (ret bool) {
	i := int(0x1)
	bs := (*[int(unsafe.Sizeof(i))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0
}
