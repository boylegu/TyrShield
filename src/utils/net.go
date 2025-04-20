package utils

import (
	"encoding/binary"
	"net"
)

func IntToIP(ip uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], ip)
	return net.IP(b[:]).String()
}
