package utils

import (
	"bytes"
	"encoding/binary"
)

type MpInt struct {
	Length uint32
	Number []byte
}

func (n *MpInt) Marshal() []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, n.Length)
	buf.Write(n.Number)
	return buf.Bytes()
}

func EncodeMpint(s []byte) *MpInt {
	l := uint32(len(s))
	n := make([]byte, l)

	copy(n, s)

	if n[0] >= 0x10 {
		n = append([]byte{0x00}, n...)
	}

	return &MpInt{l, n}
}
