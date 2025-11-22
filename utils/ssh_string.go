package utils

import (
	"bytes"
	"encoding/binary"
	"io"
)

type SshString struct {
	Length  uint32
	Payload []byte
}

func (s *SshString) String() string {
	return string(s.Payload)
}

func (s *SshString) Marshal() []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, s.Length)
	buf.Write(s.Payload)
	return buf.Bytes()
}

func ReadSshString(b *bytes.Buffer) (*SshString, error) {
	var l uint32
	if err := binary.Read(b, binary.BigEndian, &l); err != nil {
		return nil, err
	}
	s := make([]byte, l)

	_, err := io.ReadFull(b, s)
	if err != nil {
		return nil, err
	}

	return &SshString{l, s}, nil
}
