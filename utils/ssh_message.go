package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const MIN_PAD_LEN = 4

type SSHMessage struct {
	PacketLength  uint32
	PaddingLength byte
	Payload       []byte
	Padding       []byte
	MAC           []byte
}

func (m *SSHMessage) Marshal() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, m.PacketLength)

	buf.WriteByte(m.PaddingLength)

	buf.Write(m.Payload)
	buf.Write(m.Padding)
	buf.Write(m.MAC)

	return buf.Bytes()
}

func NewSSHMessage(payload, mac []byte, blockSize int) *SSHMessage {
	packlen := len(payload) + 1 + MIN_PAD_LEN
	r := packlen % blockSize

	extrapad := blockSize - r
	packlen += extrapad

	padlen := MIN_PAD_LEN + extrapad

	pad := make([]byte, padlen)
	rand.Read(pad[:])

	return &SSHMessage{
		uint32(packlen),
		byte(padlen),
		payload,
		pad,
		mac,
	}
}

func SendMessage(conn net.Conn, data []byte) error {
	n, err := conn.Write(data)
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("short write: %d/%d", n, len(data))
	}
	return nil
}

func ReadNextMessage(conn io.Reader, maclen int) (*SSHMessage, error) {
	var packlen uint32
	if err := binary.Read(conn, binary.BigEndian, &packlen); err != nil {
		return nil, err
	}

	if packlen < 1 || packlen > 35000 {
		return nil, fmt.Errorf("invalid packet length")
	}

	var padlen byte
	if err := binary.Read(conn, binary.BigEndian, &padlen); err != nil {
		return nil, err
	}

	payloadlen := int(packlen) - int(padlen) - 1
	if payloadlen < 0 {
		return nil, fmt.Errorf("invalid payload length")
	}

	payload := make([]byte, payloadlen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	padding := make([]byte, padlen)
	if _, err := io.ReadFull(conn, padding); err != nil {
		return nil, err
	}

	mac := make([]byte, maclen)
	if _, err := io.ReadFull(conn, mac); err != nil {
		return nil, err
	}

	return &SSHMessage{
		PacketLength:  packlen,
		PaddingLength: padlen,
		Payload:       payload,
		Padding:       padding,
		MAC:           mac,
	}, nil
}
