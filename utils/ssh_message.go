package utils

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	buf := &bytes.Buffer{}

	binary.Write(buf, binary.BigEndian, m.PacketLength)

	buf.WriteByte(m.PaddingLength)

	buf.Write(m.Payload)
	buf.Write(m.Padding)
	buf.Write(m.MAC)

	return buf.Bytes()
}

func NewSSHMessage(payload, mac []byte, blockSize int) *SSHMessage {
	paylen := len(payload)
	padlen := 4
	packlen := paylen + padlen + 1

	resto := (packlen + 4) % blockSize

	padlen = padlen + blockSize - resto

	packlen = paylen + padlen + 1

	resto = (packlen + 4) % blockSize

	pad := make([]byte, padlen)

	assert := len(payload) + len(pad) + 1 + 4

	if assert%blockSize != 0 {
		panic("Largo paquete incorrecto")
	}

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
	totalBytes := 0
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
	totalBytes += 1

	payloadlen := int(packlen) - int(padlen) - 1
	if payloadlen < 0 {
		return nil, fmt.Errorf("invalid payload length")
	}

	payload := make([]byte, payloadlen)
	n := 0
	n, err := io.ReadFull(conn, payload)
	if err != nil {
		return nil, err
	}
	totalBytes += n

	padding := make([]byte, padlen)
	n, err = io.ReadFull(conn, padding)
	if err != nil {
		return nil, err
	}
	totalBytes += n

	mac := make([]byte, maclen)
	n, err = io.ReadFull(conn, mac)
	if err != nil {
		return nil, err
	}
	totalBytes += n

	if totalBytes != int(packlen) {
		return nil, errors.New("Mensaje mal leido")
	}

	return &SSHMessage{
		PacketLength:  packlen,
		PaddingLength: padlen,
		Payload:       payload,
		Padding:       padding,
		MAC:           mac,
	}, nil
}
