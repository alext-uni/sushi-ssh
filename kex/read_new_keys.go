package kex

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/alext-uni/sushi-ssh/ssh"
)

type KeyExchangeReply struct {
	KeyType       []byte
	EdDSApub      []byte
	Qs            []byte
	SignatureType []byte
	Signature     []byte
}

func ReadKeyExchangeReply(b *bytes.Buffer) (*KeyExchangeReply, error) {
	messageType, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	if messageType != 31 {
		return nil, errors.New("codigo mensaje erroneo")
	}

	var hostKeyLen uint32
	if err := binary.Read(b, binary.BigEndian, &hostKeyLen); err != nil {
		return nil, err
	}

	hostKeyType, err := ssh.ReadSshString(b)
	if err != nil {
		return nil, err
	}

	edDSApub, err := ssh.ReadSshString(b)
	if err != nil {
		return nil, err
	}

	ecdhServerEphemeral, err := ssh.ReadSshString(b)
	if err != nil {
		return nil, err
	}

	var signatureLen uint32
	if err := binary.Read(b, binary.BigEndian, &signatureLen); err != nil {
		return nil, err
	}

	signatureType, err := ssh.ReadSshString(b)
	if err != nil {
		return nil, err
	}

	signDataLen := int(signatureLen) - len(signatureType.String()) - 4
	signatureData := make([]byte, signDataLen)
	_, err = b.Read(signatureData)
	if err != nil {
		return nil, err
	}

	return &KeyExchangeReply{
		hostKeyType.Payload,
		edDSApub.Payload,
		ecdhServerEphemeral.Payload,
		signatureType.Payload,
		signatureData,
	}, nil
}

func ReadNewKeys(b *bytes.Buffer) error {
	messageType, err := b.ReadByte()
	if err != nil {
		return err
	}
	if messageType != 21 {
		fmt.Println(messageType)
		return errors.New("codigo mensaje erroneo")
	}
	return nil
}
