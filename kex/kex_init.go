package kex

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/alext-uni/sushi-ssh/ssh"
)

type KexInit struct {
	MessageCode                byte
	Cookie                     [16]byte
	KexAlgos                   ssh.NameList
	ServerHostKeyAlgos         ssh.NameList
	EncryptionClientToServer   ssh.NameList
	EncryptionServerToClient   ssh.NameList
	MacClientToServer          ssh.NameList
	MacServerToClient          ssh.NameList
	CompressionClientToServer  ssh.NameList
	CompressionServertToClient ssh.NameList
	LanguagesClientToServer    ssh.NameList
	LanguagesServerToClient    ssh.NameList
	FirstKexPacketFollows      bool
	EmptyField                 uint32
}

func (m *KexInit) Marshal() []byte {
	buf := new(bytes.Buffer)

	buf.WriteByte(m.MessageCode)

	buf.Write(m.Cookie[:])

	buf.Write(m.KexAlgos.Marshal())
	buf.Write(m.ServerHostKeyAlgos.Marshal())
	buf.Write(m.EncryptionClientToServer.Marshal())
	buf.Write(m.EncryptionServerToClient.Marshal())
	buf.Write(m.MacClientToServer.Marshal())
	buf.Write(m.MacServerToClient.Marshal())
	buf.Write(m.CompressionClientToServer.Marshal())
	buf.Write(m.CompressionServertToClient.Marshal())
	buf.Write(m.LanguagesClientToServer.Marshal())
	buf.Write(m.LanguagesServerToClient.Marshal())

	if m.FirstKexPacketFollows {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}

	binary.Write(buf, binary.BigEndian, m.EmptyField)

	return buf.Bytes()
}

func UnmarshalKexInit(data []byte) (*KexInit, error) {
	length := len(data)

	if length < 106 {
		return nil, io.ErrUnexpectedEOF
	}

	mcode := data[0]
	var cookie [16]byte
	copy(cookie[:], data[1:17])

	n := 17
	nl0, shift, err := ssh.UnmarshalNamelist(data[n:])
	if err != nil {
		return nil, err
	}
	n += shift
	nl1, shift, err := ssh.UnmarshalNamelist(data[n:])
	if err != nil {
		return nil, err
	}
	n += shift
	nl2, shift, err := ssh.UnmarshalNamelist(data[n:])
	if err != nil {
		return nil, err
	}
	n += shift
	nl3, shift, err := ssh.UnmarshalNamelist(data[n:])
	if err != nil {
		return nil, err
	}
	n += shift
	nl4, shift, err := ssh.UnmarshalNamelist(data[n:])
	if err != nil {
		return nil, err
	}
	n += shift
	nl5, shift, err := ssh.UnmarshalNamelist(data[n:])
	if err != nil {
		return nil, err
	}
	n += shift
	nl6, shift, err := ssh.UnmarshalNamelist(data[n:])
	if err != nil {
		return nil, err
	}
	n += shift
	nl7, shift, err := ssh.UnmarshalNamelist(data[n:])
	if err != nil {
		return nil, err
	}
	n += shift
	nl8, shift, err := ssh.UnmarshalNamelist(data[n:])
	if err != nil {
		return nil, err
	}
	n += shift
	nl9, shift, err := ssh.UnmarshalNamelist(data[n:])
	if err != nil {
		return nil, err
	}
	n += shift

	b := data[n] != 1
	n += 1

	empty := uint32(0)

	return &KexInit{
		mcode,
		cookie,
		nl0,
		nl1,
		nl2,
		nl3,
		nl4,
		nl5,
		nl6,
		nl7,
		nl8,
		nl9,
		b,
		empty,
	}, nil
}

type Algos struct {
	Kex                       string
	ServerHostKey             string
	EncryptionClientToServer  string
	EncryptionServerToClient  string
	MacClientToServer         string
	MacServerToServer         string
	CompressionServerToClient string
	CompressionClientToServer string
	LanguagesClientToServer   string
	LanguagesServerToClient   string
}

func ResoleveAlgos(client, server *KexInit) *Algos {
	return &Algos{
		FindMatchAlg(client.KexAlgos, server.KexAlgos),
		FindMatchAlg(client.ServerHostKeyAlgos, server.ServerHostKeyAlgos),
		FindMatchAlg(client.EncryptionClientToServer, server.EncryptionClientToServer),
		FindMatchAlg(client.EncryptionServerToClient, server.EncryptionServerToClient),
		FindMatchAlg(client.MacClientToServer, server.MacClientToServer),
		FindMatchAlg(client.MacServerToClient, server.MacServerToClient),
		FindMatchAlg(client.CompressionClientToServer, server.CompressionClientToServer),
		FindMatchAlg(client.CompressionServertToClient, server.CompressionServertToClient),
		FindMatchAlg(client.LanguagesClientToServer, server.LanguagesClientToServer),
		FindMatchAlg(client.LanguagesServerToClient, server.LanguagesServerToClient),
	}
}

func FindMatchAlg(clientList, serverList ssh.NameList) string {
	for _, v1 := range clientList {
		for _, v2 := range serverList {
			if v2 == v1 {
				return v2
			}
		}
	}
	return ""
}
