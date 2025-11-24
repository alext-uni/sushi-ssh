package kex

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"

	"github.com/alext-uni/sushi-ssh/ssh"
)

func DerivateConnState(ks *KexState) (*ssh.ConnectionState, error) {
	K, err := DerivateShareSecret(ks.ClientEphemeral, ks.ServerEphemeral)
	if err != nil {
		return nil, err
	}

	H := DerivateExchangeHash(K, ks)

	id := make([]byte, len(H))
	copy(id, H)

	fmt.Printf("Hash: [% x]\n", H)
	return &ssh.ConnectionState{
		ClientVersion:     ks.ClientVersion,
		ServerVersion:     ks.ServerVersion,
		ClientKexInit:     ks.ClientKexInit,
		ServerKexInit:     ks.ServerKexInit,
		ServerHostKey:     ks.ServerHostKey,
		ClientEphemeral:   ks.ClientEphemeral,
		ServerEphemeral:   ks.ServerEphemeral,
		SharedSecret:      K,
		ExchangeHash:      H,
		SessionId:         id,
		IVClientToServer:  deriveKey(K, H, id, 'A', 16),
		IVServerToClient:  deriveKey(K, H, id, 'B', 16),
		KeyClientToServer: deriveKey(K, H, id, 'C', 16),
		KeyServerToClient: deriveKey(K, H, id, 'D', 16),
		MACClientToServer: deriveKey(K, H, id, 'E', 32),
		MACServerToClient: deriveKey(K, H, id, 'F', 32),
	}, nil
}

func DerivateShareSecret(clientPriv *ecdh.PrivateKey, serverPub *ecdh.PublicKey) ([]byte, error) {
	K, err := clientPriv.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Shared Secret: [% x]\n", K)
	return K, nil
}

func DerivateExchangeHash(k []byte, s *KexState) []byte {
	cv := ssh.EncodeSshString(s.ClientVersion).Marshal()
	sv := ssh.EncodeSshString(s.ServerVersion).Marshal()

	cInit := ssh.EncodeSshString(s.ClientKexInit).Marshal()
	sInit := ssh.EncodeSshString(s.ServerKexInit).Marshal()

	shk := ssh.EncodeSshString(s.ServerHostKey).Marshal()

	Qc := ssh.EncodeSshString(s.ClientEphemeral.Bytes()).Marshal()
	Qs := ssh.EncodeSshString(s.ServerEphemeral.Bytes()).Marshal()

	K := ssh.EncodeMpint(k).Marshal()

	blob := make([]byte, 0)
	blob = append(blob, cv...)
	blob = append(blob, sv...)
	blob = append(blob, cInit...)
	blob = append(blob, sInit...)
	blob = append(blob, shk...)
	blob = append(blob, Qc...)
	blob = append(blob, Qs...)
	blob = append(blob, K...)

	h := sha256.Sum256(blob)
	return h[:]
}

func deriveKey(K, H, sessionId []byte, label byte, length int) []byte {
	k := ssh.EncodeMpint(K).Marshal()

	var out []byte
	previous := []byte{}

	for len(out) < length {
		h := sha256.New()
		h.Write(k)
		h.Write(H)

		if len(out) == 0 {
			h.Write([]byte{label})
		} else {
			h.Write(previous)
		}

		h.Write(sessionId)

		previous = h.Sum(nil)
		out = append(out, previous...)
	}

	return out[:length]
}
