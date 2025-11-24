package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/alext-uni/sushi-ssh/kex"
	"github.com/alext-uni/sushi-ssh/ssh"
	"github.com/alext-uni/sushi-ssh/utils"
)

func main() {
	fmt.Println("🍣 Bienvenido al proyecto Sushi!")
	port := flag.Int("p", 22, "Puerto (opcional)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Uso programa: usuario@host")
		os.Exit(1)
	}

	target := flag.Arg(0)
	parts := strings.Split(target, "@")
	if len(parts) != 2 {
		fmt.Println("Uso programa: usuario@host")
		os.Exit(1)
	}

	//user := parts[0]
	host := parts[1]

	address := fmt.Sprintf("%s:%d", host, *port)
	fmt.Println(address)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	kexState := kex.KexState{}
	version := "SSH-2.0-SUSHI"
	fmt.Println("CLIENTE: ", version)

	fmt.Fprint(conn, version+"\r\n")

	serverVersion, _ := bufio.NewReader(conn).ReadString('\n')
	serverVersion = strings.ReplaceAll(serverVersion, "\r\n", "")

	fmt.Println("SERVIDOR:", serverVersion)

	kexState.ClientVersion = []byte(version)
	kexState.ServerVersion = []byte(serverVersion)

	fmt.Println("CLIENTE: SSH_MSG_KEXINIT")

	var c [16]byte
	rand.Read(c[:])

	ckinit := &kex.KexInit{
		MessageCode:                20,
		Cookie:                     c,
		KexAlgos:                   ssh.NameList{"curve25519-sha256"},
		ServerHostKeyAlgos:         ssh.NameList{"ssh-ed25519"},
		EncryptionClientToServer:   ssh.NameList{"aes128-ctr"},
		EncryptionServerToClient:   ssh.NameList{"aes128-ctr"},
		MacClientToServer:          ssh.NameList{"hmac-sha2-256"},
		MacServerToClient:          ssh.NameList{"hmac-sha2-256"},
		CompressionClientToServer:  ssh.NameList{"none"},
		CompressionServertToClient: ssh.NameList{"none"},
		LanguagesClientToServer:    ssh.NameList{},
		LanguagesServerToClient:    ssh.NameList{},
		FirstKexPacketFollows:      false,
		EmptyField:                 0,
	}

	m := ssh.NewSshMessage(ckinit.Marshal(), 8)

	mBytes := m.Marshal()
	err = ssh.SendMessage(conn, mBytes)
	if err != nil {
		panic(err)
	}

	fmt.Println("SERVIDOR: SSH_MSH_KEXINIT ")
	serverKexInitMsg, err := ssh.ReadNextMessage(conn, 0)
	if err != nil {
		panic(err)
	}
	payload := serverKexInitMsg.Payload
	skinit, _ := kex.UnmarshalKexInit(payload)

	kexState.ClientKexInit = ckinit.Marshal()
	kexState.ServerKexInit = skinit.Marshal()

	fmt.Println("ALGORITMO KEX SELECIONADOS: ")
	algs := kex.ResoleveAlgos(ckinit, skinit)
	utils.PrettyPrint(algs)

	fmt.Println("CLIENT: SSH_MSG_KEX_ECDH_INIT")
	privECDH, err := ecdh.X25519().GenerateKey(rand.Reader)
	Qc := privECDH.PublicKey().Bytes()

	keylen := uint32(len(Qc))
	kexPayload := []byte{30}
	kexPayload = append(kexPayload,
		byte(keylen>>24),
		byte(keylen>>16),
		byte(keylen>>8),
		byte(keylen),
	)
	kexPayload = append(kexPayload, Qc...)

	kexMsg := ssh.NewSshMessage(kexPayload, 8)
	err = ssh.SendMessage(conn, kexMsg.Marshal())
	if err != nil {
		panic(err)
	}
	fmt.Println("SERVER: SSH_MSG_KEX_ECDH_REPLY")
	serverKexMsg, err := ssh.ReadNextMessage(conn, 0)
	if err != nil {
		panic(err)
	}
	payload = serverKexMsg.Payload

	b := bytes.NewBuffer(payload)

	serverKeys, err := kex.ReadKeyExchangeReply(b)
	if err != nil {
		panic(err)
	}
	utils.PrettyPrint(serverKeys)

	Qs, err := privECDH.Curve().NewPublicKey(serverKeys.Qs)
	if err != nil {
		panic(err)
	}

	kexState.ServerHostKey = serverKeys.EdDSApub
	kexState.ClientEphemeral = privECDH
	kexState.ServerEphemeral = Qs

	fmt.Println("SERVER: SSH_MSG_NEW_KEYS")
	serverNewKeys, err := ssh.ReadNextMessage(conn, 0)
	if err != nil {
		panic(err)
	}
	b = bytes.NewBuffer(serverNewKeys.Payload)
	if err = kex.ReadNewKeys(b); err != nil {
		panic(err)
	}

	fmt.Println("CLIENT: SSH_MSG_NEW_KEYS")
	clientNewKeys := ssh.NewSshMessage([]byte{21}, 8)
	err = ssh.SendMessage(conn, clientNewKeys.Marshal())
	if err != nil {
		panic(err)
	}

	ConnState, err := kex.DerivateConnState(&kexState)
	if err != nil {
		panic(err)
	}
	utils.PrettyPrint(ConnState)

	block, err := aes.NewCipher(ConnState.KeyClientToServer)
	if err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, ConnState.IVClientToServer)
	ciphexCtx := &ssh.CipherContext{
		conn,
		stream,
		ConnState.MACClientToServer,
		3,
	}

	incoming := make(chan []byte, 20)
	defer close(incoming)
	var wg sync.WaitGroup
	ssh.StartCipherWriter(&wg, ciphexCtx, incoming)

	b = bytes.NewBuffer([]byte{})
	b.Write([]byte{5})

	incoming <- b.Bytes()
	wg.Wait()
}
