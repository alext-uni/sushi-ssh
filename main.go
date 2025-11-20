package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Juancodja/sushi-ssh/kex"
	"github.com/Juancodja/sushi-ssh/utils"
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

	version := "SSH-2.0-SUSHI"
	fmt.Println("CLIENTE: ", version)

	fmt.Fprint(conn, version+"\r\n")

	msg, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Println("SERVIDOR:", msg)

	var c [16]byte
	rand.Read(c[:])

	ckinit := &kex.KexInit{
		MessageCode:                20,
		Cookie:                     c,
		KexAlgos:                   utils.NameList{"curve25519-sha256"},
		ServerHostKeyAlgos:         utils.NameList{"ssh-ed25519"},
		EncryptionClientToServer:   utils.NameList{"aes128-ctr"},
		EncryptionServerToClient:   utils.NameList{"aes128-ctr"},
		MacClientToServer:          utils.NameList{"hmac-sha2-256"},
		MacServerToClient:          utils.NameList{"hmac-sha2-256"},
		CompressionClientToServer:  utils.NameList{"none"},
		CompressionServertToClient: utils.NameList{"none"},
		LanguagesClientToServer:    utils.NameList{},
		LanguagesServerToClient:    utils.NameList{},
		FirstKexPacketFollows:      false,
		EmptyField:                 0,
	}

	fmt.Println("CLIENTE: SSH_MSG_KEXINIT")
	//utils.PrettyPrint(ckinit)

	m := utils.NewSSHMessage(ckinit.Marshal(), []byte{}, 8)

	err = utils.SendMessage(conn, m.Marshal())
	if err != nil {
		panic(err)
	}

	serverKexInitMsg, err := utils.ReadNextMessage(conn, 0)
	if err != nil {
		panic(err)
	}
	payload := serverKexInitMsg.Payload
	skinit, _ := kex.UnmarshalKexInit(payload)

	fmt.Println("SERVIDOR: SSH_MSH_KEXINIT ")
	//utils.PrettyPrint(skinit)

	algs := kex.ResoleveAlgos(ckinit, skinit)
	fmt.Println("ALGORITMO KEX SELECIONADOS: ")
	utils.PrettyPrint(algs)

	Q, err := ecdh.X25519().GenerateKey(rand.Reader)
	Q_pub := Q.PublicKey().Bytes()

	keylen := uint32(len(Q_pub))
	kexPayload := []byte{30}
	kexPayload = append(kexPayload,
		byte(keylen>>24),
		byte(keylen>>16),
		byte(keylen>>8),
		byte(keylen),
	)
	kexPayload = append(kexPayload, Q_pub...)

	fmt.Println("CLIENT: SSH_MSG_KEX_ECDH_INIT")
	kexMsg := utils.NewSSHMessage(kexPayload, []byte{}, 8)
	utils.PrettyPrint(kexMsg)

	err = utils.SendMessage(conn, kexMsg.Marshal())
	if err != nil {
		panic(err)
	}
	serverKexMsg, err := utils.ReadNextMessage(conn, 0)
	if err != nil {
		panic(err)
	}
	payload = serverKexMsg.Payload

}
