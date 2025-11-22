package utils

import (
	"crypto/ecdh"
	"fmt"
)

func DerivateKeys(clientPriv *ecdh.PrivateKey, serverPub *ecdh.PublicKey) error {
	K, err := clientPriv.ECDH(serverPub)
	if err != nil {
		return err
	}
	fmt.Printf("Shared Secret: [% x]\n", K)
	return nil
}
