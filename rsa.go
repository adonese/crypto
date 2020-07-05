package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"crypto/x509"

	"github.com/google/uuid"
	"flag"
)

var uid = uuid.New().String()

func rsaEncrypt(pubkey string, pin string, uuid string) (string, error) {
	block, err := base64.StdEncoding.DecodeString(pubkey)

	if err != nil {
		return "", err
	}

	pub, err := x509.ParsePKIXPublicKey(block)
	if err != nil {
		return "", err
	}

	rsaPub, _ := pub.(*rsa.PublicKey)
	//fmt.Printf("The key is: %v, its type is %T", rsaPub, rsaPub)

	// do the encryption
	msg := uuid + pin
	rsakey, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, []byte(msg))
	if err != nil {
		return "", err
	}
	//fmt.Printf("the encryption is: %v", rsakey)
	encodedKey := base64.StdEncoding.EncodeToString(rsakey)
	fmt.Printf("the key is: %v\n", encodedKey)
	fmt.Printf("The uuid is: %v\n", uid)
	return encodedKey, nil
}

func main(){
	key := flag.String("key", "", "public key from ebs")
	ipin := flag.String("ipin", "0000", "ipin you want to create its pin block")
	flag.Parse()
	fmt.Print(rsaEncrypt(*key, *ipin, uid))
}