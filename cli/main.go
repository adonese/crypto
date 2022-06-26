package main

import (
	"flag"
	"fmt"

	"github.com/adonese/crypto"
	"github.com/google/uuid"
)

var uid = uuid.New().String()

func main() {
	key := flag.String("key", "", "public key from ebs")
	ipin := flag.String("ipin", "0000", "ipin you want to create its pin block")
	flag.Parse()
	fmt.Print(crypto.EncryptNoebs(*key, *ipin))
}
