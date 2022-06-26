//Package crypto implements IPIN encryption as per EBS
// It supports libraries in different languages including: Go, Python, JavaScript, Java and Dart.
// The code is battle-tested and has been used in production for years.
//
// Signing and Verifying
// In addition to the EBS encryption support, crypto also supports signing and verifying for keys. Most notably, noebs uses
// crypto to sign users for token refresh.
package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

//Encrypt given a public key and payload, encrypt encrypts
// to EBS compatible RSA payload
// you must provide the payload in:
// 		msg := uuid + pin
// so that it is compatible with EBS' standard encryption
func Encrypt(pubkey string, payload string) (string, error) {
	block, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		return "", err
	}

	pub, err := x509.ParsePKIXPublicKey(block)
	if err != nil {
		return "", err
	}

	rsaPub, _ := pub.(*rsa.PublicKey)
	rsakey, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, []byte(payload))
	if err != nil {
		return "", err
	}
	//fmt.Printf("the encryption is: %v", rsakey)
	encodedKey := base64.StdEncoding.EncodeToString(rsakey)
	fmt.Printf("the key is: %v\n", encodedKey)
	return encodedKey, nil
}

//Decrypt given a private key and payload to EBS compatible RSA payload
// you must provide the payload in:
// 		msg := uuid + pin
// so that it is compatible with EBS' standard encryption
func EncryptNoebs(pubkey string, payload string) (string, error) {
	block, _ := pem.Decode([]byte(pubkey))
	if block == nil {
		panic("failed to parse PEM block containing the private key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}
	pubRsa := pub.(*rsa.PublicKey)

	rsakey, err := rsa.EncryptPKCS1v15(rand.Reader, pubRsa, []byte(payload))
	if err != nil {
		return "", err
	}

	//fmt.Printf("the encryption is: %v", rsakey)
	encodedKey := base64.StdEncoding.EncodeToString(rsakey)
	fmt.Printf("the key is: %v\n", encodedKey)
	return encodedKey, nil
}

//DecryptNoebs given a private key and payload to EBS compatible RSA payload
// you must provide the payload in:
// 		msg := uuid + pin
// so that it is compatible with EBS' standard encryption
func DecryptNoebs(privkey string, payload string) (string, error) {

	block, _ := pem.Decode([]byte(privkey))
	if block == nil {
		panic("failed to parse PEM block containing the private key")
	}

	pub, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	rsakey, err := rsa.DecryptPKCS1v15(rand.Reader, pub, []byte(payload))
	if err != nil {
		return "", err
	}
	//fmt.Printf("the encryption is: %v", rsakey)
	encodedKey := base64.StdEncoding.EncodeToString(rsakey)
	fmt.Printf("the key is: %v\n", encodedKey)
	return encodedKey, nil
}

//Sign is a reference implementation of how our signing and verification works
// it is used by noebs clients (android app) to send signed messages that we can verify
// in noebs to ensure that the message is actually correct.
// Note that:
// - we don't really sign a message, it is always hardcoded
// - we used sha256 to sign the hash of the message, instead of the actual message
// WE expect that the client side will abide by this same interface we are designing here
func Sign(privkey string) (string, error) {

	data, err := decode(privkey)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		panic("failed to parse PEM block containing the private key")
	}

	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded private key: " + err.Error())
	}
	// crypto/rand.Reader is a good source of entropy for blinding the RSA
	// operation.
	rng := rand.Reader
	message := []byte("message to be signed")

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed. This requires
	// that the hash function be collision resistant. SHA-256 is the
	// least-strong hash function that should be used for this at the time
	// of writing (2016).
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rng, pri, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return "", err
	}

	fmt.Printf("Signature: %x\n", signature)
	return fmt.Sprintf("%x", signature), nil
}

//Verify used by noebs systems to verify the authenticity of the clients.
// We are currently using it to ensure that noebs mobile clients are valid (providing their keys are valid)
// this is a rather very tricky api, but it is the only way we can ensure a simple way of authenticating our users
//
// pubkey is base64 string encoding for the public key!
func Verify(pubkey string, payload string) (bool, error) {

	data, err := decode(pubkey)
	if err != nil {
		return false, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		panic("failed to parse PEM block containing the private key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded private key: " + err.Error())
	}

	message := []byte("message to be signed")
	signature, _ := hex.DecodeString(payload)

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed. This requires
	// that the hash function be collision resistant. SHA-256 is the
	// least-strong hash function that should be used for this at the time
	// of writing (2016).
	hashed := sha256.Sum256(message)
	rsaPub := pub.(*rsa.PublicKey)
	hashErr := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from verification: %s\n", err)
		return false, hashErr
	}

	return true, nil
}

func decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}
