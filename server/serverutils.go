package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	crytpRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mathRand "math/rand"
	"os"
	"time"
)

func pwd() string {
	mydir, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}
	return mydir
}

func generateSymKey(length int) []byte {
	var seededRand *mathRand.Rand = mathRand.New(
		mathRand.NewSource(time.Now().UnixNano()))
	const charset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return b
}

func extractPubKey(location string) *rsa.PublicKey {
	key, err := ioutil.ReadFile(location)
	if err != nil {
		log.Fatal(err)
	}
	pemBlock, _ := pem.Decode(key)
	parseResult, _ := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	return parseResult.(*rsa.PublicKey)
}

func extractPrivKey(location string) *rsa.PrivateKey {
	key, err := ioutil.ReadFile(location)
	if err != nil {
		log.Fatal(err)
	}
	pemBlock, _ := pem.Decode(key)
	parseResult, _ := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	return parseResult
}

func decryptRSA(encryptedBytes []byte, privateKey *rsa.PrivateKey) []byte {
	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}
	return decryptedBytes
}

func encryptRSA(publicKey *rsa.PublicKey, payload []byte) []byte {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		crytpRand.Reader,
		publicKey,
		payload,
		nil)
	if err != nil {
		panic(err)
	}
	return encryptedBytes
}

func encryptAES(text, key []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(crytpRand.Reader, nonce); err != nil {
		fmt.Println(err)
	}
	return gcm.Seal(nonce, nonce, text, nil)
}

func decryptAES(key, ciphertext []byte) string {
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return string(plaintext)
}
