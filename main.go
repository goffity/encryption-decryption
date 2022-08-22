package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	message := "My secret for somthings."
	key := []byte("4Nhh)9DmH$37d2h5nsHez}12:MZSH**;")

	encrypted, err := encrypt(key, message)
	if err != nil {
		log.Println(err)
		os.Exit(-2)
	}

	fmt.Printf("\n\tCIPHER KEY: %s\n", string(key))
	fmt.Printf("\tENCRYPTED: %s\n", encrypted)

	decrypted, err := decrypt(key, encrypted)

	//IF the decryption failed:
	if err != nil {
		log.Println(err)
		os.Exit(-3)
	}

	//Print re-decrypted text:
	fmt.Printf("\tDECRYPTED: %s\n\n", decrypted)
}

func encrypt(key []byte, message string) (encoded string, err error) {
	plainText := []byte(message)
	block, err := aes.NewCipher(key)

	if err != nil {
		return
	}
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)
	return base64.RawStdEncoding.EncodeToString(cipherText), err
}

func decrypt(key []byte, secure string) (decoded string, err error) {
	cipherText, err := base64.RawStdEncoding.DecodeString(secure)
	if err != nil {
		return
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("ciphertext block size is too short")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), err
}
