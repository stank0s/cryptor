package cryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type Cryptor struct{}

func NewCryptor() *Cryptor {
	return &Cryptor{}
}

func (c *Cryptor) GenerateSecret() ([]byte, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}

	return bytes, nil
}

func (c *Cryptor) Encrypt(toEncrypt []byte, secret []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aesGCM.Seal(nonce, nonce, toEncrypt, nil), nil
}

func (c *Cryptor) Decrypt(toDecrypt []byte, secret []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := toDecrypt[:nonceSize], toDecrypt[nonceSize:]

	return aesGCM.Open(nil, nonce, ciphertext, nil)
}
