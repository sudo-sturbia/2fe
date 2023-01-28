package cryptfile

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"
)

// Read reads a file with encrypted contents from a given path, decrypts
// the contents and returns them.
func Read(path, passphrase string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	key, err := key(passphrase)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	bytes := make([]byte, 0)

	sc := bufio.NewScanner(file)
	for sc.Scan() {
		data := sc.Bytes()

		nonceSize := gcm.NonceSize()

		nonce := data[:nonceSize]
		ciphertext := data[nonceSize:]

		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}
		bytes = append(bytes, []byte(plaintext)...)
		bytes = append(bytes, []byte("\n")...)
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}

	return bytes, nil
}

// Write encrypts contents using AES-GCM and a passphrase, and writes the
// encrypted contents to the given path.
func Write(path, passphrase string, contents []byte) error {
	key, err := key(passphrase)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nil, nonce, contents, nil)
	ciphertext = append(nonce, ciphertext...)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("opening keychain: %v", err)
	}
	f.Chmod(0o600)

	if _, err := f.Write(ciphertext); err != nil {
		return fmt.Errorf("adding key: %v", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("adding key: %v", err)
	}
	return nil
}

func key(passphrase string) ([]byte, error) {
	hash := md5.Sum([]byte(passphrase))
	key, err := scrypt.Key([]byte(passphrase), hash[:], 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}
