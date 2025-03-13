package main

import (
	"crypto/aes" // https://pkg.go.dev/crypto/aes
	"crypto/cipher" // https://pkg.go.dev/crypto/cipher
	"crypto/rand" // https://pkg.go.dev/crypto/rand
	"crypto/sha256" // https://pkg.go.dev/crypto/sha256
	"encoding/hex" // https://pkg.go.dev/encoding/hex
	"fmt"
	"os"

	"golang.org/x/crypto/pbkdf2" // https://pkg.go.dev/golang.org/x/crypto/pbkdf2
)

// Salt

func generateSalt() string {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		fmt.Println("Error generating salt", err)
		os.Exit(1)
	}
	return hex.EncodeToString(salt)
}

// Key Derivation

func deriveKey(password, salt string) []byte {
	saltBytes, _ := hex.DecodeString(salt)
	return pbkdf2.Key([]byte(password), saltBytes, 100000, 32, sha256.New)
}


// Encryption

func encrypt(password, plaintext string) {
	salt := generateSalt()
	key := deriveKey(password, salt)

	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	if err != nil {
		fmt.Println("Error generating nonce", err)
		os.Exit(1)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error creating cipher block", err)
		os.Exit(1)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Error creating GCM", err)
		os.Exit(1)
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)
	fullCiphertext := append(nonce, ciphertext...)

    fmt.Println("Password:", password)
	fmt.Println("Plaintext:", plaintext)
	fmt.Println("Salt:", salt)
	fmt.Println("Nonce:", hex.EncodeToString(nonce))
	fmt.Println("Ciphertext:", hex.EncodeToString(fullCiphertext))
}

// Decryption

func decrypt(password, salt, ciphertextHex string) {
	key := deriveKey(password, salt)

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		fmt.Println("Invalid ciphertext format.")
		os.Exit(1)
	}

	nonce := ciphertext[:12]
	encryptedData := ciphertext[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error creating cipher block", err)
		os.Exit(1)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Error creating GCM", err)
		os.Exit(1)
	}

	plaintext, err := aesGCM.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		fmt.Println("Decryption failed", err)
		os.Exit(1)
	}

	fmt.Println("Decrypted Text:", string(plaintext))
}



func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage:")
		fmt.Println("  ./gocypher encrypt password \"plaintext\"")
		fmt.Println("  ./gocypher decrypt password salt \"ciphertext\"")
		return
	}

	command := os.Args[1]
	password := os.Args[2]

	if command == "encrypt" && len(os.Args) == 4 {
		plaintext := os.Args[3]
		encrypt(password, plaintext)
	} else if command == "decrypt" && len(os.Args) == 5 {
		salt := os.Args[3]
		ciphertext := os.Args[4]
		decrypt(password, salt, ciphertext)
	} else {
		fmt.Println("Invalid command")
	}
}