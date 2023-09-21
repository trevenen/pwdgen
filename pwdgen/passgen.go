package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
)

const (
	LowerLetters = "abcdefghijklmnopqrstuvwxyz"
	UpperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Digits       = "0123456789"
	Symbols      = "~!@#$%^&*()_+`-={}|[]\\:\"<>?,./"
)

var (
	commonPasswords = make(map[string]bool)
	commonWords     = []string{"apple", "banana", "cherry", "date", "elderberry"} // Simplified list. You can expand this.
)

func loadCommonPasswords(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		commonPasswords[scanner.Text()] = true
	}

	return scanner.Err()
}

type PasswordPolicy struct {
	MinLength          int
	MinUppercase       int
	MinLowercase       int
	MinDigit           int
	MinSpecialChar     int
	ExcludeSimilar     bool
	GeneratePassphrase bool
}

type Generator struct {
	policy PasswordPolicy
}

func NewGenerator(policy PasswordPolicy) *Generator {
	return &Generator{
		policy: policy,
	}
}

func (g *Generator) Generate() string {
	if g.policy.GeneratePassphrase {
		return g.generatePassphrase()
	}

	letters := LowerLetters + UpperLetters
	digits := Digits
	symbols := Symbols

	if g.policy.ExcludeSimilar {
		letters = strings.ReplaceAll(letters, "O", "")
		letters = strings.ReplaceAll(letters, "0", "")
		letters = strings.ReplaceAll(letters, "l", "")
		letters = strings.ReplaceAll(letters, "1", "")
	}

	length := g.policy.MinLength
	for {
		result := ""
		result += randomString(letters, g.policy.MinUppercase+g.policy.MinLowercase)
		result += randomString(digits, g.policy.MinDigit)
		result += randomString(symbols, g.policy.MinSpecialChar)

		remaining := length - len(result)
		result += randomString(letters+digits+symbols, remaining)

		if !containsCommonPassword(result) {
			return result
		}
	}
}

func (g *Generator) generatePassphrase() string {
	words := []string{}
	for i := 0; i < g.policy.MinLength; i++ {
		word := commonWords[randomInt(len(commonWords))]
		words = append(words, word)
	}
	return strings.Join(words, "-")
}

func containsCommonPassword(password string) bool {
	for common := range commonPasswords {
		if strings.Contains(password, common) {
			return true
		}
	}
	return false
}

func randomString(charset string, length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[randomInt(len(charset))]
	}
	return string(result)
}

func randomInt(n int) int {
	val, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(val.Int64())
}

func main() {
	if err := loadCommonPasswords("10k-most-common.txt"); err != nil {
		log.Fatalf("Failed to load common passwords: %v", err)
	}

	policy := PasswordPolicy{
		MinLength:          40,
		MinUppercase:       10,
		MinLowercase:       10,
		MinDigit:           10,
		MinSpecialChar:     10,
		ExcludeSimilar:     true,
		GeneratePassphrase: false,
	}

	gen := NewGenerator(policy)
	password := gen.Generate()
	fmt.Println("Generated Password:", password)
}
