package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"math/big"
	mathrand "math/rand" // Alias for clarity
	"os"
	"strings"
	"time"
)

const (
	LowerLetters = "abcdefghijklmnopqrstuvwxyz"
	UpperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Digits       = "0123456789"
	Symbols      = "~!@#$%^&*()_+`-={}|[]\\:\"<>?,./"
)

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
	policy          PasswordPolicy
	commonPasswords map[string]struct{}
	dictionary      []string
}

func NewGenerator(policy PasswordPolicy) *Generator {
	gen := &Generator{
		policy:          policy,
		commonPasswords: make(map[string]struct{}),
	}

	// Load common passwords
	file, err := os.Open("10k-most-common.txt")
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		gen.commonPasswords[scanner.Text()] = struct{}{}
	}
	file.Close()

	// Load dictionary words
	file, err = os.Open("words_alpha.txt")
	if err != nil {
		panic(err)
	}
	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		gen.dictionary = append(gen.dictionary, scanner.Text())
	}
	file.Close()

	return gen
}

func (g *Generator) Generate() string {
	letters := LowerLetters + UpperLetters
	digits := Digits
	symbols := Symbols

	if g.policy.ExcludeSimilar {
		letters = strings.ReplaceAll(letters, "O", "")
		letters = strings.ReplaceAll(letters, "0", "")
		letters = strings.ReplaceAll(letters, "l", "")
		letters = strings.ReplaceAll(letters, "1", "")
	}

	passwordParts := make([]string, 0)
	passwordParts = append(passwordParts, randomString(UpperLetters, g.policy.MinUppercase))
	passwordParts = append(passwordParts, randomString(LowerLetters, g.policy.MinLowercase))
	passwordParts = append(passwordParts, randomString(digits, g.policy.MinDigit))
	passwordParts = append(passwordParts, randomString(symbols, g.policy.MinSpecialChar))

	remaining := g.policy.MinLength - (g.policy.MinUppercase + g.policy.MinLowercase + g.policy.MinDigit + g.policy.MinSpecialChar)
	passwordParts = append(passwordParts, randomString(letters+digits+symbols, remaining))

	password := shuffleAndJoin(passwordParts)

	for len(password) > 0 && !isAlpha(rune(password[0])) {
		password = password[1:] + string(password[0])
	}

	// Re-checking against common passwords and dictionary words after shuffling
	for {
		// Check against common passwords
		if _, exists := g.commonPasswords[password]; exists {
			password = shuffleAndJoin(passwordParts)
			continue
		}

		// Check against dictionary words
		isValid := true
		for _, word := range g.dictionary {
			if strings.Contains(password, word) {
				isValid = false
				password = shuffleAndJoin(passwordParts)
				break
			}
		}

		if isValid {
			break
		}
	}

	return password
}

func shuffleAndJoin(parts []string) string {
	password := strings.Join(parts, "")
	runePass := []rune(password)
	mathrand.Shuffle(len(runePass), func(i, j int) {
		runePass[i], runePass[j] = runePass[j], runePass[i]
	})
	return string(runePass)
}
func isAlpha(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
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
	// Seed the math/rand package's default source
	mathrand.Seed(time.Now().UnixNano())

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
