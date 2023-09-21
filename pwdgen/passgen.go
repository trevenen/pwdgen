package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
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
	policy PasswordPolicy
}

func NewGenerator(policy PasswordPolicy) *Generator {
	return &Generator{
		policy: policy,
	}
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

	return password
}

func shuffleAndJoin(parts []string) string {
	password := strings.Join(parts, "")
	runePass := []rune(password)
	for i := len(runePass) - 1; i > 0; i-- {
		j := randomInt(i + 1)
		runePass[i], runePass[j] = runePass[j], runePass[i]
	}
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
