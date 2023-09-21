package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	LowerLetters = "abcdefghijklmnopqrstuvwxyz"
	UpperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Digits       = "0123456789"
	Symbols      = "~!@#$%^&*()_+`-={}|[]\\:\"<>?,./"
)

var commonPasswords = make(map[string]bool)

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

type Auditor struct {
	policy PasswordPolicy
}

func NewAuditor(policy PasswordPolicy) *Auditor {
	return &Auditor{policy: policy}
}

func (a *Auditor) AuditPassword(password string) {
	if len(password) < a.policy.MinLength {
		fmt.Printf("Password is too short. It should be at least %d characters long.\n", a.policy.MinLength)
	}

	if countChars(password, UpperLetters) < a.policy.MinUppercase {
		fmt.Printf("Password should contain at least %d uppercase letters.\n", a.policy.MinUppercase)
	}

	if countChars(password, LowerLetters) < a.policy.MinLowercase {
		fmt.Printf("Password should contain at least %d lowercase letters.\n", a.policy.MinLowercase)
	}

	if countChars(password, Digits) < a.policy.MinDigit {
		fmt.Printf("Password should contain at least %d digits.\n", a.policy.MinDigit)
	}

	if countChars(password, Symbols) < a.policy.MinSpecialChar {
		fmt.Printf("Password should contain at least %d symbols.\n", a.policy.MinSpecialChar)
	}

	if containsCommonPassword(password) {
		fmt.Println("Password matches a commonly used password. Consider using a more unique password.")
	}

	// TODO: Add check for dictionary words and other policies here if required.
}

func countChars(s, chars string) int {
	count := 0
	for _, char := range s {
		if strings.ContainsRune(chars, char) {
			count++
		}
	}
	return count
}

func containsCommonPassword(password string) bool {
	return commonPasswords[password]
}

func main() {
	if err := loadCommonPasswords("10k-most-common.txt"); err != nil {
		fmt.Printf("Failed to load common passwords: %v\n", err)
		return
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

	auditor := NewAuditor(policy)

	fmt.Println("Enter the password to audit:")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		password := scanner.Text()
		auditor.AuditPassword(password)
	}
}
