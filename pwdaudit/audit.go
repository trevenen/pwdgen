package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"
)

const (
	commonPasswordsFile = "10k-most-common.txt"
	dictionaryFile      = "words_alpha.txt"
)

type PasswordPolicy struct {
	MinLength        int
	MinUppercase     int
	MinLowercase     int
	MinDigit         int
	MinSpecialChar   int
	ExcludeSimilar   bool
	CheckCommonWords bool
	CheckDictionary  bool
}

type PasswordAuditor struct {
	commonPasswords map[string]struct{}
	dictionary      []string
	policy          PasswordPolicy
}

func NewPasswordAuditor(policy PasswordPolicy) *PasswordAuditor {
	auditor := &PasswordAuditor{
		commonPasswords: make(map[string]struct{}),
		policy:          policy,
	}

	if policy.CheckCommonWords {
		file, err := os.Open(commonPasswordsFile)
		if err != nil {
			panic(err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			auditor.commonPasswords[scanner.Text()] = struct{}{}
		}
		file.Close()
	}

	if policy.CheckDictionary {
		file, err := os.Open(dictionaryFile)
		if err != nil {
			panic(err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			auditor.dictionary = append(auditor.dictionary, scanner.Text())
		}
		file.Close()
	}

	return auditor
}

func (a *PasswordAuditor) AuditPassword(password string) {
	// Pattern Matching
	a.checkCommonPasswords(password)
	a.checkDictionaryWords(password)
	a.checkKeyboardPatterns(password)
	a.checkL33tSpeak(password)
	// ... Additional pattern checks can be added here

	// Feedback System
	a.provideFeedback(password)

	// Additional functionalities like Crack Time Estimation, Score System, etc.
	// can be added in similar fashion
}

func (a *PasswordAuditor) checkCommonPasswords(password string) {
	if _, exists := a.commonPasswords[password]; exists {
		fmt.Println("Warning: The password is a common password.")
	}
}

func (a *PasswordAuditor) checkDictionaryWords(password string) {
	for _, word := range a.dictionary {
		if strings.Contains(password, word) {
			fmt.Println("Warning: The password contains a dictionary word.")
			break
		}
	}
}

func (a *PasswordAuditor) checkKeyboardPatterns(password string) {
	// Simple example: Check for "qwerty" pattern
	if strings.Contains(password, "qwerty") {
		fmt.Println("Warning: The password contains a keyboard pattern.")
	}
}

func (a *PasswordAuditor) checkL33tSpeak(password string) {
	leetPattern := regexp.MustCompile(`[a@4][b8][c<\(][d][e3][f][g9][h#][i1\|][j][k][l1\|][m][n][o0][p][q][r][s5\$][t7\+][u][v][w][x][y][z2]`)
	if leetPattern.MatchString(password) {
		fmt.Println("Warning: The password contains L33t speak.")
	}
}

func (a *PasswordAuditor) provideFeedback(password string) {
	if len(password) < a.policy.MinLength {
		fmt.Println("Suggestion: Increase the length of your password.")
	}

	var upper, lower, digit, special int
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper++
		case unicode.IsLower(r):
			lower++
		case unicode.IsDigit(r):
			digit++
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			special++
		}
	}

	if upper < a.policy.MinUppercase {
		fmt.Println("Suggestion: Use more uppercase characters.")
	}
	if lower < a.policy.MinLowercase {
		fmt.Println("Suggestion: Use more lowercase characters.")
	}
	if digit < a.policy.MinDigit {
		fmt.Println("Suggestion: Use more digits.")
	}
	if special < a.policy.MinSpecialChar {
		fmt.Println("Suggestion: Use more special characters.")
	}
}

func main() {
	policy := PasswordPolicy{
		MinLength:        40,
		MinUppercase:     10,
		MinLowercase:     10,
		MinDigit:         10,
		MinSpecialChar:   10,
		ExcludeSimilar:   true,
		CheckCommonWords: true,
		CheckDictionary:  true,
	}

	auditor := NewPasswordAuditor(policy)

	// Take the password to be audited as input from the user
	fmt.Print("Enter the password to be audited: ")
	var password string
	fmt.Scanln(&password)

	auditor.AuditPassword(password)
}
