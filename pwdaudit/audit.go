package main

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// PasswordPolicy defines the criteria for password strength
type PasswordPolicy struct {
	MinLength           int
	MinUppercase        int
	MinLowercase        int
	MinDigit            int
	MinSpecialChar      int
	MinEntropy          float64
}

// calculateEntropy calculates the entropy of a given password
func calculateEntropy(password string) float64 {
	var charsetSize int
	if regexp.MustCompile(`[a-z]`).MatchString(password) {
		charsetSize += 26
	}
	if regexp.MustCompile(`[A-Z]`).MatchString(password) {
		charsetSize += 26
	}
	if regexp.MustCompile(`\d`).MatchString(password) {
		charsetSize += 10
	}
	if regexp.MustCompile(`[!@#\$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>\/?]+`).MatchString(password) {
		charsetSize += 32 // Approximation of the number of special characters generally available on keyboards
	}

	entropy := float64(len(password)) * math.Log2(float64(charsetSize))

	return entropy
}

// CheckPasswordStrength accepts a password string and a PasswordPolicy struct to check it against a set of criteria to determine its strength
func CheckPasswordStrength(password string, policy PasswordPolicy) map[string]bool {
	entropy := calculateEntropy(password)

	criteria := map[string]interface{}{
		fmt.Sprintf("Minimum %d characters", policy.MinLength):             regexp.MustCompile(fmt.Sprintf(`.{%d,}`, policy.MinLength)),
		fmt.Sprintf("At least %d uppercase", policy.MinUppercase):         regexp.MustCompile(fmt.Sprintf(`(?=(?:[^A-Z]*[A-Z]){%d})`, policy.MinUppercase)),
		fmt.Sprintf("At least %d lowercase", policy.MinLowercase):         regexp.MustCompile(fmt.Sprintf(`(?=(?:[^a-z]*[a-z]){%d})`, policy.MinLowercase)),
		fmt.Sprintf("At least %d digit", policy.MinDigit):                 regexp.MustCompile(fmt.Sprintf(`(?=(?:[^\d]*\d){%d})`, policy.MinDigit)),
		fmt.Sprintf("At least %d special character", policy.MinSpecialChar): regexp.MustCompile(fmt.Sprintf(`(?=(?:[^!@#\$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>\/?]*[!@#\$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>\/?+]){%d})`, policy.MinSpecialChar)),
		fmt.Sprintf("Minimum entropy of %.2f bits", policy.MinEntropy):     entropy >= policy.MinEntropy,
	}

	results := make(map[string]bool)
	for description, criterion := range criteria {
		switch criterion.(type) {
		case *regexp.Regexp:
			results[description] = criterion.(*regexp.Regexp).MatchString(password)
		case bool:
			results[description] = criterion.(bool)
		}
	}

	return results
}

func main() {
	var password string
	fmt.Print("Please enter a password to audit: ")
	fmt.Scanln(&password)

	policy := PasswordPolicy{
		MinLength:      16,
		MinUppercase:   1,
		MinLowercase:   1,
		MinDigit:       1,
		MinSpecialChar: 1,
		MinEntropy:     60.0,
	}

	results := CheckPasswordStrength(password, policy)
	for description, pass := range results {
		if pass {
			fmt.Printf("Pass: %s\n", description)
		} else {
			fmt.Printf("Fail: %s\n", description)
		}
	}
}
