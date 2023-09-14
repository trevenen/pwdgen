package main

import (
	"awesomeProject/pwdgen"
	"log"
)

// TODO insert viper / cobra for cli here so I can use this as a cli tool and just pass in the args

func main() {
	// Generate a password with pwd.Generate(length, numDigits, numSymbols int, noUpper, allowRepeat bool)
	res, err := pwdgen.Generate(40, 10, 10, false, true)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	pwdgen.TestPasswordEntropy(res)
}
