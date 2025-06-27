package utils

import (
	"math/rand"
	"strings"
	"time"
)

// Obfuscate inserts random spacing or comments between characters (for general purpose)
func Obfuscate(input string) string {
	rand.Seed(time.Now().UnixNano())
	var obf strings.Builder
	for _, c := range input {
		obf.WriteRune(c)
		switch rand.Intn(3) {
		case 0:
			obf.WriteString(" ")
		case 1:
			obf.WriteString("/**/")
		case 2:
			obf.WriteString("<!-- -->")
		}
	}
	return obf.String()
}

// RandomizeSQLCase randomizes the casing of SQL keywords to evade WAFs
func RandomizeSQLCase(input string) string {
	rand.Seed(time.Now().UnixNano())
	var mixed strings.Builder
	for _, r := range input {
		if rand.Intn(2) == 0 {
			mixed.WriteRune(toUpper(r))
		} else {
			mixed.WriteRune(toLower(r))
		}
	}
	return mixed.String()
}

func toUpper(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return r
}

func toLower(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 32
	}
	return r
}

// InsertSQLComments inserts comment tokens between SQL keywords
func InsertSQLComments(input string) string {
	replacements := map[string]string{
		"SELECT": "SE/**/LECT",
		"FROM":   "FR/**/OM",
		"WHERE":  "WH/**/ERE",
		"AND":    "A/**/ND",
		"OR":     "O/**/R",
		"UNION":  "UN/**/ION",
		"INSERT": "IN/**/SERT",
		"UPDATE": "UP/**/DATE",
		"DELETE": "DE/**/LETE",
		"DROP":   "DR/**/OP",
		"TABLE":  "TA/**/BLE",
	}

	out := input
	for key, val := range replacements {
		out = strings.ReplaceAll(out, key, val)
		out = strings.ReplaceAll(out, strings.ToLower(key), val)
		out = strings.ReplaceAll(out, strings.ToUpper(key), val)
	}

	return out
}

// ObfuscateXSS applies XSS-specific obfuscation (spaces, comments)
func ObfuscateXSS(input string) string {
	rand.Seed(time.Now().UnixNano())
	var obf strings.Builder
	for _, c := range input {
		obf.WriteRune(c)
		// Obfuscate only inside script strings like "alert" or "onerror"
		if rand.Intn(3) == 0 {
			obf.WriteString(" ")
		} else if rand.Intn(3) == 1 {
			obf.WriteString("<!-- -->")
		}
	}
	return obf.String()
}

// ObfuscateCMDi adds shell-specific obfuscation using random whitespace and chaining symbols
func ObfuscateCMDi(input string) string {
	rand.Seed(time.Now().UnixNano())
	var result strings.Builder
	for _, c := range input {
		result.WriteRune(c)
		switch rand.Intn(4) {
		case 0:
			result.WriteString(" ") // space
		case 1:
			result.WriteString(" # ") // shell comment
		case 2:
			result.WriteString(" \\") // escape
		case 3:
			result.WriteString(" && ") // chaining
		}
	}
	return result.String()
}
