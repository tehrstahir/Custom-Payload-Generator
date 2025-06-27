package utils

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// EncodeURL returns URL-encoded representation of input string
func EncodeURL(input string) string {
	return url.QueryEscape(input)
}

// EncodeBase64 returns Base64-encoded string
func EncodeBase64(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

// EncodeHex returns a hex-encoded representation of the input string
func EncodeHex(input string) string {
	var result strings.Builder
	for _, c := range input {
		result.WriteString(fmt.Sprintf("\\x%02x", c))
	}
	return result.String()
}

// EncodeUnicode returns a Unicode-escaped representation of the input string
func EncodeUnicode(input string) string {
	var result strings.Builder
	for _, r := range input {
		result.WriteString(fmt.Sprintf("\\u%04x", r))
	}
	return result.String()
}

// EncodeCMDi escapes symbols used in shell commands to help evade filters
func EncodeCMDi(input string) string {
	replacements := map[string]string{
		";":  "%3B",
		"&":  "%26",
		"|":  "%7C",
		"`":  "%60",
		"$(": "%24%28",
		")":  "%29",
	}

	encoded := input
	for symbol, escape := range replacements {
		encoded = strings.ReplaceAll(encoded, symbol, escape)
	}
	return encoded
}
