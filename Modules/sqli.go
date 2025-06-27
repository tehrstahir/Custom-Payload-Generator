package modules

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/rajaabdullahnasir/Custom-Payload-Generator/utils"
)

type SQLiPayload struct {
	Type     string `json:"type"`      // Error-based, Union-based, Blind, etc.
	Category string `json:"category"`  // Boolean, Time-based, WAF-bypass, etc.
	Payload  string `json:"payload"`
	Bypass   bool   `json:"bypass"`
	Encoded  string `json:"encoded"`
	Base64   string `json:"base64"`
	Hexed    string `json:"hexed"`
	Unicode  string `json:"unicode"`
	Obf      string `json:"obfuscated"`
}

// Load raw SQLi payloads from JSON
func LoadSQLiPayloads() ([]SQLiPayload, error) {
	var payloads []SQLiPayload
	path := filepath.Join("payloads", "sqli.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &payloads); err != nil {
		return nil, err
	}
	return payloads, nil
}

// SaveSQLiPayloadsToFile writes the generated SQLi payloads to payloads/sqli.json
func SaveSQLiPayloadsToFile(payloads []SQLiPayload) error {
	return utils.SaveAsJSON(payloads, "sqli")
}


// GenerateSQLiPayloads applies encodings and WAF bypass variants
func GenerateSQLiPayloads() ([]SQLiPayload, error) {
	payloads, err := LoadSQLiPayloads()
	if err != nil {
		return nil, err
	}

	var final []SQLiPayload
	for _, p := range payloads {
		// Base variant
		p.Encoded = utils.EncodeURL(p.Payload)
		p.Base64 = utils.EncodeBase64(p.Payload)
		p.Hexed = utils.EncodeHex(p.Payload)
		p.Unicode = utils.EncodeUnicode(p.Payload)
		p.Obf = utils.Obfuscate(p.Payload)
		final = append(final, p)

		// Mixed-case WAF bypass
		wafMixed := p
		wafMixed.Payload = utils.RandomizeSQLCase(p.Payload)
		wafMixed.Type += " (WAF-Cased)"
		wafMixed.Bypass = true
		wafMixed.Category = "WAF-bypass"
		wafMixed.Encoded = utils.EncodeURL(wafMixed.Payload)
		wafMixed.Base64 = utils.EncodeBase64(wafMixed.Payload)
		wafMixed.Hexed = utils.EncodeHex(wafMixed.Payload)
		wafMixed.Unicode = utils.EncodeUnicode(wafMixed.Payload)
		wafMixed.Obf = utils.Obfuscate(wafMixed.Payload)
		final = append(final, wafMixed)

		// Inline comments bypass
		wafComment := p
		wafComment.Payload = utils.InsertSQLComments(p.Payload)
		wafComment.Type += " (WAF-Commented)"
		wafComment.Bypass = true
		wafComment.Category = "WAF-bypass"
		wafComment.Encoded = utils.EncodeURL(wafComment.Payload)
		wafComment.Base64 = utils.EncodeBase64(wafComment.Payload)
		wafComment.Hexed = utils.EncodeHex(wafComment.Payload)
		wafComment.Unicode = utils.EncodeUnicode(wafComment.Payload)
		wafComment.Obf = utils.Obfuscate(wafComment.Payload)
		final = append(final, wafComment)
	}

	return final, nil
}
