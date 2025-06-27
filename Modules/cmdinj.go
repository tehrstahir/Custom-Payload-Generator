package modules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rajaabdullahnasir/Custom-Payload-Generator/utils"
)

type CMDPayload struct {
	OS             string `json:"os"`
	Command        string `json:"command"`
	Operator       string `json:"operator"`
	Original       string `json:"original"`
	Base64         string `json:"base64"`
	URLEncoded     string `json:"url_encoded"`
	HexEncoded     string `json:"hex_encoded"`
	Unicode        string `json:"unicode"`
	Obfuscated     string `json:"obfuscated"`
	ObfuscatedCMDi string `json:"obfuscated_cmdi"`
	CMDiEscaped    string `json:"cmdi_escaped"`
}

type CMDInput struct {
	Linux   []string `json:"linux"`
	Windows []string `json:"windows"`
}

// GenerateCMDiPayloads reads cmd.json and generates encoded & obfuscated payloads
func GenerateCMDiPayloads() []CMDPayload {
	var allPayloads []CMDPayload

	// Load JSON file
	filePath := filepath.Join("payloads", "cmd.json")
	raw, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("❌ Failed to read cmd.json:", err)
		return nil
	}

	// Parse JSON input
	var data CMDInput
	if err := json.Unmarshal(raw, &data); err != nil {
		fmt.Println("❌ Failed to parse cmd.json:", err)
		return nil
	}

	// Define OS-specific shell operators
	linuxOps := []string{";", "&&", "||", "|"}
	winOps := []string{"&&", "||", "|", "&"}

	// Generate Linux payloads
	for _, cmd := range data.Linux {
		for _, op := range linuxOps {
			full := fmt.Sprintf("%s %s", op, cmd)
			payload := buildCMDPayload("linux", cmd, op, full)
			allPayloads = append(allPayloads, payload)
		}
	}

	// Generate Windows payloads
	for _, cmd := range data.Windows {
		for _, op := range winOps {
			full := fmt.Sprintf("%s %s", op, cmd)
			payload := buildCMDPayload("windows", cmd, op, full)
			allPayloads = append(allPayloads, payload)
		}
	}

	return allPayloads
}

// SaveCMDiPayloadsToFile writes the generated CMDi payloads to payloads/cmd.json
func SaveCMDiPayloadsToFile(payloads []CMDPayload) error {
	return utils.SaveAsJSON(payloads, "cmd")
}

// buildCMDPayload generates encoded and obfuscated versions of a command
func buildCMDPayload(osType, cmd, op, original string) CMDPayload {
	return CMDPayload{
		OS:             osType,
		Command:        cmd,
		Operator:       op,
		Original:       original,
		Base64:         utils.EncodeBase64(original),
		URLEncoded:     utils.EncodeURL(original),
		HexEncoded:     utils.EncodeHex(original),
		Unicode:        utils.EncodeUnicode(original),
		Obfuscated:     utils.Obfuscate(original),
		ObfuscatedCMDi: utils.ObfuscateCMDi(original),
		CMDiEscaped:    utils.EncodeCMDi(original),
	}
}
