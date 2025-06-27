package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// SaveAsJSON saves any data structure as formatted JSON
func SaveAsJSON(data interface{}, fileName string) error {
	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	path := filepath.Join("reports", fileName+".json")
	err = os.WriteFile(path, content, 0644)
	if err != nil {
		return fmt.Errorf("failed to write JSON file: %v", err)
	}
	return nil
}

// SaveAsTXT saves simple line-based payloads
func SaveAsTXT(lines []string, fileName string) error {
	path := filepath.Join("reports", fileName+".txt")
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create txt file: %v", err)
	}
	defer file.Close()

	for _, line := range lines {
		_, err := file.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("failed to write to txt file: %v", err)
		}
	}
	return nil
}

// PrintToConsole displays payloads to stdout in readable format
func PrintToConsole(title string, data interface{}) {
	fmt.Println("====", title, "====")
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("Error displaying data: %v\n", err)
		return
	}
	fmt.Println(string(jsonBytes))
}
