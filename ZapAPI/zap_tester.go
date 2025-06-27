package zapapi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	
	"time"

	"github.com/rajaabdullahnasir/Custom-Payload-Generator/reports"
)

// ScanResult is the structure of the scan result saved in JSON
type ScanResult struct {
	TargetURL string                   `json:"target_url"`
	ScanID    string                   `json:"scan_id"`
	Timestamp string                   `json:"timestamp"`
	Alerts    []map[string]interface{} `json:"alerts"`
}

// RunZAPScan performs the full scan and generates both JSON and HTML reports
func RunZAPScan(targetURL, host, port, apiKey string) error {
	fmt.Println("🚀 Starting ZAP Scan on:", targetURL)

	client := ZAPClient{
		BaseURL: fmt.Sprintf("http://%s:%s", host, port),
		APIKey:  apiKey,
	}

	// Step 1: Spider the target
	fmt.Println("🕷️ Spidering target...")
	if err := client.SpiderURL(targetURL); err != nil {
		return fmt.Errorf("❌ Spider error: %v", err)
	}
	time.Sleep(5 * time.Second)

	// Step 2: Start active scan
	scanID, err := client.StartScan(targetURL)
	if err != nil {
		return fmt.Errorf("❌ Failed to start scan: %v", err)
	}
	fmt.Println("🔍 Scan ID:", scanID)

	// Step 3: Wait for completion
	fmt.Println("⏳ Waiting for scan to complete...")
	if err := client.WaitForCompletion(scanID); err != nil {
		return fmt.Errorf("❌ Scan wait error: %v", err)
	}
	fmt.Println("✅ Scan complete!")

	// Step 4: Fetch alerts
	alerts, err := client.GetAlerts(targetURL)
	if err != nil {
		return fmt.Errorf("❌ Failed to retrieve alerts: %v", err)
	}
	fmt.Printf("📦 Retrieved %d alerts\n", len(alerts))

	// Step 5: Save alerts in JSON format
	if err := os.MkdirAll("reports", 0755); err != nil {
		return fmt.Errorf("❌ Failed to create reports directory: %v", err)
	}

	result := ScanResult{
		TargetURL: targetURL,
		ScanID:    scanID,
		Timestamp: time.Now().Format(time.RFC3339),
		Alerts:    alerts,
	}

	jsonPath := filepath.Join("reports", "results.json")
	if err := saveScanResult(result, jsonPath); err != nil {
		return fmt.Errorf("❌ Failed to save results.json: %v", err)
	}
	fmt.Println("📝 Results saved to", jsonPath)

	// Step 6: Generate HTML report
	fmt.Println("📄 Generating HTML report...")
	if err := reports.GenerateHTMLReport(jsonPath); err != nil {
		return fmt.Errorf("❌ HTML report generation failed: %v", err)
	}
	fmt.Println("✅ HTML report generated successfully.")
	return nil
}

// saveScanResult encodes and writes ScanResult to a file
func saveScanResult(result ScanResult, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
