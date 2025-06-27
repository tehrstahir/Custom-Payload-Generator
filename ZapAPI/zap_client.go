package zapapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rajaabdullahnasir/Custom-Payload-Generator/reports"
)

// ZAPClient represents a client for interacting with the ZAP API
type ZAPClient struct {
	BaseURL string
	APIKey  string
}

// StartScan initiates an active scan using ZAP
func (z *ZAPClient) StartScan(target string) (string, error) {
	url := fmt.Sprintf("%s/JSON/ascan/action/scan/?apikey=%s&url=%s", z.BaseURL, z.APIKey, target)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("start scan error: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]string
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &result)
	return result["scan"], nil
}

// CheckScanStatus returns scan status from ZAP
func (z *ZAPClient) CheckScanStatus(scanID string) (string, error) {
	url := fmt.Sprintf("%s/JSON/ascan/view/status/?apikey=%s&scanId=%s", z.BaseURL, z.APIKey, scanID)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("status check error: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]string
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &result)
	return result["status"], nil
}

// GetAlerts fetches ZAP alerts for a URL
func (z *ZAPClient) GetAlerts(target string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/JSON/core/view/alerts/?apikey=%s&baseurl=%s", z.BaseURL, z.APIKey, target)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("get alerts error: %v", err)
	}
	defer resp.Body.Close()

	var result map[string][]map[string]interface{}
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &result)
	return result["alerts"], nil
}

// WaitForCompletion blocks until the scan reaches 100%
func (z *ZAPClient) WaitForCompletion(scanID string) error {
	for {
		status, err := z.CheckScanStatus(scanID)
		if err != nil {
			return err
		}
		if status == "100" {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
}

// SpiderURL triggers the ZAP spider to crawl the target
func (z *ZAPClient) SpiderURL(target string) error {
	url := fmt.Sprintf("%s/JSON/spider/action/scan/?apikey=%s&url=%s", z.BaseURL, z.APIKey, target)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("spider error: %v", err)
	}
	defer resp.Body.Close()
	return nil
}

// RunFullZAPScan performs spider, active scan, filtering alerts, saves JSON & generates HTML report
func RunFullZAPScan(targetURL, host, port, apiKey string) error {
	client := &ZAPClient{
		BaseURL: fmt.Sprintf("http://%s:%s", host, port),
		APIKey:  apiKey,
	}

	fmt.Println("📡 Crawling target to populate scan tree...")
	if err := client.SpiderURL(targetURL); err != nil {
		return fmt.Errorf("spider failed: %v", err)
	}
	time.Sleep(5 * time.Second)

	fmt.Println("🚀 Starting active scan on:", targetURL)
	scanID, err := client.StartScan(targetURL)
	if err != nil {
		return fmt.Errorf("failed to start scan: %v", err)
	}

	fmt.Println("🌀 Scan started with ID:", scanID)
	fmt.Println("⏳ Waiting for scan to complete...")
	if err := client.WaitForCompletion(scanID); err != nil {
		return fmt.Errorf("scan wait failed: %v", err)
	}

	fmt.Println("📥 Fetching alerts...")
	alerts, err := client.GetAlerts(targetURL)
	if err != nil {
		return fmt.Errorf("failed to fetch alerts: %v", err)
	}

	if len(alerts) == 0 {
		fmt.Println("✅ No alerts found!")
	} else {
		fmt.Printf("⚠️ Found %d alerts in total\n", len(alerts))
	}

	filtered := filterImportantAlerts(alerts)
	if len(filtered) > 0 {
		printAlerts(filtered)
	} else {
		fmt.Println("ℹ️ No high or medium risk alerts to display.")
	}

	// Save filtered results
	scanResult := reports.ScanResult{
		TargetURL: targetURL,
		ScanID:    scanID,
		Timestamp: time.Now().Format(time.RFC3339),
		Alerts:    filtered,
	}

	_ = os.MkdirAll("reports", 0755)
	jsonPath := filepath.Join("reports", "results.json")

	file, err := os.Create(jsonPath)
	if err != nil {
		return fmt.Errorf("failed to create results.json: %v", err)
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(scanResult); err != nil {
		return fmt.Errorf("failed to encode results.json: %v", err)
	}

	fmt.Println("📝 JSON report saved to:", jsonPath)

	// Always generate HTML report, even if alerts are empty
	if err := reports.GenerateHTMLReport(jsonPath); err != nil {
		return fmt.Errorf("failed to generate HTML report: %v", err)
	}

	fmt.Println("📄 HTML report generated.")
	return nil
}

// filterImportantAlerts returns only high and medium risk alerts
func filterImportantAlerts(alerts []map[string]interface{}) []map[string]interface{} {
	filtered := []map[string]interface{}{}
	for _, alert := range alerts {
		risk := fmt.Sprintf("%v", alert["risk"])
		if risk == "High" || risk == "Medium" {
			filtered = append(filtered, alert)
		}
	}
	return filtered
}

// printAlerts prints filtered alerts to console
func printAlerts(alerts []map[string]interface{}) {
	for _, alert := range alerts {
		fmt.Println("--------- ALERT ---------")
		fmt.Printf("Risk:        %v\n", alert["risk"])
		fmt.Printf("Alert:       %v\n", alert["alert"])
		fmt.Printf("URL:         %v\n", alert["url"])
		fmt.Printf("Description: %v\n", alert["desc"])
		fmt.Printf("Solution:    %v\n", alert["solution"])
		fmt.Println("-------------------------")
	}
}
