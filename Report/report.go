package reports

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"time"
)

// Alert defines the structure of a ZAP scan alert
type Alert struct {
	Alert    string `json:"alert"`
	Name     string `json:"name"`
	Risk     string `json:"risk"`
	Desc     string `json:"description"`
	Solution string `json:"solution"`
	Param    string `json:"param"`
	Evidence string `json:"evidence"`
	URL      string `json:"url"`
}

// ScanResult is the full structure of scan result
type ScanResult struct {
	TargetURL string                   `json:"target_url"`
	ScanID    string                   `json:"scan_id"`
	Timestamp string                   `json:"timestamp"`
	Alerts    []map[string]interface{} `json:"alerts"`
}

// HTMLReportData is passed to the HTML template
type HTMLReportData struct {
	Title       string
	Date        string
	TargetURL   string
	ScanID      string
	AlertCount  int
	Alerts      []Alert
	HighCount   int
	MediumCount int
	LowCount    int
	InfoCount   int
}

// Helper to count risk levels
func countRisk(alerts []Alert, level string) int {
	count := 0
	for _, a := range alerts {
		if a.Risk == level {
			count++
		}
	}
	return count
}

// GenerateHTMLReport creates an HTML report from JSON scan results
func GenerateHTMLReport(scanPath string) error {
	file, err := os.ReadFile(scanPath)
	if err != nil {
		return fmt.Errorf("failed to read scan result: %v", err)
	}

	var result ScanResult
	if err := json.Unmarshal(file, &result); err != nil {
		return fmt.Errorf("failed to parse scan result: %v", err)
	}

	var alerts []Alert
	for _, a := range result.Alerts {
		alert := Alert{
			Alert:    toString(a["alert"]),
			Name:     toString(a["name"]),
			Risk:     toString(a["risk"]),
			Desc:     toString(a["description"]),
			Solution: toString(a["solution"]),
			Param:    toString(a["param"]),
			Evidence: toString(a["evidence"]),
			URL:      toString(a["url"]),
		}
		alerts = append(alerts, alert)
	}

	data := HTMLReportData{
		Title:       "Automated Vulnerability Assessment Report",
		Date:        time.Now().Format("02-Jan-2006 15:04:05"),
		TargetURL:   result.TargetURL,
		ScanID:      result.ScanID,
		AlertCount:  len(alerts),
		Alerts:      alerts,
		HighCount:   countRisk(alerts, "High"),
		MediumCount: countRisk(alerts, "Medium"),
		LowCount:    countRisk(alerts, "Low"),
		InfoCount:   countRisk(alerts, "Informational"),
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %v", err)
	}

	_ = os.MkdirAll("reports", 0755)
	fileName := fmt.Sprintf("reports/report_%s.html", time.Now().Format("20060102_150405"))
	fileOut, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to create report file: %v", err)
	}
	defer fileOut.Close()

	err = tmpl.Execute(fileOut, data)
	if err != nil {
		return fmt.Errorf("failed to write HTML report: %v", err)
	}

	fmt.Println("✅ HTML report generated:", fileName)
	return nil
}

// Convert interface{} to string safely
func toString(i interface{}) string {
	if str, ok := i.(string); ok {
		return str
	}
	return ""
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{{ .Title }}</title>
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      margin: 0;
      color: #333;
      background-color: #f4f4f4;
    }
    pre.logo {
      font-family: monospace;
      font-size: 12px;
      line-height: 14px;
      white-space: pre-wrap;
      text-align: center;
      color: #ddd;
      margin: 0;
    }
    .header {
      background-color: #2d3e50;
      color: #fff;
      text-align: center;
      padding: 20px;
    }
    .footer {
      background-color: #2d3e50;
      color: #fff;
      text-align: center;
      padding: 15px;
      font-size: 13px;
    }
    .section {
      margin: 40px auto;
      background: #fff;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
      width: 80%;
    }
    .alert {
      border-left: 5px solid #c0392b;
      padding-left: 15px;
      margin-bottom: 20px;
    }
    .risk-High { color: red; }
    .risk-Medium { color: orange; }
    .risk-Low { color: green; }
    .risk-Informational { color: blue; }
    table {
      width: 60%;
      margin: 0 auto;
      border-collapse: collapse;
    }
    th, td {
      border: 1px solid #999;
      padding: 8px;
      text-align: center;
    }
    th {
      background-color: #eaeaea;
    }
  </style>
</head>
<body>

<div class="header">
  <pre class="logo">
██████╗ ██████╗ ██████╗ ███████╗██████╗  ██████╗  ██████╗  ██████╗ 
██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝ 
██████╔╝██║   ██║██████╔╝█████╗  ██████╔╝██║   ██║██║   ██║██║  ███╗
██╔═══╝ ██║   ██║██╔═══╝ ██╔══╝  ██╔═══╝ ██║   ██║██║   ██║██║   ██║
██║     ╚██████╔╝██║     ███████╗██║     ╚██████╔╝╚██████╔╝╚██████╔╝
╚═╝      ╚═════╝ ╚═╝     ╚══════╝╚═╝      ╚═════╝  ╚═════╝  ╚═════╝ 
                     <strong>CyberScan Inc.</strong>
  </pre>
  <h1>{{ .Title }}</h1>
  <p><strong>Date:</strong> {{ .Date }}</p>
  <p><strong>Target:</strong> {{ .TargetURL }}</p>
  <p><strong>Scan ID:</strong> {{ .ScanID }}</p>
</div>

<div class="section">
  <h2>1. Executive Summary</h2>
  <p>This report summarizes findings from an automated security scan using the Modular Payload Generator Tool and OWASP ZAP. It outlines discovered vulnerabilities including XSS, SQLi, and CMDi in the target application.</p>
</div>

<div class="section">
  <h2>2. Methodology</h2>
  <ul>
    <li>Payload generation (XSS, SQLi, CMDi)</li>
    <li>Encoding, obfuscation, and WAF bypass</li>
    <li>Automatic injection and fuzzing</li>
    <li>Active scan using OWASP ZAP Daemon API</li>
    <li>Alert analysis and structured report generation</li>
  </ul>
</div>

<div class="section">
  <h2>3. Vulnerability Summary ({{ .AlertCount }} Total)</h2>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    <tr><td style="color:red;"><strong>High</strong></td><td>{{.HighCount}}</td></tr>
    <tr><td style="color:orange;"><strong>Medium</strong></td><td>{{.MediumCount}}</td></tr>
    <tr><td style="color:green;"><strong>Low</strong></td><td>{{.LowCount}}</td></tr>
    <tr><td style="color:blue;"><strong>Informational</strong></td><td>{{.InfoCount}}</td></tr>
  </table>
</div>

<div class="section">
  <h2>4. Detailed Findings</h2>
  {{range .Alerts}}
  <div class="alert">
    <h3>{{.Alert}}</h3>
    <p><strong>Risk:</strong> <span class="risk-{{.Risk}}">{{.Risk}}</span></p>
    <p><strong>Parameter:</strong> {{.Param}}</p>
    <p><strong>Evidence:</strong> {{.Evidence}}</p>
    <p><strong>Description:</strong> {{.Desc}}</p>
    <p><strong>Solution:</strong> {{.Solution}}</p>
    <p><strong>URL:</strong> {{.URL}}</p>
  </div>
  {{end}}
</div>

<div class="footer">
  <p>&copy; {{ .Date }} — CyberScan Inc. | Report generated by PayloadGen Toolkit</p>
</div>

</body>
</html>
`
