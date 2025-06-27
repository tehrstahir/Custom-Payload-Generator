package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/rajaabdullahnasir/Custom-Payload-Generator/modules"
	"github.com/rajaabdullahnasir/Custom-Payload-Generator/reports"
	"github.com/rajaabdullahnasir/Custom-Payload-Generator/utils"
	"github.com/rajaabdullahnasir/Custom-Payload-Generator/zapapi"
)

var helpText = `
██████╗ ██████╗ ██████╗ ███████╗██████╗  ██████╗  ██████╗  ██████╗ 
██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝ 
██████╔╝██║   ██║██████╔╝█████╗  ██████╔╝██║   ██║██║   ██║██║  ███╗
██╔═══╝ ██║   ██║██╔═══╝ ██╔══╝  ██╔═══╝ ██║   ██║██║   ██║██║   ██║
██║     ╚██████╔╝██║     ███████╗██║     ╚██████╔╝╚██████╔╝╚██████╔╝
╚═╝      ╚═════╝ ╚═╝     ╚══════╝╚═╝      ╚═════╝  ╚═════╝  ╚═════╝ 

Modular Payload Generator Tool by @rajaabdullahnasir

USAGE:
  ./payloadgen [--xss | --sqli | --cmdi | --zapscan | --generate-report] [flags]

FLAGS:
  --xss              Generate XSS payloads
  --sqli             Generate SQL Injection payloads
  --cmdi             Generate Command Injection payloads
  --zapscan          Run an automated ZAP scan
  --target           Target URL (required for --zapscan)
  --zap-host         ZAP daemon host (default: localhost)
  --zap-port         ZAP daemon port (default: 8080)
  --zap-key          ZAP API key
  --generate-report  Generate HTML report from existing ZAP results
  --output           Output format: json, txt, console
  --save             Save output to ./reports/
  --clipboard        Copy output to clipboard
  --help             Show help menu

EXAMPLES:
  ./payloadgen --xss --output=json 
  ./payloadgen --cmdi --output=txt 
  ./payloadgen --sqli
  ./payloadgen --zapscan --target=http://example.com --zap-key=abc123
  ./payloadgen --generate-report

  Enjoy hacking ethically! 🔐
`

func main() {
	// Payload generation flags
	xss := flag.Bool("xss", false, "Generate XSS payloads")
	sqli := flag.Bool("sqli", false, "Generate SQLi payloads")
	cmdi := flag.Bool("cmdi", false, "Generate CMDi payloads")

	// Output options
	output := flag.String("output", "console", "Output format: json, txt, console")
	save := flag.Bool("save", false, "Save output to ./reports/")
	clip := flag.Bool("clipboard", false, "Copy output to clipboard")

	// ZAP scan flags
	zapscan := flag.Bool("zapscan", false, "Run an automated ZAP scan")
	target := flag.String("target", "", "Target URL for scanning")
	zapHost := flag.String("zap-host", "localhost", "ZAP daemon host")
	zapPort := flag.String("zap-port", "8080", "ZAP daemon port")
	zapKey := flag.String("zap-key", "", "ZAP API key")

	// Report flag
	generateReport := flag.Bool("generate-report", false, "Generate HTML report from existing ZAP results")

	// Help
	help := flag.Bool("help", false, "Show help menu")
	flag.Parse()

	// Show help
	if *help || (!*xss && !*sqli && !*cmdi && !*zapscan && !*generateReport) {
		fmt.Println(helpText)
		return
	}

	// Payload Generator
	if *xss {
		payloads, err := modules.GenerateXSSPayloads()
		if err != nil {
			log.Fatalf("❌ Failed to generate XSS payloads: %v", err)
		}
		handleOutput("xss_payloads", payloads, *output, *save, *clip)
	}

	if *sqli {
		payloads, err := modules.GenerateSQLiPayloads()
		if err != nil {
			log.Fatalf("❌ Failed to generate SQLi payloads: %v", err)
		}
		handleOutput("sqli_payloads", payloads, *output, *save, *clip)
	}

	if *cmdi {
		payloads := modules.GenerateCMDiPayloads()
		handleOutput("cmdi_payloads", payloads, *output, *save, *clip)
	}

	// ZAP Scanner
	if *zapscan {
		if *target == "" || *zapKey == "" {
			log.Fatal("❌ Target URL and ZAP API key are required for ZAP scan.")
		}

		err := zapapi.RunFullZAPScan(*target, *zapHost, *zapPort, *zapKey)
		if err != nil {
			log.Fatalf("❌ ZAP Scan failed: %v", err)
		}

		// Automatically generate HTML report from ZAP output
		reportPath := "reports/results.json"
		if _, err := os.Stat(reportPath); err == nil {
			err := reports.GenerateHTMLReport(reportPath)
			if err != nil {
				log.Fatalf("❌ Failed to generate HTML report: %v", err)
			}
		} else {
			log.Println("⚠️ No results.json found. Skipping report generation.")
		}
	}

	// Manual report generation
	if *generateReport {
		reportPath := "reports/results.json"
		if _, err := os.Stat(reportPath); err == nil {
			err := reports.GenerateHTMLReport(reportPath)
			if err != nil {
				log.Fatalf("❌ Failed to generate HTML report: %v", err)
			} else {
				fmt.Println("📄 Report successfully generated.")
			}
		} else {
			log.Println("⚠️ No results.json found. Skipping report generation.")
		}
	}
}

func handleOutput(name string, payloads interface{}, format string, save bool, clip bool) {
	switch format {
	case "json":
		if save {
			err := utils.SaveAsJSON(payloads, name)
			if err != nil {
				log.Printf("⚠️ Could not save JSON: %v", err)
			} else {
				fmt.Printf("✅ Saved %s.json in /reports/\n", name)
			}
		} else {
			utils.PrintToConsole(name, payloads)
		}
	case "txt":
		lines := flattenPayloads(payloads)
		if save {
			err := utils.SaveAsTXT(lines, name)
			if err != nil {
				log.Printf("⚠️ Could not save TXT: %v", err)
			} else {
				fmt.Printf("✅ Saved %s.txt in /reports/\n", name)
			}
		} else {
			utils.PrintToConsole(name, lines)
		}
	case "console":
		utils.PrintToConsole(name, payloads)
	default:
		fmt.Println("❌ Invalid output format. Use json, txt, or console.")
		os.Exit(1)
	}

	if clip {
		lines := flattenPayloads(payloads)
		if len(lines) > 0 {
			err := utils.CopyToClipboard(lines[0])
			if err != nil {
				log.Printf("⚠️ Could not copy to clipboard: %v", err)
			} else {
				fmt.Println("📋 First payload copied to clipboard!")
			}
		}
	}
}

func flattenPayloads(data interface{}) []string {
	var lines []string
	switch v := data.(type) {
	case []modules.XSSPayload:
		for _, p := range v {
			lines = append(lines, p.Payload)
		}
	case []modules.SQLiPayload:
		for _, p := range v {
			lines = append(lines, p.Payload)
		}
	case []modules.CMDPayload:
		for _, p := range v {
			lines = append(lines, p.Original)
		}
	default:
		lines = append(lines, fmt.Sprintf("%v", v))
	}
	return lines
}
