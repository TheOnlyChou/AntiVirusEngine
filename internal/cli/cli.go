package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/theonlychou/antivirusengine/internal/model"
	"github.com/theonlychou/antivirusengine/internal/scanner"
)

// CLI handles command-line interface operations.
type CLI struct {
	engine *scanner.Engine
	// TODO: Add logging and config
}

// NewCLI creates a new CLI instance.
func NewCLI(engine *scanner.Engine) *CLI {
	return &CLI{
		engine: engine,
	}
}

// Run executes the CLI with provided arguments.
func (c *CLI) Run(args []string) error {
	if len(args) < 1 {
		c.printUsage()
		return nil
	}

	command := args[0]

	switch command {
	case "scan":
		return c.handleScan(args[1:])
	case "version":
		return c.handleVersion()
	case "help":
		c.printUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		c.printUsage()
		return fmt.Errorf("unknown command: %s", command)
	}
}

// handleScan processes the scan command.
// Phase 4: Hash + YARA + PE + heuristics scanning with text/JSON output.
func (c *CLI) handleScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)

	var (
		filePath       = fs.String("file", "", "Path to file or directory to scan")
		recursive      = fs.Bool("recursive", true, "Recursively scan subdirectories when target is a directory")
		workers        = fs.Int("workers", 4, "Number of worker goroutines for directory scans")
		outputFormat   = fs.String("format", "text", "Output format: text, json")
		reportOutput   = fs.String("report", "", "Path to save scan report (optional)")
		scanHashes     = fs.Bool("hashes", true, "Enable hash-based detection")
		scanSignatures = fs.Bool("signatures", true, "Enable signature matching")
		scanYARA       = fs.Bool("yara", true, "Enable YARA rule scanning (Phase 2)")
		scanPE         = fs.Bool("pe", true, "Enable PE analysis (Phase 3)")
		scanHeuristics = fs.Bool("heuristics", true, "Enable heuristic checks (Phase 4)")
	)

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "Error: --file flag is required")
		fs.PrintDefaults()
		return fmt.Errorf("missing required flag: --file")
	}

	opts := model.ScanOptions{
		ScanHashes:     *scanHashes,
		ScanSignatures: *scanSignatures,
		ScanYARA:       *scanYARA,
		ScanPE:         *scanPE,
		ScanHeuristics: *scanHeuristics,
		Workers:        *workers,
	}

	pathInfo, err := os.Stat(*filePath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if pathInfo.IsDir() {
		report, scanErr := c.engine.ScanDirectory(*filePath, opts, *recursive)
		if scanErr != nil {
			return fmt.Errorf("scan failed: %w", scanErr)
		}

		if *outputFormat == "json" {
			return c.outputReportJSON(report, *reportOutput)
		}

		c.outputReportText(report)
		if *reportOutput != "" {
			return c.saveJSONToFile(report, *reportOutput)
		}
		return nil
	}

	// Single-file scan behavior remains unchanged.
	result, scanErr := c.engine.ScanFile(*filePath, opts)
	if scanErr != nil {
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	if *outputFormat == "json" {
		return c.outputJSON(result, *reportOutput)
	} else {
		c.outputText(result)
		if *reportOutput != "" {
			return c.saveJSONToFile(result, *reportOutput)
		}
	}

	return nil
}

// outputText prints scan result in human-readable format.
func (c *CLI) outputText(result *model.ScanResult) {
	separator := strings.Repeat("=", 70)

	fmt.Println()
	fmt.Println(separator)
	fmt.Println("ANTIVIRUS ENGINE - SCAN RESULT")
	fmt.Println(separator)
	fmt.Println()

	// File information
	fmt.Printf("File Path:       %s\n", result.FilePath)
	fmt.Printf("File Name:       %s\n", result.FileName)
	fmt.Printf("File Size:       %d bytes\n", result.FileSize)
	fmt.Printf("Last Modified:   %s\n", result.LastModified.Format(time.RFC3339))
	fmt.Println()

	// Hashes
	fmt.Println("HASHES:")
	fmt.Printf("  MD5:           %s\n", result.Hashes.MD5)
	fmt.Printf("  SHA1:          %s\n", result.Hashes.SHA1)
	fmt.Printf("  SHA256:        %s\n", result.Hashes.SHA256)
	fmt.Println()

	// Detections
	fmt.Println("DETECTIONS:")
	if len(result.Detections) == 0 {
		fmt.Println("  (No detections)")
	} else {
		for i, det := range result.Detections {
			fmt.Printf("  [%d] %s\n", i+1, det.Name)
			fmt.Printf("      Engine:    %s\n", det.Engine)
			fmt.Printf("      Type:      %s\n", det.Type)
			fmt.Printf("      Severity:  %s\n", det.Severity)
			fmt.Printf("      Score:     %.2f\n", det.Score)
			fmt.Printf("      Message:   %s\n", det.Message)
		}
	}
	fmt.Println()

	// Verdict
	fmt.Printf("VERDICT:         %s\n", result.Verdict)
	fmt.Printf("RISK SCORE:      %.2f\n", result.TotalScore)
	fmt.Printf("Scan Time:       %v\n", result.ScanDuration)
	fmt.Println()
	fmt.Println(separator)
	fmt.Println()
}

// outputJSON prints scan result in JSON format.
func (c *CLI) outputJSON(result *model.ScanResult, reportPath string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))

	if reportPath != "" {
		return c.saveJSONToFile(result, reportPath)
	}

	return nil
}

// outputReportJSON prints directory report in JSON format.
func (c *CLI) outputReportJSON(report *model.Report, reportPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))

	if reportPath != "" {
		return c.saveJSONToFile(report, reportPath)
	}

	return nil
}

// saveJSONToFile writes any scan payload to a JSON file.
func (c *CLI) saveJSONToFile(payload interface{}, filePath string) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Report saved to: %s\n", filePath)
	return nil
}

// outputReportText prints a human-readable summary for directory scans.
func (c *CLI) outputReportText(report *model.Report) {
	separator := strings.Repeat("=", 70)

	fmt.Println()
	fmt.Println(separator)
	fmt.Println("ANTIVIRUS ENGINE - DIRECTORY SCAN SUMMARY")
	fmt.Println(separator)
	fmt.Println()

	fmt.Printf("Total Files Scanned:   %d\n", report.TotalFiles)
	fmt.Printf("Clean Files:           %d\n", report.CleanFiles)
	fmt.Printf("Suspicious Files:      %d\n", report.SuspiciousFiles)
	fmt.Printf("Malicious Files:       %d\n", report.MaliciousFiles)
	fmt.Printf("Files With Detections: %d\n", report.FilesWithDetections)
	fmt.Printf("Skipped Files:         %d\n", report.SkippedFiles)
	fmt.Printf("Total Scan Time:       %v\n", report.TotalDuration)
	fmt.Println()

	if len(report.ScanResults) > 0 {
		fmt.Println("FILE RESULTS:")
		for _, r := range report.ScanResults {
			fmt.Printf("  - %s | Verdict: %s | Detections: %d | Score: %.2f\n", r.FilePath, r.Verdict, len(r.Detections), r.TotalScore)
		}
		fmt.Println()
	}

	fmt.Println(separator)
	fmt.Println()
}

// handleVersion displays version information.
func (c *CLI) handleVersion() error {
	fmt.Println("AntivirusEngine v0.1.0")
	fmt.Println("Educational antivirus engine for cybersecurity learning")
	fmt.Println("Phase 4: Hash + YARA + PE + heuristic detection")
	return nil
}

// printUsage displays the CLI usage information.
func (c *CLI) printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: av <command> [options]

Commands:
	scan        Scan a file for malware (hash + YARA + PE + heuristics, Phase 4)
  version     Show version information
  help        Show this help message

Examples:
  av scan --file /path/to/file
  av scan --file test.exe --format json
  av scan --file test.txt --report result.json

Scan Flags:
  --file <path>          Path to file to scan (required)
	--recursive <true|false> Recursively scan subdirectories when scanning directories (default: true)
	--workers <int>         Worker goroutines for directory scans (default: 4)
  --format <text|json>   Output format: text (default) or json
  --report <path>        Save report to JSON file
  --hashes <true|false>  Enable hash computation (default: true)
  --signatures <true|false> Enable signature matching (default: true)
	--yara <true|false>    Enable YARA rules (Phase 2, default: true)
	--pe <true|false>      Enable PE analysis (Phase 3, default: true)
  --heuristics <true|false> Enable heuristic checks (Phase 4, default: true)

For more information, see README.md
`)
}

// TODO: Phase 2 - Add more CLI commands:
// - update: update signatures and rules
// - validate: validate signature and rule files
// - stats: show engine statistics
// - scan-dir: scan entire directory with results summary
