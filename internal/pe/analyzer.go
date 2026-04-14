package pe

import (
	"debug/pe"
	"fmt"
	"time"

	"github.com/theonlychou/antivirusengine/internal/model"
)

// PEAnalyzer handles static analysis of PE (Portable Executable) files.
type PEAnalyzer struct {
	suspiciousImportsPath string
}

// NewPEAnalyzer creates a new PEAnalyzer instance.
func NewPEAnalyzer() *PEAnalyzer {
	return &PEAnalyzer{
		suspiciousImportsPath: "data/pe/suspicious_imports.json",
	}
}

// IsExecutable checks if a file is a valid PE executable.
func (pa *PEAnalyzer) IsExecutable(filePath string) (bool, error) {
	f, err := pe.Open(filePath)
	if err != nil {
		// Not a PE file is a normal non-error outcome for this educational engine.
		return false, nil
	}
	defer f.Close()

	return true, nil
}

// AnalyzeFile performs static analysis on a PE file.
// Returns import and entropy-related detections for PE files.
func (pa *PEAnalyzer) AnalyzeFile(filePath string) ([]model.Detection, error) {
	detections := make([]model.Detection, 0)

	imports, err := pa.ExtractImports(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract imports: %w", err)
	}

	rules, err := LoadSuspiciousImports(pa.suspiciousImportsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load suspicious import dataset: %w", err)
	}

	importDetections := DetectSuspiciousImports(imports, rules)
	detections = append(detections, importDetections...)

	entropy, err := CalculateFileEntropy(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate entropy: %w", err)
	}

	// Treat entropy as a weak signal, not an automatic malicious verdict.
	if entropy >= 7.80 {
		detections = append(detections, model.Detection{
			Engine:    "PEEntropy",
			Name:      "High File Entropy",
			Severity:  "MEDIUM",
			Score:     0.35,
			Message:   fmt.Sprintf("File entropy is high (%.2f), which may indicate packing or encryption", entropy),
			Type:      "entropy",
			Timestamp: model.GetCurrentTime(),
		})
	} else if entropy >= 7.20 {
		detections = append(detections, model.Detection{
			Engine:    "PEEntropy",
			Name:      "Elevated File Entropy",
			Severity:  "LOW",
			Score:     0.20,
			Message:   fmt.Sprintf("File entropy is elevated (%.2f); treat as a weak suspicious signal", entropy),
			Type:      "entropy",
			Timestamp: model.GetCurrentTime(),
		})
	}

	// TODO: Add section-level entropy analysis for .text/.rsrc/.data sections.
	// TODO: Add richer PE checks: exports, resources, signature presence, and overlay size.

	return detections, nil
}

// ExtractMetadata extracts metadata from a PE file.
func (pa *PEAnalyzer) ExtractMetadata(filePath string) (map[string]interface{}, error) {
	f, err := pe.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("not a valid PE file: %w", err)
	}
	defer f.Close()

	metadata := make(map[string]interface{})
	metadata["machine"] = fmt.Sprintf("0x%04x", f.FileHeader.Machine)
	metadata["number_of_sections"] = f.FileHeader.NumberOfSections
	metadata["time_date_stamp"] = time.Unix(int64(f.FileHeader.TimeDateStamp), 0).UTC().Format(time.RFC3339)
	metadata["characteristics"] = fmt.Sprintf("0x%04x", f.FileHeader.Characteristics)

	if libs, libsErr := f.ImportedLibraries(); libsErr == nil {
		metadata["imported_libraries"] = libs
		metadata["imported_libraries_count"] = len(libs)
	}

	if syms, symsErr := f.ImportedSymbols(); symsErr == nil {
		metadata["imported_symbols_count"] = len(syms)
	}

	sections := make([]map[string]interface{}, 0, len(f.Sections))
	for _, sec := range f.Sections {
		sections = append(sections, map[string]interface{}{
			"name":            sec.Name,
			"virtual_size":    sec.VirtualSize,
			"virtual_address": sec.VirtualAddress,
			"raw_size":        sec.Size,
		})
	}
	metadata["sections"] = sections

	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		metadata["pe_type"] = "PE32"
		metadata["entry_point"] = fmt.Sprintf("0x%08x", oh.AddressOfEntryPoint)
		metadata["image_base"] = fmt.Sprintf("0x%08x", oh.ImageBase)
		metadata["subsystem"] = oh.Subsystem
	case *pe.OptionalHeader64:
		metadata["pe_type"] = "PE32+"
		metadata["entry_point"] = fmt.Sprintf("0x%08x", oh.AddressOfEntryPoint)
		metadata["image_base"] = fmt.Sprintf("0x%016x", oh.ImageBase)
		metadata["subsystem"] = oh.Subsystem
	default:
		metadata["pe_type"] = "UNKNOWN"
	}

	return metadata, nil
}

// CheckForPacking checks if a PE file appears to be packed or obfuscated.
// TODO: Implement packing detection heuristics.
func (pa *PEAnalyzer) CheckForPacking(filePath string) (bool, string, error) {
	// TODO: Return (isPacked, packingMethod, error)
	return false, "", nil
}
