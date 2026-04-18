package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/theonlychou/antivirusengine/internal/hashing"
	"github.com/theonlychou/antivirusengine/internal/heuristics"
	"github.com/theonlychou/antivirusengine/internal/model"
	"github.com/theonlychou/antivirusengine/internal/pe"
	"github.com/theonlychou/antivirusengine/internal/signatures"
	"github.com/theonlychou/antivirusengine/internal/yara"
)

// Engine is the central scanning orchestrator.
type Engine struct {
	hasher           *hashing.Hasher
	signatureMatcher *signatures.SignatureMatcher
	yaraScanner      *yara.YARAScanner
	peAnalyzer       *pe.PEAnalyzer
	heuristicChecker *heuristics.HeuristicChecker
	initialized      bool
	yaraInitErr      error
	// TODO: Add configuration and logging
}

// NewEngine creates and initializes a new scanning engine.
func NewEngine() *Engine {
	return &Engine{
		hasher:           hashing.NewHasher(),
		signatureMatcher: signatures.NewSignatureMatcher(),
		yaraScanner:      yara.NewYARAScanner("./rules"),
		peAnalyzer:       pe.NewPEAnalyzer(),
		heuristicChecker: heuristics.NewHeuristicChecker(),
		initialized:      false,
		yaraInitErr:      nil,
	}
}

// Initialize sets up the engine (load rules, signatures, etc.).
// Loads signatures and YARA rule metadata.
func (e *Engine) Initialize() error {
	if e.initialized {
		return nil
	}

	// Phase 1: Load hash signatures
	sigPath := "rules/signatures.json"
	if err := e.signatureMatcher.LoadSignatures(sigPath); err != nil {
		return fmt.Errorf("failed to load signatures: %w", err)
	}

	// YARA initialization is captured and surfaced only when YARA scanning is enabled.
	e.yaraInitErr = e.yaraScanner.LoadRules()

	e.initialized = true
	return nil
}

// ScanFile performs a complete scan on a single file.
// Phase 1 implementation: Hash-based detection only
func (e *Engine) ScanFile(filePath string, opts model.ScanOptions) (*model.ScanResult, error) {
	startTime := time.Now()

	// Initialize engine if not already done
	if !e.initialized {
		if err := e.Initialize(); err != nil {
			return nil, err
		}
	}

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if fileInfo.IsDir() {
		return nil, fmt.Errorf("path is a directory, not a file")
	}

	// Phase 1: Compute file hashes
	hashes, err := e.hasher.ComputeHashes(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hashes: %w", err)
	}

	// Initialize detections
	var detections []model.Detection

	// Phase 1: Hash-based signature matching
	if opts.ScanHashes && opts.ScanSignatures {
		hashDetections := e.signatureMatcher.MatchHash(hashes.MD5, hashes.SHA1, hashes.SHA256)
		detections = append(detections, hashDetections...)
	}

	// Phase 2: YARA scanning
	if opts.ScanYARA {
		if e.yaraInitErr == nil {
			yaraDetections, scanErr := e.yaraScanner.Scan(filePath)
			if scanErr != nil {
				return nil, fmt.Errorf("YARA scan failed: %w", scanErr)
			}
			detections = append(detections, yaraDetections...)
		} else {
			// TODO: Add warning propagation in ScanResult to surface skipped YARA checks.
		}
	}

	var peMetadata map[string]interface{}

	// Phase 3: PE static analysis
	if opts.ScanPE {
		isPE, peCheckErr := e.peAnalyzer.IsExecutable(filePath)
		if peCheckErr != nil {
			return nil, fmt.Errorf("PE detection failed: %w", peCheckErr)
		}

		if isPE {
			metadata, metadataErr := e.peAnalyzer.ExtractMetadata(filePath)
			if metadataErr != nil {
				return nil, fmt.Errorf("PE metadata extraction failed: %w", metadataErr)
			}
			peMetadata = metadata

			peDetections, peAnalyzeErr := e.peAnalyzer.AnalyzeFile(filePath)
			if peAnalyzeErr != nil {
				return nil, fmt.Errorf("PE analysis failed: %w", peAnalyzeErr)
			}
			detections = append(detections, peDetections...)
		}
	}

	// Phase 4: static heuristic analysis
	if opts.ScanHeuristics {
		heuristicDetections, heuristicErr := e.heuristicChecker.CheckFile(filePath, peMetadata)
		if heuristicErr != nil {
			return nil, fmt.Errorf("heuristic analysis failed: %w", heuristicErr)
		}
		detections = append(detections, heuristicDetections...)
	}

	// TODO: Add cross-engine correlation between PE imports, entropy, and string heuristics.

	totalScore := e.computeScore(detections)

	// Compute verdict based on detections
	verdict := e.computeVerdict(detections, totalScore)

	result := &model.ScanResult{
		FilePath:     filePath,
		FileName:     filepath.Base(filePath),
		FileSize:     fileInfo.Size(),
		LastModified: fileInfo.ModTime(),
		Hashes:       hashes,
		PEMetadata:   peMetadata,
		Detections:   detections,
		Verdict:      verdict,
		TotalScore:   totalScore,
		ScanDuration: time.Since(startTime),
		ScanTime:     startTime,
	}

	return result, nil
}

// ScanDirectory scans files in a directory.
// When recursive is true, subdirectories are scanned recursively.
func (e *Engine) ScanDirectory(dirPath string, opts model.ScanOptions, recursive bool) (*model.Report, error) {
	start := time.Now()

	if !e.initialized {
		if err := e.Initialize(); err != nil {
			return nil, err
		}
	}

	rootInfo, err := os.Stat(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat directory: %w", err)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("path is not a directory")
	}

	targetFiles, skippedDuringDiscovery, collectErr := collectTargetFiles(dirPath, recursive)
	if collectErr != nil {
		return nil, collectErr
	}

	report := &model.Report{
		ReportID:      fmt.Sprintf("scan-%d", start.UnixNano()),
		GeneratedAt:   start,
		ScanResults:   make([]model.ScanResult, 0),
		SkippedFiles:  skippedDuringDiscovery,
		TotalDuration: 0,
	}

	workers := opts.Workers
	if workers < 1 {
		workers = 1
	}
	if workers > len(targetFiles) && len(targetFiles) > 0 {
		workers = len(targetFiles)
	}

	jobs := make(chan scanJob)
	outcomes := make(chan scanOutcome)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				result, scanErr := e.ScanFile(job.path, opts)
				outcomes <- scanOutcome{path: job.path, result: result, err: scanErr}
			}
		}()
	}

	go func() {
		for _, path := range targetFiles {
			jobs <- scanJob{path: path}
		}
		close(jobs)
		wg.Wait()
		close(outcomes)
	}()

	for out := range outcomes {
		if out.err != nil {
			report.SkippedFiles++
			continue
		}

		report.ScanResults = append(report.ScanResults, *out.result)
		report.TotalFiles++

		if len(out.result.Detections) > 0 {
			report.FilesWithDetections++
		}

		switch out.result.Verdict {
		case model.VerdictClean:
			report.CleanFiles++
		case model.VerdictSuspicious:
			report.SuspiciousFiles++
		case model.VerdictMalicious:
			report.MaliciousFiles++
		}
	}

	sort.Slice(report.ScanResults, func(i, j int) bool {
		return report.ScanResults[i].FilePath < report.ScanResults[j].FilePath
	})

	report.TotalDuration = time.Since(start)
	return report, nil
}

func collectTargetFiles(dirPath string, recursive bool) ([]string, int, error) {
	targetFiles := make([]string, 0)
	skipped := 0

	if recursive {
		walkErr := filepath.WalkDir(dirPath, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				skipped++
				return nil
			}

			if d.IsDir() {
				return nil
			}

			info, infoErr := d.Info()
			if infoErr != nil {
				skipped++
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}

			targetFiles = append(targetFiles, path)
			return nil
		})
		if walkErr != nil {
			return nil, skipped, fmt.Errorf("failed to walk directory: %w", walkErr)
		}
		return targetFiles, skipped, nil
	}

	entries, readErr := os.ReadDir(dirPath)
	if readErr != nil {
		return nil, skipped, fmt.Errorf("failed to read directory: %w", readErr)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, infoErr := entry.Info()
		if infoErr != nil {
			skipped++
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}

		targetFiles = append(targetFiles, filepath.Join(dirPath, entry.Name()))
	}

	return targetFiles, skipped, nil
}

// GetEngineStatistics returns information about the scanning engine state.
func (e *Engine) GetEngineStatistics() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["initialized"] = e.initialized
	stats["signatures"] = e.signatureMatcher.GetStatistics()
	stats["yara"] = e.yaraScanner.GetRuleStatistics()
	if e.yaraInitErr != nil {
		stats["yara_error"] = e.yaraInitErr.Error()
	}
	return stats
}

// computeScore calculates the average score across all detections.
func (e *Engine) computeScore(detections []model.Detection) float64 {
	if len(detections) == 0 {
		return 0.0
	}

	scoreSum := 0.0
	for _, det := range detections {
		scoreSum += det.Score
	}

	return scoreSum / float64(len(detections))
}

// computeVerdict determines the verdict based on detected threats and score.
func (e *Engine) computeVerdict(detections []model.Detection, totalScore float64) model.Verdict {
	// No detections = clean
	if len(detections) == 0 {
		return model.VerdictClean
	}

	// Use score thresholds
	if totalScore >= 0.75 {
		return model.VerdictMalicious
	} else if totalScore >= 0.50 {
		return model.VerdictSuspicious
	}

	// Low score detection = suspicious
	return model.VerdictSuspicious
}
