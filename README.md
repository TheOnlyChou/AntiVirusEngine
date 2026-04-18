# AntivirusEngine

AntivirusEngine is an educational Go project that explores how a modular static malware scanning pipeline can be built step by step.

It started as a simple hash-based scanner and has gradually evolved into a multi-stage static analysis engine with support for hash matching, YARA scanning, PE analysis, suspicious import detection, entropy-based signals, heuristic checks, and recursive directory scanning.

This project is intended for learning, experimentation, and portfolio purposes. It is **not** production antivirus software.

---

## Current Features

### File hashing and signature matching
- Computes **MD5**, **SHA1**, and **SHA256**
- Loads known hash signatures from `rules/signatures.json`
- Detects exact file matches against a local signature database

### YARA-based scanning
- Supports YARA scanning through the external `yara` CLI binary
- Loads `.yar` / `.yara` rules from the `rules/` directory
- Integrates YARA matches into the global detection pipeline

### PE static analysis
- Detects Windows **PE** files
- Extracts PE metadata such as:
  - machine type
  - entry point
  - image base
  - section count
  - subsystem
  - imported symbol count
- Includes PE metadata in JSON output

### Suspicious import detection
- Extracts imported symbols from PE files
- Matches them against a local suspicious import dataset in `data/pe/suspicious_imports.json`

### Entropy analysis
- Computes file entropy as a weak static signal
- Uses entropy to enrich scoring without treating it as a standalone malicious verdict

### Heuristic checks
- Supports basic static heuristic detection for suspicious strings and patterns
- Intended to complement hash, YARA, and PE-based detections

### Recursive directory scanning
- Can scan both a **single file** and a **directory**
- Supports recursive traversal of subdirectories
- Produces aggregated directory scan summaries:
  - total files scanned
  - clean files
  - suspicious files
  - malicious files
  - files with detections
  - skipped files

### Output formats
- Human-readable terminal output
- JSON output
- JSON report export to file

---

## Project Layout

```text
.
├── cmd
│   └── av
│       └── main.go
├── data
│   └── pe
│       └── suspicious_imports.json
├── internal
│   ├── cli
│   │   └── cli.go
│   ├── hashing
│   │   └── hasher.go
│   ├── heuristics
│   │   └── checker.go
│   ├── model
│   │   └── types.go
│   ├── pe
│   │   ├── analyzer.go
│   │   ├── entropy.go
│   │   └── imports.go
│   ├── scanner
│   │   └── engine.go
│   ├── signatures
│   │   └── matcher.go
│   └── yara
│       └── yara.go
├── reports
├── rules
│   ├── example_test.yar
│   └── signatures.json
└── samples