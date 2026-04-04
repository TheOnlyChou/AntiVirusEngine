# AntivirusEngine

AntivirusEngine is an educational Go project for learning how a simple antivirus pipeline can be organized. It focuses on hash-based file scanning first, with later phases reserved for YARA, PE analysis, and heuristics.

## What it does now

- Computes MD5, SHA1, and SHA256 for a file
- Loads hash signatures from `rules/signatures.json`
- Matches hashes against known signatures
- Prints a clean terminal result or JSON output

## Project Layout

- `cmd/av` - CLI entry point
- `internal/hashing` - file hashing
- `internal/signatures` - signature loading and matching
- `internal/scanner` - scan orchestration
- `internal/model` - shared scan types
- `internal/cli` - command-line handling
- `rules` - local signature data
- `samples` - safe test files
- `reports` - generated output files

## Run

```bash
go build ./cmd/av
./av scan --file /path/to/file
./av scan --file /path/to/file --format json --report reports/result.json
```

## Notes

- This is a student project, not production antivirus software.
- YARA, PE analysis, and heuristics are planned for later phases.
- The code is intentionally small, modular, and easy to extend.