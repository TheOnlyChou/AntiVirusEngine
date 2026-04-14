# AntivirusEngine test samples

This folder contains safe sample files used to validate the current detection pipeline of AntivirusEngine.

## Included files

- `clean.txt`  
  A benign text file used to validate the clean scan path.

- `empty.bin`  
  An empty file used to validate hash-based detection when the signature database contains known empty-file hashes.

- `suspicious_powershell.ps1`  
  A PowerShell sample intended for YARA or future heuristic-based detection.  
  At the current stage of the project, this file may not trigger any detection depending on the loaded YARA rules and local environment.

- `eicar.com`  
  The classic harmless EICAR antivirus test string.  
  This file is useful for validating YARA-based detection if an EICAR rule is present and correctly loaded.

- `pe_main.go`  
  Minimal Go source file used to build a Windows PE test binary.

- `build_pe_sample.sh`  
  Helper script to build `sample_pe.exe` locally.

- `sample_pe.exe`  
  A generated Windows PE sample used to validate PE parsing, metadata extraction, import analysis, and entropy calculation.

## What is currently validated

Based on the current implementation:

- `clean.txt` validates the clean path
- `empty.bin` validates hash signature matching
- `sample_pe.exe` validates PE metadata extraction

## What may depend on environment or rules

The following samples depend on YARA availability and rule quality:

- `suspicious_powershell.ps1`
- `eicar.com`

If the `yara` binary is not installed, if rules are not loaded, or if the current rules do not match these samples, they may return `CLEAN`.

## Suggested usage

```bash
./av scan --file samples/av_test_samples/clean.txt
./av scan --file samples/av_test_samples/empty.bin
./av scan --file samples/av_test_samples/suspicious_powershell.ps1
./av scan --file samples/av_test_samples/eicar.com
./av scan --file samples/av_test_samples/sample_pe.exe --format json