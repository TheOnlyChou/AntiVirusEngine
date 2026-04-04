package hashing

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/theonlychou/antivirusengine/internal/model"
)

// Hasher provides file hashing functionality.
type Hasher struct {
	// TODO: Add configuration for hash algorithm selection
}

// NewHasher creates a new Hasher instance.
func NewHasher() *Hasher {
	return &Hasher{}
}

// ComputeHashes calculates MD5, SHA1, and SHA256 hashes for a file.
// It streams the file to handle large files efficiently without loading them entirely into memory.
func (h *Hasher) ComputeHashes(filePath string) (*model.FileHashes, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Create hash objects
	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()

	// Use MultiWriter to compute all hashes in a single pass
	if _, err := io.Copy(io.MultiWriter(md5h, sha1h, sha256h), file); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return &model.FileHashes{
		MD5:    fmt.Sprintf("%x", md5h.Sum(nil)),
		SHA1:   fmt.Sprintf("%x", sha1h.Sum(nil)),
		SHA256: fmt.Sprintf("%x", sha256h.Sum(nil)),
	}, nil
}

// IsFileModified checks if a file has been modified since last scan.
// TODO: Phase 2 - Implement file modification tracking for incremental scans.
func (h *Hasher) IsFileModified(filePath string, lastKnownHash string) (bool, error) {
	// TODO: Compare provided hash with computed hash
	return false, nil
}
