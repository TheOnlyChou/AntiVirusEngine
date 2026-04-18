package scanner

import "github.com/theonlychou/antivirusengine/internal/model"

type scanJob struct {
	path string
}

type scanOutcome struct {
	path   string
	result *model.ScanResult
	err    error
}
