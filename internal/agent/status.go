package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

const maxErrorSummary = 512

var statusMu sync.Mutex
var lastError string

func setError(err error) {
	statusMu.Lock()
	defer statusMu.Unlock()
	if err == nil {
		lastError = ""
		return
	}
	msg := err.Error()
	if len(msg) > maxErrorSummary {
		msg = string(bytes.ToValidUTF8([]byte(msg[:maxErrorSummary]), nil))
	}
	lastError = msg
}

func errorSummary() string {
	statusMu.Lock()
	defer statusMu.Unlock()
	return lastError
}

func appliedGeneration(dir string) int {
	raw, err := os.ReadFile(filepath.Join(dir, "applied-generation"))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(string(bytes.TrimSpace(raw)))
	if n < 0 {
		return 0
	}
	return n
}
