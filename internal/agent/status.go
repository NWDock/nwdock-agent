package agent

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
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

func clientCertNotAfter(dir string) time.Time {
	data, err := os.ReadFile(filepath.Join(dir, "agent.crt"))
	if err != nil {
		return time.Time{}
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}
	}
	return cert.NotAfter
}
