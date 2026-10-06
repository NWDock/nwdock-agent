package agent

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"nowhere.local/agent/internal/certpin"
)

func TestLoadConfigAbsDataDir(t *testing.T) {
	t.Setenv("AGENT_RUNTIME", "service")
	t.Setenv("AGENT_DATA_DIR", "./data/agent-demo1")
	t.Setenv("AGENT_PANEL_ENDPOINTS", "https://panel.example:8089")
	t.Setenv("AGENT_PANEL_SPKI_PIN", "abc")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(cfg.DataDir) || filepath.Base(cfg.DataDir) != "agent-demo1" {
		t.Fatal(cfg.DataDir)
	}
}

func TestEnrollRejectedKeepsKey(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	cert, err := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "agent.key")
	existing := "existing-key"
	if err := os.WriteFile(keyPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Runtime:   "service",
		DataDir:   dir,
		Endpoints: []string{srv.URL},
		Pin:       certpin.SPKI(cert),
		Token:     "spent",
	}
	if _, err := enrollCertificate(context.Background(), cfg, filepath.Join(dir, "agent.crt"), keyPath); err == nil {
		t.Fatal("want error")
	}
	have, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(have) != existing {
		t.Fatal("agent.key was overwritten")
	}
}
