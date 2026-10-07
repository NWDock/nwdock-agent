package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nowhere.local/agent/internal/keypin"
)

func TestLoadConfigAbsDataDir(t *testing.T) {
	t.Setenv("AGENT_RUNTIME", "service")
	t.Setenv("AGENT_DATA_DIR", "./data/agent-demo1")
	t.Setenv("AGENT_PANEL_ENDPOINTS", "https://panel.example")
	t.Setenv("AGENT_PANEL_KEYPIN", "abc")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(cfg.DataDir) || filepath.Base(cfg.DataDir) != "agent-demo1" {
		t.Fatal(cfg.DataDir)
	}
}

func TestLoadConfigNormalizesEndpoint(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://panel.example:8089", "wss://panel.example:8089/api/agent/channel"},
		{"http://panel.example:8088/", "ws://panel.example:8088/api/agent/channel"},
		{"ws://10.0.0.9:8088", "ws://10.0.0.9:8088/api/agent/channel"},
		{"panel.example", "wss://panel.example/api/agent/channel"},
	} {
		t.Setenv("AGENT_RUNTIME", "service")
		t.Setenv("AGENT_DATA_DIR", "/tmp/agent-data")
		t.Setenv("AGENT_PANEL_ENDPOINTS", tc.in)
		t.Setenv("AGENT_PANEL_KEYPIN", "abc")
		cfg, err := LoadConfig("")
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Endpoints) != 1 || cfg.Endpoints[0] != tc.want {
			t.Fatalf("%q -> %v", tc.in, cfg.Endpoints)
		}
	}
}

func TestLoadConfigEndpointsSplitAndPin(t *testing.T) {
	t.Setenv("AGENT_RUNTIME", "service")
	t.Setenv("AGENT_DATA_DIR", "/tmp/agent-data")
	t.Setenv("AGENT_PANEL_ENDPOINTS", "https://a.example, https://b.example:8443 ,")
	t.Setenv("AGENT_PANEL_KEYPIN", "abc")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Endpoints) != 2 || cfg.Endpoints[1] != "wss://b.example:8443/api/agent/channel" {
		t.Fatal(cfg.Endpoints)
	}
}

func TestLoadConfigKeyPinRequired(t *testing.T) {
	t.Setenv("AGENT_RUNTIME", "service")
	t.Setenv("AGENT_DATA_DIR", "/tmp/agent-data")
	t.Setenv("AGENT_PANEL_ENDPOINTS", "https://panel.example")
	t.Setenv("AGENT_PANEL_KEYPIN", "")
	if _, err := LoadConfig(""); err == nil || !strings.Contains(err.Error(), "AGENT_PANEL_KEYPIN") {
		t.Fatalf("want AGENT_PANEL_KEYPIN required, got %v", err)
	}
}

func TestLoadConfigLegacyPinRejected(t *testing.T) {
	t.Setenv("AGENT_RUNTIME", "service")
	t.Setenv("AGENT_DATA_DIR", "/tmp/agent-data")
	t.Setenv("AGENT_PANEL_ENDPOINTS", "https://panel.example")
	t.Setenv("AGENT_PANEL_KEYPIN", "")
	t.Setenv("AGENT_PANEL_SPKI_PIN", "old-spki")
	_, err := LoadConfig("")
	if err == nil || !strings.Contains(err.Error(), "AGENT_PANEL_SPKI_PIN") || !strings.Contains(err.Error(), "AGENT_PANEL_KEYPIN") {
		t.Fatalf("want rename hint, got %v", err)
	}
}

func TestLoadConfigLegacyEnrollToken(t *testing.T) {
	t.Setenv("AGENT_RUNTIME", "docker")
	t.Setenv("AGENT_DATA_DIR", "")
	t.Setenv("AGENT_PANEL_ENDPOINTS", "https://panel.example")
	t.Setenv("AGENT_PANEL_KEYPIN", "abc")
	t.Setenv("AGENT_ENROLL_TOKEN", "")
	t.Setenv("NOWHERE_ENROLL_TOKEN", "once")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "once" {
		t.Fatal(cfg.Token)
	}
}

func TestLoadOrCreateIdentityRoundTrip(t *testing.T) {
	dir := t.TempDir()
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent-identity.key")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	again, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !id.pub.Equal(again.pub) {
		t.Fatal("identity must survive reload")
	}
	sum := keypin.Fingerprint(id.pub)
	if len(sum) != 64 {
		t.Fatal(sum)
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateIdentity(dir); err == nil {
		t.Fatal("want error for bad key length")
	}
}

func TestLoadIdentityTrailingWhitespaceByte(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent-identity.key")
	// 末尾恰好是空白位（0x0a / 0x20）的 64 字节密钥必须能原样读回：
	// 对原始字节做 TrimSpace 会把它啃成 63 字节而误判为坏文件（概率约 2%，表现为偶发无法启动）。
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), priv...)
	raw[len(raw)-1] = '\n'
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !id.pub.Equal(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("identity must survive reload with trailing whitespace byte")
	}
}
