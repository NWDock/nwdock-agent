package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigFileOverridesEnv(t *testing.T) {
	t.Cleanup(ClearFileRuntime)
	dir := t.TempDir()
	body := strings.Join([]string{
		"AGENT_RUNTIME=service",
		"AGENT_DATA_DIR=/var/lib/nowhere-agent",
		"AGENT_PANEL_ENDPOINTS=https://panel.example",
		"AGENT_PANEL_KEYPIN=from-file",
		"AGENT_XRAY_BIN=/usr/local/bin/xray",
		"AGENT_SINGBOX_BIN=/usr/local/bin/sing-box",
		"AGENT_XRAY_API_ADDR=127.0.0.1:10086",
		"",
	}, "\n")
	path := filepath.Join(dir, "agent.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_RUNTIME", "docker")
	t.Setenv("AGENT_DATA_DIR", "/tmp/from-env")
	t.Setenv("AGENT_PANEL_ENDPOINTS", "https://wrong.example")
	t.Setenv("AGENT_PANEL_KEYPIN", "from-env")
	t.Setenv("AGENT_ENROLL_TOKEN", "leftover-token")
	t.Setenv("AGENT_XRAY_BIN", "/tmp/wrong-xray")
	t.Setenv("AGENT_XRAY_API_ADDR", "127.0.0.1:1")
	t.Setenv("DATA_DIR", "/tmp/wrong-data")
	t.Setenv("XRAY_API_ADDR", "127.0.0.1:2")
	t.Setenv("PANEL_DATABASE_URL", "postgres://keep")
	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.fromFile || cfg.Token != "" || cfg.Runtime != "service" || cfg.KeyPin != "from-file" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.DataDir != "/var/lib/nowhere-agent" || len(cfg.Endpoints) != 1 || cfg.Endpoints[0] != "wss://panel.example/api/agent/channel" {
		t.Fatal(cfg.DataDir, cfg.Endpoints)
	}
	if cfg.XrayBin != "/usr/local/bin/xray" || cfg.SingboxBin != "/usr/local/bin/sing-box" || cfg.XrayAPI != "127.0.0.1:10086" {
		t.Fatal(cfg.XrayBin, cfg.SingboxBin, cfg.XrayAPI)
	}
	t.Setenv("AGENT_XRAY_BIN", "/after")
	t.Setenv("AGENT_XRAY_API_ADDR", "127.0.0.1:9")
	if coreBin(coreXray) != "/usr/local/bin/xray" || coreBin(coreSingbox) != "/usr/local/bin/sing-box" || coreAPIAddr() != "127.0.0.1:10086" {
		t.Fatalf("file runtime lost: %s %s %s", coreBin(coreXray), coreBin(coreSingbox), coreAPIAddr())
	}
	if os.Getenv("AGENT_ENROLL_TOKEN") != "" || os.Getenv("DATA_DIR") != "" || os.Getenv("XRAY_API_ADDR") != "" {
		t.Fatal("agent settings remained in the environment")
	}
	if os.Getenv("PANEL_DATABASE_URL") != "postgres://keep" {
		t.Fatal(os.Getenv("PANEL_DATABASE_URL"))
	}
}

func TestLoadConfigFileDefaultsIgnoreEnv(t *testing.T) {
	t.Cleanup(ClearFileRuntime)
	dir := t.TempDir()
	body := "AGENT_RUNTIME=service\nAGENT_PANEL_ENDPOINTS=https://panel.example\nAGENT_PANEL_KEYPIN=from-file\n"
	path := filepath.Join(dir, "agent.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_DATA_DIR", "/tmp/from-env")
	t.Setenv("AGENT_XRAY_API_ADDR", "127.0.0.1:9")
	t.Setenv("AGENT_ENROLL_TOKEN", "leftover-token")
	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wantData := filepath.Join(dir, "data")
	if cfg.DataDir != wantData || cfg.Token != "" || cfg.XrayAPI != "" {
		t.Fatal(cfg.DataDir, cfg.Token, cfg.XrayAPI)
	}
	if coreAPIAddr() != "127.0.0.1:10085" || coreBin(coreXray) != "" {
		t.Fatalf("defaults followed the environment: %s %s", coreAPIAddr(), coreBin(coreXray))
	}
	if os.Getenv("AGENT_ENROLL_TOKEN") != "" {
		t.Fatal("leftover token stayed in the environment")
	}
}

func TestLoadConfigFileLegacyDataDir(t *testing.T) {
	t.Cleanup(ClearFileRuntime)
	dir := t.TempDir()
	body := "AGENT_RUNTIME=service\nDATA_DIR=./legacy-data\nAGENT_PANEL_ENDPOINTS=https://panel.example\nAGENT_PANEL_KEYPIN=from-file\n"
	path := filepath.Join(dir, "agent.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_DATA_DIR", "/tmp/from-env")
	cfg, err := LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != filepath.Join(dir, "legacy-data") {
		t.Fatal(cfg.DataDir)
	}
}

func TestLoadConfigFileRejectsWidePermission(t *testing.T) {
	t.Cleanup(ClearFileRuntime)
	dir := t.TempDir()
	body := "AGENT_RUNTIME=service\nAGENT_PANEL_ENDPOINTS=https://panel.example\nAGENT_PANEL_KEYPIN=from-file\nAGENT_ENROLL_TOKEN=file-token\n"
	path := filepath.Join(dir, "agent.conf")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_ENROLL_TOKEN", "env-token")
	t.Setenv("AGENT_XRAY_API_ADDR", "127.0.0.1:9")
	_, err := LoadConfigFile(path)
	if err == nil || !strings.Contains(err.Error(), "0600") || strings.Contains(err.Error(), "file-token") {
		t.Fatal(err)
	}
	if os.Getenv("AGENT_ENROLL_TOKEN") != "env-token" {
		t.Fatal(os.Getenv("AGENT_ENROLL_TOKEN"))
	}
	if coreAPIAddr() != "127.0.0.1:9" {
		t.Fatal("rejected file changed runtime lookup")
	}
}

func TestLoadConfigFileRejectsInvalidWithoutLeak(t *testing.T) {
	dir := t.TempDir()
	body := "AGENT_ENROLL_TOKEN=file-token\nNOT A LINE\n"
	path := filepath.Join(dir, "agent.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_ENROLL_TOKEN", "env-token")
	_, err := LoadConfigFile(path)
	if err == nil || strings.Contains(err.Error(), "file-token") {
		t.Fatal(err)
	}
	if os.Getenv("AGENT_ENROLL_TOKEN") != "env-token" {
		t.Fatal(os.Getenv("AGENT_ENROLL_TOKEN"))
	}
}

func TestLoadConfigFileMode0400(t *testing.T) {
	t.Cleanup(ClearFileRuntime)
	dir := t.TempDir()
	body := "AGENT_RUNTIME=service\nAGENT_PANEL_ENDPOINTS=https://panel.example\nAGENT_PANEL_KEYPIN=from-file\n"
	path := filepath.Join(dir, "agent.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(path); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigDataDirSplit(t *testing.T) {
	t.Setenv("AGENT_RUNTIME", "service")
	t.Setenv("AGENT_DATA_DIR", "/var/lib/nowhere-agent")
	t.Setenv("DATA_DIR", "/var/lib/nowhere-panel")
	t.Setenv("AGENT_PANEL_ENDPOINTS", "https://panel.example:8089")
	t.Setenv("PANEL_ENDPOINTS", "https://old.example:8089")
	t.Setenv("AGENT_PANEL_KEYPIN", "abc")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "/var/lib/nowhere-agent" {
		t.Fatal(cfg.DataDir)
	}
	if len(cfg.Endpoints) != 1 || cfg.Endpoints[0] != "wss://panel.example:8089/api/agent/channel" || cfg.KeyPin != "abc" {
		t.Fatal(cfg.Endpoints, cfg.KeyPin)
	}
}

func TestLoadConfigLegacyDataDir(t *testing.T) {
	t.Setenv("AGENT_RUNTIME", "docker")
	t.Setenv("AGENT_DATA_DIR", "")
	t.Setenv("DATA_DIR", "/var/lib/nowhere-agent")
	t.Setenv("AGENT_PANEL_ENDPOINTS", "")
	t.Setenv("PANEL_ENDPOINTS", "https://panel.example:8089")
	t.Setenv("AGENT_PANEL_KEYPIN", "pin")
	t.Setenv("AGENT_ENROLL_TOKEN", "")
	t.Setenv("NOWHERE_ENROLL_TOKEN", "once")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "/var/lib/nowhere-agent" || cfg.Token != "once" || cfg.KeyPin != "pin" {
		t.Fatal(cfg.DataDir, cfg.Token, cfg.KeyPin)
	}
}
