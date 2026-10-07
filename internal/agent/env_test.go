package agent

import "testing"

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
