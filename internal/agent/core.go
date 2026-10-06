package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"nowhere.local/agent/internal/envfile"
)

type coreKind string

const (
	coreXray    coreKind = "xray"
	coreMihomo  coreKind = "mihomo"
	coreSingbox coreKind = "singbox"
)

func normalizeCore(raw string) coreKind {
	switch raw {
	case string(coreMihomo):
		return coreMihomo
	case string(coreSingbox):
		return coreSingbox
	default:
		return coreXray
	}
}

func coreBinEnv(kind coreKind) string {
	switch kind {
	case coreMihomo:
		return "AGENT_MIHOMO_BIN"
	case coreSingbox:
		return "AGENT_SINGBOX_BIN"
	default:
		return "AGENT_XRAY_BIN"
	}
}

func legacyCoreBinEnv(kind coreKind) string {
	switch kind {
	case coreMihomo:
		return "MIHOMO_BIN"
	case coreSingbox:
		return "SINGBOX_BIN"
	default:
		return "XRAY_BIN"
	}
}

func coreBin(kind coreKind) string {
	value, _ := envfile.First(coreBinEnv(kind), legacyCoreBinEnv(kind))
	return value
}

func coreAPIAddr() string {
	api, _ := envfile.First("AGENT_XRAY_API_ADDR", "XRAY_API_ADDR")
	if api == "" {
		api = "127.0.0.1:10085"
	}
	return api
}

func coreConfigName(kind coreKind) string {
	switch kind {
	case coreMihomo:
		return "config.yaml"
	case coreSingbox:
		return "singbox.json"
	default:
		return "config.json"
	}
}

func coreStagingName(kind coreKind) string {
	switch kind {
	case coreMihomo:
		return "config.next.yaml"
	case coreSingbox:
		return "singbox.next.json"
	default:
		return "config.next.json"
	}
}

func coreTestArgs(kind coreKind, config, dir string) []string {
	switch kind {
	case coreMihomo:
		return []string{"-d", dir, "-t", "-f", config}
	case coreSingbox:
		return []string{"check", "-c", config}
	default:
		return []string{"run", "-test", "-c", config}
	}
}

func coreRunArgs(kind coreKind, config, dir string) []string {
	switch kind {
	case coreMihomo:
		return []string{"-d", dir, "-f", config}
	case coreSingbox:
		return []string{"run", "-c", config}
	default:
		return []string{"run", "-c", config}
	}
}

func coreVersionArgs(kind coreKind) []string {
	if kind == coreMihomo {
		return []string{"-v"}
	}
	return []string{"version"}
}

type corePlan int

const (
	planHot corePlan = iota
	planReload
	planRestart
)

func sameCorePlan(kind coreKind, skeletonChanged bool) corePlan {
	switch kind {
	case coreMihomo:
		return planReload
	case coreSingbox:
		return planRestart
	default:
		if skeletonChanged {
			return planRestart
		}
		return planHot
	}
}

func probeVersion(ctx context.Context, bin string, kind coreKind) string {
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(probe, bin, coreVersionArgs(kind)...).Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s version probe: %s\n", kind, err.Error())
		return ""
	}
	line, _, _ := strings.Cut(string(out), "\n")
	line = strings.TrimSpace(line)
	if len(line) > 64 {
		line = line[:64]
	}
	return line
}

func reloadMihomo(ctx context.Context, api, configPath string) error {
	body, _ := json.Marshal(map[string]string{"path": configPath})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://"+api+"/configs?force=true", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("mihomo reload: %w", err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("mihomo reload status %d", res.StatusCode)
	}
	return nil
}

func writeAppliedCore(dir string, kind coreKind) error {
	return os.WriteFile(filepath.Join(dir, "applied-core"), []byte(string(kind)), 0o600)
}

func clearAppliedCore(dir string) {
	_ = os.Remove(filepath.Join(dir, "applied-core"))
}
