package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	case coreSingbox:
		return "AGENT_SINGBOX_BIN"
	case coreMihomo:
		return ""
	default:
		return "AGENT_XRAY_BIN"
	}
}

func legacyCoreBinEnv(kind coreKind) string {
	switch kind {
	case coreSingbox:
		return "SINGBOX_BIN"
	default:
		return "XRAY_BIN"
	}
}

type fileRuntime struct {
	xrayBin    string
	singboxBin string
	xrayAPI    string
}

// activeFile is set only for -config. Nil means core paths still come from the environment.
var activeFile atomic.Pointer[fileRuntime]

// ApplyFileRuntime makes core bin and API lookups use cfg and ignore the environment.
func ApplyFileRuntime(cfg Config) {
	activeFile.Store(&fileRuntime{
		xrayBin:    cfg.XrayBin,
		singboxBin: cfg.SingboxBin,
		xrayAPI:    cfg.XrayAPI,
	})
}

// ClearFileRuntime restores environment lookups. Tests use it to isolate -config.
func ClearFileRuntime() {
	activeFile.Store(nil)
}

func coreBin(kind coreKind) string {
	if kind == coreMihomo {
		return ""
	}
	if rt := activeFile.Load(); rt != nil {
		switch kind {
		case coreSingbox:
			return rt.singboxBin
		default:
			return rt.xrayBin
		}
	}
	value, _ := envfile.First(coreBinEnv(kind), legacyCoreBinEnv(kind))
	return value
}

func coreAPIAddr() string {
	if rt := activeFile.Load(); rt != nil {
		if rt.xrayAPI != "" {
			return rt.xrayAPI
		}
		return "127.0.0.1:10085"
	}
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
	case coreSingbox:
		return []string{"check", "-c", config}
	default:
		return []string{"run", "-test", "-c", config}
	}
}

func coreRunArgs(kind coreKind, config, dir string) []string {
	switch kind {
	case coreSingbox:
		return []string{"run", "-c", config}
	default:
		return []string{"run", "-c", config}
	}
}

func coreVersionArgs(kind coreKind) []string {
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

func writeAppliedCore(dir string, kind coreKind) error {
	return os.WriteFile(filepath.Join(dir, "applied-core"), []byte(string(kind)), 0o600)
}

func clearAppliedCore(dir string) {
	_ = os.Remove(filepath.Join(dir, "applied-core"))
}
