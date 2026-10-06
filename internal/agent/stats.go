package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
)

func collectStats(ctx context.Context, bin, api string) (map[string]int64, error) {
	out, err := exec.CommandContext(ctx, bin, "api", "statsquery", "--server", api).CombinedOutput()
	if err != nil {
		return nil, cmdFail("statsquery", out, err)
	}
	var doc struct {
		Stat []struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &doc); err != nil {
		return nil, fmt.Errorf("statsquery output: %w", err)
	}
	counters := make(map[string]int64, len(doc.Stat))
	for _, item := range doc.Stat {
		if item.Name == "" || item.Value <= 0 {
			continue
		}
		counters[item.Name] = item.Value
	}
	return counters, nil
}

func submitStats(ctx context.Context, cfg Config, counters map[string]int64) error {
	cert, err := tls.LoadX509KeyPair(filepath.Join(cfg.DataDir, "agent.crt"), filepath.Join(cfg.DataDir, "agent.key"))
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"counters": counters})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoints[0]+"/api/agent/stats", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := httpClient(cfg.Pin, cert).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("stats status %d", res.StatusCode)
	}
	return nil
}

func reportStats(ctx context.Context, cfg Config) error {
	core, _ := runningCoreInfo()
	return reportCounters(ctx, cfg, core)
}

// reportStatsLocked 供已持 proc.mu 的 syncConfig/restartLocked 使用；Go 锁不可重入。
func reportStatsLocked(ctx context.Context, cfg Config) error {
	return reportCounters(ctx, cfg, proc.core)
}

func reportCounters(ctx context.Context, cfg Config, core coreKind) error {
	var counters map[string]int64
	var err error
	switch core {
	case coreMihomo:
		counters = mihomoStats.counters()
	case coreSingbox:
		counters, err = collectSingboxStats(ctx, coreAPIAddr())
	default:
		bin := coreBin(coreXray)
		if bin == "" {
			return errors.New("AGENT_XRAY_BIN is required")
		}
		counters, err = collectStats(ctx, bin, coreAPIAddr())
	}
	if err != nil {
		return err
	}
	if len(counters) == 0 {
		return nil
	}
	return submitStats(ctx, cfg, counters)
}
