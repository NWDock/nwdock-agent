package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
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

func submitStats(ctx context.Context, s *session, counters map[string]int64) error {
	body, err := json.Marshal(map[string]any{"counters": counters})
	if err != nil {
		return err
	}
	return s.send(ctx, message{T: msgStats, D: body})
}

func reportStats(ctx context.Context, s *session) error {
	core, _ := runningCoreInfo()
	return reportCounters(ctx, s, core)
}

// reportStatsLocked 供已持 proc.mu 的 applyDesired/restartLocked 使用；Go 锁不可重入。
func reportStatsLocked(ctx context.Context, s *session) error {
	return reportCounters(ctx, s, proc.core)
}

func reportCounters(ctx context.Context, s *session, core coreKind) error {
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
	return submitStats(ctx, s, counters)
}
