package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"sync/atomic"
	"time"
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

// statsBatchKeys 是单条 stats 消息的最大计数条数：独立转发多了以后一次全发会把
// 帧撑得过大，分批发送也让面板有机会中途确认，撤销的转发能早点退休。
const statsBatchKeys = 400

// statsAckTimeout 是等一批 stats_ack 的上限。超时不删任何计数：下一轮会带着同样的
// 累计值重发，面板按水位差只补差额；只有确认过的批次才触发退休。
const statsAckTimeout = 10 * time.Second

// submitStats 分批上报计数器并逐批等面板确认。键序固定（排序后切批），
// 保证同一份计数器在任何机器上切批结果一致，重发不会换批序。
func submitStats(ctx context.Context, s *session, counters map[string]int64) error {
	if len(counters) == 0 {
		return nil
	}
	names := make([]string, 0, len(counters))
	for name := range counters {
		names = append(names, name)
	}
	sort.Strings(names)
	for start := 0; start < len(names); start += statsBatchKeys {
		end := start + statsBatchKeys
		if end > len(names) {
			end = len(names)
		}
		batch := make(map[string]int64, end-start)
		for _, name := range names[start:end] {
			batch[name] = counters[name]
		}
		acked, err := submitStatsBatch(ctx, s, batch)
		if err != nil {
			return err
		}
		// 只有面板确认过的批次才触发退休：没确认就删，撤销前最后一笔字节会丢。
		if acked {
			retireConfirmedForwards(batch)
		}
	}
	return nil
}

// submitStatsBatch 发一批并等面板 stats_ack，返回该批是否被确认。旧面板没有 ack、
// 或确认超时：按未确认继续，不堵死上报回路（计数仍在，下一轮重发）。
func submitStatsBatch(ctx context.Context, s *session, batch map[string]int64) (bool, error) {
	batchID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), atomic.AddUint64(&statsBatchSeq, 1))
	wait := s.registerStatsAck(batchID)
	defer s.unregisterStatsAck(batchID)
	body, err := json.Marshal(map[string]any{"batch": batchID, "counters": batch})
	if err != nil {
		return false, err
	}
	if err := s.send(ctx, message{T: msgStats, D: body}); err != nil {
		return false, err
	}
	timer := time.NewTimer(statsAckTimeout)
	defer timer.Stop()
	select {
	case <-wait:
		return true, nil
	case <-timer.C:
		logf(levelWarning, "stats ack timeout: batch %s", batchID)
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

var statsBatchSeq uint64

func reportStats(ctx context.Context, s *session) error {
	core, _ := runningCoreInfo()
	return reportCounters(ctx, s, core)
}

// reportStatsLocked 供已持 proc.mu 的 applyDesired/restartLocked 使用；Go 锁不可重入。
func reportStatsLocked(ctx context.Context, s *session) error {
	return reportCounters(ctx, s, proc.core)
}

func reportCounters(ctx context.Context, s *session, core coreKind) error {
	var rt coreRuntime
	if proc.rt != nil && proc.rt.Running() && (core == "" || proc.rt.Kind() == core) {
		rt = proc.rt
		core = rt.Kind()
	}
	var counters map[string]int64
	var err error
	switch {
	case rt != nil:
		counters, err = rt.Counters(ctx)
	case core == coreMihomo:
		counters = traffic.counters()
	case core == coreSingbox:
		counters, err = collectSingboxStats(ctx, coreAPIAddr())
	case core == coreXray:
		bin := coreBin(coreXray)
		if bin == "" {
			return errors.New("AGENT_XRAY_BIN is required")
		}
		counters, err = collectStats(ctx, bin, coreAPIAddr())
	default:
		return submitStats(ctx, s, mergeRelayCounters(nil))
	}
	if err != nil {
		return err
	}
	return submitStats(ctx, s, mergeRelayCounters(counters))
}

// mergeRelayCounters 把入口转发累计并进核心 counters：一次合并全局 relay>>>all
// 与 per-forward forward>>><id> 两种键；转发与核心命名空间不重叠，核心值优先。
func mergeRelayCounters(counters map[string]int64) map[string]int64 {
	relay := relayCounters()
	forward := forwardCounters()
	if len(relay) == 0 && len(forward) == 0 {
		return counters
	}
	if counters == nil {
		counters = make(map[string]int64, len(relay)+len(forward))
	}
	for _, group := range []map[string]int64{relay, forward} {
		for name, value := range group {
			if _, ok := counters[name]; !ok {
				counters[name] = value
			}
		}
	}
	return counters
}
