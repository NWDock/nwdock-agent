package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// mihomo 外控没有累计计数器，只能轮询 /connections 活连接快照做增量聚合：
// 按连接 id 记上次读数，差值累加进与 xray 同名的计数器（inbound>>>tag / user>>>user）。
// 存活短于轮询间隔的连接整段漏计，连接关闭前最后一跳丢失，计费为下限近似（见 ADR）。
const mihomoPollInterval = 2 * time.Second

type mihomoMark struct{ up, down int64 }

type mihomoConnections struct {
	Connections []struct {
		ID       string `json:"id"`
		Upload   int64  `json:"upload"`
		Download int64  `json:"download"`
		Metadata struct {
			InboundName string `json:"inboundName"`
			InboundUser string `json:"inboundUser"`
		} `json:"metadata"`
	} `json:"connections"`
}

type mihomoStatsCollector struct {
	mu         sync.Mutex
	lastSeen   map[string]mihomoMark
	cumulative map[string]int64
	baselined  bool
}

var mihomoStats = &mihomoStatsCollector{
	lastSeen:   map[string]mihomoMark{},
	cumulative: map[string]int64{},
}

// mihomoStatsLoop 随 agent 生命周期跑：仅当 mihomo 在跑时轮询。累计值跨核心重启保留
// （面板水位要求单调）；agent 重启后累计值从零重建，由面板 delta<0 按全量兜底。
func mihomoStatsLoop(ctx context.Context) {
	ticker := time.NewTicker(mihomoPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if core, _ := runningCoreInfo(); core == coreMihomo {
				mihomoStats.poll(coreAPIAddr())
			}
		}
	}
}

func (c *mihomoStatsCollector) poll(api string) {
	client := &http.Client{Timeout: mihomoPollInterval}
	res, err := client.Get("http://" + api + "/connections")
	if err != nil {
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return
	}
	var doc mihomoConnections
	if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&doc); err != nil {
		return
	}
	c.fold(doc)
}

func (c *mihomoStatsCollector) fold(doc mihomoConnections) {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := make(map[string]bool, len(doc.Connections))
	for _, conn := range doc.Connections {
		if conn.ID == "" {
			continue
		}
		seen[conn.ID] = true
		prev, known := c.lastSeen[conn.ID]
		if !known {
			if !c.baselined {
				// 采集器启动后首张快照：已存活连接只记基线，防止 agent 重启后重复计历史字节。
				c.lastSeen[conn.ID] = mihomoMark{conn.Upload, conn.Download}
				continue
			}
			prev = mihomoMark{}
		}
		c.lastSeen[conn.ID] = mihomoMark{conn.Upload, conn.Download}
		add := func(counter string, delta int64) {
			if delta > 0 {
				c.cumulative[counter] += delta
			}
		}
		if name := conn.Metadata.InboundName; name != "" {
			add("inbound>>>"+name+">>>traffic>>>uplink", conn.Upload-prev.up)
			add("inbound>>>"+name+">>>traffic>>>downlink", conn.Download-prev.down)
		}
		if user := conn.Metadata.InboundUser; user != "" {
			add("user>>>"+user+">>>traffic>>>uplink", conn.Upload-prev.up)
			add("user>>>"+user+">>>traffic>>>downlink", conn.Download-prev.down)
		}
	}
	c.baselined = true
	for id := range c.lastSeen {
		if !seen[id] {
			delete(c.lastSeen, id)
		}
	}
}

func (c *mihomoStatsCollector) counters() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int64, len(c.cumulative))
	for name, value := range c.cumulative {
		out[name] = value
	}
	return out
}
