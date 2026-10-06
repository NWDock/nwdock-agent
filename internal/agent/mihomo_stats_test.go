package agent

import (
	"reflect"
	"testing"
)

type mihomoTestConn struct {
	id       string
	up, down int64
	tag      string
	user     string
}

func mihomoFold(t *testing.T, c *mihomoStatsCollector, conns []mihomoTestConn) {
	t.Helper()
	doc := mihomoConnections{}
	for _, conn := range conns {
		item := struct {
			ID       string `json:"id"`
			Upload   int64  `json:"upload"`
			Download int64  `json:"download"`
			Metadata struct {
				InboundName string `json:"inboundName"`
				InboundUser string `json:"inboundUser"`
			} `json:"metadata"`
		}{ID: conn.id, Upload: conn.up, Download: conn.down}
		item.Metadata.InboundName = conn.tag
		item.Metadata.InboundUser = conn.user
		doc.Connections = append(doc.Connections, item)
	}
	c.fold(doc)
}

func TestMihomoFoldBaselineAndDeltas(t *testing.T) {
	c := &mihomoStatsCollector{lastSeen: map[string]mihomoMark{}, cumulative: map[string]int64{}}

	// 首张快照只建基线：agent 重启时已在跑的连接不算历史字节。
	mihomoFold(t, c, []mihomoTestConn{
		{id: "a", up: 100, down: 50, tag: "nw-abcd1234-20000"},
		{id: "b", up: 10, down: 20, tag: "sh-trojan-21004", user: "sub-1"},
	})
	if got := c.counters(); len(got) != 0 {
		t.Fatalf("baseline snapshot must not count: %v", got)
	}

	// 增量累计：a 增长、b 关闭（尾包丢失为已知近似）、新连接 c 按全量计。
	mihomoFold(t, c, []mihomoTestConn{
		{id: "a", up: 160, down: 80, tag: "nw-abcd1234-20000"},
		{id: "c", up: 5, down: 7, tag: "sh-vless-21002", user: "sub-2"},
	})
	want := map[string]int64{
		"inbound>>>nw-abcd1234-20000>>>traffic>>>uplink":   60,
		"inbound>>>nw-abcd1234-20000>>>traffic>>>downlink": 30,
		"inbound>>>sh-vless-21002>>>traffic>>>uplink":      5,
		"inbound>>>sh-vless-21002>>>traffic>>>downlink":    7,
		"user>>>sub-2>>>traffic>>>uplink":                  5,
		"user>>>sub-2>>>traffic>>>downlink":                7,
	}
	if got := c.counters(); !reflect.DeepEqual(got, want) {
		t.Fatalf("counters: got %v want %v", got, want)
	}

	// 计数器随 mihomo 重启保留（面板水位要求单调）。
	mihomoFold(t, c, []mihomoTestConn{{id: "d", up: 3, down: 4, tag: "nw-abcd1234-20000"}})
	want["inbound>>>nw-abcd1234-20000>>>traffic>>>uplink"] += 3
	want["inbound>>>nw-abcd1234-20000>>>traffic>>>downlink"] += 4
	if got := c.counters(); !reflect.DeepEqual(got, want) {
		t.Fatalf("counters after restart: got %v want %v", got, want)
	}
}

func TestMihomoFoldSkipsEmptyIDs(t *testing.T) {
	c := &mihomoStatsCollector{lastSeen: map[string]mihomoMark{}, cumulative: map[string]int64{}}
	mihomoFold(t, c, []mihomoTestConn{{up: 100, down: 100, tag: "nw-abcd1234-20000"}})
	if got := c.counters(); len(got) != 0 {
		t.Fatalf("empty id must be ignored: %v", got)
	}
}
