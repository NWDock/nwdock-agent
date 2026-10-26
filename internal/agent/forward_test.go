package agent

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// resetForwardBytes 清零全部 per-forward 累计，供测试隔离（forwardBytes 是全局表）。
func resetForwardBytes() {
	forwardBytes.Range(func(key, _ any) bool {
		forwardBytes.Delete(key)
		return true
	})
}

func fwdCounter(id, key string) int64 {
	return forwardCounters()["forward>>>"+id+">>>traffic>>>"+key]
}

// waitFwdCounter 等到 per-forward 计数达到期望值：回显字节进内核和计数入账之间
// 差一个调度节拍，紧跟着回显读的断言必须轮询。
func waitFwdCounter(t *testing.T, id, key string, want int64) int64 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := fwdCounter(id, key); got == want {
			return got
		} else if got > want {
			t.Fatalf("forward %s %s = %d, want exactly %d", id, key, got, want)
		}
		if time.Now().After(deadline) {
			t.Fatalf("forward %s %s = %d, want %d", id, key, fwdCounter(id, key), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitGlobalCounter 等到全局聚合计数达到期望值。
func waitGlobalCounter(t *testing.T, key string, want int64) int64 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := relayCounterValue(key); got == want {
			return got
		} else if got > want {
			t.Fatalf("global %s = %d, want exactly %d", key, got, want)
		}
		if time.Now().After(deadline) {
			t.Fatalf("global %s = %d, want %d", key, relayCounterValue(key), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fwdSpec 构造一条指向 127.0.0.1 的独立转发清单项。
func fwdSpec(id string, port, target int, tcp, udp, allowPrivate bool) relaySpec {
	return relaySpec{
		ForwardID:    id,
		Port:         port,
		TargetHost:   "127.0.0.1",
		TargetPort:   target,
		TCP:          tcp,
		UDP:          udp,
		AllowPrivate: allowPrivate,
	}
}

func forwardStateByID(id string) (relayPortState, bool) {
	for _, st := range relayStates() {
		if st.ForwardID == id {
			return st, true
		}
	}
	return relayPortState{}, false
}

func waitForwardListening(t *testing.T, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, ok := forwardStateByID(id); ok && st.Listening {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("forward %s not listening: %+v", id, relayStates())
}

func waitForwardGone(t *testing.T, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := forwardStateByID(id); !ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("forward %s still present: %+v", id, relayStates())
}

// countingEchoSink 与 echoSink 相同，但累计回显字节数，用来确认连接实际打到了哪个落地。
func countingEchoSink(t *testing.T) (int, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var seen atomic.Int64
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				for {
					n, rerr := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							break
						}
						seen.Add(int64(n))
					}
					if rerr != nil {
						break
					}
				}
				_ = c.Close()
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, &seen
}

// waitSinkSeen 等到回显落地累计到期望字节数：落地 Write 返回和测试侧读到回显
// 之间同样差一个调度节拍。
func waitSinkSeen(t *testing.T, seen *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := seen.Load(); got == want {
			return
		} else if got > want {
			t.Fatalf("sink seen %d, want exactly %d", got, want)
		}
		if time.Now().After(deadline) {
			t.Fatalf("sink seen %d, want %d", seen.Load(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitConnClosed 等待对端关闭：读到 EOF/错误才算撤会话生效。
func waitConnClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 16)
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
	t.Fatal("connection still open")
}

// TestForwardIPBlocklist allow_private=false 的目标 IP 校验：私网/保留段全部拦下，公网放行。
func TestForwardIPBlocklist(t *testing.T) {
	for _, ip := range []string{
		"0.0.0.0", "0.1.2.3", // unspecified/本网络段
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", // RFC1918
		"100.64.0.1", "100.127.255.254", // CGNAT
		"127.0.0.1", "127.8.8.8", // loopback
		"169.254.1.1",                                           // link-local
		"192.0.0.1", "192.0.2.1", "198.51.100.7", "203.0.113.9", // 协议/文档保留
		"198.18.0.1", "198.19.255.255", // 基准测试
		"224.0.0.1", "240.0.0.1", "255.255.255.255", // 组播/保留/广播
		"::", "::1", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "2001:db8::10",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", // IPv4 映射按 IPv4 判断
	} {
		if !forwardIPBlocked(net.ParseIP(ip)) {
			t.Fatalf("%s must be blocked", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1", "198.20.0.1", "2606:4700::1111", "2a00:1450::1"} {
		if forwardIPBlocked(net.ParseIP(ip)) {
			t.Fatalf("%s must be allowed", ip)
		}
	}
	if !forwardIPBlocked(nil) {
		t.Fatal("nil IP must be blocked")
	}
}

// TestForwardAllowPrivateDialPolicy allow_private=false 在每次拨号解析后校验：
// 回环/私网目标（含 localhost 这类域名）拨不通；true 放开；legacy 不做校验。
func TestForwardAllowPrivateDialPolicy(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	t.Cleanup(relayStop)

	sink := echoSink(t)

	// 回环目标被阻断：客户端连上入口后很快被关掉。
	blocked := fwdSpec("fb", freePort(t), sink, true, false, false)
	relayApplyAll(dir, nil, []relaySpec{blocked})
	waitForwardListening(t, "fb")
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(blocked.Port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	waitConnClosed(t, conn)

	// localhost 域名解析成回环后同样被阻断（覆盖解析后逐地址校验）。
	domain := relaySpec{ForwardID: "fd", Port: freePort(t), TargetHost: "localhost", TargetPort: sink, TCP: true}
	relayApplyAll(dir, nil, []relaySpec{domain})
	waitForwardListening(t, "fd")
	conn, err = net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(domain.Port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	waitConnClosed(t, conn)

	// UDP 回环目标同样阻断：写入后没有回声。
	udpSink := udpEchoSink(t)
	udpBlocked := fwdSpec("fbu", freeUDPPort(t), udpSink, false, true, false)
	relayApplyAll(dir, nil, []relaySpec{udpBlocked})
	waitForwardListening(t, "fbu")
	uc, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(udpBlocked.Port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = uc.Close() })
	if _, err := uc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = uc.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 64)
	if n, err := uc.Read(buf); err == nil {
		t.Fatalf("blocked udp forward echoed %q", buf[:n])
	}

	// allow_private=true 放开回环目标。
	allowed := fwdSpec("fa", freePort(t), sink, true, false, true)
	relayApplyAll(dir, nil, []relaySpec{allowed})
	waitForwardListening(t, "fa")
	conn2, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(allowed.Port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn2.Close() })
	echoThrough(t, conn2, "allowed")

	// legacy 转发不应用该策略：回环目标照常转发。
	legacyEntry := freePort(t)
	relayEng.apply([]relaySpec{{Port: legacyEntry, TargetHost: "127.0.0.1", TargetPort: sink, TCP: true}})
	waitRelayListening(t, legacyEntry)
	conn3, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(legacyEntry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn3.Close() })
	echoThrough(t, conn3, "legacy")
}

// TestForwardTCPCountsPerForwardExactAndGlobal 两条独立转发分别精确计数，全局聚合等于两者之和。
func TestForwardTCPCountsPerForwardExactAndGlobal(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
	resetForwardBytes()
	t.Cleanup(relayStop)

	sink1, sink2 := echoSink(t), echoSink(t)
	p1, p2 := freePort(t), freePort(t)
	relayApplyAll(dir, nil, []relaySpec{
		fwdSpec("f1", p1, sink1, true, false, true),
		fwdSpec("f2", p2, sink2, true, false, true),
	})
	waitForwardListening(t, "f1")
	waitForwardListening(t, "f2")

	conn1, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(p1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn1.Close() })
	echoThrough(t, conn1, "01234")
	echoThrough(t, conn1, "01234")

	conn2, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(p2))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn2.Close() })
	echoThrough(t, conn2, "abcd")

	waitFwdCounter(t, "f1", "uplink", 10)
	waitFwdCounter(t, "f1", "downlink", 10)
	waitFwdCounter(t, "f2", "uplink", 4)
	waitFwdCounter(t, "f2", "downlink", 4)
	waitGlobalCounter(t, "relay>>>all>>>traffic>>>uplink", 14)
	waitGlobalCounter(t, "relay>>>all>>>traffic>>>downlink", 14)
	// 无流量的转发不该产生计数键。
	if _, ok := forwardCounters()["forward>>>f3>>>traffic>>>uplink"]; ok {
		t.Fatal("phantom forward key")
	}
}

// TestForwardUDPCountsPerForward UDP 独立转发双向计数并入全局聚合。
func TestForwardUDPCountsPerForward(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
	resetForwardBytes()
	t.Cleanup(relayStop)

	sink := udpEchoSink(t)
	entry := freeUDPPort(t)
	relayApplyAll(dir, nil, []relaySpec{fwdSpec("fu", entry, sink, false, true, true)})
	waitForwardListening(t, "fu")

	client, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	payload := []byte("udp-ping")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = client.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		if _, err := client.Read(buf); err != nil {
			continue
		}
		break
	}
	for i := 0; i < 3; i++ {
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		if _, err := client.Read(buf); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	// 回显读返回和计数入账差一个调度节拍，轮询到入账再断言。
	deadline = time.Now().Add(2 * time.Second)
	for {
		up, down := fwdCounter("fu", "uplink"), fwdCounter("fu", "downlink")
		if up >= int64(len(payload)) && down >= int64(len(payload)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fu counters up=%d down=%d want both >= %d", up, down, len(payload))
		}
		time.Sleep(5 * time.Millisecond)
	}
	up := relayCounterValue("relay>>>all>>>traffic>>>uplink")
	down := relayCounterValue("relay>>>all>>>traffic>>>downlink")
	if up < fwdCounter("fu", "uplink") || down < fwdCounter("fu", "downlink") {
		t.Fatalf("global counters must include per-forward bytes: up=%d down=%d", up, down)
	}
}

// TestForwardPortReuseNoCrossAccounting 同端口复用：换 id 断旧会话、各自计数不串账；
// 同 id 换目标保留旧 TCP，新连接走新目标。
func TestForwardPortReuseNoCrossAccounting(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
	resetForwardBytes()
	t.Cleanup(relayStop)

	sinkA, seenA := countingEchoSink(t)
	sinkB, seenB := countingEchoSink(t)
	entry := freePort(t)

	relayApplyAll(dir, nil, []relaySpec{fwdSpec("f1", entry, sinkA, true, false, true)})
	waitForwardListening(t, "f1")
	conn1, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn1.Close() })
	echoThrough(t, conn1, "one")

	// 同 forward_id 仅目标变化：旧连接保持且仍走旧落地，新连接走新落地。
	relayApplyAll(dir, nil, []relaySpec{fwdSpec("f1", entry, sinkB, true, false, true)})
	waitForwardListening(t, "f1")
	echoThrough(t, conn1, "kept")
	conn2, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn2.Close() })
	echoThrough(t, conn2, "moved")
	waitSinkSeen(t, seenA, 7) // "one"(3) + "kept"(4)
	waitSinkSeen(t, seenB, 5) // "moved"(5)
	waitFwdCounter(t, "f1", "uplink", 12)

	// 同端口换 forward_id：旧会话必须关闭，字节记到新 id 名下。
	relayApplyAll(dir, nil, []relaySpec{fwdSpec("f2", entry, sinkA, true, false, true)})
	waitForwardListening(t, "f2")
	waitConnClosed(t, conn1)
	waitConnClosed(t, conn2)
	conn3, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn3.Close() })
	echoThrough(t, conn3, "new")

	waitSinkSeen(t, seenA, 10) // 追加 "new"(3)
	waitSinkSeen(t, seenB, 5)
	// f1 计数停在 12 不再变化：端口复用不串账。
	waitFwdCounter(t, "f1", "uplink", 12)
	waitFwdCounter(t, "f2", "uplink", 3)
	waitFwdCounter(t, "f2", "downlink", 3)
	waitGlobalCounter(t, "relay>>>all>>>traffic>>>uplink", 15)
	waitGlobalCounter(t, "relay>>>all>>>traffic>>>downlink", 15)
}

// TestForwardRevokeProtocolAndPort 撤协议断对应会话、撤端口整体撤销，legacy 不受影响。
func TestForwardRevokeProtocolAndPort(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
	resetForwardBytes()
	t.Cleanup(relayStop)

	tcpSink := echoSink(t)
	udpSink := udpEchoSink(t)
	entry := freePort(t)
	udpEntry := freeUDPPort(t)
	legacyEntry := freePort(t)

	legacy := []relaySpec{{Port: legacyEntry, TargetHost: "127.0.0.1", TargetPort: tcpSink, TCP: true}}
	forwards := []relaySpec{{
		ForwardID: "fp", Port: entry, TargetHost: "127.0.0.1", TargetPort: tcpSink,
		TCP: true, AllowPrivate: true,
	}, {
		ForwardID: "fpu", Port: udpEntry, TargetHost: "127.0.0.1", TargetPort: udpSink,
		UDP: true, AllowPrivate: true,
	}}
	relayApplyAll(dir, legacy, forwards)
	waitForwardListening(t, "fp")
	waitForwardListening(t, "fpu")
	waitRelayListening(t, legacyEntry)

	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	echoThrough(t, conn, "hello")

	// 撤 TCP：TCP 会话关闭；UDP 转发不受影响。
	relayApplyAll(dir, legacy, []relaySpec{forwards[1]})
	waitConnClosed(t, conn)
	waitForwardListening(t, "fpu")

	// 撤 UDP：UDP 不再回声，TCP 侧重新可用。
	relayApplyAll(dir, legacy, []relaySpec{forwards[0]})
	waitForwardListening(t, "fp")
	conn2, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn2.Close() })
	echoThrough(t, conn2, "again")

	// 撤全部独立转发：legacy 保持。
	relayApplyAll(dir, legacy, nil)
	waitForwardGone(t, "fp")
	waitForwardGone(t, "fpu")
	waitConnClosed(t, conn2)
	if len(relayStates()) != 1 || relayStates()[0].Port != legacyEntry {
		t.Fatalf("legacy must survive: %+v", relayStates())
	}
	conn3, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(legacyEntry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn3.Close() })
	echoThrough(t, conn3, "legacy")
}

// TestForwardLegacyApplyIgnoresForwardID legacy apply 忽略带 forward_id 的条目：
// 独立转发只能来自 forwards 域。
func TestForwardLegacyApplyIgnoresForwardID(t *testing.T) {
	resetRelay(t.TempDir())
	t.Cleanup(relayStop)
	relayEng.apply([]relaySpec{{
		ForwardID: "fx", Port: freePort(t), TargetHost: "127.0.0.1", TargetPort: 80, TCP: true,
	}})
	if states := relayStates(); len(states) != 0 {
		t.Fatalf("forward_id entry must not start via legacy list: %+v", states)
	}
}

// TestForwardWantSeparation 独立转发落盘 forward-want.json、relay-want.json 不含 forward 条目；
// 重启后两份清单各自恢复；旧 agent 视角的 relay-want.json 反序列化不会带出独立转发。
func TestForwardWantSeparation(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	t.Cleanup(relayStop)

	sink := echoSink(t)
	legacyEntry := freePort(t)
	entry := freePort(t)
	legacy := []relaySpec{{Port: legacyEntry, TargetHost: "127.0.0.1", TargetPort: sink, TCP: true}}
	forwards := []relaySpec{fwdSpec("fw1", entry, sink, true, false, true)}
	relayApplyAll(dir, legacy, forwards)
	waitForwardListening(t, "fw1")
	waitRelayListening(t, legacyEntry)

	relayRaw, err := os.ReadFile(relayWantPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(relayRaw), `"forward_id"`) || strings.Contains(string(relayRaw), `"allow_private"`) {
		t.Fatalf("relay-want.json must stay legacy-only: %s", relayRaw)
	}
	fwdRaw, err := os.ReadFile(forwardWantPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	var restored []relaySpec
	if err := json.Unmarshal(fwdRaw, &restored); err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[0].ForwardID != "fw1" || !restored[0].AllowPrivate || restored[0].Port != entry {
		t.Fatalf("forward-want.json %+v", restored)
	}

	// 进程重启：两份清单都恢复，面板失联继续转发。
	resetRelay(dir)
	relayInit(dir)
	waitForwardListening(t, "fw1")
	waitRelayListening(t, legacyEntry)
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	echoThrough(t, conn, "after")

	// 空 forwards 清单撤销全部独立转发并落盘空清单；legacy 保持。
	relayApplyAll(dir, legacy, nil)
	waitForwardGone(t, "fw1")
	fwdRaw, err = os.ReadFile(forwardWantPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if string(fwdRaw) != "[]" {
		t.Fatalf("forward-want.json after revoke: %s", fwdRaw)
	}
	resetRelay(dir)
	relayInit(dir)
	if _, ok := forwardStateByID("fw1"); ok {
		t.Fatal("revoked forward restored from disk")
	}
	waitRelayListening(t, legacyEntry)
}

// TestForwardWantNotReadAsLegacy relay-want.json 里混入 forward_id 条目会被丢弃：
// 降级旧 agent 只读 relay-want.json，混写也不会把独立转发拉起来。
func TestForwardWantNotReadAsLegacy(t *testing.T) {
	dir := t.TempDir()
	raw := `[{"port":40001,"target_host":"127.0.0.1","target_port":80,"tcp":true,"forward_id":"f9","allow_private":true},` +
		`{"port":40002,"target_host":"127.0.0.1","target_port":80,"tcp":true}]`
	if err := os.WriteFile(relayWantPath(dir), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	specs, err := readRelayWant(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0].Port != 40002 {
		t.Fatalf("forward entries must be dropped from relay want: %+v", specs)
	}
	// forward-want.json 缺失时读出空清单，不报错。
	fwds, err := readForwardWant(dir)
	if err != nil || len(fwds) != 0 {
		t.Fatalf("missing forward want: %v %v", fwds, err)
	}
}

// TestForwardRegisterRejectsStaleHandle 拨号完成后登记会话必须校验 handle 世代：
// 撤销或同键换代后的旧 handle 一律拒绝，端口复用不串会话。
func TestForwardRegisterRejectsStaleHandle(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	t.Cleanup(relayStop)

	sink := echoSink(t)
	entry := freePort(t)
	spec := fwdSpec("f1", entry, sink, true, false, true)
	relayApplyAll(dir, nil, []relaySpec{spec})
	relayEng.mu.Lock()
	h1 := relayEng.handles[relayForwardKey("f1")]
	relayEng.mu.Unlock()
	if h1 == nil {
		t.Fatal("handle missing")
	}

	// 撤销再同端口重建：新 handle 是另一代。
	relayApplyAll(dir, nil, nil)
	relayApplyAll(dir, nil, []relaySpec{spec})
	relayEng.mu.Lock()
	h2 := relayEng.handles[relayForwardKey("f1")]
	relayEng.mu.Unlock()
	if h2 == nil || h2 == h1 {
		t.Fatalf("handle generation not rotated: %p %p", h1, h2)
	}

	staleA, staleB := net.Pipe()
	t.Cleanup(func() { _ = staleA.Close(); _ = staleB.Close() })
	if s := relayEng.registerTCPSession(h1, staleA, staleB); s != nil {
		t.Fatal("stale handle must be rejected")
	}
	liveC, liveD := net.Pipe()
	t.Cleanup(func() { _ = liveC.Close(); _ = liveD.Close() })
	s := relayEng.registerTCPSession(h2, liveC, liveD)
	if s == nil {
		t.Fatal("live handle registration failed")
	}
	relayEng.mu.Lock()
	_, registered := h2.sessions[s]
	relayEng.mu.Unlock()
	if !registered {
		t.Fatal("session not registered on live handle")
	}
	relayEng.unregisterTCPSession(s)
	relayEng.mu.Lock()
	_, registered = h2.sessions[s]
	relayEng.mu.Unlock()
	if registered {
		t.Fatal("session not unregistered")
	}

	// legacy 同理：换代后旧 handle 不许再挂会话。
	legacySpec := relaySpec{Port: entry, TargetHost: "127.0.0.1", TargetPort: sink, TCP: true}
	relayApplyAll(dir, []relaySpec{legacySpec}, nil)
	relayEng.mu.Lock()
	lh1 := relayEng.handles[relayPortKey(entry)]
	relayEng.mu.Unlock()
	relayApplyAll(dir, nil, nil)
	relayApplyAll(dir, []relaySpec{legacySpec}, nil)
	relayEng.mu.Lock()
	lh2 := relayEng.handles[relayPortKey(entry)]
	relayEng.mu.Unlock()
	if lh2 == nil || lh2 == lh1 {
		t.Fatal("legacy handle generation not rotated")
	}
	if s := relayEng.registerTCPSession(lh1, staleA, staleB); s != nil {
		t.Fatal("stale legacy handle must be rejected")
	}
}

// TestForwardUDPSweepExitsOnClose UDP 套接字关闭后 sweep goroutine 必须退出。
func TestForwardUDPSweepExitsOnClose(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tbl := &relayUDP{pc: pc, sessions: map[string]*relayUDPSession{}, done: make(chan struct{})}
	exited := make(chan struct{})
	go func() {
		tbl.sweep()
		close(exited)
	}()
	tbl.close()
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("sweep goroutine did not exit after close")
	}
	select {
	case <-tbl.done:
	default:
		t.Fatal("done channel not closed")
	}
}

// TestForwardHeartbeatTruncatedFields 心跳 relay 状态超上限时截断并带 total/truncated。
func TestForwardHeartbeatTruncatedFields(t *testing.T) {
	old := relayEng
	relayEng = &relayEngine{handles: map[string]*relayHandle{}}
	defer func() { relayEng = old }()
	for i := 1; i <= relayMaxStates+1; i++ {
		relayEng.handles[relayForwardKey(strconv.Itoa(i))] = &relayHandle{
			spec: relaySpec{Port: 30000 + i, ForwardID: strconv.Itoa(i)},
		}
	}
	states, total, truncated := relayHeartbeatStates()
	if total != relayMaxStates+1 || !truncated {
		t.Fatalf("total %d truncated %v", total, truncated)
	}
	if len(states) != relayMaxStates {
		t.Fatalf("states %d want %d", len(states), relayMaxStates)
	}
	if states[0].ForwardID == "" {
		t.Fatal("forward entries must carry forward_id")
	}

	relayEng.handles = map[string]*relayHandle{}
	states, total, truncated = relayHeartbeatStates()
	if total != 0 || truncated || len(states) != 0 {
		t.Fatalf("empty engine: %d %v %d", total, truncated, len(states))
	}
}

// TestMergeForwardCountersIntoStats stats 一次性合并全局与 per-forward 键，核心值优先。
func TestMergeForwardCountersIntoStats(t *testing.T) {
	resetRelayBytes()
	resetForwardBytes()
	if got := mergeRelayCounters(nil); len(got) != 0 {
		t.Fatalf("empty counters should pass through: %+v", got)
	}
	relayBytes.up.Store(10)
	relayBytes.down.Store(4)
	forwardTrafficOf("fz").up.Store(7)
	forwardTrafficOf("fz").down.Store(2)
	forwardTrafficOf("fempty") // 无流量：不应产生键

	got := mergeRelayCounters(map[string]int64{"inbound>>>nw>>>traffic>>>uplink": 7})
	want := map[string]int64{
		"relay>>>all>>>traffic>>>uplink":    10,
		"relay>>>all>>>traffic>>>downlink":  4,
		"forward>>>fz>>>traffic>>>uplink":   7,
		"forward>>>fz>>>traffic>>>downlink": 2,
		"inbound>>>nw>>>traffic>>>uplink":   7,
	}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("%s = %d want %d (full: %+v)", key, got[key], value, got)
		}
	}
	if _, ok := got["forward>>>fempty>>>traffic>>>uplink"]; ok {
		t.Fatal("zero-traffic forward must not emit keys")
	}
	// 核心已占用同名 key 时不被覆盖（防呆）。
	got = mergeRelayCounters(map[string]int64{"forward>>>fz>>>traffic>>>uplink": 99})
	if got["forward>>>fz>>>traffic>>>uplink"] != 99 {
		t.Fatalf("core value must win: %+v", got)
	}
}

// TestForwardInvalidIDRejected 非法 forward id（空、超长、含分隔符）不进 engine。
func TestForwardInvalidIDRejected(t *testing.T) {
	resetRelay(t.TempDir())
	t.Cleanup(relayStop)
	sink := echoSink(t)
	for _, id := range []string{"", "a>b", "has space", strings.Repeat("x", 65)} {
		spec := fwdSpec(id, freePort(t), sink, true, false, true)
		if spec.validForward() {
			t.Fatalf("id %q must be invalid", id)
		}
		relayApplyAll(t.TempDir(), nil, []relaySpec{spec})
	}
	if states := relayStates(); len(states) != 0 {
		t.Fatalf("invalid ids must not start forwards: %+v", states)
	}
	ok := fwdSpec("9f-4c_2B", freePort(t), sink, true, false, true)
	if !ok.validForward() {
		t.Fatal("uuid-shaped id must be valid")
	}
}

// TestChannelServeForwardsDesired desired 驱动独立转发生命周期：
// 带 forwards 应用；无 forwards 段（旧面板）零行为变化；显式空数组撤销但保留 legacy；
// desired_req 携带 features 声明。
func TestChannelServeForwardsDesired(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
	resetForwardBytes()
	t.Cleanup(func() {
		relayStop()
	})

	sink := echoSink(t)
	legacyEntry := freePort(t)
	fwdEntry := freePort(t)
	legacy := `{"port":` + strconv.Itoa(legacyEntry) + `,"target_host":"127.0.0.1","target_port":` + strconv.Itoa(sink) + `,"tcp":true}`
	forward := `{"id":"fd1","port":` + strconv.Itoa(fwdEntry) + `,"target_host":"127.0.0.1","target_port":` + strconv.Itoa(sink) + `,"tcp":true,"udp":false,"allow_private":true}`

	var sent1 = make(chan struct{}, 1)
	var sent2 = make(chan struct{}, 1)
	var sent3 = make(chan struct{}, 1)
	var ack1 = make(chan struct{})
	var ack2 = make(chan struct{})
	var ack3 = make(chan struct{})
	s, _, _ := dialWithPanel(t, false, func(peer *panelHandle) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		req, err := peer.read(ctx)
		if err != nil {
			t.Errorf("desired_req: %v", err)
			return
		}
		if req.T != "desired_req" {
			t.Errorf("first frame %q", req.T)
			return
		}
		var payload map[string]any
		if err := json.Unmarshal(req.D, &payload); err != nil {
			t.Errorf("desired_req payload: %v", err)
			return
		}
		feats, _ := payload["features"].([]any)
		if len(feats) != 1 || feats[0] != "forward-v1" {
			t.Errorf("desired_req features %v", payload["features"])
			return
		}
		if err := peer.send(ctx, message{T: msgDesired, D: json.RawMessage(`{"generation":101,"serving":false,"relays":[` + legacy + `],"forwards":[` + forward + `]}`)}); err != nil {
			t.Errorf("desired 1: %v", err)
			return
		}
		sent1 <- struct{}{}
		<-ack1
		// 旧面板形态：desired 不带 forwards 段。
		if err := peer.send(ctx, message{T: msgDesired, D: json.RawMessage(`{"generation":102,"serving":false,"relays":[` + legacy + `]}`)}); err != nil {
			t.Errorf("desired 2: %v", err)
			return
		}
		sent2 <- struct{}{}
		<-ack2
		// 显式空数组：撤销独立转发，保留 legacy。
		if err := peer.send(ctx, message{T: msgDesired, D: json.RawMessage(`{"generation":103,"serving":false,"relays":[` + legacy + `],"forwards":[]}`)}); err != nil {
			t.Errorf("desired 3: %v", err)
			return
		}
		sent3 <- struct{}{}
		<-ack3
		time.Sleep(300 * time.Millisecond)
		_ = peer.conn.Close(websocket.StatusNormalClosure, "done")
	})
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.serve(context.Background()) }()

	<-sent1
	waitForwardListening(t, "fd1")
	waitRelayListening(t, legacyEntry)
	close(ack1)

	<-sent2
	// gen2 不带 forwards：独立转发必须原样保留。给 gen2 一点应用时间再断言。
	time.Sleep(500 * time.Millisecond)
	if st, ok := forwardStateByID("fd1"); !ok || !st.Listening {
		t.Fatalf("desired without forwards changed the forward: ok=%v %+v all=%+v", ok, st, relayStates())
	}
	if st := relayStateFor(t, legacyEntry); !st.Listening {
		t.Fatalf("legacy relay lost: %+v", st)
	}
	close(ack2)

	<-sent3
	waitForwardGone(t, "fd1")
	if st := relayStateFor(t, legacyEntry); !st.Listening {
		t.Fatalf("legacy relay lost after empty forwards: %+v", st)
	}
	close(ack3)
	// 空清单落盘，重启不再恢复。
	fwdRaw, err := os.ReadFile(forwardWantPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if string(fwdRaw) != "[]" {
		t.Fatalf("forward-want.json after empty list: %s", fwdRaw)
	}

	select {
	case err := <-serveErr:
		if err == nil {
			t.Log("serve returned nil")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return")
	}
}

// TestForwardAllowPrivateTightenClosesSessions allow_private 由放开收紧时必须断掉
// 已建立的 TCP 会话：否则已放行的内网连接会留在收紧后的策略之外。
func TestForwardAllowPrivateTightenClosesSessions(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
	resetForwardBytes()
	t.Cleanup(relayStop)
	sink := echoSink(t)
	entry := freePort(t)

	relayApplyAll(dir, nil, []relaySpec{{
		ForwardID: "ft", Port: entry, TargetHost: "127.0.0.1", TargetPort: sink,
		TCP: true, AllowPrivate: true,
	}})
	waitForwardListening(t, "ft")
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	echoThrough(t, conn, "open")

	// 只收紧 allow_private（目标与开关都没变）：旧会话必须关闭。
	relayApplyAll(dir, nil, []relaySpec{{
		ForwardID: "ft", Port: entry, TargetHost: "127.0.0.1", TargetPort: sink,
		TCP: true, AllowPrivate: false,
	}})
	waitConnClosed(t, conn)
	waitForwardListening(t, "ft")
}

// TestForwardUDPOnlyChangeKeepsTCP 只改 UDP 开关不动 TCP：已建立的 TCP 会话保留，
// 不需要为一次 UDP 调整把在用的连接全部打断。
func TestForwardUDPOnlyChangeKeepsTCP(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
	resetForwardBytes()
	t.Cleanup(relayStop)
	sink := echoSink(t)
	entry := freePort(t)

	relayApplyAll(dir, nil, []relaySpec{{
		ForwardID: "fu", Port: entry, TargetHost: "127.0.0.1", TargetPort: sink, TCP: true, AllowPrivate: true,
	}})
	waitForwardListening(t, "fu")
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	echoThrough(t, conn, "keep")

	// 同一条转发加上 UDP：TCP 会话不断。
	relayApplyAll(dir, nil, []relaySpec{{
		ForwardID: "fu", Port: entry, TargetHost: "127.0.0.1", TargetPort: sink, TCP: true, UDP: true, AllowPrivate: true,
	}})
	waitForwardListening(t, "fu")
	echoThrough(t, conn, "still-here")
}

// TestForwardPersistFailureKeepsRuntime 清单落盘失败时不切运行时、不确认世代：
// 运行时保持上一份已验证清单，面板下一轮重推。
func TestForwardPersistFailureKeepsRuntime(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
	resetForwardBytes()
	t.Cleanup(relayStop)
	sink := echoSink(t)
	entry := freePort(t)

	if err := relayApplyAll(dir, nil, []relaySpec{{
		ForwardID: "fp", Port: entry, TargetHost: "127.0.0.1", TargetPort: sink, TCP: true,
	}}); err != nil {
		t.Fatal(err)
	}
	waitForwardListening(t, "fp")
	// 把数据目录换成只读：写 want 文件必失败。
	readOnly := t.TempDir()
	if err := os.WriteFile(readOnly+"/blocker", []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	relayEng.mu.Lock()
	relayEng.dir = filepath.Join(readOnly, "missing-subdir")
	relayEng.mu.Unlock()
	if err := relayApplyAll(relayEng.dir, nil, nil); err == nil {
		t.Fatal("persist failure must surface as error")
	}
	// 运行时没被改动：原转发还在听。
	if _, ok := forwardStateByID("fp"); !ok {
		t.Fatal("runtime must keep last good list after persist failure")
	}
	relayEng.mu.Lock()
	relayEng.dir = dir
	relayEng.mu.Unlock()
	if err := relayApplyAll(dir, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitForwardGone(t, "fp")
}

// TestForwardCounterRetireAfterAckOnly 撤销的转发计数只在面板确认后才退休：
// 没确认时持续重发，确认后从计数表消失。
func TestForwardCounterRetireAfterAckOnly(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
	resetForwardBytes()
	t.Cleanup(relayStop)

	relayApplyAll(dir, nil, []relaySpec{{
		ForwardID: "fr", Port: freePort(t), TargetHost: "127.0.0.1", TargetPort: 1, TCP: true,
	}})
	relayNoteTo("fr", 40, true)
	relayApplyAll(dir, nil, nil)
	if got := fwdCounter("fr", "uplink"); got != 40 {
		t.Fatalf("counter must survive revoke until acked: %d", got)
	}
	// 面板确认该批次后才退休（retireConfirmedForwards 只在 ack 之后被调用）。
	retireConfirmedForwards(map[string]int64{"forward>>>fr>>>traffic>>>uplink": 40})
	if got := fwdCounter("fr", "uplink"); got != 0 {
		t.Fatalf("counter must retire after ack: %d", got)
	}
	// 仍生效的转发不会被误退休。
	relayApplyAll(dir, nil, []relaySpec{{
		ForwardID: "fl", Port: freePort(t), TargetHost: "127.0.0.1", TargetPort: 1, TCP: true,
	}})
	relayNoteTo("fl", 12, true)
	retireConfirmedForwards(map[string]int64{"forward>>>fl>>>traffic>>>uplink": 12})
	if got := fwdCounter("fl", "uplink"); got != 12 {
		t.Fatalf("live forward retired: %d", got)
	}
}

// TestForwardIDFromCounter 计数键解析：只认 forward>>><id>>>traffic>>>uplink/downlink，
// relay 聚合键、核心键和畸形键都不该解析出转发 id。
func TestForwardIDFromCounter(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   string
		ok   bool
	}{
		{"forward>>>abc>>>traffic>>>uplink", "abc", true},
		{"forward>>>abc>>>traffic>>>downlink", "abc", true},
		{"relay>>>all>>>traffic>>>uplink", "", false},
		{"forward>>>>>>traffic>>>uplink", "", false},
		{"forward>>>a>>>b>>>traffic>>>uplink", "", false},
		{"forward>>>abc>>>traffic>>>sideways", "", false},
		{"user>>>x>>>inbound>>>uplink", "", false},
	} {
		id, ok := forwardIDFromCounter(tc.name)
		if ok != tc.ok || id != tc.id {
			t.Fatalf("%s → (%q,%v) want (%q,%v)", tc.name, id, ok, tc.id, tc.ok)
		}
	}
}

// TestForwardStatsAckGatesRetirement 端到端：撤销的转发计数要等面板 stats_ack 才退休。
// ack 到达前计数持续保留（面板没确认就不删，避免丢掉最后一笔字节），确认后立刻退休。
func TestForwardStatsAckGatesRetirement(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
	resetForwardBytes()
	t.Cleanup(relayStop)

	relayApplyAll(dir, nil, []relaySpec{{
		ForwardID: "fa", Port: freePort(t), TargetHost: "127.0.0.1", TargetPort: 1, TCP: true,
	}})
	relayNoteTo("fa", 64, true)
	relayApplyAll(dir, nil, nil)

	acked := make(chan struct{})
	s, _, _ := dialWithPanel(t, false, func(peer *panelHandle) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		// serve 开头先报一次用量；先只收不发，等测试侧确认「未确认不退休」。
		msg, err := peer.read(ctx)
		if err != nil {
			t.Errorf("read stats: %v", err)
			return
		}
		if msg.T != msgStats {
			t.Errorf("first frame %q want stats", msg.T)
			return
		}
		var body struct {
			Batch    string           `json:"batch"`
			Counters map[string]int64 `json:"counters"`
		}
		if err := json.Unmarshal(msg.D, &body); err != nil {
			t.Errorf("stats body: %v", err)
			return
		}
		if body.Counters["forward>>>fa>>>traffic>>>uplink"] != 64 {
			t.Errorf("stats counters %+v", body.Counters)
			return
		}
		<-acked
		if err := peer.send(ctx, message{T: msgStatsAck, D: json.RawMessage(`{"batch":"` + body.Batch + `"}`)}); err != nil {
			t.Errorf("send ack: %v", err)
		}
	})
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.serve(context.Background()) }()

	// 面板还没确认：计数必须还在（否则删除前那段字节会丢）。
	time.Sleep(300 * time.Millisecond)
	if got := fwdCounter("fa", "uplink"); got != 64 {
		t.Fatalf("counter dropped before ack: %d", got)
	}
	close(acked)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if fwdCounter("fa", "uplink") == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("counter not retired after ack: %d", fwdCounter("fa", "uplink"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
