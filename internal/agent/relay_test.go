package agent

import (
	"bytes"
	"context"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// resetRelay 把转发引擎还原成刚启动的状态，供测试隔离。
func resetRelay(dir string) {
	relayStop()
	relayEng.mu.Lock()
	relayEng.handles = map[string]*relayHandle{}
	relayEng.persist = nil
	relayEng.fwdPersist = nil
	relayEng.liveForwards = map[string]bool{}
	relayEng.retiredForwards = map[string]bool{}
	relayEng.dir = dir
	relayEng.mu.Unlock()
}

func waitRelayListening(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, st := range relayStates() {
			if st.Port == port && st.Listening {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("relay port %d not listening: %+v", port, relayStates())
}

func relayStateFor(t *testing.T, port int) relayPortState {
	t.Helper()
	for _, st := range relayStates() {
		if st.Port == port {
			return st
		}
	}
	t.Fatalf("relay port %d has no state: %+v", port, relayStates())
	return relayPortState{}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}

// echoSink 回显所有收到的字节：客户端经入口写入什么就该读回什么，
// 同时用来确认一条已建立的连接在监听器重建后仍然存活。
func echoSink(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func echoThrough(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write %q: %v", payload, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo of %q: %v", payload, err)
	}
	if string(buf) != payload {
		t.Fatalf("echo %q want %q", buf, payload)
	}
}

func udpEchoSink(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestRelayTCPForwardsAndKeepsEstablished(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	t.Cleanup(relayStop)

	sinkA := echoSink(t)
	sinkB := echoSink(t)
	entry := freePort(t)
	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sinkA, TCP: true}})
	waitRelayListening(t, entry)

	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	echoThrough(t, conn, "hello")

	// 落地端口变化：监听器重建，但已建立的连接保持。
	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sinkB, TCP: true}})
	waitRelayListening(t, entry)
	echoThrough(t, conn, "again")

	// 新连接走新落地端口。
	conn2, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn2.Close() })
	echoThrough(t, conn2, "fresh")
}

func TestRelayUDPForwardsBothDirections(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	t.Cleanup(relayStop)

	sink := udpEchoSink(t)
	entry := freeUDPPort(t)
	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sink, UDP: true}})
	waitRelayListening(t, entry)

	client, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = client.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := client.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := client.Read(buf)
		if err != nil {
			continue
		}
		if string(buf[:n]) != "ping" {
			t.Fatalf("echo %q", buf[:n])
		}
		return
	}
	t.Fatal("udp relay echo timeout")
}

func TestRelayPortFailureIsolatedFromCoreStatus(t *testing.T) {
	resetRelay(t.TempDir())
	t.Cleanup(relayStop)

	held, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	heldPort := held.Addr().(*net.TCPAddr).Port

	sink := echoSink(t)
	good := freePort(t)
	relayEng.apply([]relaySpec{
		{Port: heldPort, TargetHost: "127.0.0.1", TargetPort: sink, TCP: true},
		{Port: good, TargetHost: "127.0.0.1", TargetPort: sink, TCP: true},
	})
	waitRelayListening(t, good)

	bad := relayStateFor(t, heldPort)
	if bad.Listening || bad.Error == "" {
		t.Fatalf("held port should fail with reason: %+v", bad)
	}
	if len(bad.Error) > 256 || !utf8.ValidString(bad.Error) {
		t.Fatalf("error not heartbeat-safe: %q", bad.Error)
	}
	// 转发出错不把核心标为异常。
	if summary := errorSummary(); summary != "" {
		t.Fatalf("relay error leaked into core status: %q", summary)
	}

	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(good))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	echoThrough(t, conn, "ok")
}

func TestRelayPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	t.Cleanup(relayStop)

	sink := echoSink(t)
	entry := freePort(t)
	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sink, TCP: true}})
	waitRelayListening(t, entry)

	// 进程重启：新引擎从磁盘清单恢复，面板不在线也继续转发。
	resetRelay(dir)
	relayInit(dir)
	waitRelayListening(t, entry)
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	echoThrough(t, conn, "after")

	// 空清单清空全部端口。
	resetRelay(dir)
	relayInit(dir)
	relayEng.apply(nil)
	if len(relayStates()) != 0 {
		t.Fatalf("ports not cleared: %+v", relayStates())
	}
}

func TestRelayStatesCapAndTruncate(t *testing.T) {
	handles := map[string]*relayHandle{}
	long := strings.Repeat("x", 1000)
	for i := 1; i <= 300; i++ {
		handles[relayPortKey(i)] = &relayHandle{spec: relaySpec{Port: i}, err: long}
		handles[relayForwardKey(strconv.Itoa(i))] = &relayHandle{spec: relaySpec{Port: i, ForwardID: strconv.Itoa(i)}, err: long}
	}
	all := relayStateList(handles)
	if len(all) != len(handles) {
		t.Fatalf("full list %d want %d", len(all), len(handles))
	}
	// 全表排序：失败段在前，段内按端口与 forward id 升序。
	for i := 1; i < len(all); i++ {
		prev, cur := all[i-1], all[i]
		if (prev.Error == "") != (cur.Error == "") {
			if prev.Error == "" {
				t.Fatalf("failed entry after live at %d", i)
			}
			continue
		}
		if prev.Port > cur.Port {
			t.Fatalf("port order broken at %d: %+v %+v", i, prev, cur)
		}
	}
	capped := all[:relayMaxStates]
	legacySeen := false
	for _, st := range capped {
		if len(st.Error) > 256 || !utf8.ValidString(st.Error) {
			t.Fatalf("error not heartbeat-safe: %q", st.Error)
		}
		if st.Listening {
			t.Fatalf("failed port reported listening: %+v", st)
		}
		if st.ForwardID == "" {
			legacySeen = true
		}
	}
	if !legacySeen {
		t.Fatal("no legacy entries in capped list")
	}
}

func TestRelayHeartbeatStateFields(t *testing.T) {
	handles := map[string]*relayHandle{
		relayPortKey(80):      {spec: relaySpec{Port: 80}, err: "boom"},
		relayForwardKey("f1"): {spec: relaySpec{Port: 81, ForwardID: "f1"}},
	}
	all := relayStateList(handles)
	if len(all) != 2 {
		t.Fatalf("states %+v", all)
	}
	if all[0].Port != 80 || all[0].Error != "boom" || all[0].Listening {
		t.Fatalf("failed entry first: %+v", all[0])
	}
	if all[1].ForwardID != "f1" || !all[1].Listening || all[1].Error != "" {
		t.Fatalf("forward entry: %+v", all[1])
	}
}

func TestRelayUDPSessionCapAndIdlePrune(t *testing.T) {
	tbl := &relayUDP{sessions: map[string]*relayUDPSession{}}
	conns := make([]net.Conn, 0, relayUDPSessions*2)
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	for i := range relayUDPSessions {
		a, b := net.Pipe()
		conns = append(conns, a, b)
		if s := tbl.add(strconv.Itoa(i), a); s == nil {
			t.Fatalf("add %d", i)
		}
	}
	if len(tbl.sessions) != relayUDPSessions {
		t.Fatalf("sessions %d want %d", len(tbl.sessions), relayUDPSessions)
	}
	// 表满后再加一个：最旧的被淘汰，上游连接随之关闭。
	oldest := tbl.sessions["0"].up
	a, b := net.Pipe()
	conns = append(conns, a, b)
	if s := tbl.add("new", a); s == nil {
		t.Fatal("add at cap")
	}
	if _, ok := tbl.sessions["0"]; ok {
		t.Fatal("oldest session not evicted")
	}
	if _, err := oldest.Write([]byte("x")); err == nil {
		t.Fatal("evicted session upstream still open")
	}

	// 空闲超过 60 秒的会话被拆除，活跃会话保留。
	idle := time.Now().Add(-2 * relayUDPIdle).UnixNano()
	for key, s := range tbl.sessions {
		if key != "new" {
			s.last.Store(idle)
		}
	}
	tbl.prune(time.Now().UnixNano())
	if len(tbl.sessions) != 1 {
		t.Fatalf("sessions after prune %d want 1", len(tbl.sessions))
	}
	if _, ok := tbl.sessions["new"]; !ok {
		t.Fatal("active session pruned")
	}
}

func TestRelaySpecValidation(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	t.Cleanup(relayStop)
	relayEng.apply([]relaySpec{
		{Port: 0, TargetHost: "127.0.0.1", TargetPort: 1, TCP: true},
		{Port: 70000, TargetHost: "127.0.0.1", TargetPort: 1, TCP: true},
		{Port: 40000, TargetHost: "", TargetPort: 1, TCP: true},
		{Port: 40000, TargetHost: "127.0.0.1", TargetPort: 0, TCP: true},
		{Port: 40000, TargetHost: "127.0.0.1", TargetPort: 1},
		{Port: 40000, TargetHost: "127.0.0.1", TargetPort: 1, TCP: true},
	})
	states := relayStates()
	if len(states) != 1 || states[0].Port != 40000 {
		t.Fatalf("only the valid spec should apply: %+v", states)
	}
	raw, err := readRelayWant(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 || raw[0].Port != 40000 || !raw[0].TCP {
		t.Fatalf("persisted %+v", raw)
	}
}

func TestRelayTCPHalfClosePropagated(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	t.Cleanup(relayStop)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := io.ReadAll(conn)
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("ack:" + string(req)))
		if cw, ok := conn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()

	entry := freePort(t)
	sinkPort := ln.Addr().(*net.TCPAddr).Port
	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sinkPort, TCP: true}})
	waitRelayListening(t, entry)

	start := time.Now()
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("half-close-payload")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	if string(resp) != "ack:half-close-payload" {
		t.Fatalf("resp %q", resp)
	}
	if elapsed := time.Since(start); elapsed >= 3*time.Second {
		t.Fatalf("half-close waited too long: %v", elapsed)
	}
}

func TestRelayCarriedOverTCPSessionsClosedOnDeleteOrStop(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	t.Cleanup(relayStop)

	sinkA := echoSink(t)
	sinkB := echoSink(t)
	sinkC := echoSink(t)
	entry := freePort(t)

	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sinkA, TCP: true}})
	waitRelayListening(t, entry)

	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	echoThrough(t, conn, "gen1")

	// 连续两次热更新目标后撤销条目：迁移过来的旧 TCP 会话必须被立即关闭，不许变成孤儿连接。
	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sinkB, TCP: true}})
	waitRelayListening(t, entry)
	echoThrough(t, conn, "gen2")

	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sinkC, TCP: true}})
	waitRelayListening(t, entry)
	echoThrough(t, conn, "gen3")

	relayEng.apply(nil)
	waitConnClosed(t, conn)
}

func TestRelayNonBlockingUDPDialAndPendingCap(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	t.Cleanup(relayStop)

	sink := udpEchoSink(t)
	entry := freeUDPPort(t)

	var dialCount atomic.Int32
	slowEntered := make(chan struct{})
	unblockSlow := make(chan struct{})
	testRelayDial = func(_ relaySpec, ctx context.Context, network, addr string) (net.Conn, error) {
		if dialCount.Add(1) == 1 {
			close(slowEntered)
			select {
			case <-unblockSlow:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	t.Cleanup(func() { testRelayDial = nil })

	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sink, UDP: true}})
	waitRelayListening(t, entry)

	slowClient, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slowClient.Close() })
	if _, err := slowClient.Write([]byte("slow-init")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-slowEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("slow dial did not start")
	}

	// 第一个会话拨号仍卡住时，第二个客户端的收发不被 ReadFrom 阻塞。
	fastClient, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fastClient.Close() })
	_ = fastClient.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fastClient.Write([]byte("fast-ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := fastClient.Read(buf)
	if err != nil {
		t.Fatalf("fast client blocked by slow dial: %v", err)
	}
	if string(buf[:n]) != "fast-ping" {
		t.Fatalf("fast echo %q", buf[:n])
	}

	// 放行慢拨号后，其首包仍能正常转发并回显。
	close(unblockSlow)
	_ = slowClient.SetDeadline(time.Now().Add(2 * time.Second))
	n, err = slowClient.Read(buf)
	if err != nil {
		t.Fatalf("slow client initial packet lost: %v", err)
	}
	if string(buf[:n]) != "slow-init" {
		t.Fatalf("slow echo %q", buf[:n])
	}

	// 并发挂起拨号上限与同源去重校验。
	tbl := &relayUDP{sessions: map[string]*relayUDPSession{}}
	if _, start := tbl.lookupOrStartDial("dup"); !start {
		t.Fatal("first pending dial should start")
	}
	if _, start := tbl.lookupOrStartDial("dup"); start {
		t.Fatal("duplicate pending key should not start second dial")
	}
	tbl.clearPending("dup")
	for i := range relayUDPPendingMax {
		if _, start := tbl.lookupOrStartDial("p-" + strconv.Itoa(i)); !start {
			t.Fatalf("pending slot %d rejected", i)
		}
	}
	if _, start := tbl.lookupOrStartDial("overflow"); start {
		t.Fatal("pending dial cap exceeded")
	}
}

// 验证 UDP 转发在 Unix 上采用 RawConn 零空闲缓冲挂起 + 池化读包：
// 256 条并发空闲真实 UDP 会话既能原样回传 4KiB 大包，又不再每会话常驻 64KiB（总计 16MiB）堆内存。
func TestRelayUDPZeroIdleBufferAndLargeDatagram(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	t.Cleanup(relayStop)

	sink := udpEchoSink(t)
	entry := freeUDPPort(t)
	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sink, UDP: true}})
	waitRelayListening(t, entry)

	const sessions = 256
	payload := bytes.Repeat([]byte("U"), 4096)
	rx := make([]byte, len(payload))
	clients := make([]net.Conn, 0, sessions)
	t.Cleanup(func() {
		for _, c := range clients {
			_ = c.Close()
		}
	})

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	baseG := runtime.NumGoroutine()

	for i := range sessions {
		c, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(entry))
		if err != nil {
			t.Fatalf("dial udp %d: %v", i, err)
		}
		clients = append(clients, c)
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(payload); err != nil {
			t.Fatalf("write udp %d: %v", i, err)
		}
		n, err := c.Read(rx)
		if err != nil || !bytes.Equal(rx[:n], payload) {
			t.Fatalf("echo udp %d: n=%d err=%v", i, n, err)
		}
	}

	// 清理 sync.Pool 并采样 256 条空闲会话仍在活跃挂起时的堆占用。
	runtime.GC()
	runtime.GC()
	var during runtime.MemStats
	runtime.ReadMemStats(&during)
	var liveDelta int64
	if during.HeapAlloc > before.HeapAlloc {
		liveDelta = int64(during.HeapAlloc - before.HeapAlloc)
	}
	t.Logf("256 idle UDP sessions HeapAlloc delta=%d KiB (naive 64KiB/session=%d KiB)", liveDelta>>10, sessions*64)
	if relayUDPPooledSupported && liveDelta > 8<<20 {
		t.Fatalf("idle UDP sessions retained too much heap: %d bytes (want < 8MiB)", liveDelta)
	}

	relayStop()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseG+16 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("UDP relay goroutines did not exit after stop: before=%d after=%d", baseG, runtime.NumGoroutine())
}
