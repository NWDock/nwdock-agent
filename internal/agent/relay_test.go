package agent

import (
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// resetRelay 把转发引擎还原成刚启动的状态，供测试隔离。
func resetRelay(dir string) {
	relayStop()
	relayEng.mu.Lock()
	relayEng.ports = map[int]*relayHandle{}
	relayEng.persist = nil
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
	ports := map[int]*relayHandle{}
	long := strings.Repeat("x", 1000)
	for i := 1; i <= 600; i++ {
		ports[i] = &relayHandle{spec: relaySpec{Port: i}, err: long}
	}
	states := relayStateList(ports)
	if len(states) != relayMaxStates {
		t.Fatalf("states %d want %d", len(states), relayMaxStates)
	}
	for _, st := range states {
		if len(st.Error) > 256 || !utf8.ValidString(st.Error) {
			t.Fatalf("error not heartbeat-safe: %q", st.Error)
		}
		if st.Listening {
			t.Fatalf("failed port reported listening: %+v", st)
		}
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
