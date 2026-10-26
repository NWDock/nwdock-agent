package agent

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// resetRelayBytes 清零进程级转发累计，供测试隔离（relayBytes 是全局计数器）。
func resetRelayBytes() {
	relayBytes.up.Store(0)
	relayBytes.down.Store(0)
}

func relayCounterValue(name string) int64 {
	return relayCounters()[name]
}

// waitRelayCounter 等到全局转发计数达到期望值：回显字节进内核与计数入账之间
// 差一个调度节拍，紧跟着回显读的精确断言必须轮询。
func waitRelayCounter(t *testing.T, name string, want int64) int64 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := relayCounterValue(name); got == want {
			return got
		} else if got > want {
			t.Fatalf("%s = %d, want exactly %d", name, got, want)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s = %d, want %d", name, relayCounterValue(name), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRelayCountsActualBytes TCP 转发按成功写入计实际字节：客户端写入落地计 uplink，
// 落地回显计 downlink；半关闭后宽限窗口内不再补计。
func TestRelayCountsActualBytes(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
	t.Cleanup(relayStop)

	sink := echoSink(t)
	entry := freePort(t)
	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sink, TCP: true}})
	waitRelayListening(t, entry)

	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	payload := "0123456789"
	echoThrough(t, conn, payload)
	echoThrough(t, conn, payload)

	if up := waitRelayCounter(t, "relay>>>all>>>traffic>>>uplink", int64(2*len(payload))); up != int64(2*len(payload)) {
		t.Fatalf("uplink %d want %d", up, 2*len(payload))
	}
	if down := waitRelayCounter(t, "relay>>>all>>>traffic>>>downlink", int64(2*len(payload))); down != int64(2*len(payload)) {
		t.Fatalf("downlink %d want %d", down, 2*len(payload))
	}
}

// TestRelayUDPCountsBothDirections UDP 转发双向都按实际写入计数。
func TestRelayUDPCountsBothDirections(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
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
	payload := []byte("udp-ping")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = client.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := client.Read(buf)
		if err != nil {
			continue
		}
		if string(buf[:n]) != string(payload) {
			t.Fatalf("echo %q", buf[:n])
		}
		break
	}
	// 重传几次凑足可断言的累计量。
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
	// 轮询到入账再断言（回显读返回与计数入账差一个调度节拍）。
	deadline = time.Now().Add(2 * time.Second)
	for {
		up := relayCounterValue("relay>>>all>>>traffic>>>uplink")
		down := relayCounterValue("relay>>>all>>>traffic>>>downlink")
		if up >= int64(len(payload)) && down >= int64(len(payload)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("udp counters up=%d down=%d want both >= %d", up, down, len(payload))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRelayPortRevocationClosesSessions 端口撤销时关闭已建立的 TCP 会话两端，
// 客户端连接立即断开；同端口仅目标变化时连接保持。
func TestRelayPortRevocationClosesSessions(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
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
	echoThrough(t, conn, "before")

	// 端口整体撤销：会话两端关闭，客户端应很快收到 EOF。
	relayEng.apply(nil)
	waitNoRelayPort(t, entry)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("revoked port session still open")
	}

	// 重新开端口并建新连接：换落地目标时保持已建立连接（覆盖 keepSessions 路径）。
	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sinkB, TCP: true}})
	waitRelayListening(t, entry)
	conn2, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(entry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn2.Close() })
	echoThrough(t, conn2, "fresh")
	relayEng.apply([]relaySpec{{Port: entry, TargetHost: "127.0.0.1", TargetPort: sinkA, TCP: true}})
	waitRelayListening(t, entry)
	echoThrough(t, conn2, "kept")
}

func waitNoRelayPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		found := false
		for _, st := range relayStates() {
			if st.Port == port {
				found = true
			}
		}
		if !found {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("relay port %d still present: %+v", port, relayStates())
}

// TestMergeRelayCounters 转发计数并进核心 counters：命名空间不重叠，核心值优先，
// 无核心（counters 为 nil）时也能独立上报。
func TestMergeRelayCounters(t *testing.T) {
	resetRelayBytes()
	if got := mergeRelayCounters(nil); len(got) != 0 {
		t.Fatalf("empty relay counters should pass through: %+v", got)
	}
	relayBytes.up.Store(10)
	relayBytes.down.Store(4)
	got := mergeRelayCounters(map[string]int64{"inbound>>>nw>>>traffic>>>uplink": 7})
	if got["relay>>>all>>>traffic>>>uplink"] != 10 || got["relay>>>all>>>traffic>>>downlink"] != 4 {
		t.Fatalf("relay counters missing: %+v", got)
	}
	if got["inbound>>>nw>>>traffic>>>uplink"] != 7 {
		t.Fatalf("core counter overwritten: %+v", got)
	}
	if len(mergeRelayCounters(nil)) != 2 {
		t.Fatalf("nil counters should still carry relay bytes: %+v", relayCounters())
	}
	// 核心已占用同名 key 时不被覆盖（命名空间实际不重叠，防呆）。
	got = mergeRelayCounters(map[string]int64{"relay>>>all>>>traffic>>>uplink": 99})
	if got["relay>>>all>>>traffic>>>uplink"] != 99 {
		t.Fatalf("core value must win: %+v", got)
	}
}
