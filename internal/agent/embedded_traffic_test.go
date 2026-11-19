package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
)

const trafficTestPassword = "0123456789abcdef0123456789abcdef"

func TestEmbeddedNowhereCountsAllTraffic(t *testing.T) {
	const total int64 = 10 << 20
	resetTraffic()
	t.Cleanup(resetTraffic)

	sink, sinkPort := listenSink(t)
	port := freePort(t)
	dir := t.TempDir()
	cfg := fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: nw
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw2]
rules:
  - MATCH,DIRECT
`, port, trafficTestPassword)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := newEmbeddedRuntime()
	if err := rt.Start(context.Background(), path, dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Stop)

	client, err := outbound.NewNowhereV2(outbound.NowhereOption{
		Name: "c", Server: "127.0.0.1", Port: port,
		Password: trafficTestPassword, SkipCertVerify: true,
		ALPN: []string{"nw2"},
		Up:   "tcp", Down: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, &C.Metadata{Host: "127.0.0.1", DstPort: uint16(sinkPort)})
	if err != nil {
		t.Fatal(err)
	}
	writeUntilStop(t, conn, total)
	_ = conn.Close()
	waitSink(t, sink, total)
	if got := counterValue("inbound>>>nw>>>traffic>>>uplink"); got != total {
		t.Fatalf("uplink counter %d want %d counters %v", got, total, traffic.counters())
	}
}

// nw3 默认栈：监听不写 alpn（核心默认 nw3），客户端同样不写 up/down，计数口径不变。
func TestEmbeddedNowhereNw3CountsAllTraffic(t *testing.T) {
	const total int64 = 10 << 20
	resetTraffic()
	t.Cleanup(resetTraffic)

	sink, sinkPort := listenSink(t)
	port := freePort(t)
	dir := t.TempDir()
	cfg := fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: nw3
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
rules:
  - MATCH,DIRECT
`, port, trafficTestPassword)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := newEmbeddedRuntime()
	if err := rt.Start(context.Background(), path, dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Stop)

	client, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "c", Server: "127.0.0.1", Port: port,
		Password: trafficTestPassword, SkipCertVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, &C.Metadata{Host: "127.0.0.1", DstPort: uint16(sinkPort)})
	if err != nil {
		t.Fatal(err)
	}
	writeUntilStop(t, conn, total)
	_ = conn.Close()
	waitSink(t, sink, total)
	if got := counterValue("inbound>>>nw3>>>traffic>>>uplink"); got != total {
		t.Fatalf("uplink counter %d want %d counters %v", got, total, traffic.counters())
	}
}

func TestEmbeddedUserListenersCountAllTraffic(t *testing.T) {
	const total int64 = 1 << 20
	resetTraffic()
	t.Cleanup(func() {
		resetTraffic()
		if rt, ok := proc.rt.(*embeddedRuntime); ok {
			rt.Stop()
		}
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("log-level: silent\nfind-process-mode: \"off\"\nrules:\n  - MATCH,DIRECT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := newEmbeddedRuntime()
	if err := rt.Start(context.Background(), path, dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.Stop)

	cert, key, fingerprint, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	const uuid = "01234567-89ab-cdef-0123-456789abcdef"

	vlessIn, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:  inbound.BaseOption{NameStr: "vless-in", Listen: "127.0.0.1", Port: "0"},
		Users:       []inbound.VlessUser{{Username: "test", UUID: uuid}},
		Certificate: cert,
		PrivateKey:  key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := vlessIn.Listen(meterTunnel{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = vlessIn.Close() })
	pushThrough(t, "vless", total, func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		addr := netip.MustParseAddrPort(vlessIn.Address())
		client, err := outbound.NewVless(outbound.VlessOption{
			Name: "vless-out", Server: addr.Addr().String(), Port: int(addr.Port()),
			UUID: uuid, TLS: true, SkipCertVerify: true, Fingerprint: fingerprint,
		})
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { _ = client.Close() })
		return client.DialContext(ctx, &C.Metadata{Host: host, DstPort: port})
	})

	anyIn, err := inbound.NewAnyTLS(&inbound.AnyTLSOption{
		BaseOption:  inbound.BaseOption{NameStr: "anytls-in", Listen: "127.0.0.1", Port: "0"},
		Users:       map[string]string{"test": uuid},
		Certificate: cert,
		PrivateKey:  key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := anyIn.Listen(meterTunnel{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = anyIn.Close() })
	pushThrough(t, "anytls", total, func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		addr := netip.MustParseAddrPort(anyIn.Address())
		client, err := outbound.NewAnyTLS(outbound.AnyTLSOption{
			Name: "anytls-out", Server: addr.Addr().String(), Port: int(addr.Port()),
			Password: uuid, SkipCertVerify: true, Fingerprint: fingerprint,
		})
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { _ = client.Close() })
		return client.DialContext(ctx, &C.Metadata{Host: host, DstPort: port})
	})
}

func pushThrough(t *testing.T, label string, total int64, dial func(context.Context, string, uint16) (net.Conn, error)) {
	t.Helper()
	before := userUplink()
	sunk, port := listenSink(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := dial(ctx, "127.0.0.1", uint16(port))
	if err != nil {
		t.Fatalf("%s dial: %v counters %v", label, err, traffic.counters())
	}
	writeUntilStop(t, conn, total)
	_ = conn.Close()
	waitSink(t, sunk, total)
	if got := userUplink() - before; got != total {
		t.Fatalf("%s user uplink %d want %d counters %v", label, got, total, traffic.counters())
	}
}

func userUplink() int64 {
	var total int64
	for name, value := range traffic.counters() {
		if strings.HasPrefix(name, "user>>>") && strings.HasSuffix(name, ">>>traffic>>>uplink") {
			total += value
		}
	}
	return total
}

func counterValue(name string) int64 {
	return traffic.counters()[name]
}

func listenSink(t *testing.T) (*atomic.Int64, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	sunk := &atomic.Int64{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				n, _ := io.Copy(io.Discard, conn)
				sunk.Add(n)
				_ = conn.Close()
			}(conn)
		}
	}()
	return sunk, ln.Addr().(*net.TCPAddr).Port
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func writeUntilStop(t *testing.T, conn net.Conn, total int64) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, 32<<10)
	left := total
	for left > 0 {
		n := int64(len(buf))
		if n > left {
			n = left
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			return
		}
		left -= n
	}
}

func waitSink(t *testing.T, sunk *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if sunk.Load() >= want {
			if sunk.Load() != want {
				t.Fatalf("sink %d want %d counters %v", sunk.Load(), want, traffic.counters())
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("sink %d want %d counters %v", sunk.Load(), want, traffic.counters())
}

func resetTraffic() {
	traffic = newTrafficMeter()
}

func TestEmbeddedTestClosesResourcesAndRunningRaceFree(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfg := fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: nw-test
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
proxies:
  - name: out-1
    type: nowhere
    server: 127.0.0.1
    port: %d
    password: %s
    skip-cert-verify: true
proxy-groups:
  - name: auto
    type: url-test
    proxies: [out-1]
    url: http://127.0.0.1:1/generate_204
    interval: 1
rules:
  - MATCH,auto
`, port, trafficTestPassword, port, trafficTestPassword)
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	rt := newEmbeddedRuntime()
	// 先做一轮预热，再检查多次 Test 不会持续堆积后台健康检查协程。
	if err := rt.Test(context.Background(), path, dir); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	baseG := runtime.NumGoroutine()
	for range 20 {
		if err := rt.Test(context.Background(), path, dir); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if leaked := runtime.NumGoroutine() - baseG; leaked > 10 {
		t.Fatalf("embedded Test leaked goroutines: before=%d after=%d", baseG, baseG+leaked)
	}

	// 并发读写 Running() 与 Start/Stop（-race 下验证 atomic.Bool 无竞态）。
	simplePath := filepath.Join(dir, "simple.yaml")
	if err := os.WriteFile(simplePath, []byte("log-level: silent\nfind-process-mode: \"off\"\nrules:\n  - MATCH,DIRECT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stopPoll := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopPoll:
				return
			default:
				_ = rt.Running()
			}
		}
	}()
	if err := rt.Start(context.Background(), simplePath, dir); err != nil {
		close(stopPoll)
		wg.Wait()
		t.Fatal(err)
	}
	if !rt.Running() {
		rt.Stop()
		close(stopPoll)
		wg.Wait()
		t.Fatal("expected Running() == true after Start")
	}
	rt.Stop()
	close(stopPoll)
	wg.Wait()
	if rt.Running() {
		t.Fatal("expected Running() == false after Stop")
	}
}

func TestEmbeddedApplyPartialFailureDropsClosedListener(t *testing.T) {
	dir := t.TempDir()
	portA := freePort(t)
	busyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busyLn.Close()
	busyPort := busyLn.Addr().(*net.TCPAddr).Port

	writeCfg := func(name string, port int) string {
		p := filepath.Join(dir, name)
		body := fmt.Sprintf("log-level: silent\nfind-process-mode: \"off\"\nlisteners:\n  - name: lis-a\n    type: socks\n    listen: 127.0.0.1\n    port: %d\nrules:\n  - MATCH,DIRECT\n", port)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfgGood := writeCfg("good.yaml", portA)
	cfgConflict := writeCfg("conflict.yaml", busyPort)

	rt := newEmbeddedRuntime()
	defer rt.Stop()
	if err := rt.Start(context.Background(), cfgGood, dir); err != nil {
		t.Fatal(err)
	}
	// Apply 改到已被占用的端口：旧 lis-a 先关、新 lis-a Listen 失败。
	if err := rt.Apply(context.Background(), cfgConflict, dir, nil, "", nil, false, false); err == nil {
		t.Fatal("expected Apply to fail on occupied port")
	}
	// 随后直接 Apply 回原配置：不得把已关闭的旧 lis-a 当存活句柄复用，portA 必须重新监听成功。
	if err := rt.Apply(context.Background(), cfgGood, dir, nil, "", nil, false, false); err != nil {
		t.Fatalf("recovery Apply failed: %v", err)
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", portA), 2*time.Second)
	if err != nil {
		t.Fatalf("portA should be listening after recovery Apply, dial failed: %v", err)
	}
	_ = c.Close()
}

func TestEmbeddedSharedShadowsocksMultiUserAndHotReload(t *testing.T) {
	resetTraffic()
	t.Cleanup(resetTraffic)

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echoLn.Close() })
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	echoPort := uint16(echoLn.Addr().(*net.TCPAddr).Port)

	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpEcho.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udpEcho.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteTo(buf[:n], addr)
		}
	}()
	udpEchoAddr := udpEcho.LocalAddr().(*net.UDPAddr)

	portAEAD := freePort(t)
	port2022 := freePort(t)
	// 32-byte base64 keys for 2022-blake3-aes-256-gcm
	const aeadSkeletonSecret = "c2tlbGV0b24tc2VjcmV0LWZvci10ZXN0LW9ubHktMTIzNA=="
	const serverPSK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const user1PSK = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	const user2PSK = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	const user3PSK = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="

	dir := t.TempDir()
	cfgYAML := fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: sh-aead
    type: shadowsocks
    listen: 127.0.0.1
    port: %d
    cipher: aes-256-gcm
    password: %s
    udp: true
  - name: sh-2022
    type: shadowsocks
    listen: 127.0.0.1
    port: %d
    cipher: 2022-blake3-aes-256-gcm
    password: %s
    udp: true
rules:
  - IN-NAME,sh-aead,DIRECT
  - IN-NAME,sh-2022,DIRECT
  - MATCH,REJECT
`, portAEAD, aeadSkeletonSecret, port2022, serverPSK)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	shared := []sharedDesired{
		{
			Tag: "sh-aead", Protocol: "shadowsocks", Method: "aes-256-gcm",
			Users: []sharedUser{
				{Email: "sub-a1", Secret: "pass-alpha-0001"},
				{Email: "sub-a2", Secret: "pass-bravo-0002"},
			},
		},
		{
			Tag: "sh-2022", Protocol: "shadowsocks", Method: "2022-blake3-aes-256-gcm",
			Users: []sharedUser{
				{Email: "sub-b1", Secret: user1PSK},
				{Email: "sub-b2", Secret: user2PSK},
			},
		},
	}

	rt := newEmbeddedRuntime()
	if err := rt.Test(context.Background(), cfgPath, dir); err != nil {
		t.Fatalf("Test config failed: %v", err)
	}
	if err := rt.StartShared(context.Background(), cfgPath, dir, shared); err != nil {
		t.Fatalf("StartShared failed: %v", err)
	}
	t.Cleanup(rt.Stop)

	makeClient := func(name string, port int, cipher, password string, uot bool) C.ProxyAdapter {
		c, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{
			Name: name, Server: "127.0.0.1", Port: port,
			Cipher: cipher, Password: password, UDP: true,
			UDPOverTCP: uot, UDPOverTCPVersion: 2,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	ca1 := makeClient("ca1", portAEAD, "aes-256-gcm", "pass-alpha-0001", false)
	ca2 := makeClient("ca2", portAEAD, "aes-256-gcm", "pass-bravo-0002", true)
	cb1 := makeClient("cb1", port2022, "2022-blake3-aes-256-gcm", serverPSK+":"+user1PSK, false)
	cb2 := makeClient("cb2", port2022, "2022-blake3-aes-256-gcm", serverPSK+":"+user2PSK, true)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	roundTripTCP := func(client C.ProxyAdapter, payload string) net.Conn {
		conn, err := client.DialContext(ctx, &C.Metadata{Host: "127.0.0.1", DstPort: echoPort})
		if err != nil {
			t.Fatalf("%s dial tcp: %v", client.Name(), err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatalf("%s write tcp: %v", client.Name(), err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("%s read tcp: %v", client.Name(), err)
		}
		if string(got) != payload {
			t.Fatalf("%s echo mismatch: got %q want %q", client.Name(), got, payload)
		}
		return conn
	}

	roundTripUDP := func(client C.ProxyAdapter, payload string) {
		pc, err := client.ListenPacketContext(ctx, &C.Metadata{
			NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(udpEchoAddr.Port),
		})
		if err != nil {
			t.Fatalf("%s dial udp: %v", client.Name(), err)
		}
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := pc.WriteTo([]byte(payload), udpEchoAddr); err != nil {
			t.Fatalf("%s write udp: %v", client.Name(), err)
		}
		buf := make([]byte, 256)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("%s read udp: %v", client.Name(), err)
		}
		if string(buf[:n]) != payload {
			t.Fatalf("%s udp mismatch: got %q want %q", client.Name(), buf[:n], payload)
		}
	}

	// 同端口双用户 TCP + 原生 UDP + UoT 并发通行。
	connKeep := roundTripTCP(cb1, "keep-alive-before")
	defer connKeep.Close()
	connRevoke := roundTripTCP(cb2, "revoke-me-before")
	defer connRevoke.Close()
	// 保持一条 UoT 长连接，验证热删用户时 UoT 连接同样立刻掐断，而保留用户的 UoT 不受影响。
	cb1UoT := makeClient("cb1-uot", port2022, "2022-blake3-aes-256-gcm", serverPSK+":"+user1PSK, true)
	uotKeep, err := cb1UoT.ListenPacketContext(ctx, &C.Metadata{
		NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(udpEchoAddr.Port),
	})
	if err != nil {
		t.Fatalf("cb1-uot dial: %v", err)
	}
	defer uotKeep.Close()
	uotRevoke, err := cb2.ListenPacketContext(ctx, &C.Metadata{
		NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(udpEchoAddr.Port),
	})
	if err != nil {
		t.Fatalf("cb2-uot dial: %v", err)
	}
	defer uotRevoke.Close()
	checkUoTPacket := func(pc C.PacketConn, payload string) error {
		_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
		if _, werr := pc.WriteTo([]byte(payload), udpEchoAddr); werr != nil {
			return werr
		}
		b := make([]byte, 256)
		n, _, rerr := pc.ReadFrom(b)
		if rerr != nil {
			return rerr
		}
		if string(b[:n]) != payload {
			return fmt.Errorf("got %q want %q", b[:n], payload)
		}
		return nil
	}
	if err := checkUoTPacket(uotKeep, "uot-keep-before"); err != nil {
		t.Fatalf("uotKeep before reload: %v", err)
	}
	if err := checkUoTPacket(uotRevoke, "uot-revoke-before"); err != nil {
		t.Fatalf("uotRevoke before reload: %v", err)
	}
	c1 := roundTripTCP(ca1, "hello-a1")
	_ = c1.Close()
	c2 := roundTripTCP(ca2, "hello-a2")
	_ = c2.Close()

	roundTripUDP(ca1, "udp-native-a1")
	roundTripUDP(ca2, "udp-uot-a2")
	roundTripUDP(cb1, "udp-native-b1")
	roundTripUDP(cb2, "udp-uot-b2")

	// 验证 user>>>、inbound>>>、pair>>> 三组计数器全部就位。
	ctrs := traffic.counters()
	for _, key := range []string{
		"user>>>sub-a1>>>traffic>>>uplink",
		"user>>>sub-a2>>>traffic>>>uplink",
		"user>>>sub-b1>>>traffic>>>uplink",
		"user>>>sub-b2>>>traffic>>>uplink",
		"inbound>>>sh-aead>>>traffic>>>uplink",
		"inbound>>>sh-2022>>>traffic>>>uplink",
		"pair>>>sub-a1>>>sh-aead>>>traffic>>>uplink",
		"pair>>>sub-b2>>>sh-2022>>>traffic>>>downlink",
	} {
		if ctrs[key] <= 0 {
			t.Fatalf("missing or zero counter %s in %v", key, ctrs)
		}
	}

	// 先新增 sub-b3（触发 keptGens 留存），再校验重复 email 不误判变更。
	ss2022Lis, ok := rt.listeners["sh-2022"].(*embeddedSSListener)
	if !ok {
		t.Fatalf("expected embeddedSSListener for sh-2022, got %T", rt.listeners["sh-2022"])
	}
	sharedAdd := []sharedDesired{
		shared[0],
		{
			Tag: "sh-2022", Protocol: "shadowsocks", Method: "2022-blake3-aes-256-gcm",
			Users: []sharedUser{
				{Email: "sub-b1", Secret: user1PSK},
				{Email: "sub-b2", Secret: user2PSK},
				{Email: "sub-b3", Secret: user3PSK},
			},
		},
	}
	if err := rt.Apply(context.Background(), cfgPath, dir, nil, "", sharedAdd, false, false); err != nil {
		t.Fatalf("hot add Apply failed: %v", err)
	}
	genAfterAdd := ss2022Lis.gen.Load()
	if _, err := ss2022Lis.UpdateUsers([]sharedUser{
		{Email: "sub-b1", Secret: user1PSK},
		{Email: "sub-b1", Secret: user1PSK},
		{Email: "sub-b2", Secret: user2PSK},
		{Email: "sub-b3", Secret: user3PSK},
	}); err != nil {
		t.Fatalf("duplicate email UpdateUsers: %v", err)
	}
	if ss2022Lis.gen.Load() != genAfterAdd {
		t.Fatal("duplicate email in want list triggered unexpected generation rebuild")
	}

	// 热更新：从 sh-2022 移除 sub-b2 和 sub-b3，保留 sub-b1，同时验证 keptGens 被全部清空。
	sharedAfter := []sharedDesired{
		shared[0],
		{
			Tag: "sh-2022", Protocol: "shadowsocks", Method: "2022-blake3-aes-256-gcm",
			Users: []sharedUser{{Email: "sub-b1", Secret: user1PSK}},
		},
	}
	if err := rt.Apply(context.Background(), cfgPath, dir, nil, "", sharedAfter, false, false); err != nil {
		t.Fatalf("hot Apply failed: %v", err)
	}
	ss2022Lis.mu.Lock()
	keptCount := len(ss2022Lis.keptGens)
	ss2022Lis.mu.Unlock()
	if keptCount != 0 {
		t.Fatalf("expected keptGens drained after user revocation, got %d", keptCount)
	}

	// sub-b1 的既有长连接与既有 UoT 连接必须零中断继续收发！
	_ = connKeep.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connKeep.Write([]byte("still-alive-after")); err != nil {
		t.Fatalf("kept user connection broke on hot reload: %v", err)
	}
	still := make([]byte, len("still-alive-after"))
	if _, err := io.ReadFull(connKeep, still); err != nil || string(still) != "still-alive-after" {
		t.Fatalf("kept user read after hot reload: got %q err %v", still, err)
	}
	if err := checkUoTPacket(uotKeep, "uot-keep-after"); err != nil {
		t.Fatalf("kept user UoT connection broke on hot reload: %v", err)
	}

	// 被移除的 sub-b2 存量 TCP 与 UoT 连接必须已被关闭，且新建连接鉴权失败。
	_ = connRevoke.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = connRevoke.Write([]byte("should-fail"))
	buf := make([]byte, 16)
	if _, err := connRevoke.Read(buf); err == nil {
		t.Fatal("expected revoked user's existing TCP connection to be closed")
	}
	if err := checkUoTPacket(uotRevoke, "uot-should-fail"); err == nil {
		t.Fatal("expected revoked user's existing UoT connection to be closed")
	}

	badConn, err := cb2.DialContext(ctx, &C.Metadata{Host: "127.0.0.1", DstPort: echoPort})
	if err == nil {
		_ = badConn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = badConn.Write([]byte("probe"))
		if _, rerr := badConn.Read(buf); rerr == nil {
			_ = badConn.Close()
			t.Fatal("revoked SS2022 user succeeded dialing after removal")
		}
		_ = badConn.Close()
	}
}
