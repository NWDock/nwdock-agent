package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	"github.com/metacubex/mihomo/component/geodata"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel"
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
	// 完成 SOCKS5 方法协商，确保服务端 accept 协程已越过入站全局过滤再关闭并结束用例，
	// 避免下一用例 ApplyConfig 写全局过滤切片时与残余 accept 协程竞态。
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = c.Close()
		t.Fatalf("socks5 greeting write failed: %v", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil || reply[0] != 0x05 {
		_ = c.Close()
		t.Fatalf("socks5 greeting reply failed: got %x err=%v", reply, err)
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

	// 验证 clash-meta-nw v3.4.0 新增 ShadowSocksOption.Users 的克隆隔离与不支持多用户算法的错误口径。
	origUsers := map[string]string{"u1": "p1"}
	optWithUsers := &inbound.ShadowSocksOption{
		BaseOption: inbound.BaseOption{NameStr: "ss-clone", Listen: "127.0.0.1", Port: "0"},
		Cipher:     "aes-256-gcm",
		Password:   aeadSkeletonSecret,
		Users:      origUsers,
	}
	clonedLis, err := newEmbeddedSSListener(optWithUsers, []sharedUser{{Email: "u1", Secret: "p1"}})
	if err != nil {
		t.Fatalf("newEmbeddedSSListener with Users failed: %v", err)
	}
	t.Cleanup(func() { _ = clonedLis.Close() })
	origUsers["u1"] = "mutated"
	if got := clonedLis.config.Users["u1"]; got != "p1" {
		t.Fatalf("embeddedSSListener aliased ShadowSocksOption.Users map: got %q want p1", got)
	}
	if _, err := newEmbeddedSSListener(&inbound.ShadowSocksOption{
		BaseOption: inbound.BaseOption{NameStr: "ss-chacha-2022", Listen: "127.0.0.1", Port: "0"},
		Cipher:     "2022-blake3-chacha20-poly1305",
		Password:   serverPSK,
	}, []sharedUser{{Email: "u1", Secret: user1PSK}}); err == nil || !strings.Contains(err.Error(), "unsupported multi-user cipher") {
		t.Fatalf("expected unsupported multi-user cipher error for 2022-blake3-chacha20-poly1305, got: %v", err)
	}
}

// Nowhere 3.4.0（clash-meta-nw v3.4.0）：验证 Morph Cipher（cipher: aes）在 TCP 与 QUIC/UDP 载体、
// UDP 数据报转发计数、密码算法校验（含 nw2 拒收 cipher）、算法不匹配拒连与 probe 端到端探测。
func TestEmbeddedNowhereNw3CipherAESAndUDP(t *testing.T) {
	resetTraffic()
	t.Cleanup(resetTraffic)

	origGuard := probeURLGuardEnabled
	origTLS := probeHTTPClientTLS
	probeURLGuardEnabled = false
	t.Cleanup(func() {
		probeURLGuardEnabled = origGuard
		probeHTTPClientTLS = origTLS
	})

	dir := t.TempDir()
	rt := newEmbeddedRuntime()

	// 配置校验：非法 cipher 以及 nw2 指定 cipher 都必须在 Test 阶段被拒收。
	for _, tc := range []struct {
		name string
		yaml string
	}{
		{
			name: "invalid-cipher",
			yaml: fmt.Sprintf("log-level: silent\nfind-process-mode: \"off\"\nlisteners:\n  - name: bad1\n    type: nowhere\n    listen: 127.0.0.1\n    port: 0\n    password: %s\n    cipher: bogus\nrules:\n  - MATCH,DIRECT\n", trafficTestPassword),
		},
		{
			name: "nw2-rejects-cipher",
			yaml: fmt.Sprintf("log-level: silent\nfind-process-mode: \"off\"\nlisteners:\n  - name: bad2\n    type: nowhere\n    listen: 127.0.0.1\n    port: 0\n    password: %s\n    alpn: [nw2]\n    cipher: aes\nrules:\n  - MATCH,DIRECT\n", trafficTestPassword),
		},
	} {
		p := filepath.Join(dir, tc.name+".yaml")
		if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := rt.Test(context.Background(), p, dir); err == nil {
			t.Fatalf("%s: expected Test to reject invalid nowhere cipher config", tc.name)
		}
	}

	sink, sinkPort := listenSink(t)
	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpEcho.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, rerr := udpEcho.ReadFrom(buf)
			if rerr != nil {
				return
			}
			_, _ = udpEcho.WriteTo(buf[:n], addr)
		}
	}()
	udpEchoAddr := udpEcho.LocalAddr().(*net.UDPAddr)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	probeHTTPClientTLS = &tls.Config{RootCAs: pool}

	tcpPort := freePort(t)
	udpPort := freeLoopbackDualPort(t)
	cfg := fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: nw3-aes-tcp
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: tcp
    morph: true
    cipher: aes
  - name: nw3-aes-udp
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: udp
    morph: true
    cipher: aes
rules:
  - MATCH,DIRECT
`, tcpPort, trafficTestPassword, udpPort, trafficTestPassword)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.Test(context.Background(), cfgPath, dir); err != nil {
		t.Fatalf("Test nw3 cipher:aes config failed: %v", err)
	}
	if err := rt.Start(context.Background(), cfgPath, dir); err != nil {
		t.Fatalf("Start nw3 cipher:aes failed: %v", err)
	}
	t.Cleanup(rt.Stop)

	const total int64 = 1 << 20
	morphOn := true

	// 1) TCP 载体 + cipher: aes 精确计数。
	tcpClient, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nw3-tcp-aes", Server: "127.0.0.1", Port: tcpPort,
		Password: trafficTestPassword, SkipCertVerify: true,
		ALPN: []string{"nw3"}, Net: "tcp", Morph: &morphOn, Cipher: "aes",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpClient.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := tcpClient.DialContext(ctx, &C.Metadata{Host: "127.0.0.1", DstPort: uint16(sinkPort)})
	if err != nil {
		t.Fatalf("nw3 tcp cipher:aes dial: %v", err)
	}
	writeUntilStop(t, conn, total)
	_ = conn.Close()
	waitSink(t, sink, total)
	if got := counterValue("inbound>>>nw3-aes-tcp>>>traffic>>>uplink"); got != total {
		t.Fatalf("nw3-aes-tcp uplink %d want %d counters %v", got, total, traffic.counters())
	}

	// 2) QUIC/UDP 载体 + cipher: aes：验证 PreAuth 窗口放行后的 TCP 流与 UDP 数据报双向计数。
	udpClient, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nw3-udp-aes", Server: "127.0.0.1", Port: udpPort,
		Password: trafficTestPassword, SkipCertVerify: true,
		ALPN: []string{"nw3"}, Net: "udp", Morph: &morphOn, Cipher: "aes",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpClient.Close() })
	qConn, err := udpClient.DialContext(ctx, &C.Metadata{Host: "127.0.0.1", DstPort: uint16(sinkPort)})
	if err != nil {
		t.Fatalf("nw3 udp cipher:aes tcp-flow dial: %v", err)
	}
	writeUntilStop(t, qConn, total)
	_ = qConn.Close()
	waitSink(t, sink, total*2)

	pc, err := udpClient.ListenPacketContext(ctx, &C.Metadata{
		NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(udpEchoAddr.Port),
	})
	if err != nil {
		t.Fatalf("nw3 udp cipher:aes udp-flow dial: %v", err)
	}
	const udpPayload = "nowhere-3.4-aes-datagram"
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := pc.WriteTo([]byte(udpPayload), udpEchoAddr); err != nil {
		_ = pc.Close()
		t.Fatalf("nw3 udp write: %v", err)
	}
	rbuf := make([]byte, 256)
	rn, _, err := pc.ReadFrom(rbuf)
	_ = pc.Close()
	if err != nil || string(rbuf[:rn]) != udpPayload {
		t.Fatalf("nw3 udp echo mismatch: got %q err=%v", rbuf[:rn], err)
	}
	if got := counterValue("inbound>>>nw3-aes-udp>>>traffic>>>uplink"); got != total+int64(len(udpPayload)) {
		t.Fatalf("nw3-aes-udp uplink %d want %d counters %v", got, total+int64(len(udpPayload)), traffic.counters())
	}
	if got := counterValue("inbound>>>nw3-aes-udp>>>traffic>>>downlink"); got < int64(len(udpPayload)) {
		t.Fatalf("nw3-aes-udp downlink %d want >= %d counters %v", got, len(udpPayload), traffic.counters())
	}

	// 3) Morph Cipher 不匹配（chacha 客户端连 aes 服务端）必须无法建连。
	wrongCipher, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nw3-tcp-chacha", Server: "127.0.0.1", Port: tcpPort,
		Password: trafficTestPassword, SkipCertVerify: true,
		ALPN: []string{"nw3"}, Net: "tcp", Morph: &morphOn, Cipher: "chacha",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrongCipher.Close() })
	shortCtx, shortCancel := context.WithTimeout(ctx, 2*time.Second)
	defer shortCancel()
	if bad, err := wrongCipher.DialContext(shortCtx, &C.Metadata{Host: "127.0.0.1", DstPort: uint16(sinkPort)}); err == nil {
		_ = bad.Close()
		t.Fatal("expected mismatched morph cipher (chacha vs aes) to fail handshake")
	}

	// 4) probe.go 通过 adapter.ParseProxy 解析 cipher: aes 并完成真实 URL 探测。
	probeRes := executeProbe(ctx, probeRequest{
		ID:           "nw3-aes-probe",
		Host:         "127.0.0.1",
		Port:         tcpPort,
		AllowPrivate: true,
		Proxy: map[string]any{
			"name":             "probe-nw3-aes",
			"type":             "nowhere",
			"server":           "127.0.0.1",
			"port":             tcpPort,
			"password":         trafficTestPassword,
			"alpn":             []string{"nw3"},
			"net":              "tcp",
			"morph":            true,
			"cipher":           "aes",
			"skip-cert-verify": true,
		},
		LatencyURL: ts.URL + "/generate_204",
	})
	if probeRes.URLTest == nil || probeRes.URLTest.Status != "ok" || probeRes.URLTest.HTTPStatus != 204 {
		t.Fatalf("expected nw3 cipher:aes probe ok 204, got %+v", probeRes.URLTest)
	}
}

// Nowhere 3.5.0（clash-meta-nw v3.5.0）：验证 Morph Grade（grade: core）在 TCP 与 QUIC/UDP 载体、
// ChaCha20 与 AES-128-CTR 算法组合下的转发与计费、配置校验（含 morph=false 与 nw2 拒收）、
// grade 不匹配拒连与 probe 端到端探测。
func TestEmbeddedNowhereNw3GradeCore(t *testing.T) {
	resetTraffic()
	t.Cleanup(resetTraffic)

	origGuard := probeURLGuardEnabled
	origTLS := probeHTTPClientTLS
	probeURLGuardEnabled = false
	t.Cleanup(func() {
		probeURLGuardEnabled = origGuard
		probeHTTPClientTLS = origTLS
	})

	dir := t.TempDir()
	rt := newEmbeddedRuntime()

	// 配置校验：非法 grade、morph=false 下的非法 grade 以及 nw2 指定 grade 都必须在 Test 阶段被拒收。
	for _, tc := range []struct {
		name string
		yaml string
	}{
		{
			name: "invalid-grade",
			yaml: fmt.Sprintf("log-level: silent\nfind-process-mode: \"off\"\nlisteners:\n  - name: bad-grade-1\n    type: nowhere\n    listen: 127.0.0.1\n    port: 0\n    password: %s\n    grade: light\nrules:\n  - MATCH,DIRECT\n", trafficTestPassword),
		},
		{
			name: "invalid-grade-morph-off",
			yaml: fmt.Sprintf("log-level: silent\nfind-process-mode: \"off\"\nlisteners:\n  - name: bad-grade-2\n    type: nowhere\n    listen: 127.0.0.1\n    port: 0\n    password: %s\n    morph: false\n    grade: CORE\nrules:\n  - MATCH,DIRECT\n", trafficTestPassword),
		},
		{
			name: "nw2-rejects-grade",
			yaml: fmt.Sprintf("log-level: silent\nfind-process-mode: \"off\"\nlisteners:\n  - name: bad-grade-3\n    type: nowhere\n    listen: 127.0.0.1\n    port: 0\n    password: %s\n    alpn: [nw2]\n    grade: core\nrules:\n  - MATCH,DIRECT\n", trafficTestPassword),
		},
	} {
		p := filepath.Join(dir, tc.name+".yaml")
		if err := os.WriteFile(p, []byte(tc.yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := rt.Test(context.Background(), p, dir); err == nil {
			t.Fatalf("%s: expected Test to reject invalid nowhere grade config", tc.name)
		}
	}

	sink, sinkPort := listenSink(t)
	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpEcho.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, rerr := udpEcho.ReadFrom(buf)
			if rerr != nil {
				return
			}
			_, _ = udpEcho.WriteTo(buf[:n], addr)
		}
	}()
	udpEchoAddr := udpEcho.LocalAddr().(*net.UDPAddr)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	probeHTTPClientTLS = &tls.Config{RootCAs: pool}

	tcpChaChaPort := freePort(t)
	tcpAESPort := freePort(t)
	udpAESPort := freeLoopbackDualPort(t)
	cfg := fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: nw3-core-chacha-tcp
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: tcp
    morph: true
    grade: core
  - name: nw3-core-aes-tcp
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: tcp
    morph: true
    grade: core
    cipher: aes
  - name: nw3-core-aes-udp
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: udp
    morph: true
    grade: core
    cipher: aes
rules:
  - MATCH,DIRECT
`, tcpChaChaPort, trafficTestPassword, tcpAESPort, trafficTestPassword, udpAESPort, trafficTestPassword)
	cfgPath := filepath.Join(dir, "config-grade.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.Test(context.Background(), cfgPath, dir); err != nil {
		t.Fatalf("Test nw3 grade:core config failed: %v", err)
	}
	if err := rt.Start(context.Background(), cfgPath, dir); err != nil {
		t.Fatalf("Start nw3 grade:core failed: %v", err)
	}
	t.Cleanup(rt.Stop)

	const total int64 = 256 << 10
	morphOn := true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 1) TCP + grade: core + 默认 chacha 转发与精确计数。
	tcpChaCha, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nw3-tcp-core-chacha", Server: "127.0.0.1", Port: tcpChaChaPort,
		Password: trafficTestPassword, SkipCertVerify: true,
		ALPN: []string{"nw3"}, Net: "tcp", Morph: &morphOn, Grade: "core",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpChaCha.Close() })
	c1, err := tcpChaCha.DialContext(ctx, &C.Metadata{Host: "127.0.0.1", DstPort: uint16(sinkPort)})
	if err != nil {
		t.Fatalf("nw3 tcp grade:core chacha dial: %v", err)
	}
	writeUntilStop(t, c1, total)
	_ = c1.Close()
	waitSink(t, sink, total)
	if got := counterValue("inbound>>>nw3-core-chacha-tcp>>>traffic>>>uplink"); got != total {
		t.Fatalf("nw3-core-chacha-tcp uplink %d want %d counters %v", got, total, traffic.counters())
	}

	// 2) TCP + grade: core + cipher: aes 转发与精确计数。
	tcpAES, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nw3-tcp-core-aes", Server: "127.0.0.1", Port: tcpAESPort,
		Password: trafficTestPassword, SkipCertVerify: true,
		ALPN: []string{"nw3"}, Net: "tcp", Morph: &morphOn, Grade: "core", Cipher: "aes",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpAES.Close() })
	c2, err := tcpAES.DialContext(ctx, &C.Metadata{Host: "127.0.0.1", DstPort: uint16(sinkPort)})
	if err != nil {
		t.Fatalf("nw3 tcp grade:core aes dial: %v", err)
	}
	writeUntilStop(t, c2, total)
	_ = c2.Close()
	waitSink(t, sink, total*2)
	if got := counterValue("inbound>>>nw3-core-aes-tcp>>>traffic>>>uplink"); got != total {
		t.Fatalf("nw3-core-aes-tcp uplink %d want %d counters %v", got, total, traffic.counters())
	}

	// 3) QUIC/UDP + grade: core + cipher: aes 流与数据报双向转发计数。
	udpAES, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nw3-udp-core-aes", Server: "127.0.0.1", Port: udpAESPort,
		Password: trafficTestPassword, SkipCertVerify: true,
		ALPN: []string{"nw3"}, Net: "udp", Morph: &morphOn, Grade: "core", Cipher: "aes",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpAES.Close() })
	qConn, err := udpAES.DialContext(ctx, &C.Metadata{Host: "127.0.0.1", DstPort: uint16(sinkPort)})
	if err != nil {
		t.Fatalf("nw3 udp grade:core aes tcp-flow dial: %v", err)
	}
	writeUntilStop(t, qConn, total)
	_ = qConn.Close()
	waitSink(t, sink, total*3)

	pc, err := udpAES.ListenPacketContext(ctx, &C.Metadata{
		NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(udpEchoAddr.Port),
	})
	if err != nil {
		t.Fatalf("nw3 udp grade:core aes udp-flow dial: %v", err)
	}
	const udpPayload = "nowhere-3.5-core-aes-datagram"
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := pc.WriteTo([]byte(udpPayload), udpEchoAddr); err != nil {
		_ = pc.Close()
		t.Fatalf("nw3 udp write: %v", err)
	}
	rbuf := make([]byte, 256)
	rn, _, err := pc.ReadFrom(rbuf)
	_ = pc.Close()
	if err != nil || string(rbuf[:rn]) != udpPayload {
		t.Fatalf("nw3 udp echo mismatch: got %q err=%v", rbuf[:rn], err)
	}
	if got := counterValue("inbound>>>nw3-core-aes-udp>>>traffic>>>uplink"); got != total+int64(len(udpPayload)) {
		t.Fatalf("nw3-core-aes-udp uplink %d want %d counters %v", got, total+int64(len(udpPayload)), traffic.counters())
	}
	if got := counterValue("inbound>>>nw3-core-aes-udp>>>traffic>>>downlink"); got < int64(len(udpPayload)) {
		t.Fatalf("nw3-core-aes-udp downlink %d want >= %d counters %v", got, len(udpPayload), traffic.counters())
	}

	// 4) Morph Grade 不匹配（full 客户端连 core 服务端）在 TCP 与 QUIC 下均必须失败。
	wrongTCP, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nw3-tcp-full-mismatch", Server: "127.0.0.1", Port: tcpAESPort,
		Password: trafficTestPassword, SkipCertVerify: true,
		ALPN: []string{"nw3"}, Net: "tcp", Morph: &morphOn, Grade: "full", Cipher: "aes",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrongTCP.Close() })
	shortCtx, shortCancel := context.WithTimeout(ctx, 2*time.Second)
	defer shortCancel()
	if bad, err := wrongTCP.DialContext(shortCtx, &C.Metadata{Host: "127.0.0.1", DstPort: uint16(sinkPort)}); err == nil {
		_ = bad.Close()
		t.Fatal("expected mismatched morph grade (full vs core) on TCP to fail handshake")
	}

	wrongUDP, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nw3-udp-full-mismatch", Server: "127.0.0.1", Port: udpAESPort,
		Password: trafficTestPassword, SkipCertVerify: true,
		ALPN: []string{"nw3"}, Net: "udp", Morph: &morphOn, Grade: "full", Cipher: "aes",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrongUDP.Close() })
	shortUDPCtx, shortUDPCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer shortUDPCancel()
	if bad, err := wrongUDP.DialContext(shortUDPCtx, &C.Metadata{Host: "127.0.0.1", DstPort: uint16(sinkPort)}); err == nil {
		_ = bad.Close()
		t.Fatal("expected mismatched morph grade (full vs core) on QUIC to fail handshake")
	}

	// 5) probe.go 通过 adapter.ParseProxy 解析 grade: core + cipher: aes 并完成真实 URL 探测。
	probeRes := executeProbe(ctx, probeRequest{
		ID:           "nw3-core-aes-probe",
		Host:         "127.0.0.1",
		Port:         tcpAESPort,
		AllowPrivate: true,
		Proxy: map[string]any{
			"name":             "probe-nw3-core-aes",
			"type":             "nowhere",
			"server":           "127.0.0.1",
			"port":             tcpAESPort,
			"password":         trafficTestPassword,
			"alpn":             []string{"nw3"},
			"net":              "tcp",
			"morph":            true,
			"grade":            "core",
			"cipher":           "aes",
			"skip-cert-verify": true,
		},
		LatencyURL: ts.URL + "/generate_204",
	})
	if probeRes.URLTest == nil || probeRes.URLTest.Status != "ok" || probeRes.URLTest.HTTPStatus != 204 {
		t.Fatalf("expected nw3 grade:core+cipher:aes probe ok 204, got %+v", probeRes.URLTest)
	}
}

// 验证 embeddedRuntime.Stop() 会一并释放 mihomo 全局 proxies/rules 与 geodata singleflight 缓存，
// 避免切到 xray/sing-box 或整机停服后常驻几十 MiB 旧索引与出站对象。
func TestEmbeddedStopReleasesTunnelAndGeoCache(t *testing.T) {
	dir := t.TempDir()
	writeGeoSiteDat(t, dir, "geosite.dat", "alpha.example")
	t.Cleanup(func() {
		geodata.ClearGeoSiteCache()
		geodata.ClearGeoIPCache()
	})

	cfg := `log-level: silent
find-process-mode: "off"
geodata-mode: true
proxies:
  - name: direct-out
    type: direct
    udp: true
rules:
  - GEOSITE,china-list,direct-out
  - MATCH,DIRECT
`
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	rt := newEmbeddedRuntime()
	if err := rt.Start(context.Background(), cfgPath, dir); err != nil {
		t.Fatalf("Start embedded with geosite failed: %v", err)
	}
	if _, ok := tunnel.Proxies()["direct-out"]; !ok {
		rt.Stop()
		t.Fatalf("expected direct-out in tunnel.Proxies() before Stop")
	}
	if len(tunnel.Rules()) == 0 {
		rt.Stop()
		t.Fatal("expected non-empty tunnel.Rules() before Stop")
	}
	mBefore, err := geodata.LoadGeoSiteMatcher("china-list")
	if err != nil || !mBefore.ApplyDomain("alpha.example") {
		rt.Stop()
		t.Fatalf("geosite matcher before Stop: err=%v", err)
	}

	rt.Stop()

	if tunnel.Status() != tunnel.Suspend {
		t.Fatalf("expected tunnel suspended after Stop, got %v", tunnel.Status())
	}
	if _, ok := tunnel.Proxies()["direct-out"]; ok {
		t.Fatal("expected custom outbound direct-out released after Stop")
	}
	for name, p := range tunnel.Proxies() {
		if p == nil || p.Type() != C.Reject {
			t.Fatalf("expected only built-in Reject fallback proxies after Stop, got %q=%v", name, p)
		}
	}
	for _, required := range []string{"DIRECT", "REJECT", "GLOBAL"} {
		if p := tunnel.Proxies()[required]; p == nil || p.Type() != C.Reject {
			t.Fatalf("expected built-in Reject fallback for %s after Stop, got %v", required, p)
		}
	}
	if len(tunnel.Rules()) != 0 {
		t.Fatalf("expected tunnel.Rules() empty after Stop, got %d", len(tunnel.Rules()))
	}
	// 覆写 geosite.dat 后应直接读到新内容，证明 Stop() 已清掉核内 GeoSite 缓存。
	writeGeoSiteDat(t, dir, "geosite.dat", "beta.example")
	mAfter, err := geodata.LoadGeoSiteMatcher("china-list")
	if err != nil {
		t.Fatalf("LoadGeoSiteMatcher after Stop: %v", err)
	}
	if mAfter.ApplyDomain("alpha.example") || !mAfter.ApplyDomain("beta.example") {
		t.Fatal("expected geosite cache cleared on Stop() so updated dat reloads")
	}
}

// 验证 embeddedSSListener 连续新增用户时 keptGens 严格受 maxKeptSSGens 封顶，
// 超出上限的最早代上下文被及时取消，避免高频增人叠加过多历史快照。
func TestEmbeddedSSKeptGensCapped(t *testing.T) {
	const serverPSK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	lis, err := newEmbeddedSSListener(&inbound.ShadowSocksOption{
		BaseOption: inbound.BaseOption{NameStr: "ss-cap", Listen: "127.0.0.1", Port: "0"},
		Cipher:     "aes-256-gcm",
		Password:   serverPSK,
	}, []sharedUser{{Email: "u0", Secret: "secret-0"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })

	firstGen := lis.gen.Load()
	users := []sharedUser{{Email: "u0", Secret: "secret-0"}}
	for i := 1; i <= maxKeptSSGens+4; i++ {
		users = append(users, sharedUser{
			Email:  fmt.Sprintf("u%d", i),
			Secret: fmt.Sprintf("secret-%d", i),
		})
		if _, err := lis.UpdateUsers(users); err != nil {
			t.Fatalf("UpdateUsers #%d: %v", i, err)
		}
		lis.mu.Lock()
		kept := len(lis.keptGens)
		lis.mu.Unlock()
		if kept > maxKeptSSGens {
			t.Fatalf("keptGens=%d exceeded cap %d at iteration %d", kept, maxKeptSSGens, i)
		}
	}
	select {
	case <-firstGen.ctx.Done():
	default:
		t.Fatal("expected evicted oldest SS generation context to be cancelled")
	}
}

// 验证核心配置与文件均未变化时，ApplySharedOnly 仅原地热更共享 SS 用户，
// 不重新解析配置也不调 executor.ApplyConfig，保留既有出站代理与 Nowhere 监听实例。
func TestEmbeddedApplySharedOnlySkipsReload(t *testing.T) {
	resetTraffic()
	t.Cleanup(resetTraffic)

	dir := t.TempDir()
	nwPort := freePort(t)
	ssPort := freePort(t)
	const serverPSK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	cfg := fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: nw-keep
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: tcp
    morph: true
    grade: core
  - name: sh-ss-only
    type: shadowsocks
    listen: 127.0.0.1
    port: %d
    cipher: aes-256-gcm
    password: %s
    udp: true
proxies:
  - name: direct-out
    type: direct
    udp: true
rules:
  - MATCH,direct-out
`, nwPort, trafficTestPassword, ssPort, serverPSK)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	rt := newEmbeddedRuntime()
	initialShared := []sharedDesired{{
		Tag:      "sh-ss-only",
		Protocol: "shadowsocks",
		Users:    []sharedUser{{Email: "u1", Secret: "secret-1"}},
	}}
	if err := rt.StartShared(context.Background(), cfgPath, dir, initialShared); err != nil {
		t.Fatalf("StartShared failed: %v", err)
	}
	t.Cleanup(rt.Stop)

	proxyBefore := tunnel.Proxies()["direct-out"]
	nwBefore := rt.listeners["nw-keep"]
	ssBefore, ok := rt.listeners["sh-ss-only"].(*embeddedSSListener)
	if proxyBefore == nil || nwBefore == nil || !ok {
		t.Fatalf("unexpected initial state: proxy=%v nw=%v ss=%T", proxyBefore, nwBefore, rt.listeners["sh-ss-only"])
	}

	// 1) 原地新增 u2 并踢除 u1：ApplySharedOnly 必须命中且不重建出站与 Nowhere 监听。
	updatedShared := []sharedDesired{{
		Tag:      "sh-ss-only",
		Protocol: "shadowsocks",
		Users:    []sharedUser{{Email: "u2", Secret: "secret-2"}},
	}}
	if !rt.ApplySharedOnly(updatedShared) {
		t.Fatal("expected ApplySharedOnly to succeed when shared SS tags are unchanged")
	}
	if tunnel.Proxies()["direct-out"] != proxyBefore {
		t.Fatal("ApplySharedOnly must not rebuild tunnel proxies")
	}
	if rt.listeners["nw-keep"] != nwBefore {
		t.Fatal("ApplySharedOnly must not recreate nowhere listener")
	}
	if rt.listeners["sh-ss-only"] != ssBefore {
		t.Fatal("ApplySharedOnly must update embeddedSSListener in-place")
	}
	gen := ssBefore.gen.Load()
	if gen == nil || len(gen.users) != 1 || gen.users["u2"] != "secret-2" {
		t.Fatalf("unexpected updated SS users: %+v", gen)
	}

	// 2) 共享 SS 标签集合发生变化时，必须返回 false 回退全量 Apply。
	if rt.ApplySharedOnly(nil) {
		t.Fatal("expected ApplySharedOnly to return false when an active shared SS tag is removed")
	}
	if rt.ApplySharedOnly([]sharedDesired{
		updatedShared[0],
		{Tag: "sh-ss-new", Protocol: "shadowsocks", Users: []sharedUser{{Email: "u3", Secret: "secret-3"}}},
	}) {
		t.Fatal("expected ApplySharedOnly to return false when a new shared SS tag is added")
	}
}

// 验证 embeddedRuntime.Apply 在 filesChanged=false 时复用未变监听，
// 在 filesChanged=true（证书内容同路径续期）时重建监听以立即加载新证书。
func TestEmbeddedApplyFilesChangedRecreatesListener(t *testing.T) {
	resetTraffic()
	t.Cleanup(resetTraffic)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	certA, keyA, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte(certA), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(keyA), 0o600); err != nil {
		t.Fatal(err)
	}

	port := freePort(t)
	cfg := fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: nw-cert
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    certificate: %q
    private-key: %q
    alpn: [nw3]
    net: tcp
    morph: true
rules:
  - MATCH,DIRECT
`, port, trafficTestPassword, certPath, keyPath)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	rt := newEmbeddedRuntime()
	if err := rt.Start(context.Background(), cfgPath, dir); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(rt.Stop)

	first := rt.listeners["nw-cert"]
	if first == nil {
		t.Fatal("expected nw-cert listener")
	}

	// filesChanged=false：配置未变应复用原监听实例。
	if err := rt.Apply(context.Background(), cfgPath, dir, nil, "", nil, false, false); err != nil {
		t.Fatalf("Apply filesChanged=false failed: %v", err)
	}
	if rt.listeners["nw-cert"] != first {
		t.Fatal("expected unchanged listener to be reused when filesChanged=false")
	}

	// 覆写同路径证书并传 filesChanged=true：必须重建监听而非继续复用。
	certB, keyB, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte(certB), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(keyB), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rt.Apply(context.Background(), cfgPath, dir, nil, "", nil, false, true); err != nil {
		t.Fatalf("Apply filesChanged=true failed: %v", err)
	}
	if rt.listeners["nw-cert"] == first {
		t.Fatal("expected listener to be recreated when filesChanged=true")
	}
}

// 回归：embeddedRuntime.Stop() 后若仍有已越过 isHandle() 的在途 TCP/UDP 协程进入
// tunnel.handleTCPConn / handleUDPConn，不得因 proxies["DIRECT"] 为 nil 触发空指针 panic。
func TestEmbeddedStopNoPanicOnInFlightTunnelConn(t *testing.T) {
	resetTraffic()
	t.Cleanup(resetTraffic)

	dir := t.TempDir()
	port := freePort(t)
	cfg := fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: nw-stop-safe
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: tcp
    morph: true
rules:
  - MATCH,DIRECT
`, port, trafficTestPassword)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	rt := newEmbeddedRuntime()
	if err := rt.Start(context.Background(), cfgPath, dir); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	rt.Stop()
	t.Cleanup(tunnel.OnSuspend)

	// 模拟已越过 isHandle() 门禁的在途 TCP 协程：在 Stop() 后的代理表状态下走完整 handleTCPConn。
	tunnel.OnRunning()
	cli, srv := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		tunnel.Tunnel.HandleTCPConn(srv, &C.Metadata{
			NetWork: C.TCP,
			Type:    C.SOCKS5,
			SrcIP:   netip.MustParseAddr("127.0.0.1"),
			SrcPort: 12345,
			DstIP:   netip.MustParseAddr("127.0.0.1"),
			DstPort: 80,
		})
	}()
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	_, _ = cli.Read(buf)
	_ = cli.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight HandleTCPConn after Stop did not finish")
	}

	// 同理验证停服后在途 UDP 包由内置 Reject 安全收束，不触发空指针 panic。
	dropped := make(chan struct{}, 1)
	pkt := &testDummyUDPPacket{data: []byte("ping"), dropped: dropped}
	tunnel.Tunnel.HandleUDPPacket(pkt, &C.Metadata{
		NetWork: C.UDP,
		Type:    C.SOCKS5,
		SrcIP:   netip.MustParseAddr("127.0.0.1"),
		SrcPort: 23456,
		DstIP:   netip.MustParseAddr("127.0.0.1"),
		DstPort: 53,
	})
	select {
	case <-dropped:
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight HandleUDPPacket after Stop was not dropped")
	}
}

type testDummyUDPPacket struct {
	data    []byte
	dropped chan struct{}
	once    sync.Once
}

func (p *testDummyUDPPacket) Data() []byte                            { return p.data }
func (p *testDummyUDPPacket) WriteBack([]byte, net.Addr) (int, error) { return 0, io.EOF }
func (p *testDummyUDPPacket) Drop()                                   { p.once.Do(func() { p.dropped <- struct{}{} }) }
func (p *testDummyUDPPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 23456}
}

func freeDualPort(t *testing.T) int {
	t.Helper()
	for range 32 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, uerr := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		_ = ln.Close()
		if uerr == nil {
			_ = pc.Close()
			return port
		}
	}
	t.Fatal("could not allocate free tcp+udp port")
	return 0
}

// 回归：embeddedRuntime.Apply 必须先关闭待删/换名/换端口旧监听再打开新监听，
// 覆盖同端口换 tag（如 nw2 单监听切 nw3 TCP+UDP 双监听）与两监听互换端口。
func TestEmbeddedApplyPortRenameAndSwapNoConflict(t *testing.T) {
	resetTraffic()
	t.Cleanup(resetTraffic)

	dir := t.TempDir()
	portA := freeDualPort(t)
	portB := freeDualPort(t)
	sink, sinkPort := listenSink(t)

	writeCfg := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// 初始：portA 跑 nw2（同时占 TCP+UDP），portB 跑 nw3 UDP。
	cfg1 := writeCfg("step1.yaml", fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: nw-v2-a
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw2]
  - name: nw-v3-b
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: udp
    morph: true
rules:
  - MATCH,DIRECT
`, portA, trafficTestPassword, portB, trafficTestPassword))

	rt := newEmbeddedRuntime()
	if err := rt.Start(context.Background(), cfg1, dir); err != nil {
		t.Fatalf("Start step1 failed: %v", err)
	}
	t.Cleanup(rt.Stop)

	// 切到 step2：portA 从 nw2 单 tag 换成 nw3 的 -t 与 -u 两个新 tag，portB 也换成新 tag。
	cfg2 := writeCfg("step2.yaml", fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: nw-v3-a-t
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: tcp
    morph: true
  - name: nw-v3-a-u
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: udp
    morph: true
  - name: nw-v3-b-renamed
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: udp
    morph: true
rules:
  - MATCH,DIRECT
`, portA, trafficTestPassword, portA, trafficTestPassword, portB, trafficTestPassword))

	if err := rt.Apply(context.Background(), cfg2, dir, nil, "", nil, false, false); err != nil {
		t.Fatalf("Apply step2 (tag rename on same UDP/TCP ports) failed: %v", err)
	}

	// 同名两监听互换端口多轮重复，确保不依赖 Go map 遍历顺序。
	for i := range 6 {
		p1, p2 := portA, portB
		if i%2 == 1 {
			p1, p2 = portB, portA
		}
		swapCfg := writeCfg(fmt.Sprintf("swap-%d.yaml", i), fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: nw-swap-1
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: udp
    morph: true
  - name: nw-swap-2
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: udp
    morph: true
rules:
  - MATCH,DIRECT
`, p1, trafficTestPassword, p2, trafficTestPassword))
		if err := rt.Apply(context.Background(), swapCfg, dir, nil, "", nil, false, false); err != nil {
			t.Fatalf("Apply swap #%d failed: %v", i, err)
		}
	}

	// 验证最终 UDP/QUIC 监听可正常转发真实流量。
	morphOn := true
	cli, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "c-swap", Server: "127.0.0.1", Port: portB,
		Password: trafficTestPassword, SkipCertVerify: true,
		ALPN: []string{"nw3"}, Net: "udp", Morph: &morphOn,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := cli.DialContext(ctx, &C.Metadata{Host: "127.0.0.1", DstPort: uint16(sinkPort)})
	if err != nil {
		t.Fatalf("dial after port swap failed: %v", err)
	}
	writeUntilStop(t, conn, 64<<10)
	_ = conn.Close()
	waitSink(t, sink, 64<<10)
}

// 回归：端口刚被短暂占用并于几十毫秒内释放时，embeddedRuntime.Apply 应通过有界退避重试成功监听。
func TestEmbeddedApplyTransientAddrInUseRetries(t *testing.T) {
	resetTraffic()
	t.Cleanup(resetTraffic)

	dir := t.TempDir()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port

	cfgPath := filepath.Join(dir, "transient.yaml")
	cfg := fmt.Sprintf(`log-level: silent
find-process-mode: "off"
listeners:
  - name: nw-transient
    type: nowhere
    listen: 127.0.0.1
    port: %d
    password: %s
    alpn: [nw3]
    net: udp
    morph: true
rules:
  - MATCH,DIRECT
`, port, trafficTestPassword)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		_ = pc.Close()
		t.Fatal(err)
	}

	go func() {
		time.Sleep(40 * time.Millisecond)
		_ = pc.Close()
	}()

	rt := newEmbeddedRuntime()
	if err := rt.Start(context.Background(), cfgPath, dir); err != nil {
		t.Fatalf("Start should succeed after transient UDP EADDRINUSE clears: %v", err)
	}
	rt.Stop()
}
