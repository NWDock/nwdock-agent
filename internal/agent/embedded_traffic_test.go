package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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
