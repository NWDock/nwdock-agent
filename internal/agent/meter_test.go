package agent

import (
	"io"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func testMeter(clock *time.Time) *trafficMeter {
	m := newTrafficMeter()
	m.now = func() time.Time { return *clock }
	return m
}

func TestMeterTCPCountsUplinkAndDownlink(t *testing.T) {
	now := time.Unix(1_000, 0)
	m := testMeter(&now)
	ctr := m.counterLocked("inbound>>>nw")

	upClient, upServer := net.Pipe()
	up := &meterConn{m: m, Conn: upServer, ctr: ctr}
	defer up.Close()
	go func() {
		_, _ = upClient.Write([]byte("hello"))
		_ = upClient.Close()
	}()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(up, buf); err != nil {
		t.Fatal(err)
	}
	if ctr.up.Load() != 5 {
		t.Fatalf("uplink counter %d", ctr.up.Load())
	}

	downPeer, downLocal := net.Pipe()
	down := &meterConn{m: m, Conn: downLocal, ctr: ctr}
	defer down.Close()
	sunk := make(chan int, 1)
	go func() {
		b := make([]byte, 7)
		n, _ := io.ReadFull(downPeer, b)
		sunk <- n
	}()
	if n, err := down.Write([]byte("goodbye")); err != nil || n != 7 {
		t.Fatalf("write n %d err %v", n, err)
	}
	if got := <-sunk; got != 7 {
		t.Fatalf("peer read %d", got)
	}
	if ctr.down.Load() != 7 {
		t.Fatalf("downlink counter %d", ctr.down.Load())
	}
}

func TestMeterSharedInboundDualCount(t *testing.T) {
	now := time.Unix(1_000, 0)
	m := testMeter(&now)
	ctr, inCtr, pairCtr := m.accept(&C.Metadata{InUser: "u1", InName: "sh-ss-21003"})
	if inCtr == nil || pairCtr == nil {
		t.Fatal("shared listener must get an inbound-level counter and a user×inbound pair counter")
	}
	peer, local := net.Pipe()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	conn := &meterConn{m: m, Conn: local, ctr: ctr, inCtr: inCtr, pairCtr: pairCtr}
	if _, err := conn.Write(make([]byte, 400)); err != nil {
		t.Fatal(err)
	}
	if ctr.down.Load() != 400 || inCtr.down.Load() != 400 || pairCtr.down.Load() != 400 {
		t.Fatalf("dual count: user %d inbound %d pair %d", ctr.down.Load(), inCtr.down.Load(), pairCtr.down.Load())
	}
	// Nowhere 连接没有 InUser，键本身就是入站级，不再带辅助计数器。
	if nwCtr, nwIn, nwPair := m.accept(&C.Metadata{InName: "nw-abcd1234-20000"}); nwCtr == nil || nwIn != nil || nwPair != nil {
		t.Fatal("nowhere conn must only count at inbound level")
	}
	// 计费键、入站级键与联合键都随 stats 上报，面板各取所需。
	counters := m.counters()
	if counters["user>>>u1>>>traffic>>>downlink"] != 400 ||
		counters["inbound>>>sh-ss-21003>>>traffic>>>downlink"] != 400 ||
		counters["pair>>>u1>>>sh-ss-21003>>>traffic>>>downlink"] != 400 {
		t.Fatalf("counters: %v", counters)
	}
}

func TestMeterUDPCountsWithoutDropping(t *testing.T) {
	now := time.Unix(1_000, 0)
	m := testMeter(&now)
	ctr := m.counterLocked("user>>>u1")
	inner := &fakePacket{data: make([]byte, 80)}
	pkt := &meterPacket{m: m, UDPPacket: inner, ctr: ctr}
	if got := pkt.Data(); len(got) != 80 || inner.dropped {
		t.Fatalf("packet len %d dropped %v", len(got), inner.dropped)
	}
	if got := pkt.Data(); len(got) != 80 {
		t.Fatalf("second read len %d", len(got))
	}
	if ctr.up.Load() != 80 {
		t.Fatalf("uplink %d, packet must count once", ctr.up.Load())
	}
	if n, err := pkt.WriteBack(make([]byte, 30), nil); err != nil || n != 30 {
		t.Fatalf("writeback n %d err %v", n, err)
	}
	if ctr.down.Load() != 30 {
		t.Fatalf("downlink %d", ctr.down.Load())
	}
}

func TestMeterCloseInbound(t *testing.T) {
	now := time.Unix(1_000, 0)
	m := testMeter(&now)
	a, b := &closeProbe{}, &closeProbe{}
	m.track(a, "in-a")
	m.track(b, "in-b")
	m.closeInbound("in-a")
	if !a.closed || b.closed {
		t.Fatalf("closed a=%v b=%v", a.closed, b.closed)
	}
}

type closeProbe struct{ closed bool }

func (c *closeProbe) Read([]byte) (int, error)  { return 0, io.EOF }
func (c *closeProbe) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (c *closeProbe) Close() error              { c.closed = true; return nil }
func (c *closeProbe) LocalAddr() net.Addr       { return nil }
func (c *closeProbe) RemoteAddr() net.Addr      { return nil }
func (c *closeProbe) SetDeadline(time.Time) error {
	return nil
}
func (c *closeProbe) SetReadDeadline(time.Time) error {
	return nil
}
func (c *closeProbe) SetWriteDeadline(time.Time) error {
	return nil
}

type fakePacket struct {
	data    []byte
	back    []byte
	dropped bool
}

func (p *fakePacket) Data() []byte { return p.data }
func (p *fakePacket) WriteBack(b []byte, _ net.Addr) (int, error) {
	p.back = append([]byte(nil), b...)
	return len(b), nil
}
func (p *fakePacket) Drop()               { p.dropped = true }
func (p *fakePacket) LocalAddr() net.Addr { return nil }
