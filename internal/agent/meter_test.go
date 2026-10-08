package agent

import (
	"errors"
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

func grantJSON(sub string, granted int64, rate int, key, mode string) string {
	return `{"epoch":"e1","mode":"` + mode + `","ttl_s":600,"low_water":50,"leases":[{"sub":"` + sub + `","granted":` + itoa(granted) + `,"keys":{"` + key + `":` + itoa(int64(rate)) + `}}]}`
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func mustGrant(t *testing.T, m *trafficMeter, raw string) *meterAccount {
	t.Helper()
	if err := m.ApplySnapshot([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, acc := range m.accounts {
		return acc
	}
	t.Fatal("no account")
	return nil
}

func TestMeterTCPTruncatesUplinkAndDownlink(t *testing.T) {
	const grant = int64(4 << 20)
	now := time.Unix(1_000, 0)
	m := testMeter(&now)
	acc := mustGrant(t, m, grantJSON("s1", grant, 100, "inbound>>>nw", "strict"))
	ctr := m.counterLocked("inbound>>>nw")

	upClient, upServer := net.Pipe()
	up := &meterConn{m: m, Conn: upServer, acc: acc, rate: 100, ctr: ctr}
	go func() {
		buf := make([]byte, 32<<10)
		left := int64(10 << 20)
		for left > 0 {
			n := int64(len(buf))
			if n > left {
				n = left
			}
			if _, err := upClient.Write(buf[:n]); err != nil {
				return
			}
			left -= n
		}
	}()
	got := int64(0)
	buf := make([]byte, 64<<10)
	for {
		n, err := up.Read(buf)
		got += int64(n)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && got != grant {
				t.Fatal(err)
			}
			break
		}
	}
	if got != grant || acc.used.Load() != grant {
		t.Fatalf("uplink got %d used %d want %d", got, acc.used.Load(), grant)
	}
	if ctr.up.Load() != grant {
		t.Fatalf("uplink counter %d", ctr.up.Load())
	}
	_ = upClient.Close()

	acc.used.Store(0)
	downPeer, downLocal := net.Pipe()
	down := &meterConn{m: m, Conn: downLocal, acc: acc, rate: 100, ctr: ctr}
	done := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(io.Discard, downPeer)
		done <- n
	}()
	payload := make([]byte, 64<<10)
	left := int64(10 << 20)
	written := int64(0)
	for left > 0 {
		n := int64(len(payload))
		if n > left {
			n = left
		}
		w, err := down.Write(payload[:n])
		written += int64(w)
		left -= n
		if err != nil {
			break
		}
	}
	_ = down.Close()
	sunk := <-done
	if written != grant || sunk != grant || acc.used.Load() != grant {
		t.Fatalf("downlink written %d sunk %d used %d want %d", written, sunk, acc.used.Load(), grant)
	}
	if ctr.down.Load() != grant {
		t.Fatalf("downlink counter %d", ctr.down.Load())
	}
}

func TestMeterRateFloorsToGrant(t *testing.T) {
	now := time.Unix(1_000, 0)
	m := testMeter(&now)
	acc := mustGrant(t, m, grantJSON("s1", 1000, 200, "inbound>>>nw", "strict"))
	peer, local := net.Pipe()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	conn := &meterConn{m: m, Conn: local, acc: acc, rate: 200, ctr: m.counterLocked("inbound>>>nw")}
	n, err := conn.Write(make([]byte, 800))
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("err %v", err)
	}
	if n != 500 || acc.used.Load() != 1000 {
		t.Fatalf("n %d used %d", n, acc.used.Load())
	}
}

func TestMeterUDPDropsAndTrips(t *testing.T) {
	now := time.Unix(1_000, 0)
	m := testMeter(&now)
	acc := mustGrant(t, m, grantJSON("s1", 100, 100, "user>>>u1", "strict"))
	ctr := m.counterLocked("user>>>u1")
	inner := &fakePacket{data: make([]byte, 80)}
	pkt := &meterPacket{m: m, UDPPacket: inner, acc: acc, rate: 100, ctr: ctr}
	other := &meterConn{m: m, Conn: &closeProbe{}, acc: acc}
	m.track(acc, other, "in")
	if got := pkt.Data(); len(got) != 80 || inner.dropped {
		t.Fatalf("first packet len %d dropped %v", len(got), inner.dropped)
	}
	second := &fakePacket{data: make([]byte, 40)}
	pkt2 := &meterPacket{m: m, UDPPacket: second, acc: acc, rate: 100, ctr: ctr}
	if got := pkt2.Data(); got != nil || !second.dropped {
		t.Fatalf("overflow must drop, got %d dropped %v", len(got), second.dropped)
	}
	if acc.used.Load() != 80 {
		t.Fatalf("used %d, dropped packet must not be billed", acc.used.Load())
	}
	if ctr.up.Load() != 80 {
		t.Fatalf("uplink %d", ctr.up.Load())
	}
	if !other.Conn.(*closeProbe).closed {
		t.Fatal("trip must close every connection on the account")
	}
	back := &fakePacket{}
	pkt3 := &meterPacket{m: m, UDPPacket: back, acc: acc, rate: 100, ctr: ctr}
	if _, err := pkt3.WriteBack(make([]byte, 30), nil); err == nil {
		t.Fatal("exhausted account must reject writeback")
	}
}

func TestMeterStrictRejectsUnknownLooseAllows(t *testing.T) {
	now := time.Unix(2_000, 0)
	m := testMeter(&now)
	if err := m.ApplySnapshot([]byte(grantJSON("s1", 100, 100, "inbound>>>nw", "strict"))); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, ok := m.accept(&C.Metadata{InName: "other"}); ok {
		t.Fatal("strict mode must reject an unknown key")
	}
	if _, _, _, _, ok := m.accept(&C.Metadata{InName: "nw"}); !ok {
		t.Fatal("known key must pass")
	}
	if err := m.ApplySnapshot([]byte(grantJSON("s1", 100, 100, "inbound>>>nw", "loose"))); err != nil {
		t.Fatal(err)
	}
	key, acc, _, _, ok := m.accept(&C.Metadata{InName: "other"})
	if !ok || acc != nil || key != "inbound>>>other" {
		t.Fatalf("loose unknown: ok %v acc %v key %q", ok, acc != nil, key)
	}
}

func TestMeterExpiryEpochTopUp(t *testing.T) {
	now := time.Unix(3_000, 0)
	m := testMeter(&now)
	acc := mustGrant(t, m, grantJSON("s1", 100, 100, "inbound>>>nw", "strict"))
	acc.used.Store(100)
	if _, _, _, _, ok := m.accept(&C.Metadata{InName: "nw"}); ok {
		t.Fatal("exhausted grant must reject")
	}
	if err := m.ApplySnapshot([]byte(`{"epoch":"e1","mode":"strict","ttl_s":600,"low_water":50,"leases":[{"sub":"s1","granted":250,"keys":{"inbound>>>nw":100}}]}`)); err != nil {
		t.Fatal(err)
	}
	if acc.used.Load() != 100 || acc.granted.Load() != 250 {
		t.Fatalf("top-up used %d granted %d", acc.used.Load(), acc.granted.Load())
	}
	if _, _, _, _, ok := m.accept(&C.Metadata{InName: "nw"}); !ok {
		t.Fatal("top-up must reopen")
	}
	now = now.Add(571 * time.Second)
	if _, _, _, _, ok := m.accept(&C.Metadata{InName: "nw"}); ok {
		t.Fatal("expired grant must reject")
	}
	acc.used.Store(40)
	if err := m.ApplySnapshot([]byte(`{"epoch":"e2","mode":"strict","ttl_s":600,"low_water":50,"leases":[{"sub":"s1","granted":100,"keys":{"inbound>>>nw":100}}]}`)); err != nil {
		t.Fatal(err)
	}
	if acc.used.Load() != 0 || acc.granted.Load() != 100 {
		t.Fatalf("new epoch used %d granted %d", acc.used.Load(), acc.granted.Load())
	}
	if _, _, _, _, ok := m.accept(&C.Metadata{InName: "nw"}); !ok {
		t.Fatal("new epoch must pass")
	}
}

func TestMeterLooseOpensAfterDisconnect(t *testing.T) {
	now := time.Unix(4_000, 0)
	m := testMeter(&now)
	acc := mustGrant(t, m, grantJSON("s1", 10, 100, "inbound>>>nw", "loose"))
	m.setConnected(true)
	if m.looseBypass() {
		t.Fatal("connected loose mode must still enforce")
	}
	m.setConnected(false)
	now = now.Add(31 * time.Second)
	if !m.looseBypass() {
		t.Fatal("loose mode must open 30s after disconnect")
	}
	peer, local := net.Pipe()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	conn := &meterConn{m: m, Conn: local, acc: acc, rate: 100, ctr: m.counterLocked("inbound>>>nw")}
	n, err := conn.Write(make([]byte, 50))
	if err != nil || n != 50 {
		t.Fatalf("loose write n %d err %v", n, err)
	}
	if acc.used.Load() != 50 {
		t.Fatalf("loose usage %d", acc.used.Load())
	}
}

func TestMeterGrantedDoesNotShrink(t *testing.T) {
	now := time.Unix(5_000, 0)
	m := testMeter(&now)
	acc := mustGrant(t, m, grantJSON("s1", 500, 100, "inbound>>>nw", "strict"))
	if err := m.ApplySnapshot([]byte(grantJSON("s1", 100, 100, "inbound>>>nw", "strict"))); err != nil {
		t.Fatal(err)
	}
	if acc.granted.Load() != 500 {
		t.Fatalf("granted shrank to %d", acc.granted.Load())
	}
}

func TestMeterLowWaterSignals(t *testing.T) {
	now := time.Unix(6_000, 0)
	m := testMeter(&now)
	acc := mustGrant(t, m, grantJSON("s1", 100, 100, "inbound>>>nw", "strict"))
	peer, local := net.Pipe()
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	conn := &meterConn{m: m, Conn: local, acc: acc, rate: 100, ctr: m.counterLocked("inbound>>>nw")}
	if _, err := conn.Write(make([]byte, 60)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.wake:
	default:
		t.Fatal("balance under low water must wake a report")
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
