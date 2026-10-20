package agent

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

const statsNudgeMin = 500 * time.Millisecond

// trafficMeter 在入站与 clash-meta-nw 隧道之间按块计原始字节。
// 只计数，不截断；限额由面板在下一次 desired 收敛。
type trafficMeter struct {
	mu         sync.Mutex
	raw        map[string]*rawCounter
	live       map[ioCloser]string
	lastSignal time.Time
	wake       chan struct{}
	now        func() time.Time
}

type rawCounter struct {
	up   atomic.Int64
	down atomic.Int64
}

type ioCloser interface {
	Close() error
}

func newTrafficMeter() *trafficMeter {
	return &trafficMeter{
		raw:  map[string]*rawCounter{},
		live: map[ioCloser]string{},
		wake: make(chan struct{}, 1),
		now:  time.Now,
	}
}

var traffic = newTrafficMeter()

// meterTunnel 实现 mihomo 的 Tunnel。监听器把连接交给它，它计数后再进真隧道。
type meterTunnel struct{}

func (meterTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	inbound := ""
	if metadata != nil {
		inbound = metadata.InName
	}
	ctr, inCtr, pairCtr := traffic.accept(metadata)
	wrapped := &meterConn{m: traffic, Conn: conn, ctr: ctr, inCtr: inCtr, pairCtr: pairCtr, inbound: inbound}
	traffic.track(wrapped, inbound)
	tunnel.Tunnel.HandleTCPConn(wrapped, metadata)
}

func (meterTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	ctr, inCtr, pairCtr := traffic.accept(metadata)
	base := &meterPacket{m: traffic, UDPPacket: packet, ctr: ctr, inCtr: inCtr, pairCtr: pairCtr}
	var out C.UDPPacket = base
	if in, ok := packet.(C.UDPPacketInAddr); ok {
		out = &meterPacketIn{meterPacket: base, in: in.InAddr()}
	}
	tunnel.Tunnel.HandleUDPPacket(out, metadata)
}

func (meterTunnel) NatTable() C.NatTable { return tunnel.Tunnel.NatTable() }

func trafficKeyOf(md *C.Metadata) string {
	if md == nil {
		return ""
	}
	if md.InUser != "" {
		return "user>>>" + md.InUser
	}
	if md.InName != "" {
		return "inbound>>>" + md.InName
	}
	return ""
}

// accept 返回这条连接要记的计数器。
// 共享监听器的连接带两个只统计的辅助计数器（不影响计费）：
// inbound>>> 入站级实际流量键（计费仍只按 user>>> 键），
// pair>>>用户>>>监听名 用户×入站联合键，供面板落节点×用户明细。
// Nowhere 连接没有 InUser、键本身就是入站级，两个辅助计数器都为 nil。
func (m *trafficMeter) accept(md *C.Metadata) (*rawCounter, *rawCounter, *rawCounter) {
	key := trafficKeyOf(md)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counterLocked(key), m.sharedInboundCounterLocked(md), m.sharedPairCounterLocked(md)
}

func (m *trafficMeter) sharedInboundCounterLocked(md *C.Metadata) *rawCounter {
	if md == nil || md.InUser == "" || md.InName == "" {
		return nil
	}
	return m.counterLocked("inbound>>>" + md.InName)
}

func (m *trafficMeter) sharedPairCounterLocked(md *C.Metadata) *rawCounter {
	if md == nil || md.InUser == "" || md.InName == "" {
		return nil
	}
	return m.counterLocked("pair>>>" + md.InUser + ">>>" + md.InName)
}

func (m *trafficMeter) counterLocked(key string) *rawCounter {
	if key == "" {
		key = "unknown"
	}
	ctr := m.raw[key]
	if ctr == nil {
		ctr = &rawCounter{}
		m.raw[key] = ctr
	}
	return ctr
}

func (m *trafficMeter) track(conn ioCloser, inbound string) {
	m.mu.Lock()
	m.live[conn] = inbound
	m.mu.Unlock()
}

func (m *trafficMeter) detach(conn ioCloser) {
	m.mu.Lock()
	delete(m.live, conn)
	m.mu.Unlock()
}

// closeInbound 关掉某个监听名上的全部连接。共享协议的计数键是用户，不能只按键删。
func (m *trafficMeter) closeInbound(name string) {
	m.mu.Lock()
	conns := make([]ioCloser, 0)
	for conn, inbound := range m.live {
		if inbound == name {
			conns = append(conns, conn)
		}
	}
	m.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (m *trafficMeter) counters() map[string]int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int64{}
	for name, ctr := range m.raw {
		if name == "" || name == "unknown" {
			continue
		}
		if v := ctr.up.Load(); v > 0 {
			out[name+">>>traffic>>>uplink"] = v
		}
		if v := ctr.down.Load(); v > 0 {
			out[name+">>>traffic>>>downlink"] = v
		}
	}
	return out
}

func (m *trafficMeter) signal() {
	now := m.now()
	m.mu.Lock()
	if now.Sub(m.lastSignal) < statsNudgeMin {
		m.mu.Unlock()
		return
	}
	m.lastSignal = now
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

type meterConn struct {
	net.Conn
	m       *trafficMeter
	ctr     *rawCounter
	inCtr   *rawCounter
	pairCtr *rawCounter
	inbound string
}

// note 同时累加计费键、入站级辅助计数器与用户×入站联合计数器
// （后两个只有共享协议连接带）。
func (c *meterConn) note(n int64, upload bool) {
	if n <= 0 {
		return
	}
	if c.ctr != nil {
		if upload {
			c.ctr.up.Add(n)
		} else {
			c.ctr.down.Add(n)
		}
	}
	if c.inCtr != nil {
		if upload {
			c.inCtr.up.Add(n)
		} else {
			c.inCtr.down.Add(n)
		}
	}
	if c.pairCtr != nil {
		if upload {
			c.pairCtr.up.Add(n)
		} else {
			c.pairCtr.down.Add(n)
		}
	}
}

func (c *meterConn) ReadBuffer(buffer *buf.Buffer) error {
	n, err := buffer.ReadOnceFrom(c.Conn)
	if n > 0 {
		c.note(int64(n), true)
	}
	return err
}

func (c *meterConn) WriteBuffer(buffer *buf.Buffer) error {
	n, err := c.Write(buffer.Bytes())
	if n > 0 {
		buffer.Advance(n)
	}
	return err
}

func (c *meterConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.note(int64(n), true)
	}
	return n, err
}

func (c *meterConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.note(int64(n), false)
	}
	return n, err
}

func (c *meterConn) Close() error {
	c.m.detach(c)
	return c.Conn.Close()
}

// meterPacket 给 UDP 计数。Data 计上行，WriteBack 计下行。
type meterPacket struct {
	C.UDPPacket
	m       *trafficMeter
	ctr     *rawCounter
	inCtr   *rawCounter
	pairCtr *rawCounter
	counted atomic.Bool
}

// note 同时累加计费键、入站级辅助计数器与用户×入站联合计数器
// （后两个只有共享协议连接带）。
func (p *meterPacket) note(n int64, upload bool) {
	if n <= 0 {
		return
	}
	if p.ctr != nil {
		if upload {
			p.ctr.up.Add(n)
		} else {
			p.ctr.down.Add(n)
		}
	}
	if p.inCtr != nil {
		if upload {
			p.inCtr.up.Add(n)
		} else {
			p.inCtr.down.Add(n)
		}
	}
	if p.pairCtr != nil {
		if upload {
			p.pairCtr.up.Add(n)
		} else {
			p.pairCtr.down.Add(n)
		}
	}
}

func (p *meterPacket) Data() []byte {
	buf := p.UDPPacket.Data()
	if !p.counted.CompareAndSwap(false, true) {
		return buf
	}
	p.note(int64(len(buf)), true)
	return buf
}

func (p *meterPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	n, err := p.UDPPacket.WriteBack(b, addr)
	if n > 0 {
		p.note(int64(n), false)
	}
	return n, err
}

type meterPacketIn struct {
	*meterPacket
	in net.Addr
}

func (p *meterPacketIn) InAddr() net.Addr { return p.in }
