package agent

import (
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

const (
	quotaClockSkew  = 30 * time.Second
	quotaLooseAfter = 30 * time.Second
	quotaReportMin  = 500 * time.Millisecond
)

// quotaSnapshot 是面板下发的本机额度。granted 在同一 epoch 内只增不减。
type quotaSnapshot struct {
	Epoch    string       `json:"epoch"`
	Mode     string       `json:"mode"`
	TTL      int          `json:"ttl_s"`
	LowWater int          `json:"low_water"`
	Leases   []quotaLease `json:"leases"`
}

type quotaLease struct {
	Sub       string         `json:"sub"`
	Unlimited bool           `json:"unlimited"`
	Granted   int64          `json:"granted"`
	Keys      map[string]int `json:"keys"`
}

// quotaUsage 是节点上报的本轮次计费字节。
type quotaUsage struct {
	Epoch string           `json:"epoch"`
	Used  map[string]int64 `json:"used"`
}

// trafficMeter 在入站与 clash-meta-nw 隧道之间按块计原始字节，并按预支额度截断。
// 连接建立时记下账户指针，读写路径只做原子加减。
type trafficMeter struct {
	mu             sync.Mutex
	epoch          string
	mode           string
	lowWater       int
	expires        time.Time
	connected      bool
	disconnectedAt time.Time
	lastSignal     time.Time
	accounts       map[string]*meterAccount
	keys           map[string]meterKey
	raw            map[string]*rawCounter
	live           map[ioCloser]string
	lastKey        string
	wake           chan struct{}
	now            func() time.Time
}

type meterKey struct {
	sub  string
	rate int64
}

type meterAccount struct {
	sub       string
	granted   atomic.Int64
	used      atomic.Int64
	lastTopUp atomic.Int64
	unlimited bool
	conns     map[ioCloser]struct{}
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
		mode:     "strict",
		lowWater: 50,
		accounts: map[string]*meterAccount{},
		keys:     map[string]meterKey{},
		raw:      map[string]*rawCounter{},
		live:     map[ioCloser]string{},
		wake:     make(chan struct{}, 1),
		now:      time.Now,
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
	key, acc, rate, ctr, ok := traffic.accept(metadata)
	if !ok {
		_ = conn.Close()
		return
	}
	wrapped := &meterConn{m: traffic, Conn: conn, acc: acc, key: key, rate: rate, ctr: ctr, inbound: inbound}
	traffic.track(acc, wrapped, inbound)
	tunnel.Tunnel.HandleTCPConn(wrapped, metadata)
}

func (meterTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	key, acc, rate, ctr, ok := traffic.accept(metadata)
	if !ok {
		packet.Drop()
		return
	}
	base := &meterPacket{m: traffic, UDPPacket: packet, acc: acc, rate: rate, ctr: ctr, key: key}
	var out C.UDPPacket = base
	if in, ok := packet.(C.UDPPacketInAddr); ok {
		out = &meterPacketIn{meterPacket: base, in: in.InAddr()}
	}
	tunnel.Tunnel.HandleUDPPacket(out, metadata)
}

func (meterTunnel) NatTable() C.NatTable { return tunnel.Tunnel.NatTable() }

func quotaKeyOf(md *C.Metadata) string {
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

// accept 决定这条连接能否进入隧道，并返回缓存用的账户与计数器。
func (m *trafficMeter) accept(md *C.Metadata) (string, *meterAccount, int64, *rawCounter, bool) {
	key := quotaKeyOf(md)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastKey = key
	open := m.looseOpenLocked()
	ref, known := m.keys[key]
	if key == "" || !known {
		if m.mode == "loose" || open {
			return key, nil, 100, m.counterLocked(key), true
		}
		return key, nil, 0, nil, false
	}
	acc := m.accounts[ref.sub]
	if acc == nil {
		return key, nil, 0, nil, false
	}
	if acc.unlimited || open {
		return key, acc, ref.rate, m.counterLocked(key), true
	}
	if m.expiredLocked() || acc.granted.Load() <= acc.used.Load() {
		return key, acc, ref.rate, m.counterLocked(key), false
	}
	return key, acc, ref.rate, m.counterLocked(key), true
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

func (m *trafficMeter) looseOpenLocked() bool {
	if m.mode != "loose" || m.connected || m.disconnectedAt.IsZero() {
		return false
	}
	return m.now().Sub(m.disconnectedAt) > quotaLooseAfter
}

func (m *trafficMeter) expiredLocked() bool {
	return !m.expires.IsZero() && !m.now().Before(m.expires)
}

func (m *trafficMeter) track(acc *meterAccount, conn ioCloser, inbound string) {
	m.mu.Lock()
	m.live[conn] = inbound
	if acc != nil {
		if acc.conns == nil {
			acc.conns = map[ioCloser]struct{}{}
		}
		acc.conns[conn] = struct{}{}
	}
	m.mu.Unlock()
}

func (m *trafficMeter) detach(acc *meterAccount, conn ioCloser) {
	m.mu.Lock()
	delete(m.live, conn)
	if acc != nil {
		delete(acc.conns, conn)
	}
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

func (m *trafficMeter) trip(acc *meterAccount) {
	if acc == nil {
		return
	}
	m.mu.Lock()
	conns := make([]ioCloser, 0, len(acc.conns))
	for conn := range acc.conns {
		conns = append(conns, conn)
	}
	m.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	m.signal()
}

func (m *trafficMeter) setConnected(on bool) {
	m.mu.Lock()
	m.connected = on
	if !on {
		m.disconnectedAt = m.now()
	}
	m.mu.Unlock()
}

// ApplySnapshot 应用面板的额度快照。同一 epoch 的 granted 只升不降；换 epoch 清零本轮用量。
func (m *trafficMeter) ApplySnapshot(raw []byte) error {
	var snap quotaSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return err
	}
	if snap.Mode != "loose" {
		snap.Mode = "strict"
	}
	if snap.LowWater <= 0 || snap.LowWater > 100 {
		snap.LowWater = 50
	}
	ttl := time.Duration(snap.TTL) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	now := m.now()
	m.mu.Lock()
	fresh := snap.Epoch != "" && snap.Epoch != m.epoch
	m.epoch = snap.Epoch
	m.mode = snap.Mode
	m.lowWater = snap.LowWater
	m.expires = now.Add(ttl - quotaClockSkew)
	keep := map[string]bool{}
	m.keys = map[string]meterKey{}
	var drop []ioCloser
	for _, lease := range snap.Leases {
		if lease.Sub == "" {
			continue
		}
		keep[lease.Sub] = true
		acc := m.accounts[lease.Sub]
		if acc == nil {
			acc = &meterAccount{sub: lease.Sub, conns: map[ioCloser]struct{}{}}
			m.accounts[lease.Sub] = acc
		}
		acc.unlimited = lease.Unlimited
		prev := acc.granted.Load()
		if fresh {
			acc.used.Store(0)
			prev = 0
		}
		next := lease.Granted
		if !fresh && next < prev && !lease.Unlimited {
			next = prev
		}
		if lease.Unlimited {
			next = 0
		}
		acc.granted.Store(next)
		switch {
		case fresh:
			acc.lastTopUp.Store(next)
		case next > prev:
			acc.lastTopUp.Store(next - prev)
		}
		for key, rate := range lease.Keys {
			if rate <= 0 {
				rate = 100
			}
			m.keys[key] = meterKey{sub: lease.Sub, rate: int64(rate)}
		}
	}
	for sub, acc := range m.accounts {
		if keep[sub] {
			continue
		}
		for conn := range acc.conns {
			drop = append(drop, conn)
		}
		delete(m.accounts, sub)
	}
	m.mu.Unlock()
	for _, conn := range drop {
		_ = conn.Close()
	}
	return nil
}

func (m *trafficMeter) usage() (quotaUsage, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.epoch == "" {
		return quotaUsage{}, false
	}
	used := map[string]int64{}
	for id, acc := range m.accounts {
		used[id] = acc.used.Load()
	}
	return quotaUsage{Epoch: m.epoch, Used: used}, true
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
	if now.Sub(m.lastSignal) < quotaReportMin {
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

func (m *trafficMeter) maybeSignal(acc *meterAccount) {
	if acc == nil || acc.unlimited {
		return
	}
	remain := acc.granted.Load() - acc.used.Load()
	top := acc.lastTopUp.Load()
	m.mu.Lock()
	water := int64(m.lowWater)
	m.mu.Unlock()
	if remain <= 0 || (top > 0 && remain*100 < top*water) {
		m.signal()
	}
}

func (m *trafficMeter) looseBypass() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.looseOpenLocked()
}

// admit 在账户上扣计费字节，返回本次允许转发的原始字节。不足则截断到额度边界。
// bill 为 false 时不扣账户（不限量、或宽松失联），调用方仍要自己记原始字节。
func admit(acc *meterAccount, raw, rate int64, bill bool) int64 {
	if raw <= 0 {
		return 0
	}
	if acc == nil || acc.unlimited || !bill {
		return raw
	}
	if rate <= 0 {
		rate = 100
	}
	for {
		used := acc.used.Load()
		remain := acc.granted.Load() - used
		if remain <= 0 {
			return 0
		}
		maxRaw := remain * 100 / rate
		if maxRaw <= 0 {
			return 0
		}
		if maxRaw > raw {
			maxRaw = raw
		}
		billed := maxRaw * rate / 100
		if acc.used.CompareAndSwap(used, used+billed) {
			return maxRaw
		}
	}
}

func refund(acc *meterAccount, raw, rate int64) {
	if acc == nil || acc.unlimited || raw <= 0 {
		return
	}
	if rate <= 0 {
		rate = 100
	}
	acc.used.Add(-(raw * rate / 100))
}

type meterConn struct {
	net.Conn
	m       *trafficMeter
	acc     *meterAccount
	key     string
	rate    int64
	ctr     *rawCounter
	inbound string
}

func (c *meterConn) ReadBuffer(buffer *buf.Buffer) error {
	before := buffer.Len()
	n, err := buffer.ReadOnceFrom(c.Conn)
	if n <= 0 {
		return err
	}
	allow, cerr := c.consume(int64(n), err, true)
	if allow < n {
		buffer.Truncate(before + allow)
	}
	return cerr
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
	if n <= 0 {
		return n, err
	}
	return c.consume(int64(n), err, true)
}

func (c *meterConn) Write(p []byte) (int, error) {
	if c.m.looseBypass() {
		n, err := c.Conn.Write(p)
		c.noteLoose(int64(n), false)
		return n, err
	}
	allow := admit(c.acc, int64(len(p)), c.rate, c.acc != nil)
	if allow <= 0 {
		c.m.trip(c.acc)
		return 0, net.ErrClosed
	}
	n, err := c.Conn.Write(p[:allow])
	if gap := allow - int64(n); gap > 0 {
		refund(c.acc, gap, c.rate)
	}
	if n > 0 && c.ctr != nil {
		c.ctr.down.Add(int64(n))
	}
	if allow < int64(len(p)) {
		c.m.trip(c.acc)
		return n, net.ErrClosed
	}
	c.m.maybeSignal(c.acc)
	return n, err
}

// consume 处理已经从对端读到的上行字节：超额部分丢弃，不转发给隧道。
func (c *meterConn) consume(n int64, err error, upload bool) (int, error) {
	if c.m.looseBypass() {
		c.noteLoose(n, upload)
		return int(n), err
	}
	allow := admit(c.acc, n, c.rate, c.acc != nil)
	if allow > 0 && c.ctr != nil {
		if upload {
			c.ctr.up.Add(allow)
		} else {
			c.ctr.down.Add(allow)
		}
	}
	if allow < n {
		c.m.trip(c.acc)
		if allow == 0 {
			return 0, net.ErrClosed
		}
		return int(allow), net.ErrClosed
	}
	c.m.maybeSignal(c.acc)
	return int(n), err
}

func (c *meterConn) noteLoose(n int64, upload bool) {
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
	if c.acc == nil || c.acc.unlimited {
		return
	}
	rate := c.rate
	if rate <= 0 {
		rate = 100
	}
	c.acc.used.Add(n * rate / 100)
}

func (c *meterConn) Close() error {
	c.m.detach(c.acc, c)
	return c.Conn.Close()
}

// meterPacket 给 UDP 计数。Data 计上行，WriteBack 计下行；额度不够就丢弃并熔断。
type meterPacket struct {
	C.UDPPacket
	m       *trafficMeter
	acc     *meterAccount
	rate    int64
	ctr     *rawCounter
	key     string
	counted atomic.Bool
}

func (p *meterPacket) Data() []byte {
	buf := p.UDPPacket.Data()
	if !p.counted.CompareAndSwap(false, true) {
		return buf
	}
	allow := p.charge(int64(len(buf)), true)
	if allow <= 0 {
		p.UDPPacket.Drop()
		return nil
	}
	if allow < int64(len(buf)) {
		return buf[:allow]
	}
	return buf
}

func (p *meterPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	allow := p.charge(int64(len(b)), false)
	if allow <= 0 {
		return 0, net.ErrClosed
	}
	if allow < int64(len(b)) {
		b = b[:allow]
	}
	return p.UDPPacket.WriteBack(b, addr)
}

func (p *meterPacket) charge(raw int64, upload bool) int64 {
	if p.m.looseBypass() {
		if p.ctr != nil && raw > 0 {
			if upload {
				p.ctr.up.Add(raw)
			} else {
				p.ctr.down.Add(raw)
			}
		}
		if p.acc != nil && !p.acc.unlimited && raw > 0 {
			rate := p.rate
			if rate <= 0 {
				rate = 100
			}
			p.acc.used.Add(raw * rate / 100)
		}
		return raw
	}
	allow := admit(p.acc, raw, p.rate, p.acc != nil)
	if allow < raw {
		refund(p.acc, allow, p.rate)
		p.m.trip(p.acc)
		return 0
	}
	if allow > 0 && p.ctr != nil {
		if upload {
			p.ctr.up.Add(allow)
		} else {
			p.ctr.down.Add(allow)
		}
	}
	p.m.maybeSignal(p.acc)
	return allow
}

type meterPacketIn struct {
	*meterPacket
	in net.Addr
}

func (p *meterPacketIn) InAddr() net.Addr { return p.in }
