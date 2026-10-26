package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

// relaySpec 与 panel 侧 RelaySpec 对应：desired.relays 下发的单条入口转发指令。
// 入口端口把客户端流量原样转到落地节点的入站端口：不解密、不终结 TLS。
// ForwardID 非空表示 desired.forwards 下发的独立转发：字节按 forward>>><id> 单列，
// 且 allow_private=false 时拨号目标必须是公网 IP；legacy 条目两个字段恒为零值，
// 也不应用公网校验。
type relaySpec struct {
	Port         int    `json:"port"`
	TargetHost   string `json:"target_host"`
	TargetPort   int    `json:"target_port"`
	TCP          bool   `json:"tcp"`
	UDP          bool   `json:"udp"`
	ForwardID    string `json:"forward_id,omitempty"`
	AllowPrivate bool   `json:"allow_private,omitempty"`
}

// relayPortState 与 panel 侧 RelayPortState 一致，随心跳上报；独立转发额外带 forward_id。
type relayPortState struct {
	Port      int    `json:"port"`
	Listening bool   `json:"listening"`
	Error     string `json:"error,omitempty"`
	ForwardID string `json:"forward_id,omitempty"`
}

const (
	relayDialTimeout    = 10 * time.Second
	relayHalfCloseGrace = 30 * time.Second
	relayUDPIdle        = 60 * time.Second
	relayUDPSweep       = 10 * time.Second
	relayUDPSessions    = 4096
	relayUDPBuffer      = 64 << 10
	relayWantFile       = "relay-want.json"
	// forwardCounterPrefix 是独立转发计数键的固定前缀：forward>>><id>>>traffic>>><方向>。
	forwardCounterPrefix = "forward>>>"
	forwardWantFile      = "forward-want.json"
	relayMaxStates       = 512
	relayMaxErrorLen     = 256
)

// relayHandle 是一条转发（legacy 入口端口或独立转发）的句柄。TCP 与 UDP 各自独立监听，
// 单侧绑定失败不影响另一侧，也不影响其它条目。sessions 由 engine.mu 保护。
type relayHandle struct {
	spec     relaySpec
	tcp      net.Listener
	udp      *relayUDP
	err      string
	sessions map[*relayTCPSession]struct{}
}

// key 是 engine 内的句柄主键：legacy 按入口端口、独立转发按 forward id，两域不重叠。
func (h *relayHandle) key() string {
	if h.spec.ForwardID != "" {
		return "fwd:" + h.spec.ForwardID
	}
	return "port:" + strconv.Itoa(h.spec.Port)
}

func relayPortKey(port int) string     { return "port:" + strconv.Itoa(port) }
func relayForwardKey(id string) string { return "fwd:" + id }

// relayUDP 持有入口端口的 UDP 套接字与客户端会话表；会话空闲 60 秒拆除，表有上限。
// done 在 close 时关闭，sweep goroutine 据此退出。
type relayUDP struct {
	pc       net.PacketConn
	mu       sync.Mutex
	sessions map[string]*relayUDPSession
	closed   bool
	done     chan struct{}
	fwd      string
}

// relayUDPSession 是一条客户端到落地的 UDP 会话；last 为最近一次收发的时间（unix nano）。
type relayUDPSession struct {
	up   net.Conn
	last atomic.Int64
	once sync.Once
}

func (s *relayUDPSession) closeConn() { s.once.Do(func() { _ = s.up.Close() }) }

// relayTraffic 是一类转发的进程级累计实际字节：uplink 为客户端写入落地，
// downlink 为落地写回客户端。只按成功写入计数，面板用水位差累计机器本期用量。
type relayTraffic struct {
	up   atomic.Int64
	down atomic.Int64
}

func (t *relayTraffic) note(n int64, upload bool) {
	if n <= 0 {
		return
	}
	if upload {
		t.up.Add(n)
		return
	}
	t.down.Add(n)
}

func (t *relayTraffic) counters(prefix string) map[string]int64 {
	out := map[string]int64{}
	if v := t.up.Load(); v > 0 {
		out[prefix+">>>traffic>>>uplink"] = v
	}
	if v := t.down.Load(); v > 0 {
		out[prefix+">>>traffic>>>downlink"] = v
	}
	return out
}

// relayBytes 是全局聚合：legacy 与独立转发都计入 relay>>>all，键集只增不减。
var relayBytes = &relayTraffic{}

// forwardBytes 按独立转发 id 单列累计；撤销后计数保留到进程退出，已产生的用量不丢。
var forwardBytes sync.Map // forward id -> *relayTraffic

func forwardTrafficOf(id string) *relayTraffic {
	if v, ok := forwardBytes.Load(id); ok {
		return v.(*relayTraffic)
	}
	v, _ := forwardBytes.LoadOrStore(id, &relayTraffic{})
	return v.(*relayTraffic)
}

// relayNoteTo 记一笔实际字节：全局聚合必记，独立转发另记 per-forward 键。
func relayNoteTo(fwd string, n int64, upload bool) {
	relayBytes.note(n, upload)
	if fwd != "" {
		forwardTrafficOf(fwd).note(n, upload)
	}
}

// relayWakeStats 在连接/会话结束后唤醒合并上报；字节已实时入账，这里不再加尾量。
func relayWakeStats() {
	traffic.signal()
}

func relayCounters() map[string]int64 {
	return relayBytes.counters("relay>>>all")
}

func forwardCounters() map[string]int64 {
	out := map[string]int64{}
	forwardBytes.Range(func(key, value any) bool {
		for name, v := range value.(*relayTraffic).counters(forwardCounterPrefix + key.(string)) {
			out[name] = v
		}
		return true
	})
	return out
}

// relayCountingWriter 只计实际写入落地的字节，读取后没写出去的尾部不计。
// fwd 在 writer 创建时捕获：端口复用或目标变化都不会把字节记到别的转发头上。
type relayCountingWriter struct {
	dst    io.Writer
	upload bool
	fwd    string
}

func (w relayCountingWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		relayNoteTo(w.fwd, int64(n), w.upload)
	}
	return n, err
}

// relayTCPSession 是一条登记在具体 handle 上的 TCP 转发会话；handle 撤销或换代时关闭两端。
type relayTCPSession struct {
	h        *relayHandle
	client   net.Conn
	upstream net.Conn
	once     sync.Once
}

func (s *relayTCPSession) closeConns() {
	s.once.Do(func() {
		_ = s.client.Close()
		_ = s.upstream.Close()
	})
}

// relayEngine 按面板清单维护入口转发：legacy 与独立转发合并在同一 engine、
// 各自按键收敛；只开、关有变化的条目，撤销时关闭会话，同键仅目标变化时保留已建立的 TCP。
type relayEngine struct {
	mu              sync.Mutex
	dir             string
	handles         map[string]*relayHandle
	persist         []relaySpec     // legacy 最近一次落盘清单，用于跳过无变化的写盘
	fwdPersist      []relaySpec     // 独立转发最近一次落盘清单
	liveForwards    map[string]bool // 当前生效的独立转发 id 集合
	retiredForwards map[string]bool // 已撤销、等面板 stats_ack 确认后退休的 id
}

var relayEng = &relayEngine{
	handles:         map[string]*relayHandle{},
	liveForwards:    map[string]bool{},
	retiredForwards: map[string]bool{},
}

// retireConfirmedForwards 退休「已撤销且面板已确认收到最后一笔」的转发计数。
// 只在 stats_ack 之后调用：没确认就删条目，删除前那段字节会永久丢失。
func retireConfirmedForwards(counters map[string]int64) {
	if len(counters) == 0 {
		return
	}
	ids := map[string]bool{}
	for name := range counters {
		if id, ok := forwardIDFromCounter(name); ok {
			ids[id] = true
		}
	}
	if len(ids) == 0 {
		return
	}
	relayEng.mu.Lock()
	defer relayEng.mu.Unlock()
	for id := range ids {
		if !relayEng.retiredForwards[id] {
			continue
		}
		delete(relayEng.retiredForwards, id)
		forwardBytes.Delete(id)
	}
}

// forwardIDFromCounter 从 forward>>><id>>>traffic>>><方向> 取出转发 id。
func forwardIDFromCounter(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, forwardCounterPrefix)
	if !ok {
		return "", false
	}
	rest, ok = strings.CutSuffix(rest, ">>>traffic>>>uplink")
	if !ok {
		rest, ok = strings.CutSuffix(rest, ">>>traffic>>>downlink")
		if !ok {
			return "", false
		}
	}
	if rest == "" || strings.Contains(rest, ">>>") {
		return "", false
	}
	return rest, true
}

func (sp relaySpec) valid() bool {
	return sp.Port >= 1 && sp.Port <= 65535 &&
		sp.TargetPort >= 1 && sp.TargetPort <= 65535 &&
		sp.TargetHost != "" && (sp.TCP || sp.UDP)
}

// validForward 在基础校验外要求 forward id 非空且字符安全：id 进计数键与心跳 JSON，
// 不允许分隔符与控制字符。
func (sp relaySpec) validForward() bool {
	return sp.valid() && validForwardID(sp.ForwardID)
}

func validForwardID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func (sp relaySpec) target() string {
	return net.JoinHostPort(sp.TargetHost, strconv.Itoa(sp.TargetPort))
}

// dial 按清单拨号到落地。独立转发在 allow_private=false 时对解析出的每个地址做
// 非公网校验（防 DNS 重绑定）；legacy 一律不校验。
func (sp relaySpec) dial(network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: relayDialTimeout}
	if sp.ForwardID != "" && !sp.AllowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			return checkPublicTarget(sp.ForwardID, address)
		}
	}
	return d.Dial(network, addr)
}

// checkPublicTarget 校验拨号地址是公网 IP；在解析后、连接前逐地址调用，
// 域名重绑定到私网地址时拨号直接失败。
func checkPublicTarget(id, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if forwardIPBlocked(net.ParseIP(host)) {
		return fmt.Errorf("forward %s: target %s is not public", id, host)
	}
	return nil
}

var forwardReservedV4 = mustIPBlocks(
	"0.0.0.0/8",       // 本网络段（含 unspecified）
	"10.0.0.0/8",      // RFC1918 私网
	"100.64.0.0/10",   // CGNAT
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local
	"172.16.0.0/12",   // RFC1918 私网
	"192.0.0.0/24",    // IETF 协议保留
	"192.0.2.0/24",    // TEST-NET-1
	"192.168.0.0/16",  // RFC1918 私网
	"198.18.0.0/15",   // 组网基准测试保留
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // 组播
	"240.0.0.0/4",     // 保留段（含受限广播）
)

var forwardReservedV6 = mustIPBlocks(
	"::/128",        // unspecified
	"::1/128",       // loopback
	"fe80::/10",     // link-local
	"fc00::/7",      // ULA 私网
	"ff00::/8",      // 组播
	"2001:db8::/32", // 文档示例段
)

func mustIPBlocks(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		out = append(out, block)
	}
	return out
}

// forwardIPBlocked 判断解析出的目标 IP 是否非公网：loopback、私网/ULA、link-local、
// 组播、unspecified、CGNAT 与其他保留段都拦下；IPv4 映射的 IPv6 先归一到 IPv4 判断。
func forwardIPBlocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		for _, block := range forwardReservedV4 {
			if block.Contains(v4) {
				return true
			}
		}
		return false
	}
	for _, block := range forwardReservedV6 {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// relayInit 载入进程重启前落盘的两份清单并立即开始转发：面板失联期间也按最后一份清单工作。
func relayInit(dir string) {
	relayEng.mu.Lock()
	relayEng.dir = dir
	relayEng.mu.Unlock()
	legacy, err := readRelayWant(dir)
	if err != nil {
		logf(levelWarning, "%s", err.Error())
	}
	forwards, err := readForwardWant(dir)
	if err != nil {
		logf(levelWarning, "%s", err.Error())
	}
	if err := relayEng.applyAll(legacy, forwards); err != nil {
		logf(levelWarning, "%s", err.Error())
	}
}

func relayApply(dir string, legacy []relaySpec) error {
	return relayEng.apply(legacy)
}

// relayApplyAll 同时收敛 legacy 与独立转发；forwards 传 nil 表示撤销全部独立转发。
func relayApplyAll(dir string, legacy, forwards []relaySpec) error {
	return relayEng.applyAll(legacy, forwards)
}

// relayHeartbeatStates 输出心跳上报用的状态：失败优先、最多 relayMaxStates 条，
// total/truncated 让面板看到被截断的全量。独立转发条目带 forward_id。
func relayHeartbeatStates() (states []relayPortState, total int, truncated bool) {
	relayEng.retryFailed()
	relayEng.mu.Lock()
	defer relayEng.mu.Unlock()
	all := relayStateList(relayEng.handles)
	total = len(all)
	truncated = total > relayMaxStates
	if truncated {
		all = all[:relayMaxStates]
	}
	return all, total, truncated
}

func relayStates() []relayPortState {
	states, _, _ := relayHeartbeatStates()
	return states
}

// relayStateList 生成失败优先、按端口（同端口按 forward id）排序的状态表。
func relayStateList(handles map[string]*relayHandle) []relayPortState {
	failed := make([]relayPortState, 0, len(handles))
	live := make([]relayPortState, 0, len(handles))
	for _, h := range handles {
		st := relayPortState{Port: h.spec.Port, ForwardID: h.spec.ForwardID}
		if h.err != "" {
			st.Error = relayTruncate(h.err)
			failed = append(failed, st)
			continue
		}
		st.Listening = true
		live = append(live, st)
	}
	sort.Slice(failed, func(i, j int) bool {
		if failed[i].Port != failed[j].Port {
			return failed[i].Port < failed[j].Port
		}
		return failed[i].ForwardID < failed[j].ForwardID
	})
	sort.Slice(live, func(i, j int) bool {
		if live[i].Port != live[j].Port {
			return live[i].Port < live[j].Port
		}
		return live[i].ForwardID < live[j].ForwardID
	})
	return append(failed, live...)
}

// retryFailed 重试上次没打开成功的条目：瞬时冲突（如核心重启还没让出端口）恢复后自动补上。
func (e *relayEngine) retryFailed() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for key, h := range e.handles {
		if h.err == "" {
			continue
		}
		e.closeHandleLocked(h, false)
		e.handles[key] = e.openLocked(h.spec)
	}
}

// apply 只收敛 legacy 清单，不触碰独立转发：旧面板的 desired 没有 forwards 段。
func (e *relayEngine) apply(legacy []relaySpec) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.applyLegacyLocked(legacy)
}

// applyAll 同时收敛 legacy 与独立转发。任一份清单落盘失败就整体返回错误：
// 调用方据此不确认世代，面板下一轮重推，运行时保持上一份已验证的清单。
func (e *relayEngine) applyAll(legacy, forwards []relaySpec) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.applyLegacyLocked(legacy); err != nil {
		return err
	}
	return e.applyForwardsLocked(forwards)
}

// isForward 报告 handle 属于哪个域：独立转发按 forward id 收敛，legacy 按入口端口。
func (h *relayHandle) isForward() bool { return h.spec.ForwardID != "" }

func (e *relayEngine) applyLegacyLocked(specs []relaySpec) error {
	want := map[string]relaySpec{}
	for _, sp := range specs {
		if sp.ForwardID != "" || !sp.valid() {
			continue
		}
		if _, dup := want[relayPortKey(sp.Port)]; dup {
			continue
		}
		want[relayPortKey(sp.Port)] = sp
	}
	// 先落盘再切运行时：落盘失败时运行中的清单不动，调用方不确认世代。
	if err := e.persistWantLocked(&e.persist, want, writeRelayWant); err != nil {
		return err
	}
	e.reconcileLocked(false, want)
	return nil
}

func (e *relayEngine) applyForwardsLocked(forwards []relaySpec) error {
	want := map[string]relaySpec{}
	for _, sp := range forwards {
		if !sp.validForward() {
			continue
		}
		if _, dup := want[sp.ForwardID]; dup {
			continue
		}
		want[relayForwardKey(sp.ForwardID)] = sp
	}
	// 先落盘再切运行时：落盘失败时运行中的清单不动，调用方不确认世代。
	if err := e.persistWantLocked(&e.fwdPersist, want, writeForwardWant); err != nil {
		return err
	}
	// 本批消失的 id 进退休队列：累计计数保留到面板 stats_ack 确认后才丢，
	// 否则删除前最后一笔字节会随条目一起蒸发。
	for id := range e.liveForwards {
		if _, ok := want[relayForwardKey(id)]; !ok {
			e.retiredForwards[id] = true
		}
	}
	e.liveForwards = make(map[string]bool, len(want))
	for key := range want {
		e.liveForwards[key[len(relayForwardKey("")):]] = true
	}
	e.reconcileLocked(true, want)
	return nil
}

// reconcileLocked 把一个域的 handles 收敛到 want：只触碰本域，另一域不受影响。
// 缺失的撤销，规格没变的保持，同键变化时按 TCP/UDP 开关是否变化决定是否断掉已建立的
// TCP 会话。
func (e *relayEngine) reconcileLocked(forwardDomain bool, want map[string]relaySpec) {
	for key, h := range e.handles {
		if h.isForward() != forwardDomain {
			continue
		}
		if _, ok := want[key]; ok {
			continue
		}
		e.closeHandleLocked(h, false)
		delete(e.handles, key)
	}
	for key, sp := range want {
		h, ok := e.handles[key]
		if ok && h.err == "" && h.spec == sp {
			continue // 无变化：监听器与已建立的连接都保持
		}
		if ok {
			// 同键存在：仅换目标或只动 UDP 开关时保留已建立的 TCP 会话，新连接走新目标；
			// TCP 开关变化、或 allow_private 被收紧（放开→收紧）都必须断掉旧会话，
			// 否则已放行的内网连接会留在收紧后的策略外。
			keep := sp.TCP && h.spec.TCP && !(h.spec.AllowPrivate && !sp.AllowPrivate)
			e.closeHandleLocked(h, keep)
		}
		e.handles[key] = e.openLocked(sp)
	}
}

// openLocked 打开一条转发的监听；失败只记录在该条目上，不影响其它条目。
func (e *relayEngine) openLocked(sp relaySpec) *relayHandle {
	h := &relayHandle{spec: sp, sessions: map[*relayTCPSession]struct{}{}}
	addr := net.JoinHostPort("", strconv.Itoa(sp.Port))
	if sp.TCP {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			h.err = joinRelayErr(h.err, "tcp: "+err.Error())
		} else {
			h.tcp = ln
			go e.serveTCP(ln, h)
		}
	}
	if sp.UDP {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			h.err = joinRelayErr(h.err, "udp: "+err.Error())
		} else {
			h.udp = &relayUDP{pc: pc, sessions: map[string]*relayUDPSession{}, done: make(chan struct{}), fwd: sp.ForwardID}
			go e.serveUDP(h.udp, sp)
			go h.udp.sweep()
		}
	}
	return h
}

// closeHandleLocked 关闭一条转发。keepSessions 表示同键仅目标变化：
// 保留已建立的 TCP 会话；撤销、重试失败和进程退出一律关闭会话。
func (e *relayEngine) closeHandleLocked(h *relayHandle, keepSessions bool) {
	if h.tcp != nil {
		// 关监听器本身不动会话；是否断已有连接由 keepSessions 决定。
		_ = h.tcp.Close()
	}
	if !keepSessions {
		e.closeTCPSessionsLocked(h)
	}
	if h.udp != nil {
		h.udp.close()
	}
}

// registerTCPSession 把拨号完成的会话登记到它的 handle 上。校验的是 handle 本身
// 是否仍是当前生效代：拨号期间条目被撤销或同键被换代（端口复用）都不许挂上去。
func (e *relayEngine) registerTCPSession(h *relayHandle, client, up net.Conn) *relayTCPSession {
	s := &relayTCPSession{h: h, client: client, upstream: up}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handles[h.key()] != h {
		return nil
	}
	h.sessions[s] = struct{}{}
	return s
}

func (e *relayEngine) unregisterTCPSession(s *relayTCPSession) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s.h == nil {
		return
	}
	delete(s.h.sessions, s)
}

// closeTCPSessionsLocked 关闭登记在某 handle 上的全部 TCP 会话。
func (e *relayEngine) closeTCPSessionsLocked(h *relayHandle) {
	for s := range h.sessions {
		s.closeConns()
	}
	h.sessions = map[*relayTCPSession]struct{}{}
}

func (e *relayEngine) serveTCP(ln net.Listener, h *relayHandle) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go e.relayPipeTCP(conn, h)
	}
}

// relayPipeTCP 原样转发一条 TCP 连接，双向拷贝到落地入站端口；按成功写入计实际字节。
// 计数的 forward id 取自 handle 规格，端口复用或目标变化都不串账。
func (e *relayEngine) relayPipeTCP(client net.Conn, h *relayHandle) {
	defer client.Close()
	up, err := h.spec.dial("tcp", h.spec.target())
	if err != nil {
		return
	}
	defer up.Close()
	session := e.registerTCPSession(h, client, up)
	if session == nil {
		return
	}
	defer e.unregisterTCPSession(session)
	defer session.closeConns()
	defer relayWakeStats()
	done := make(chan struct{}, 2)
	fwd := h.spec.ForwardID
	go func() {
		_, _ = io.Copy(relayCountingWriter{dst: up, upload: true, fwd: fwd}, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(relayCountingWriter{dst: client, upload: false, fwd: fwd}, up)
		done <- struct{}{}
	}()
	<-done
	// 一侧结束后给反向流一个宽限窗口（半关闭场景），超时后两侧一起收。
	select {
	case <-done:
	case <-time.After(relayHalfCloseGrace):
	}
}

func (e *relayEngine) serveUDP(t *relayUDP, sp relaySpec) {
	target := sp.target()
	buf := make([]byte, relayUDPBuffer)
	for {
		n, addr, err := t.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		key := addr.String()
		s, ok := t.lookup(key)
		if !ok {
			up, derr := sp.dial("udp", target)
			if derr != nil {
				continue
			}
			if s = t.add(key, up); s == nil {
				_ = up.Close()
				continue
			}
			go t.pumpBack(s, addr)
		}
		s.last.Store(time.Now().UnixNano())
		written, werr := s.up.Write(buf[:n])
		if written > 0 {
			relayNoteTo(t.fwd, int64(written), true)
		}
		if werr != nil {
			t.drop(key, s)
		}
	}
}

func (t *relayUDP) lookup(key string) (*relayUDPSession, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.sessions[key]
	return s, ok
}

func (t *relayUDP) add(key string, up net.Conn) *relayUDPSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	if len(t.sessions) >= relayUDPSessions {
		t.evictOldestLocked()
	}
	s := &relayUDPSession{up: up}
	s.last.Store(time.Now().UnixNano())
	t.sessions[key] = s
	return s
}

// evictOldestLocked 淘汰最近最不活跃的会话，给新客户端让位。
func (t *relayUDP) evictOldestLocked() {
	oldestKey := ""
	var oldest int64
	for key, s := range t.sessions {
		if v := s.last.Load(); oldestKey == "" || v < oldest {
			oldestKey, oldest = key, v
		}
	}
	if s, ok := t.sessions[oldestKey]; ok {
		delete(t.sessions, oldestKey)
		s.closeConn()
		relayWakeStats()
	}
}

func (t *relayUDP) pumpBack(s *relayUDPSession, addr net.Addr) {
	buf := make([]byte, relayUDPBuffer)
	for {
		n, err := s.up.Read(buf)
		if n > 0 {
			written, werr := t.pc.WriteTo(buf[:n], addr)
			if written > 0 {
				relayNoteTo(t.fwd, int64(written), false)
			}
			if werr != nil {
				break
			}
			s.last.Store(time.Now().UnixNano())
		}
		if err != nil {
			break
		}
	}
	t.drop(addr.String(), s)
}

func (t *relayUDP) drop(key string, s *relayUDPSession) {
	t.mu.Lock()
	if cur, ok := t.sessions[key]; ok && cur == s {
		delete(t.sessions, key)
	}
	t.mu.Unlock()
	s.closeConn()
	relayWakeStats()
}

// sweep 周期性拆除空闲会话；UDP 套接字关闭后 done 关闭，本 goroutine 随之退出。
func (t *relayUDP) sweep() {
	ticker := time.NewTicker(relayUDPSweep)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.prune(time.Now().UnixNano())
		}
	}
}

// prune 拆除空闲超过 relayUDPIdle 的会话。
func (t *relayUDP) prune(now int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	removed := false
	for key, s := range t.sessions {
		if now-s.last.Load() >= int64(relayUDPIdle) {
			delete(t.sessions, key)
			s.closeConn()
			removed = true
		}
	}
	if removed {
		relayWakeStats()
	}
}

func (t *relayUDP) close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	close(t.done)
	sessions := make([]*relayUDPSession, 0, len(t.sessions))
	for key, s := range t.sessions {
		sessions = append(sessions, s)
		delete(t.sessions, key)
	}
	t.mu.Unlock()
	_ = t.pc.Close()
	for _, s := range sessions {
		s.closeConn()
	}
	if len(sessions) > 0 {
		relayWakeStats()
	}
}

// persistWantLocked 把一个域的生效清单落盘；内容没变不写，减少面板失联期的写盘。
func (e *relayEngine) persistWantLocked(slot *[]relaySpec, want map[string]relaySpec, write func(string, []byte) error) error {
	next := make([]relaySpec, 0, len(want))
	for _, sp := range want {
		next = append(next, sp)
	}
	sort.Slice(next, func(i, j int) bool {
		if next[i].Port != next[j].Port {
			return next[i].Port < next[j].Port
		}
		return next[i].ForwardID < next[j].ForwardID
	})
	if sameRelaySpecs(*slot, next) {
		return nil
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := write(e.dir, raw); err != nil {
		return err
	}
	*slot = next
	return nil
}

func sameRelaySpecs(a, b []relaySpec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func relayWantPath(dir string) string { return filepath.Join(dir, relayWantFile) }

func forwardWantPath(dir string) string { return filepath.Join(dir, forwardWantFile) }

func writeWantFile(dir, name string, raw []byte) error {
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeRelayWant(dir string, raw []byte) error { return writeWantFile(dir, relayWantFile, raw) }

func writeForwardWant(dir string, raw []byte) error {
	return writeWantFile(dir, forwardWantFile, raw)
}

func readRelayWant(dir string) ([]relaySpec, error) {
	raw, err := os.ReadFile(relayWantPath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var specs []relaySpec
	if err := json.Unmarshal(raw, &specs); err != nil {
		return nil, fmt.Errorf("relay want: %w", err)
	}
	// 独立转发只允许待在 forward-want.json：relay-want.json 里出现 forward_id 一律丢弃，
	// 文件混写或降级都不会把独立转发从 legacy 清单拉起来。
	out := make([]relaySpec, 0, len(specs))
	for _, sp := range specs {
		if sp.ForwardID == "" {
			out = append(out, sp)
		}
	}
	return out, nil
}

func readForwardWant(dir string) ([]relaySpec, error) {
	raw, err := os.ReadFile(forwardWantPath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var specs []relaySpec
	if err := json.Unmarshal(raw, &specs); err != nil {
		return nil, fmt.Errorf("forward want: %w", err)
	}
	return specs, nil
}

func joinRelayErr(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

// relayTruncate 把错误摘要裁到心跳上限内，且不留下半个 UTF-8  rune。
func relayTruncate(msg string) string {
	if len(msg) <= relayMaxErrorLen {
		return msg
	}
	cut := msg[:relayMaxErrorLen]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// relayStop 关闭全部转发监听器与会话（进程退出路径）。
func relayStop() {
	relayEng.mu.Lock()
	defer relayEng.mu.Unlock()
	for key, h := range relayEng.handles {
		relayEng.closeHandleLocked(h, false)
		delete(relayEng.handles, key)
	}
}
