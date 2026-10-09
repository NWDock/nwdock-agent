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
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// relaySpec 与 panel 侧 RelaySpec 逐字一致：desired.relays 下发的单条入口转发指令。
// 入口端口把客户端流量原样转到落地节点的入站端口：不解密、不终结 TLS、不计流量。
type relaySpec struct {
	Port       int    `json:"port"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
	TCP        bool   `json:"tcp"`
	UDP        bool   `json:"udp"`
}

// relayPortState 与 panel 侧 RelayPortState 一致，随心跳上报；只描述转发，与核心状态隔离。
type relayPortState struct {
	Port      int    `json:"port"`
	Listening bool   `json:"listening"`
	Error     string `json:"error,omitempty"`
}

const (
	relayDialTimeout    = 10 * time.Second
	relayHalfCloseGrace = 30 * time.Second
	relayUDPIdle        = 60 * time.Second
	relayUDPSweep       = 10 * time.Second
	relayUDPSessions    = 4096
	relayUDPBuffer      = 64 << 10
	relayWantFile       = "relay-want.json"
	relayMaxStates      = 512
	relayMaxErrorLen    = 256
)

// relayHandle 是一个入口端口的转发句柄。TCP 与 UDP 各自独立监听，单侧绑定失败
// 不影响另一侧，也不影响其它端口。
type relayHandle struct {
	spec relaySpec
	tcp  net.Listener
	udp  *relayUDP
	err  string
}

// relayUDP 持有入口端口的 UDP 套接字与客户端会话表；会话空闲 60 秒拆除，表有上限。
type relayUDP struct {
	pc       net.PacketConn
	mu       sync.Mutex
	sessions map[string]*relayUDPSession
	closed   bool
}

// relayUDPSession 是一条客户端到落地的 UDP 会话；last 为最近一次收发的时间（unix nano）。
type relayUDPSession struct {
	up   net.Conn
	last atomic.Int64
	once sync.Once
}

func (s *relayUDPSession) closeConn() { s.once.Do(func() { _ = s.up.Close() }) }

// relayEngine 按面板清单维护入口端口：只开、关有变化的端口，已建立的连接保持。
type relayEngine struct {
	mu      sync.Mutex
	dir     string
	ports   map[int]*relayHandle
	persist []relaySpec // 最近一次落盘的清单，用于跳过无变化的写盘
}

var relayEng = &relayEngine{ports: map[int]*relayHandle{}}

func (sp relaySpec) valid() bool {
	return sp.Port >= 1 && sp.Port <= 65535 &&
		sp.TargetPort >= 1 && sp.TargetPort <= 65535 &&
		sp.TargetHost != "" && (sp.TCP || sp.UDP)
}

func (sp relaySpec) target() string {
	return net.JoinHostPort(sp.TargetHost, strconv.Itoa(sp.TargetPort))
}

// relayInit 载入进程重启前落盘的清单并立即开始转发：面板失联期间也按最后一份清单工作。
func relayInit(dir string) {
	relayEng.mu.Lock()
	relayEng.dir = dir
	relayEng.mu.Unlock()
	specs, err := readRelayWant(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	relayEng.apply(specs)
}

func relayApply(dir string, specs []relaySpec) {
	relayEng.apply(specs)
}

// relayStates 输出心跳上报用的端口状态：面板对单次心跳的条数有上限，失败的端口优先。
func relayStates() []relayPortState {
	relayEng.retryFailed()
	relayEng.mu.Lock()
	defer relayEng.mu.Unlock()
	return relayStateList(relayEng.ports)
}

func relayStateList(ports map[int]*relayHandle) []relayPortState {
	failed := make([]relayPortState, 0, len(ports))
	live := make([]relayPortState, 0, len(ports))
	for port, h := range ports {
		if h.err != "" {
			failed = append(failed, relayPortState{Port: port, Error: relayTruncate(h.err)})
			continue
		}
		live = append(live, relayPortState{Port: port, Listening: true})
	}
	sort.Slice(failed, func(i, j int) bool { return failed[i].Port < failed[j].Port })
	sort.Slice(live, func(i, j int) bool { return live[i].Port < live[j].Port })
	out := append(failed, live...)
	if len(out) > relayMaxStates {
		out = out[:relayMaxStates]
	}
	return out
}

// retryFailed 重试上次没打开成功的端口：瞬时冲突（如核心重启还没让出端口）恢复后自动补上。
func (e *relayEngine) retryFailed() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for port, h := range e.ports {
		if h.err == "" {
			continue
		}
		e.closeHandleLocked(h)
		e.ports[port] = e.openLocked(h.spec)
	}
}

func (e *relayEngine) apply(specs []relaySpec) {
	want := map[int]relaySpec{}
	for _, sp := range specs {
		if !sp.valid() {
			continue
		}
		if _, dup := want[sp.Port]; dup {
			continue
		}
		want[sp.Port] = sp
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for port, h := range e.ports {
		if _, ok := want[port]; ok {
			continue
		}
		e.closeHandleLocked(h)
		delete(e.ports, port)
	}
	for port, sp := range want {
		h, ok := e.ports[port]
		if ok && h.err == "" && h.spec == sp {
			continue // 无变化：监听器与已建立的连接都保持
		}
		if ok {
			e.closeHandleLocked(h)
		}
		e.ports[port] = e.openLocked(sp)
	}
	e.persistLocked(want)
}

// openLocked 打开一个入口端口；失败只记录在该端口上，不影响其它端口。
func (e *relayEngine) openLocked(sp relaySpec) *relayHandle {
	h := &relayHandle{spec: sp}
	addr := net.JoinHostPort("", strconv.Itoa(sp.Port))
	if sp.TCP {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			h.err = joinRelayErr(h.err, "tcp: "+err.Error())
		} else {
			h.tcp = ln
			go e.serveTCP(ln, sp)
		}
	}
	if sp.UDP {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			h.err = joinRelayErr(h.err, "udp: "+err.Error())
		} else {
			h.udp = &relayUDP{pc: pc, sessions: map[string]*relayUDPSession{}}
			go e.serveUDP(h.udp, sp)
			go h.udp.sweep()
		}
	}
	return h
}

func (e *relayEngine) closeHandleLocked(h *relayHandle) {
	if h.tcp != nil {
		// 关监听器不动已建立的连接，客户端会话自然走到结束。
		_ = h.tcp.Close()
	}
	if h.udp != nil {
		h.udp.close()
	}
}

func (e *relayEngine) serveTCP(ln net.Listener, sp relaySpec) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go relayPipeTCP(conn, sp)
	}
}

// relayPipeTCP 原样转发一条 TCP 连接，双向拷贝到落地入站端口。
func relayPipeTCP(client net.Conn, sp relaySpec) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", sp.target(), relayDialTimeout)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, up)
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
			up, derr := net.DialTimeout("udp", target, relayDialTimeout)
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
		if _, err := s.up.Write(buf[:n]); err != nil {
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
	}
}

func (t *relayUDP) pumpBack(s *relayUDPSession, addr net.Addr) {
	buf := make([]byte, relayUDPBuffer)
	for {
		n, err := s.up.Read(buf)
		if n > 0 {
			if _, werr := t.pc.WriteTo(buf[:n], addr); werr != nil {
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
}

// sweep 周期性拆除空闲会话。
func (t *relayUDP) sweep() {
	ticker := time.NewTicker(relayUDPSweep)
	defer ticker.Stop()
	for range ticker.C {
		t.prune(time.Now().UnixNano())
	}
}

// prune 拆除空闲超过 relayUDPIdle 的会话。
func (t *relayUDP) prune(now int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	for key, s := range t.sessions {
		if now-s.last.Load() >= int64(relayUDPIdle) {
			delete(t.sessions, key)
			s.closeConn()
		}
	}
}

func (t *relayUDP) close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
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
}

func (e *relayEngine) persistLocked(want map[int]relaySpec) {
	next := make([]relaySpec, 0, len(want))
	for _, sp := range want {
		next = append(next, sp)
	}
	sort.Slice(next, func(i, j int) bool { return next[i].Port < next[j].Port })
	if sameRelaySpecs(e.persist, next) {
		return
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return
	}
	if err := writeRelayWant(e.dir, raw); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return
	}
	e.persist = next
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

func writeRelayWant(dir string, raw []byte) error {
	path := relayWantPath(dir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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

// relayStop 关闭全部入口监听器（进程退出路径）；已建立的连接随之自然结束。
func relayStop() {
	relayEng.mu.Lock()
	defer relayEng.mu.Unlock()
	for port, h := range relayEng.ports {
		relayEng.closeHandleLocked(h)
		delete(relayEng.ports, port)
	}
}
