package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	defaultProbePingCount   = 3
	probeICMPTimeout        = 1500 * time.Millisecond
	probeICMPInterval       = 100 * time.Millisecond
	probeTCPTimeout         = 3 * time.Second
	probeTCPInterval        = 80 * time.Millisecond
	probeURLTimeout         = 10 * time.Second
	probeSecondRTTTimeout   = 3 * time.Second
	probeSpeedDialTimeout   = 10 * time.Second
	probeSpeedTransferLimit = 10 * time.Second
	probeSpeedMaxBytes      = 100 << 20
	probeSteadyMaxBytes     = 2 << 30
	probeSpeedDefaultBytes  = 25 << 20
	probeDefaultStreams     = 4
	probeMaxStreams         = 8
	probeDefaultDurationMs  = 4000
	probeMaxDurationMs      = 10000
	probeDefaultWarmupMs    = 800
	probeMaxWarmupMs        = 2000
	probeChainTimeout       = 6 * time.Second
)

// probeURLGuardEnabled 控制代理探测目标 URL 的内网/回环拦截；单测 httptest 可临时关闭。
var probeURLGuardEnabled = true

// probeHTTPClientTLS 仅供单测注入自签 httptest.Server 根证书配置；生产恒为 nil。
var probeHTTPClientTLS *tls.Config

// probeSem 限制单台 agent 同时执行的探测总数，speedSem 限制同时跑满带宽的测速为 1。
var (
	probeSem = make(chan struct{}, 4)
	speedSem = make(chan struct{}, 1)

	activeProbesMu sync.Mutex
	activeProbes   = map[string]context.CancelFunc{}
)

type probeRequest struct {
	ID            string         `json:"id"`
	Host          string         `json:"host"`
	Port          int            `json:"port"`
	AllowPrivate  bool           `json:"allow_private,omitempty"`
	RunPing       bool           `json:"run_ping"`
	RunTCPing     bool           `json:"run_tcping"`
	SkipTCPing    string         `json:"skip_tcping,omitempty"`
	Proxy         map[string]any `json:"proxy,omitempty"`
	DirectURLTest bool           `json:"direct_url_test,omitempty"`
	LatencyURL    string         `json:"latency_url,omitempty"`
	SpeedTest     bool           `json:"speed_test,omitempty"`
	SpeedURL      string         `json:"speed_url,omitempty"`
	SpeedBytes    int64          `json:"speed_bytes,omitempty"`
	Streams       int            `json:"streams,omitempty"`
	DurationMs    int            `json:"duration_ms,omitempty"`
	WarmupMs      int            `json:"warmup_ms,omitempty"`
	ChainToken    string         `json:"chain_token,omitempty"`
	ChainTCP      bool           `json:"chain_tcp,omitempty"`
	ChainUDP      bool           `json:"chain_udp,omitempty"`
	PeerToken     string         `json:"peer_token,omitempty"`
	PeerTCP       bool           `json:"peer_tcp,omitempty"`
	PeerUDP       bool           `json:"peer_udp,omitempty"`
	PeerSpeed     bool           `json:"peer_speed,omitempty"`
	PeerDir       string         `json:"peer_dir,omitempty"` // both | send | recv
	PeerBytes     int64          `json:"peer_bytes,omitempty"`
}

type probePingResult struct {
	Status  string `json:"status"` // ok | error | skipped | unsupported
	AvgMs   int    `json:"avg_ms,omitempty"`
	MinMs   int    `json:"min_ms,omitempty"`
	MaxMs   int    `json:"max_ms,omitempty"`
	LossPct int    `json:"loss_pct"`
	Error   string `json:"error,omitempty"`
}

type probeURLResult struct {
	Status     string `json:"status"` // ok | error | skipped
	DelayMs    int    `json:"delay_ms,omitempty"`
	RTTMs      int    `json:"rtt_ms,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Error      string `json:"error,omitempty"`
}

type probeSpeedResult struct {
	Status      string  `json:"status"` // ok | error | skipped
	Bytes       int64   `json:"bytes,omitempty"`
	DurationMs  int     `json:"duration_ms,omitempty"`
	BytesPerSec int64   `json:"bytes_per_sec,omitempty"`
	Mbps        float64 `json:"mbps,omitempty"`
	Streams     int     `json:"streams,omitempty"`
	Error       string  `json:"error,omitempty"`
}

type probeChainResult struct {
	Status       string `json:"status"` // ok | error | skipped
	RTTMs        int    `json:"rtt_ms,omitempty"`
	TargetDialMs int    `json:"target_dial_ms,omitempty"`
	Error        string `json:"error,omitempty"`
}

type probeResponse struct {
	ID       string            `json:"id"`
	Ping     *probePingResult  `json:"ping,omitempty"`
	TCPing   *probePingResult  `json:"tcping,omitempty"`
	URLTest  *probeURLResult   `json:"url_test,omitempty"`
	Speed    *probeSpeedResult `json:"speed,omitempty"`
	ChainTCP *probeChainResult `json:"chain_tcp,omitempty"`
	ChainUDP *probeChainResult `json:"chain_udp,omitempty"`
	PeerTCP  *probePingResult  `json:"peer_tcp,omitempty"`
	PeerUDP  *probePingResult  `json:"peer_udp,omitempty"`
	PeerSend *probeSpeedResult `json:"peer_send,omitempty"`
	PeerRecv *probeSpeedResult `json:"peer_recv,omitempty"`
	Error    string            `json:"error,omitempty"`
}

func registerActiveProbe(id string, cancel context.CancelFunc) {
	activeProbesMu.Lock()
	activeProbes[id] = cancel
	activeProbesMu.Unlock()
}

func unregisterActiveProbe(id string) {
	activeProbesMu.Lock()
	delete(activeProbes, id)
	activeProbesMu.Unlock()
}

func cancelActiveProbe(id string) {
	if id == "" {
		return
	}
	activeProbesMu.Lock()
	cancel := activeProbes[id]
	activeProbesMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *session) handleProbeCancel(raw json.RawMessage) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.ID == "" {
		return
	}
	cancelActiveProbe(req.ID)
}

func (s *session) handleProbeArm(ctx context.Context, raw json.RawMessage) {
	var req struct {
		ID        string `json:"id"`
		ForwardID string `json:"forward_id"`
		TokenHex  string `json:"token_hex"`
		TTLMs     int    `json:"ttl_ms"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.ID == "" {
		return
	}
	res := map[string]any{"id": req.ID, "ok": true}
	tokenBytes, decErr := hex.DecodeString(strings.TrimSpace(req.TokenHex))
	if decErr != nil || len(tokenBytes) != 32 {
		res["ok"] = false
		res["error"] = "invalid probe token"
	} else {
		var tok [32]byte
		copy(tok[:], tokenBytes)
		ttl := time.Duration(req.TTLMs) * time.Millisecond
		if armErr := armRelayProbe(req.ForwardID, tok, ttl); armErr != nil {
			res["ok"] = false
			res["error"] = sanitizeProbeErr(armErr)
		}
	}
	rawRes, err := json.Marshal(res)
	if err != nil {
		return
	}
	if err := s.send(ctx, message{T: msgProbeArmResp, D: rawRes}); err != nil {
		logf(levelWarning, "%s", err.Error())
	}
}

func (s *session) handleProbeReq(ctx context.Context, raw json.RawMessage) {
	var req probeRequest
	if err := json.Unmarshal(raw, &req); err != nil || req.ID == "" {
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, 65*time.Second)
	registerActiveProbe(req.ID, cancel)
	defer func() {
		unregisterActiveProbe(req.ID)
		cancel()
	}()

	resp := executeProbe(probeCtx, req)
	rawRes, err := json.Marshal(resp)
	if err != nil {
		return
	}
	if err := s.send(ctx, message{T: msgProbeResp, D: rawRes}); err != nil {
		logf(levelWarning, "%s", err.Error())
	}
}

func executeProbe(ctx context.Context, req probeRequest) probeResponse {
	resp := probeResponse{ID: req.ID}
	select {
	case probeSem <- struct{}{}:
		defer func() { <-probeSem }()
	case <-ctx.Done():
		resp.Error = "测试已取消"
		return resp
	}

	host := strings.TrimSpace(req.Host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "" && (req.RunPing || req.RunTCPing || req.ChainToken != "" || req.PeerToken != "") {
		resp.Error = "探测目标地址为空"
		return resp
	}

	// Ping 与 TCPing 并发执行以缩短整体等待时间。
	var wg sync.WaitGroup
	if req.RunPing {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := runICMPPing(ctx, host, req.AllowPrivate)
			resp.Ping = &res
		}()
	}
	if req.RunTCPing {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := runTCPing(ctx, host, req.Port, req.SkipTCPing, req.AllowPrivate)
			resp.TCPing = &res
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		resp.Error = "测试已取消或超时"
		return resp
	}

	// 多链转发自定义地址贯穿校验。
	if req.ChainToken != "" {
		tokenBytes, err := hex.DecodeString(strings.TrimSpace(req.ChainToken))
		if err != nil || len(tokenBytes) != 32 {
			resp.Error = "贯穿令牌无效"
			return resp
		}
		var tok [32]byte
		copy(tok[:], tokenBytes)
		if req.ChainTCP {
			tcpRes := runChainTCPProbe(ctx, host, req.Port, tok, req.AllowPrivate)
			resp.ChainTCP = &tcpRes
		} else {
			resp.ChainTCP = &probeChainResult{Status: "skipped", Error: "未启用 TCP"}
		}
		if req.ChainUDP {
			udpRes := runChainUDPProbe(ctx, host, req.Port, tok, req.AllowPrivate)
			resp.ChainUDP = &udpRes
		} else {
			resp.ChainUDP = &probeChainResult{Status: "skipped", Error: "未启用 UDP"}
		}
	}

	// 代理协议端到端延迟与可选下行测速，或机器本机直连公网测试。
	if len(req.Proxy) > 0 {
		urlRes, speedRes := runProxyProbe(ctx, req)
		resp.URLTest = &urlRes
		resp.Speed = &speedRes
	} else if req.DirectURLTest {
		urlRes, speedRes := runDirectPublicProbe(ctx, req)
		resp.URLTest = &urlRes
		resp.Speed = &speedRes
	}

	// 受管机器间 / 链内端到端闭环互测（TCP 全链 RTT、UDP 往返与多并发稳态双向吞吐极限，零外部依赖）。
	if req.PeerToken != "" {
		runPeerProbe(ctx, req, host, &resp)
	}
	return resp
}

func resolveProbeIP(ctx context.Context, host string, allowPrivate bool) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !allowPrivate && forwardIPBlocked(ip) {
			return nil, errors.New("目标地址不是公网地址")
		}
		return ip, nil
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil || len(addrs) == 0 {
		if err != nil {
			return nil, fmt.Errorf("域名解析失败: %w", err)
		}
		return nil, errors.New("域名解析结果为空")
	}
	for _, a := range addrs {
		if a.IP == nil {
			continue
		}
		if !allowPrivate && forwardIPBlocked(a.IP) {
			continue
		}
		return a.IP, nil
	}
	return nil, errors.New("目标域名解析到了受限内网地址")
}

func openICMPConn(isV6 bool) (*icmp.PacketConn, bool, error) {
	if isV6 {
		if c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::"); err == nil {
			return c, true, nil
		}
		c, err := icmp.ListenPacket("udp6", "::")
		return c, false, err
	}
	if c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		return c, true, nil
	}
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	return c, false, err
}

func isICMPPermErr(err error) bool {
	return errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) ||
		errors.Is(err, syscall.EAFNOSUPPORT)
}

func runICMPPing(ctx context.Context, host string, allowPrivate bool) probePingResult {
	ip, err := resolveProbeIP(ctx, host, allowPrivate)
	if err != nil {
		return probePingResult{Status: "error", LossPct: 100, Error: sanitizeProbeErr(err)}
	}
	isV6 := ip.To4() == nil
	conn, rawSock, err := openICMPConn(isV6)
	if err != nil {
		if isICMPPermErr(err) {
			return probePingResult{Status: "unsupported", LossPct: 0, Error: "当前运行环境无 ICMP 权限"}
		}
		return probePingResult{Status: "error", LossPct: 100, Error: sanitizeProbeErr(err)}
	}
	defer conn.Close()

	var dst net.Addr
	var echoType icmp.Type
	var proto int
	if isV6 {
		echoType = ipv6.ICMPTypeEchoRequest
		proto = 58 // IPv6-ICMP
		if rawSock {
			dst = &net.IPAddr{IP: ip}
		} else {
			dst = &net.UDPAddr{IP: ip}
		}
	} else {
		echoType = ipv4.ICMPTypeEcho
		proto = 1 // ICMPv4
		if rawSock {
			dst = &net.IPAddr{IP: ip}
		} else {
			dst = &net.UDPAddr{IP: ip}
		}
	}

	var idBuf [10]byte
	_, _ = rand.Read(idBuf[:])
	echoID := int(binary.BigEndian.Uint16(idBuf[:2])) & 0x7fff
	if echoID == 0 {
		echoID = 1
	}
	nonce := idBuf[2:10]

	var samples []int
	var lastErr error
	rxBuf := make([]byte, 1500)
	for seq := 1; seq <= defaultProbePingCount; seq++ {
		if ctx.Err() != nil {
			break
		}
		payload := make([]byte, 16)
		copy(payload[:8], nonce)
		binary.BigEndian.PutUint64(payload[8:], uint64(seq))
		msg := icmp.Message{
			Type: echoType,
			Code: 0,
			Body: &icmp.Echo{
				ID:   echoID,
				Seq:  seq,
				Data: payload,
			},
		}
		wire, merr := msg.Marshal(nil)
		if merr != nil {
			lastErr = merr
			continue
		}
		start := time.Now()
		deadline := start.Add(probeICMPTimeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)
		if _, werr := conn.WriteTo(wire, dst); werr != nil {
			if isICMPPermErr(werr) && seq == 1 {
				return probePingResult{Status: "unsupported", LossPct: 0, Error: "当前运行环境无 ICMP 权限"}
			}
			lastErr = werr
			continue
		}
		matched := false
		for {
			n, _, rerr := conn.ReadFrom(rxBuf)
			if rerr != nil {
				lastErr = rerr
				break
			}
			parsed, perr := icmp.ParseMessage(proto, rxBuf[:n])
			if perr != nil {
				continue
			}
			if (isV6 && parsed.Type != ipv6.ICMPTypeEchoReply) || (!isV6 && parsed.Type != ipv4.ICMPTypeEchoReply) {
				continue
			}
			echo, ok := parsed.Body.(*icmp.Echo)
			if !ok || echo.Seq != seq || len(echo.Data) < 8 || !bytes.Equal(echo.Data[:8], nonce) {
				continue
			}
			if rawSock && echo.ID != echoID {
				continue
			}
			ms := int(time.Since(start).Milliseconds())
			if ms < 1 {
				ms = 1
			}
			samples = append(samples, ms)
			matched = true
			break
		}
		if !matched && lastErr == nil {
			lastErr = errors.New("请求超时")
		}
		if seq < defaultProbePingCount {
			sleep(ctx, probeICMPInterval)
		}
	}
	return summarizePingSamples(samples, defaultProbePingCount, lastErr)
}

// newSafeTCPDialer 保留 Go 双栈 Happy Eyeballs 回退并在真实建连前校验对端 IP，
// 避免手选单条解析结果在单栈机器上误报 network is unreachable，同时杜绝 DNS 重绑定 SSRF。
func newSafeTCPDialer(timeout time.Duration, allowPrivate bool, blockedMsg string) *net.Dialer {
	if blockedMsg == "" {
		blockedMsg = "目标地址不是公网地址"
	}
	return &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			if allowPrivate {
				return nil
			}
			h, _, err := parseDialTarget(address)
			if err != nil {
				return err
			}
			if forwardIPBlocked(net.ParseIP(h)) {
				return errors.New(blockedMsg)
			}
			return nil
		},
	}
}

func runTCPing(ctx context.Context, host string, port int, skipReason string, allowPrivate bool) probePingResult {
	if skipReason != "" {
		return probePingResult{Status: "skipped", LossPct: 0, Error: skipReason}
	}
	if port < 1 || port > 65535 {
		return probePingResult{Status: "error", LossPct: 100, Error: "端口无效"}
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := newSafeTCPDialer(probeTCPTimeout, allowPrivate, "目标地址不是公网地址")

	var samples []int
	var lastErr error
	for i := 0; i < defaultProbePingCount; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		dialCtx, cancel := context.WithTimeout(ctx, probeTCPTimeout)
		conn, err := dialer.DialContext(dialCtx, "tcp", target)
		cancel()
		if err != nil {
			lastErr = err
		} else {
			ms := int(time.Since(start).Milliseconds())
			if ms < 1 {
				ms = 1
			}
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				_ = tcpConn.SetLinger(0)
			}
			_ = conn.Close()
			samples = append(samples, ms)
		}
		if i+1 < defaultProbePingCount {
			sleep(ctx, probeTCPInterval)
		}
	}
	return summarizePingSamples(samples, defaultProbePingCount, lastErr)
}

func summarizePingSamples(samples []int, sent int, lastErr error) probePingResult {
	if sent <= 0 {
		sent = 1
	}
	if len(samples) == 0 {
		errText := "请求超时"
		if lastErr != nil {
			errText = sanitizeProbeErr(lastErr)
		}
		return probePingResult{Status: "error", LossPct: 100, Error: errText}
	}
	minMs, maxMs, sum := samples[0], samples[0], 0
	for _, v := range samples {
		if v < minMs {
			minMs = v
		}
		if v > maxMs {
			maxMs = v
		}
		sum += v
	}
	loss := ((sent - len(samples)) * 100) / sent
	return probePingResult{
		Status:  "ok",
		AvgMs:   int(math.Round(float64(sum) / float64(len(samples)))),
		MinMs:   minMs,
		MaxMs:   maxMs,
		LossPct: loss,
	}
}

func validateTargetHTTPURL(raw string) (*url.URL, C.Metadata, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return nil, C.Metadata{}, errors.New("测试 URL 无效")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, C.Metadata{}, errors.New("测试 URL 仅支持 http 或 https")
	}
	host := u.Hostname()
	if probeURLGuardEnabled {
		lower := strings.ToLower(host)
		if lower == "localhost" || strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") {
			return nil, C.Metadata{}, errors.New("测试 URL 不允许指向内网主机")
		}
		if ip := net.ParseIP(host); ip != nil && forwardIPBlocked(ip) {
			return nil, C.Metadata{}, errors.New("测试 URL 不允许指向内网地址")
		}
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	var meta C.Metadata
	if err := meta.SetRemoteAddress(net.JoinHostPort(host, port)); err != nil {
		return nil, C.Metadata{}, fmt.Errorf("测试目标地址无效: %w", err)
	}
	return u, meta, nil
}

func buildProxyTLSConfig(serverName string) *tls.Config {
	if probeHTTPClientTLS != nil {
		cfg := probeHTTPClientTLS.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = serverName
		}
		return cfg
	}
	return &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
}

func resolveSpeedParams(req probeRequest) (streams int, warmupDur, steadyDur time.Duration, maxCap int64, steadyMode bool) {
	// 兼容旧版按固定字节数拉取的单流调用。
	if req.DurationMs <= 0 && req.Streams <= 0 && (req.SpeedBytes > 0 || req.PeerBytes > 0) {
		capBytes := req.SpeedBytes
		if capBytes <= 0 {
			capBytes = req.PeerBytes
		}
		if capBytes > probeSpeedMaxBytes {
			capBytes = probeSpeedMaxBytes
		}
		return 1, 0, probeSpeedTransferLimit, capBytes, false
	}
	streams = req.Streams
	if streams <= 0 {
		streams = probeDefaultStreams
	}
	if streams > probeMaxStreams {
		streams = probeMaxStreams
	}
	durMs := req.DurationMs
	if durMs <= 0 {
		durMs = probeDefaultDurationMs
	}
	if durMs < 400 {
		durMs = 400
	}
	if durMs > probeMaxDurationMs {
		durMs = probeMaxDurationMs
	}
	warmMs := req.WarmupMs
	if warmMs < 0 {
		warmMs = 0
	} else if warmMs == 0 && durMs >= 1500 {
		warmMs = probeDefaultWarmupMs
	}
	if warmMs > probeMaxWarmupMs {
		warmMs = probeMaxWarmupMs
	}
	return streams, time.Duration(warmMs) * time.Millisecond, time.Duration(durMs) * time.Millisecond, probeSteadyMaxBytes, true
}

func runProxyProbe(ctx context.Context, req probeRequest) (probeURLResult, probeSpeedResult) {
	skippedSpeed := probeSpeedResult{Status: "skipped"}
	proxy, err := adapter.ParseProxy(req.Proxy)
	if err != nil {
		return probeURLResult{Status: "error", Error: "代理解析失败: " + sanitizeProbeErr(err)}, skippedSpeed
	}
	defer func() {
		_ = proxy.Close()
	}()

	latencyRaw := strings.TrimSpace(req.LatencyURL)
	if latencyRaw == "" {
		latencyRaw = "https://cp.cloudflare.com/generate_204"
	}
	latURL, latMeta, err := validateTargetHTTPURL(latencyRaw)
	if err != nil {
		return probeURLResult{Status: "error", Error: err.Error()}, skippedSpeed
	}

	urlRes := runDialerURLTest(ctx, latURL, func(dctx context.Context) (net.Conn, error) {
		m := latMeta
		return proxy.DialContext(dctx, &m)
	})
	if !req.SpeedTest {
		return urlRes, skippedSpeed
	}
	if urlRes.Status != "ok" {
		return urlRes, probeSpeedResult{Status: "skipped", Error: "外网连通未通过，已跳过测速"}
	}

	streams, warmupDur, steadyDur, maxCap, steadyMode := resolveSpeedParams(req)
	speedRaw := strings.TrimSpace(req.SpeedURL)
	if speedRaw == "" {
		if steadyMode {
			speedRaw = "https://speed.cloudflare.com/__down?bytes=50000000"
		} else {
			reqBytes := maxCap
			if reqBytes > 50_000_000 {
				reqBytes = 50_000_000
			}
			speedRaw = fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", reqBytes)
		}
	}
	spdURL, _, err := validateTargetHTTPURL(speedRaw)
	if err != nil {
		return urlRes, probeSpeedResult{Status: "error", Error: err.Error()}
	}
	spdRes := runHTTPMultiStreamSpeedTest(ctx, spdURL, streams, warmupDur, steadyDur, maxCap, steadyMode, func(dctx context.Context, addr string) (net.Conn, error) {
		var m C.Metadata
		if merr := m.SetRemoteAddress(addr); merr != nil {
			return nil, merr
		}
		return proxy.DialContext(dctx, &m)
	})
	return urlRes, spdRes
}

func runDirectPublicProbe(ctx context.Context, req probeRequest) (probeURLResult, probeSpeedResult) {
	skippedSpeed := probeSpeedResult{Status: "skipped"}
	latencyRaw := strings.TrimSpace(req.LatencyURL)
	if latencyRaw == "" {
		latencyRaw = "https://cp.cloudflare.com/generate_204"
	}
	latURL, _, err := validateTargetHTTPURL(latencyRaw)
	if err != nil {
		return probeURLResult{Status: "error", Error: err.Error()}, skippedSpeed
	}

	dialPublicAddr := func(dctx context.Context, addr string) (net.Conn, error) {
		d := newSafeTCPDialer(probeSpeedDialTimeout, !probeURLGuardEnabled, "测试 URL 不允许指向内网地址")
		return d.DialContext(dctx, "tcp", addr)
	}
	latPort := latURL.Port()
	if latPort == "" {
		if strings.EqualFold(latURL.Scheme, "https") {
			latPort = "443"
		} else {
			latPort = "80"
		}
	}
	latAddr := net.JoinHostPort(latURL.Hostname(), latPort)

	urlRes := runDialerURLTest(ctx, latURL, func(dctx context.Context) (net.Conn, error) {
		return dialPublicAddr(dctx, latAddr)
	})
	if !req.SpeedTest {
		return urlRes, skippedSpeed
	}
	if urlRes.Status != "ok" {
		return urlRes, probeSpeedResult{Status: "skipped", Error: "外网连通未通过，已跳过测速"}
	}

	streams, warmupDur, steadyDur, maxCap, steadyMode := resolveSpeedParams(req)
	speedRaw := strings.TrimSpace(req.SpeedURL)
	if speedRaw == "" {
		if steadyMode {
			speedRaw = "https://speed.cloudflare.com/__down?bytes=50000000"
		} else {
			reqBytes := maxCap
			if reqBytes > 50_000_000 {
				reqBytes = 50_000_000
			}
			speedRaw = fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", reqBytes)
		}
	}
	spdURL, _, err := validateTargetHTTPURL(speedRaw)
	if err != nil {
		return urlRes, probeSpeedResult{Status: "error", Error: err.Error()}
	}
	spdRes := runHTTPMultiStreamSpeedTest(ctx, spdURL, streams, warmupDur, steadyDur, maxCap, steadyMode, dialPublicAddr)
	return urlRes, spdRes
}

func runDialerURLTest(ctx context.Context, targetURL *url.URL, dialFn func(context.Context) (net.Conn, error)) probeURLResult {
	latCtx, cancel := context.WithTimeout(ctx, probeURLTimeout)
	defer cancel()

	start := time.Now()
	firstConn, err := dialFn(latCtx)
	if err != nil {
		return probeURLResult{Status: "error", Error: sanitizeProbeErr(err)}
	}

	var firstOnce sync.Once
	usedFirst := false
	defer func() {
		if !usedFirst {
			_ = firstConn.Close()
		}
	}()

	tr := &http.Transport{
		DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
			var c net.Conn
			firstOnce.Do(func() {
				c = firstConn
				usedFirst = true
			})
			if c != nil {
				return c, nil
			}
			return dialFn(dctx)
		},
		TLSClientConfig:       buildProxyTLSConfig(targetURL.Hostname()),
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		IdleConnTimeout:       15 * time.Second,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		ForceAttemptHTTP2:     false,
	}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	httpReq, err := http.NewRequestWithContext(latCtx, http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return probeURLResult{Status: "error", Error: sanitizeProbeErr(err)}
	}
	httpReq.Header.Set("User-Agent", "curl/8.5.0")

	resp, err := client.Do(httpReq)
	if err != nil {
		return probeURLResult{Status: "error", Error: sanitizeProbeErr(err)}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()

	delayMs := int(time.Since(start).Milliseconds())
	if delayMs < 1 {
		delayMs = 1
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return probeURLResult{
			Status:     "error",
			HTTPStatus: resp.StatusCode,
			DelayMs:    delayMs,
			Error:      fmt.Sprintf("目标返回 HTTP %d", resp.StatusCode),
		}
	}

	rttMs := delayMs
	rttCtx, rttCancel := context.WithTimeout(ctx, probeSecondRTTTimeout)
	defer rttCancel()
	if req2, err2 := http.NewRequestWithContext(rttCtx, http.MethodGet, targetURL.String(), nil); err2 == nil {
		req2.Header.Set("User-Agent", "curl/8.5.0")
		t2 := time.Now()
		if resp2, doErr := client.Do(req2); doErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp2.Body, 64<<10))
			_ = resp2.Body.Close()
			if resp2.StatusCode >= 200 && resp2.StatusCode < 400 {
				rttMs = int(time.Since(t2).Milliseconds())
				if rttMs < 1 {
					rttMs = 1
				}
			}
		}
	}

	return probeURLResult{
		Status:     "ok",
		DelayMs:    delayMs,
		RTTMs:      rttMs,
		HTTPStatus: resp.StatusCode,
	}
}

func runHTTPMultiStreamSpeedTest(
	ctx context.Context,
	targetURL *url.URL,
	streams int,
	warmupDur, steadyDur time.Duration,
	maxCap int64,
	steadyMode bool,
	dialFn func(context.Context, string) (net.Conn, error),
) probeSpeedResult {
	select {
	case speedSem <- struct{}{}:
		defer func() { <-speedSem }()
	case <-ctx.Done():
		return probeSpeedResult{Status: "error", Error: "测速已取消"}
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	var (
		clockOnce   sync.Once
		totalStart  time.Time
		warmupEnd   time.Time
		windowTimer *time.Timer

		totalBytes  atomic.Int64
		steadyBytes atomic.Int64

		errMu    sync.Mutex
		firstErr error
	)
	noteErr := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}

	startClock := func() {
		clockOnce.Do(func() {
			totalStart = time.Now()
			warmupEnd = totalStart.Add(warmupDur)
			windowTimer = time.AfterFunc(warmupDur+steadyDur, cancelRun)
		})
	}
	defer func() {
		if windowTimer != nil {
			windowTimer.Stop()
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := &http.Transport{
				DialContext: func(dctx context.Context, _, addr string) (net.Conn, error) {
					return dialFn(dctx, addr)
				},
				TLSClientConfig:       buildProxyTLSConfig(""),
				TLSHandshakeTimeout:   8 * time.Second,
				ResponseHeaderTimeout: 8 * time.Second,
				DisableCompression:    true,
				ForceAttemptHTTP2:     false,
				MaxIdleConnsPerHost:   1,
			}
			client := &http.Client{
				Transport: tr,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if len(via) >= 5 {
						return errors.New("测速地址重定向次数过多")
					}
					if _, _, verr := validateTargetHTTPURL(req.URL.String()); verr != nil {
						return verr
					}
					return nil
				},
			}
			defer client.CloseIdleConnections()

			buf := make([]byte, 128<<10)
			for runCtx.Err() == nil {
				httpReq, err := http.NewRequestWithContext(runCtx, http.MethodGet, targetURL.String(), nil)
				if err != nil {
					noteErr(err)
					return
				}
				httpReq.Header.Set("User-Agent", "curl/8.5.0")

				resp, err := client.Do(httpReq)
				if err != nil {
					if runCtx.Err() == nil {
						noteErr(err)
					}
					return
				}
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					_ = resp.Body.Close()
					noteErr(fmt.Errorf("测速源返回 HTTP %d", resp.StatusCode))
					return
				}

				startClock()
				for {
					n, rerr := resp.Body.Read(buf)
					if n > 0 {
						now := time.Now()
						curTotal := totalBytes.Add(int64(n))
						if !now.Before(warmupEnd) {
							steadyBytes.Add(int64(n))
						}
						if curTotal >= maxCap {
							cancelRun()
							break
						}
					}
					if rerr != nil {
						break
					}
				}
				_ = resp.Body.Close()
				if !steadyMode {
					return
				}
			}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		return probeSpeedResult{Status: "error", Error: "测速已取消"}
	}
	tot := totalBytes.Load()
	if tot <= 0 {
		if firstErr != nil {
			return probeSpeedResult{Status: "error", Error: sanitizeProbeErr(firstErr)}
		}
		return probeSpeedResult{Status: "error", Error: "测速源返回空响应"}
	}

	now := time.Now()
	stBytes := steadyBytes.Load()
	if steadyMode && warmupDur > 0 && stBytes > 0 && now.Sub(warmupEnd) >= 50*time.Millisecond {
		res := formatPeerSpeedResult(stBytes, now.Sub(warmupEnd))
		res.Streams = streams
		return res
	}
	res := formatPeerSpeedResult(tot, now.Sub(totalStart))
	res.Streams = streams
	return res
}

func runChainTCPProbe(ctx context.Context, host string, port int, token [32]byte, allowPrivate bool) probeChainResult {
	if port < 1 || port > 65535 {
		return probeChainResult{Status: "error", Error: "首跳端口无效"}
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	cctx, cancel := context.WithTimeout(ctx, probeChainTimeout)
	defer cancel()

	dialer := newSafeTCPDialer(probeChainTimeout, allowPrivate, "首跳地址不是公网地址")
	start := time.Now()
	conn, err := dialer.DialContext(cctx, "tcp", target)
	if err != nil {
		return probeChainResult{Status: "error", Error: sanitizeProbeErr(err)}
	}
	defer conn.Close()
	if deadline, ok := cctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(chainProbeFrame(token)); err != nil {
		return probeChainResult{Status: "error", Error: sanitizeProbeErr(err)}
	}
	line, err := bufio.NewReaderSize(conn, 512).ReadString('\n')
	line = strings.TrimSpace(line)
	if err != nil && line == "" {
		if errors.Is(err, io.EOF) {
			return probeChainResult{Status: "error", Error: "链路中途断开（下游跳或目标不可达）"}
		}
		return probeChainResult{Status: "error", Error: sanitizeProbeErr(err)}
	}
	rttMs := int(time.Since(start).Milliseconds())
	if rttMs < 1 {
		rttMs = 1
	}
	if rest, ok := strings.CutPrefix(line, "NWDPROBE_OK:"); ok {
		dialMs, _ := strconv.Atoi(strings.TrimSpace(rest))
		return probeChainResult{Status: "ok", RTTMs: rttMs, TargetDialMs: dialMs}
	}
	if rest, ok := strings.CutPrefix(line, "NWDPROBE_ERR:"); ok {
		return probeChainResult{Status: "error", RTTMs: rttMs, Error: "末跳连接目标失败: " + strings.TrimSpace(rest)}
	}
	return probeChainResult{Status: "error", Error: "未收到末跳贯穿回执（端口可能指向非预期服务）"}
}

func runChainUDPProbe(ctx context.Context, host string, port int, token [32]byte, allowPrivate bool) probeChainResult {
	if port < 1 || port > 65535 {
		return probeChainResult{Status: "error", Error: "首跳端口无效"}
	}
	ip, err := resolveProbeIP(ctx, host, allowPrivate)
	if err != nil {
		return probeChainResult{Status: "error", Error: sanitizeProbeErr(err)}
	}
	network := "udp4"
	if ip.To4() == nil {
		network = "udp6"
	}
	conn, err := net.DialUDP(network, nil, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return probeChainResult{Status: "error", Error: sanitizeProbeErr(err)}
	}
	defer conn.Close()

	// UDP 允许最多重试 2 次以吸收首包异步建会话抖动。
	frame := chainProbeFrame(token)
	rx := make([]byte, 512)
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		deadline := start.Add(2500 * time.Millisecond)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)
		if _, werr := conn.Write(frame); werr != nil {
			lastErr = werr
			break
		}
		n, rerr := conn.Read(rx)
		if rerr != nil {
			lastErr = rerr
			continue
		}
		reply := strings.TrimSpace(string(rx[:n]))
		rttMs := int(time.Since(start).Milliseconds())
		if rttMs < 1 {
			rttMs = 1
		}
		if reply == "NWDPROBE_OK" {
			return probeChainResult{Status: "ok", RTTMs: rttMs}
		}
		if rest, ok := strings.CutPrefix(reply, "NWDPROBE_ERR:"); ok {
			return probeChainResult{Status: "error", RTTMs: rttMs, Error: "末跳 UDP 校验失败: " + strings.TrimSpace(rest)}
		}
		return probeChainResult{Status: "error", Error: "收到未知 UDP 回包"}
	}
	if lastErr != nil {
		return probeChainResult{Status: "error", Error: "UDP 整链超时或不通: " + sanitizeProbeErr(lastErr)}
	}
	return probeChainResult{Status: "error", Error: "UDP 整链超时"}
}

func sanitizeProbeErr(err error) string {
	if err == nil {
		return ""
	}
	text := safeOut([]byte(err.Error()))
	if text == "" {
		return "连接失败"
	}
	return text
}

const (
	peerTCPMagic     = "NWDPEER1"
	peerUDPMagic     = "NWDPEERU"
	peerHeaderBytes  = 8 + 1 + 32 + 8 + 4
	peerUDPPktBytes  = 8 + 32 + 8
	peerMaxActiveSrv = 4
	peerMaxTTL       = 45 * time.Second
	peerStreamLimit  = 20 * time.Second
)

var (
	peerRandOnce sync.Once
	peerRandBuf  [256 << 10]byte

	peerSrvMu      sync.Mutex
	activePeerSrvs = map[string]*peerServer{}
)

func peerPayloadChunk() []byte {
	peerRandOnce.Do(func() {
		if _, err := rand.Read(peerRandBuf[:]); err != nil {
			for i := range peerRandBuf {
				peerRandBuf[i] = byte(i*31 + 17)
			}
		}
	})
	return peerRandBuf[:]
}

type peerServer struct {
	id        string
	token     [32]byte
	tcpLn     net.Listener
	udpConn   net.PacketConn
	closeOnce sync.Once
	timer     *time.Timer

	connsMu sync.Mutex
	stopped bool
	conns   map[net.Conn]struct{}
}

func (ps *peerServer) trackConn(c net.Conn) bool {
	ps.connsMu.Lock()
	defer ps.connsMu.Unlock()
	if ps.stopped {
		return false
	}
	if ps.conns == nil {
		ps.conns = map[net.Conn]struct{}{}
	}
	ps.conns[c] = struct{}{}
	return true
}

func (ps *peerServer) untrackConn(c net.Conn) {
	ps.connsMu.Lock()
	delete(ps.conns, c)
	ps.connsMu.Unlock()
}

func (ps *peerServer) stop() {
	ps.closeOnce.Do(func() {
		if ps.timer != nil {
			ps.timer.Stop()
		}
		if ps.tcpLn != nil {
			_ = ps.tcpLn.Close()
		}
		if ps.udpConn != nil {
			_ = ps.udpConn.Close()
		}
		ps.connsMu.Lock()
		ps.stopped = true
		active := make([]net.Conn, 0, len(ps.conns))
		for c := range ps.conns {
			active = append(active, c)
		}
		ps.conns = nil
		ps.connsMu.Unlock()
		for _, c := range active {
			_ = c.Close()
		}
		peerSrvMu.Lock()
		if activePeerSrvs[ps.id] == ps {
			delete(activePeerSrvs, ps.id)
		}
		peerSrvMu.Unlock()
	})
}

func stopPeerServerByID(id string) {
	if id == "" {
		return
	}
	peerSrvMu.Lock()
	ps := activePeerSrvs[id]
	peerSrvMu.Unlock()
	if ps != nil {
		ps.stop()
	}
}

func (s *session) handlePeerStop(raw json.RawMessage) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.ID == "" {
		return
	}
	stopPeerServerByID(req.ID)
}

func (s *session) handlePeerServeReq(ctx context.Context, raw json.RawMessage) {
	var req struct {
		ID         string `json:"id"`
		ListenHost string `json:"listen_host"`
		Port       int    `json:"port"`
		TokenHex   string `json:"token_hex"`
		TTLMs      int    `json:"ttl_ms"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.ID == "" {
		return
	}
	reply := func(payload map[string]any) {
		rawRes, err := json.Marshal(payload)
		if err != nil {
			return
		}
		if err := s.send(ctx, message{T: msgPeerServeResp, D: rawRes}); err != nil {
			logf(levelWarning, "%s", err.Error())
		}
	}

	tokBytes, err := hex.DecodeString(strings.TrimSpace(req.TokenHex))
	if err != nil || len(tokBytes) != 32 {
		reply(map[string]any{"id": req.ID, "ok": false, "error": "invalid peer token"})
		return
	}
	if req.Port < 0 || req.Port > 65535 {
		reply(map[string]any{"id": req.ID, "ok": false, "error": "invalid peer port"})
		return
	}

	peerSrvMu.Lock()
	if old := activePeerSrvs[req.ID]; old != nil {
		peerSrvMu.Unlock()
		old.stop()
		peerSrvMu.Lock()
	}
	if len(activePeerSrvs) >= peerMaxActiveSrv {
		peerSrvMu.Unlock()
		reply(map[string]any{"id": req.ID, "ok": false, "error": "目标机器当前并发测试已满，请稍后重试"})
		return
	}
	peerSrvMu.Unlock()

	listenHost := strings.TrimSpace(req.ListenHost)
	bindAddr := net.JoinHostPort(listenHost, strconv.Itoa(req.Port))
	tcpLn, err := net.Listen("tcp", bindAddr)
	if err != nil {
		reply(map[string]any{"id": req.ID, "ok": false, "error": sanitizeProbeErr(err)})
		return
	}
	actualPort := req.Port
	if tcpAddr, ok := tcpLn.Addr().(*net.TCPAddr); ok && tcpAddr.Port > 0 {
		actualPort = tcpAddr.Port
	}

	udpConn, udpErr := net.ListenPacket("udp", net.JoinHostPort(listenHost, strconv.Itoa(actualPort)))
	udpOK := udpErr == nil

	ttl := time.Duration(req.TTLMs) * time.Millisecond
	if ttl <= 0 || ttl > peerMaxTTL {
		ttl = 35 * time.Second
	}
	ps := &peerServer{
		id:      req.ID,
		tcpLn:   tcpLn,
		udpConn: udpConn,
		conns:   map[net.Conn]struct{}{},
	}
	copy(ps.token[:], tokBytes)

	peerSrvMu.Lock()
	if old := activePeerSrvs[req.ID]; old != nil {
		// 并发同 ID 竞争时先替换占位，再在锁外关闭旧实例，避免覆盖泄漏。
		delete(activePeerSrvs, req.ID)
		peerSrvMu.Unlock()
		old.stop()
		peerSrvMu.Lock()
	}
	if len(activePeerSrvs) >= peerMaxActiveSrv {
		peerSrvMu.Unlock()
		_ = tcpLn.Close()
		if udpConn != nil {
			_ = udpConn.Close()
		}
		reply(map[string]any{"id": req.ID, "ok": false, "error": "目标机器当前并发测试已满，请稍后重试"})
		return
	}
	ps.timer = time.AfterFunc(ttl, ps.stop)
	activePeerSrvs[req.ID] = ps
	peerSrvMu.Unlock()

	go ps.serveTCP()
	if udpOK {
		go ps.serveUDP()
	}

	reply(map[string]any{
		"id":     req.ID,
		"ok":     true,
		"port":   actualPort,
		"udp_ok": udpOK,
	})
}

func (ps *peerServer) serveTCP() {
	sem := make(chan struct{}, 24)
	for {
		conn, err := ps.tcpLn.Accept()
		if err != nil {
			return
		}
		if !ps.trackConn(conn) {
			_ = conn.Close()
			return
		}
		select {
		case sem <- struct{}{}:
			go func(c net.Conn) {
				defer func() {
					<-sem
					ps.untrackConn(c)
					_ = c.Close()
				}()
				ps.handleTCPConn(c)
			}(conn)
		default:
			ps.untrackConn(conn)
			_ = conn.Close()
		}
	}
}

func (ps *peerServer) handleTCPConn(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	var hdr [peerHeaderBytes]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		// TCPing 握手后直接关闭会命中 EOF，静默结束即可。
		return
	}
	if string(hdr[:8]) != peerTCPMagic {
		return
	}
	if subtle.ConstantTimeCompare(hdr[9:41], ps.token[:]) != 1 {
		return
	}
	mode := hdr[8]
	if mode == 'P' {
		_, _ = conn.Write([]byte("NWDPEER_PONG\n"))
		return
	}

	size := int64(binary.BigEndian.Uint64(hdr[41:49]))
	if size <= 0 || size > probeSteadyMaxBytes {
		size = probeSteadyMaxBytes
	}
	warmupMs := int(binary.BigEndian.Uint32(hdr[49:53]))
	if warmupMs < 0 {
		warmupMs = 0
	}
	if warmupMs > probeMaxWarmupMs {
		warmupMs = probeMaxWarmupMs
	}
	_ = conn.SetDeadline(time.Now().Add(peerStreamLimit + 4*time.Second))

	switch mode {
	case 'D':
		// 目标机器 → 发起机器（接收/下行极限测速）
		if _, err := conn.Write([]byte("NWDPEER_OK\n")); err != nil {
			return
		}
		chunk := peerPayloadChunk()
		deadline := time.Now().Add(peerStreamLimit)
		var sent int64
		for sent < size && time.Now().Before(deadline) {
			step := int64(len(chunk))
			if rem := size - sent; rem < step {
				step = rem
			}
			n, werr := conn.Write(chunk[:step])
			if n > 0 {
				sent += int64(n)
			}
			if werr != nil {
				return
			}
		}
	case 'U':
		// 发起机器 → 目标机器（发送/上行极限测速，由对端剔除预热后如实统计接收速率）
		if _, err := conn.Write([]byte("NWDPEER_READY\n")); err != nil {
			return
		}
		buf := make([]byte, 256<<10)
		var (
			received    int64
			steadyRx    int64
			measureFrom time.Time
			warmupEnd   time.Time
		)
		warmupDur := time.Duration(warmupMs) * time.Millisecond
		deadline := time.Now().Add(peerStreamLimit)
		for received < size && time.Now().Before(deadline) {
			step := int64(len(buf))
			if rem := size - received; rem < step {
				step = rem
			}
			n, rerr := conn.Read(buf[:step])
			if n > 0 {
				now := time.Now()
				if measureFrom.IsZero() {
					measureFrom = now
					warmupEnd = now.Add(warmupDur)
				}
				received += int64(n)
				if !now.Before(warmupEnd) {
					steadyRx += int64(n)
				}
			}
			if rerr != nil {
				break
			}
		}
		endAt := time.Now()
		durMs := int(endAt.Sub(measureFrom).Milliseconds())
		if measureFrom.IsZero() || durMs < 1 {
			durMs = 1
		}
		steadyMs := 0
		if !measureFrom.IsZero() && endAt.After(warmupEnd) {
			steadyMs = int(endAt.Sub(warmupEnd).Milliseconds())
		}
		_, _ = fmt.Fprintf(conn, "NWDPEER_DONE:%d:%d:%d:%d\n", received, durMs, steadyRx, steadyMs)
	}
}

func (ps *peerServer) serveUDP() {
	buf := make([]byte, 256)
	for {
		n, addr, err := ps.udpConn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n != peerUDPPktBytes || string(buf[:8]) != peerUDPMagic {
			continue
		}
		if subtle.ConstantTimeCompare(buf[8:40], ps.token[:]) != 1 {
			continue
		}
		var reply [20]byte
		copy(reply[:12], "NWDPEERU_OK:")
		copy(reply[12:20], buf[40:48])
		_, _ = ps.udpConn.WriteTo(reply[:], addr)
	}
}

func runPeerProbe(ctx context.Context, req probeRequest, host string, resp *probeResponse) {
	tokBytes, err := hex.DecodeString(strings.TrimSpace(req.PeerToken))
	if err != nil || len(tokBytes) != 32 {
		resp.Error = "机器互测令牌无效"
		return
	}
	var tok [32]byte
	copy(tok[:], tokBytes)

	if req.PeerTCP {
		tcpRes := runPeerTCPProbe(ctx, host, req.Port, tok, req.AllowPrivate)
		resp.PeerTCP = &tcpRes
	}
	if req.PeerUDP {
		udpRes := runPeerUDPProbe(ctx, host, req.Port, tok, req.AllowPrivate)
		resp.PeerUDP = &udpRes
	} else {
		resp.PeerUDP = &probePingResult{Status: "skipped", Error: "未启用 UDP"}
	}

	if !req.PeerSpeed {
		resp.PeerSend = &probeSpeedResult{Status: "skipped"}
		resp.PeerRecv = &probeSpeedResult{Status: "skipped"}
		return
	}

	if (resp.PeerTCP != nil && resp.PeerTCP.Status != "ok") || (resp.PeerTCP == nil && resp.TCPing != nil && resp.TCPing.Status != "ok") {
		skipMsg := "链内 TCP 未连通，已跳过测速"
		resp.PeerSend = &probeSpeedResult{Status: "skipped", Error: skipMsg}
		resp.PeerRecv = &probeSpeedResult{Status: "skipped", Error: skipMsg}
		return
	}

	select {
	case speedSem <- struct{}{}:
		defer func() { <-speedSem }()
	case <-ctx.Done():
		resp.PeerSend = &probeSpeedResult{Status: "error", Error: "测试已取消"}
		resp.PeerRecv = &probeSpeedResult{Status: "error", Error: "测试已取消"}
		return
	}

	streams, warmupDur, steadyDur, maxCap, steadyMode := resolveSpeedParams(req)
	dir := strings.ToLower(strings.TrimSpace(req.PeerDir))
	if dir == "" {
		dir = "both"
	}
	if dir == "both" || dir == "send" {
		sendRes := runPeerMultiStreamSend(ctx, host, req.Port, tok, streams, warmupDur, steadyDur, maxCap, steadyMode, req.AllowPrivate)
		resp.PeerSend = &sendRes
	} else {
		resp.PeerSend = &probeSpeedResult{Status: "skipped", Error: "未选择发送方向"}
	}
	if ctx.Err() != nil {
		if resp.PeerRecv == nil {
			resp.PeerRecv = &probeSpeedResult{Status: "error", Error: "测试已取消"}
		}
		return
	}
	if dir == "both" || dir == "recv" {
		recvRes := runPeerMultiStreamRecv(ctx, host, req.Port, tok, streams, warmupDur, steadyDur, maxCap, steadyMode, req.AllowPrivate)
		resp.PeerRecv = &recvRes
	} else {
		resp.PeerRecv = &probeSpeedResult{Status: "skipped", Error: "未选择接收方向"}
	}
}

func runPeerTCPProbe(ctx context.Context, host string, port int, token [32]byte, allowPrivate bool) probePingResult {
	if port < 1 || port > 65535 {
		return probePingResult{Status: "error", LossPct: 100, Error: "端口无效"}
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := newSafeTCPDialer(probeTCPTimeout, allowPrivate, "目标地址不是公网地址")
	hdr := buildPeerTCPHeader('P', token, 0, 0)

	var samples []int
	var lastErr error
	for i := 0; i < defaultProbePingCount; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		dctx, cancel := context.WithTimeout(ctx, probeTCPTimeout)
		conn, derr := dialer.DialContext(dctx, "tcp", target)
		cancel()
		if derr != nil {
			lastErr = derr
		} else {
			_ = conn.SetDeadline(time.Now().Add(probeTCPTimeout))
			if _, werr := conn.Write(hdr[:]); werr != nil {
				lastErr = werr
			} else {
				br := bufio.NewReaderSize(conn, 64)
				line, rerr := br.ReadString('\n')
				if rerr != nil {
					lastErr = rerr
				} else if strings.TrimSpace(line) == "NWDPEER_PONG" {
					ms := int(time.Since(start).Milliseconds())
					if ms < 1 {
						ms = 1
					}
					samples = append(samples, ms)
				} else {
					lastErr = errors.New("未收到链内握手回包")
				}
			}
			_ = conn.Close()
		}
		if i+1 < defaultProbePingCount {
			sleep(ctx, probeTCPInterval)
		}
	}
	return summarizePingSamples(samples, defaultProbePingCount, lastErr)
}

func runPeerUDPProbe(ctx context.Context, host string, port int, token [32]byte, allowPrivate bool) probePingResult {
	if port < 1 || port > 65535 {
		return probePingResult{Status: "error", LossPct: 100, Error: "端口无效"}
	}
	ip, err := resolveProbeIP(ctx, host, allowPrivate)
	if err != nil {
		return probePingResult{Status: "error", LossPct: 100, Error: sanitizeProbeErr(err)}
	}
	network := "udp4"
	if ip.To4() == nil {
		network = "udp6"
	}
	conn, err := net.DialUDP(network, nil, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return probePingResult{Status: "error", LossPct: 100, Error: sanitizeProbeErr(err)}
	}
	defer conn.Close()

	var samples []int
	var lastErr error
	rx := make([]byte, 128)
	for i := 0; i < defaultProbePingCount; i++ {
		if ctx.Err() != nil {
			break
		}
		var nonce [8]byte
		_, _ = rand.Read(nonce[:])
		var pkt [peerUDPPktBytes]byte
		copy(pkt[:8], peerUDPMagic)
		copy(pkt[8:40], token[:])
		copy(pkt[40:48], nonce[:])

		start := time.Now()
		deadline := start.Add(probeICMPTimeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)
		if _, werr := conn.Write(pkt[:]); werr != nil {
			lastErr = werr
		} else {
			n, rerr := conn.Read(rx)
			if rerr != nil {
				lastErr = rerr
			} else if n == 20 && string(rx[:12]) == "NWDPEERU_OK:" && bytes.Equal(rx[12:20], nonce[:]) {
				ms := int(time.Since(start).Milliseconds())
				if ms < 1 {
					ms = 1
				}
				samples = append(samples, ms)
			}
		}
		if i+1 < defaultProbePingCount {
			select {
			case <-ctx.Done():
			case <-time.After(probeTCPInterval):
			}
		}
	}
	return summarizePingSamples(samples, defaultProbePingCount, lastErr)
}

func dialPeerTCP(ctx context.Context, host string, port int, allowPrivate bool) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, probeSpeedDialTimeout)
	defer cancel()
	d := newSafeTCPDialer(probeSpeedDialTimeout, allowPrivate, "目标地址不是公网地址")
	return d.DialContext(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

func buildPeerTCPHeader(mode byte, token [32]byte, sizeBytes int64, warmupMs uint32) [peerHeaderBytes]byte {
	var hdr [peerHeaderBytes]byte
	copy(hdr[:8], peerTCPMagic)
	hdr[8] = mode
	copy(hdr[9:41], token[:])
	binary.BigEndian.PutUint64(hdr[41:49], uint64(sizeBytes))
	binary.BigEndian.PutUint32(hdr[49:53], warmupMs)
	return hdr
}

func runPeerMultiStreamRecv(
	ctx context.Context,
	host string,
	port int,
	token [32]byte,
	streams int,
	warmupDur, steadyDur time.Duration,
	maxCap int64,
	steadyMode bool,
	allowPrivate bool,
) probeSpeedResult {
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	perStreamCap := maxCap
	if steadyMode && streams > 1 {
		perStreamCap = maxCap / int64(streams)
		if perStreamCap < (64 << 20) {
			perStreamCap = 64 << 20
		}
	}
	warmupMs := uint32(warmupDur.Milliseconds())

	var (
		clockOnce   sync.Once
		totalStart  time.Time
		warmupEnd   time.Time
		windowTimer *time.Timer

		totalBytes  atomic.Int64
		steadyBytes atomic.Int64

		errMu    sync.Mutex
		firstErr error
	)
	noteErr := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}
	startClock := func() {
		clockOnce.Do(func() {
			totalStart = time.Now()
			warmupEnd = totalStart.Add(warmupDur)
			windowTimer = time.AfterFunc(warmupDur+steadyDur, cancelRun)
		})
	}
	defer func() {
		if windowTimer != nil {
			windowTimer.Stop()
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dialPeerTCP(runCtx, host, port, allowPrivate)
			if err != nil {
				if runCtx.Err() == nil {
					noteErr(err)
				}
				return
			}
			stopOnCancel := context.AfterFunc(runCtx, func() { _ = conn.Close() })
			defer func() {
				stopOnCancel()
				_ = conn.Close()
			}()

			_ = conn.SetDeadline(time.Now().Add(peerStreamLimit + 4*time.Second))
			hdr := buildPeerTCPHeader('D', token, perStreamCap, warmupMs)
			if _, err := conn.Write(hdr[:]); err != nil {
				if runCtx.Err() == nil {
					noteErr(err)
				}
				return
			}

			br := bufio.NewReaderSize(conn, 256<<10)
			line, err := br.ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "NWDPEER_OK" {
				if runCtx.Err() == nil {
					noteErr(errors.New("目标机器未确认测速握手"))
				}
				return
			}

			startClock()
			buf := make([]byte, 256<<10)
			for {
				n, rerr := br.Read(buf)
				if n > 0 {
					now := time.Now()
					curTotal := totalBytes.Add(int64(n))
					if !now.Before(warmupEnd) {
						steadyBytes.Add(int64(n))
					}
					if curTotal >= maxCap {
						cancelRun()
						return
					}
				}
				if rerr != nil {
					return
				}
			}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		return probeSpeedResult{Status: "error", Error: "测速已取消"}
	}
	tot := totalBytes.Load()
	if tot <= 0 {
		if firstErr != nil {
			return probeSpeedResult{Status: "error", Error: sanitizeProbeErr(firstErr)}
		}
		return probeSpeedResult{Status: "error", Error: "未收到对端测速数据"}
	}

	now := time.Now()
	stBytes := steadyBytes.Load()
	if steadyMode && warmupDur > 0 && stBytes > 0 && now.Sub(warmupEnd) >= 50*time.Millisecond {
		res := formatPeerSpeedResult(stBytes, now.Sub(warmupEnd))
		res.Streams = streams
		return res
	}
	res := formatPeerSpeedResult(tot, now.Sub(totalStart))
	res.Streams = streams
	return res
}

func runPeerMultiStreamSend(
	ctx context.Context,
	host string,
	port int,
	token [32]byte,
	streams int,
	warmupDur, steadyDur time.Duration,
	maxCap int64,
	steadyMode bool,
	allowPrivate bool,
) probeSpeedResult {
	sendCtx, stopSending := context.WithCancel(ctx)
	defer stopSending()

	perStreamCap := maxCap
	if steadyMode && streams > 1 {
		perStreamCap = maxCap / int64(streams)
		if perStreamCap < (64 << 20) {
			perStreamCap = 64 << 20
		}
	}
	warmupMs := uint32(warmupDur.Milliseconds())
	chunk := peerPayloadChunk()

	var (
		clockOnce   sync.Once
		totalStart  time.Time
		windowTimer *time.Timer

		sentTotal   atomic.Int64
		rxTotalSum  atomic.Int64
		rxSteadySum atomic.Int64
		rxMaxTotal  atomic.Int64
		rxMaxSteady atomic.Int64

		errMu    sync.Mutex
		firstErr error
	)
	noteErr := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}
	startClock := func() {
		clockOnce.Do(func() {
			totalStart = time.Now()
			windowTimer = time.AfterFunc(warmupDur+steadyDur, stopSending)
		})
	}
	defer func() {
		if windowTimer != nil {
			windowTimer.Stop()
		}
	}()

	updateMax := func(dst *atomic.Int64, val int64) {
		for {
			cur := dst.Load()
			if val <= cur || dst.CompareAndSwap(cur, val) {
				return
			}
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dialPeerTCP(sendCtx, host, port, allowPrivate)
			if err != nil {
				if sendCtx.Err() == nil {
					noteErr(err)
				}
				return
			}
			abortOnUserCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer func() {
				abortOnUserCancel()
				_ = conn.Close()
			}()

			_ = conn.SetDeadline(time.Now().Add(peerStreamLimit + 4*time.Second))
			hdr := buildPeerTCPHeader('U', token, perStreamCap, warmupMs)
			if _, err := conn.Write(hdr[:]); err != nil {
				if sendCtx.Err() == nil {
					noteErr(err)
				}
				return
			}

			br := bufio.NewReaderSize(conn, 4096)
			line, err := br.ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "NWDPEER_READY" {
				if sendCtx.Err() == nil {
					noteErr(errors.New("目标机器未就绪接收测速"))
				}
				return
			}

			startClock()
			// 当定时窗口结束（sendCtx 取消）时打断阻塞 Write，以便进入半关闭读取对端真实收包统计。
			unblockWrite := context.AfterFunc(sendCtx, func() {
				_ = conn.SetWriteDeadline(time.Now())
			})
			var streamSent int64
			for streamSent < perStreamCap && sendCtx.Err() == nil {
				step := int64(len(chunk))
				if rem := perStreamCap - streamSent; rem < step {
					step = rem
				}
				n, werr := conn.Write(chunk[:step])
				if n > 0 {
					streamSent += int64(n)
					if sentTotal.Add(int64(n)) >= maxCap {
						stopSending()
						break
					}
				}
				if werr != nil {
					break
				}
			}
			unblockWrite()
			if ctx.Err() != nil {
				return
			}
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				_ = tcpConn.CloseWrite()
			}
			_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
			doneLine, rerr := br.ReadString('\n')
			if rerr == nil {
				if rest, ok := strings.CutPrefix(strings.TrimSpace(doneLine), "NWDPEER_DONE:"); ok {
					parts := strings.Split(rest, ":")
					if len(parts) >= 2 {
						rxB, bErr := strconv.ParseInt(parts[0], 10, 64)
						rxMs, mErr := strconv.ParseInt(parts[1], 10, 64)
						if bErr == nil && mErr == nil && rxB > 0 {
							rxTotalSum.Add(rxB)
							updateMax(&rxMaxTotal, rxMs)
						}
					}
					if len(parts) >= 4 {
						stB, bErr := strconv.ParseInt(parts[2], 10, 64)
						stMs, mErr := strconv.ParseInt(parts[3], 10, 64)
						if bErr == nil && mErr == nil && stB > 0 {
							rxSteadySum.Add(stB)
							updateMax(&rxMaxSteady, stMs)
						}
					}
				}
			}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		return probeSpeedResult{Status: "error", Error: "测速已取消"}
	}

	now := time.Now()
	if steadyMode && warmupDur > 0 && rxSteadySum.Load() > 0 && rxMaxSteady.Load() >= 50 {
		dur := time.Duration(rxMaxSteady.Load()) * time.Millisecond
		res := formatPeerSpeedResult(rxSteadySum.Load(), dur)
		res.Streams = streams
		return res
	}
	if rxTotalSum.Load() > 0 {
		dur := time.Duration(rxMaxTotal.Load()) * time.Millisecond
		if localDur := now.Sub(totalStart); localDur > dur {
			dur = localDur
		}
		res := formatPeerSpeedResult(rxTotalSum.Load(), dur)
		res.Streams = streams
		return res
	}
	if sentTotal.Load() > 0 {
		res := formatPeerSpeedResult(sentTotal.Load(), now.Sub(totalStart))
		res.Streams = streams
		return res
	}
	if firstErr != nil {
		return probeSpeedResult{Status: "error", Error: sanitizeProbeErr(firstErr)}
	}
	return probeSpeedResult{Status: "error", Error: "发送测速未传出数据"}
}

func formatPeerSpeedResult(totalBytes int64, dur time.Duration) probeSpeedResult {
	if dur < time.Millisecond {
		dur = time.Millisecond
	}
	durMs := int(dur.Milliseconds())
	if durMs < 1 {
		durMs = 1
	}
	bps := int64(float64(totalBytes) / dur.Seconds())
	mbps := math.Round((float64(bps)*8.0/1_000_000.0)*10) / 10
	return probeSpeedResult{
		Status:      "ok",
		Bytes:       totalBytes,
		DurationMs:  durMs,
		BytesPerSec: bps,
		Mbps:        mbps,
	}
}
