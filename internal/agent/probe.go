package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
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
	probeSpeedDefaultBytes  = 25 << 20
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
	ID           string         `json:"id"`
	Host         string         `json:"host"`
	Port         int            `json:"port"`
	AllowPrivate bool           `json:"allow_private,omitempty"`
	RunPing      bool           `json:"run_ping"`
	RunTCPing    bool           `json:"run_tcping"`
	SkipTCPing   string         `json:"skip_tcping,omitempty"`
	Proxy        map[string]any `json:"proxy,omitempty"`
	LatencyURL   string         `json:"latency_url,omitempty"`
	SpeedTest    bool           `json:"speed_test,omitempty"`
	SpeedURL     string         `json:"speed_url,omitempty"`
	SpeedBytes   int64          `json:"speed_bytes,omitempty"`
	ChainToken   string         `json:"chain_token,omitempty"`
	ChainTCP     bool           `json:"chain_tcp,omitempty"`
	ChainUDP     bool           `json:"chain_udp,omitempty"`
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
	probeCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
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
	if host == "" && (req.RunPing || req.RunTCPing || req.ChainToken != "") {
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

	// 代理协议端到端延迟与可选下行测速。
	if len(req.Proxy) > 0 {
		urlRes, speedRes := runProxyProbe(ctx, req)
		resp.URLTest = &urlRes
		resp.Speed = &speedRes
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

func runTCPing(ctx context.Context, host string, port int, skipReason string, allowPrivate bool) probePingResult {
	if skipReason != "" {
		return probePingResult{Status: "skipped", LossPct: 0, Error: skipReason}
	}
	if port < 1 || port > 65535 {
		return probePingResult{Status: "error", LossPct: 100, Error: "端口无效"}
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{
		Timeout: probeTCPTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			if allowPrivate {
				return nil
			}
			h, _, err := parseDialTarget(address)
			if err != nil {
				return err
			}
			if forwardIPBlocked(net.ParseIP(h)) {
				return errors.New("目标地址不是公网地址")
			}
			return nil
		},
	}

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

	urlRes := runProxyURLTest(ctx, proxy, latURL, latMeta)
	if !req.SpeedTest {
		return urlRes, skippedSpeed
	}
	if urlRes.Status != "ok" {
		return urlRes, probeSpeedResult{Status: "skipped", Error: "端到端连通未通过，已跳过测速"}
	}

	speedRaw := strings.TrimSpace(req.SpeedURL)
	maxBytes := req.SpeedBytes
	if maxBytes <= 0 {
		maxBytes = probeSpeedDefaultBytes
	}
	if maxBytes > probeSpeedMaxBytes {
		maxBytes = probeSpeedMaxBytes
	}
	if speedRaw == "" {
		speedRaw = fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", maxBytes)
	}
	spdURL, spdMeta, err := validateTargetHTTPURL(speedRaw)
	if err != nil {
		return urlRes, probeSpeedResult{Status: "error", Error: err.Error()}
	}
	spdRes := runProxySpeedTest(ctx, proxy, spdURL, spdMeta, maxBytes)
	return urlRes, spdRes
}

func runProxyURLTest(ctx context.Context, proxy C.Proxy, targetURL *url.URL, meta C.Metadata) probeURLResult {
	latCtx, cancel := context.WithTimeout(ctx, probeURLTimeout)
	defer cancel()

	start := time.Now()
	firstConn, err := proxy.DialContext(latCtx, &meta)
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
			m := meta
			return proxy.DialContext(dctx, &m)
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

func runProxySpeedTest(ctx context.Context, proxy C.Proxy, targetURL *url.URL, meta C.Metadata, maxBytes int64) probeSpeedResult {
	select {
	case speedSem <- struct{}{}:
		defer func() { <-speedSem }()
	case <-ctx.Done():
		return probeSpeedResult{Status: "error", Error: "测速已取消"}
	}

	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	dialCtx, dialCancel := context.WithTimeout(reqCtx, probeSpeedDialTimeout)
	conn, err := proxy.DialContext(dialCtx, &meta)
	dialCancel()
	if err != nil {
		return probeSpeedResult{Status: "error", Error: sanitizeProbeErr(err)}
	}

	var connOnce sync.Once
	handed := false
	defer func() {
		if !handed {
			_ = conn.Close()
		}
	}()

	tr := &http.Transport{
		DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
			var c net.Conn
			connOnce.Do(func() {
				c = conn
				handed = true
			})
			if c != nil {
				return c, nil
			}
			m := meta
			return proxy.DialContext(dctx, &m)
		},
		TLSClientConfig:       buildProxyTLSConfig(targetURL.Hostname()),
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
	}
	client := &http.Client{Transport: tr}
	defer client.CloseIdleConnections()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return probeSpeedResult{Status: "error", Error: sanitizeProbeErr(err)}
	}
	httpReq.Header.Set("User-Agent", "curl/8.5.0")

	resp, err := client.Do(httpReq)
	if err != nil {
		return probeSpeedResult{Status: "error", Error: sanitizeProbeErr(err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return probeSpeedResult{
			Status: "error",
			Error:  fmt.Sprintf("测速源返回 HTTP %d", resp.StatusCode),
		}
	}

	// 从首包响应头到达后启动定长测量窗：到期主动 cancel 使阻塞 Read 立即收敛。
	transferStart := time.Now()
	timer := time.AfterFunc(probeSpeedTransferLimit, cancel)
	defer timer.Stop()

	buf := make([]byte, 64<<10)
	var total int64
	for total < maxBytes {
		want := len(buf)
		if rem := maxBytes - total; rem < int64(want) {
			want = int(rem)
		}
		n, rerr := resp.Body.Read(buf[:want])
		if n > 0 {
			total += int64(n)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) || (reqCtx.Err() != nil && ctx.Err() == nil && total > 0) {
				break
			}
			if ctx.Err() != nil {
				return probeSpeedResult{Status: "error", Error: "测速已取消"}
			}
			if total == 0 {
				return probeSpeedResult{Status: "error", Error: sanitizeProbeErr(rerr)}
			}
			break
		}
	}
	if total == 0 {
		return probeSpeedResult{Status: "error", Error: "测速源返回空响应"}
	}
	elapsed := time.Since(transferStart)
	if elapsed < time.Millisecond {
		elapsed = time.Millisecond
	}
	sec := elapsed.Seconds()
	bps := int64(math.Round(float64(total) / sec))
	mbps := math.Round((float64(total)*8)/(sec*1_000_000)*10) / 10
	return probeSpeedResult{
		Status:      "ok",
		Bytes:       total,
		DurationMs:  int(elapsed.Milliseconds()),
		BytesPerSec: bps,
		Mbps:        mbps,
	}
}

func runChainTCPProbe(ctx context.Context, host string, port int, token [32]byte, allowPrivate bool) probeChainResult {
	if port < 1 || port > 65535 {
		return probeChainResult{Status: "error", Error: "首跳端口无效"}
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	cctx, cancel := context.WithTimeout(ctx, probeChainTimeout)
	defer cancel()

	dialer := &net.Dialer{
		Timeout: probeChainTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			if allowPrivate {
				return nil
			}
			h, _, err := parseDialTarget(address)
			if err != nil {
				return err
			}
			if forwardIPBlocked(net.ParseIP(h)) {
				return errors.New("首跳地址不是公网地址")
			}
			return nil
		},
	}
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
