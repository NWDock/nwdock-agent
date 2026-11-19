package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func freeLoopbackTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func freeLoopbackDualPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 32; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		uc, uerr := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		_ = ln.Close()
		if uerr == nil {
			_ = uc.Close()
			return port
		}
	}
	t.Fatal("failed to find free dual tcp+udp port")
	return 0
}

func TestProbePingAndTCPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	res := executeProbe(context.Background(), probeRequest{
		ID:           "p1",
		Host:         "127.0.0.1",
		Port:         port,
		AllowPrivate: true,
		RunPing:      true,
		RunTCPing:    true,
	})
	if res.Ping == nil || (res.Ping.Status != "ok" && res.Ping.Status != "unsupported") {
		t.Fatalf("unexpected ping result: %+v", res.Ping)
	}
	if res.Ping.Status == "ok" && res.Ping.AvgMs < 1 {
		t.Fatalf("ping avg_ms < 1: %+v", res.Ping)
	}
	if res.TCPing == nil || res.TCPing.Status != "ok" || res.TCPing.LossPct != 0 || res.TCPing.AvgMs < 1 {
		t.Fatalf("unexpected tcping result: %+v", res.TCPing)
	}

	// 纯 UDP 监听跳过 TCPing。
	udpOnly := executeProbe(context.Background(), probeRequest{
		ID:           "p2",
		Host:         "127.0.0.1",
		Port:         port,
		AllowPrivate: true,
		RunTCPing:    true,
		SkipTCPing:   "仅 UDP 监听",
	})
	if udpOnly.TCPing == nil || udpOnly.TCPing.Status != "skipped" {
		t.Fatalf("expected skipped tcping, got %+v", udpOnly.TCPing)
	}

	// 内网拦截默认开启：AllowPrivate=false 访问 127.0.0.1 必须失败。
	blocked := executeProbe(context.Background(), probeRequest{
		ID:           "p3",
		Host:         "127.0.0.1",
		Port:         port,
		AllowPrivate: false,
		RunPing:      true,
		RunTCPing:    true,
	})
	if blocked.TCPing == nil || blocked.TCPing.Status != "error" {
		t.Fatalf("expected private target tcping blocked, got %+v", blocked.TCPing)
	}
}

func TestProbeProxyURLAndSpeed(t *testing.T) {
	resetTraffic()
	t.Cleanup(resetTraffic)
	origGuard := probeURLGuardEnabled
	origTLS := probeHTTPClientTLS
	probeURLGuardEnabled = false
	defer func() {
		probeURLGuardEnabled = origGuard
		probeHTTPClientTLS = origTLS
	}()

	payload := bytes.Repeat([]byte("A"), 512<<10)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generate_204":
			w.WriteHeader(http.StatusNoContent)
		case "/__down":
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	probeHTTPClientTLS = &tls.Config{RootCAs: pool}

	// 启动内嵌核心 Shadowsocks 监听做真实端到端回环验证。
	dir := t.TempDir()
	ssPort := freeLoopbackTCPPort(t)
	ctrlPort := freeLoopbackTCPPort(t)
	mihomoCfg := map[string]any{
		"port":                0,
		"socks-port":          0,
		"allow-lan":           true,
		"mode":                "rule",
		"log-level":           "error",
		"dns":                 map[string]any{"enable": false},
		"external-controller": net.JoinHostPort("127.0.0.1", strconv.Itoa(ctrlPort)),
		"listeners": []any{
			map[string]any{
				"name":     "ss-prb-test",
				"type":     "shadowsocks",
				"listen":   "127.0.0.1",
				"port":     ssPort,
				"cipher":   "aes-256-gcm",
				"password": "change-me-probe-secret",
				"udp":      true,
			},
		},
		"proxies": []any{
			map[string]any{"name": "direct", "type": "direct", "udp": true},
		},
		"rules": []string{"MATCH,direct"},
	}
	rawCfg, err := json.Marshal(mihomoCfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, rawCfg, 0o600); err != nil {
		t.Fatal(err)
	}
	rt := newEmbeddedRuntime()
	if err := rt.Start(context.Background(), cfgPath, dir); err != nil {
		t.Fatal(err)
	}
	defer rt.Stop()

	resp := executeProbe(context.Background(), probeRequest{
		ID:           "proxy-1",
		Host:         "127.0.0.1",
		Port:         ssPort,
		AllowPrivate: true,
		RunTCPing:    true,
		Proxy: map[string]any{
			"name":     "probe-node",
			"type":     "ss",
			"server":   "127.0.0.1",
			"port":     ssPort,
			"cipher":   "aes-256-gcm",
			"password": "change-me-probe-secret",
			"udp":      true,
		},
		LatencyURL: ts.URL + "/generate_204",
		SpeedTest:  true,
		SpeedURL:   ts.URL + "/__down",
		SpeedBytes: int64(len(payload)),
	})
	if resp.URLTest == nil || resp.URLTest.Status != "ok" || resp.URLTest.HTTPStatus != 204 || resp.URLTest.DelayMs < 1 || resp.URLTest.RTTMs < 1 {
		t.Fatalf("unexpected url_test: %+v", resp.URLTest)
	}
	if resp.Speed == nil || resp.Speed.Status != "ok" || resp.Speed.Bytes != int64(len(payload)) || resp.Speed.Mbps <= 0 {
		t.Fatalf("unexpected speed: %+v", resp.Speed)
	}
}

func TestProbeMultiHopChainTCPAndUDP(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetRelayBytes()
	t.Cleanup(func() {
		resetRelay(t.TempDir())
		resetRelayBytes()
	})

	// 模拟外部自定义目标：记录收到的业务字节数，验证整链探针不会向外部目标写入任何载荷，
	// 同时验证真实业务（含服务端先发 banner 与客户端先发数据）在探针挂载期间零损透传。
	var externalPayloadBytes atomic.Int64
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				for {
					n, rerr := conn.Read(buf)
					if n > 0 {
						externalPayloadBytes.Add(int64(n))
						_, _ = conn.Write(buf[:n])
					}
					if rerr != nil {
						return
					}
				}
			}(c)
		}
	}()
	targetPort := targetLn.Addr().(*net.TCPAddr).Port

	hop1Port := freeLoopbackDualPort(t)
	hop2Port := freeLoopbackDualPort(t)
	hop3Port := freeLoopbackDualPort(t)

	specs := []relaySpec{
		{Port: hop1Port, TargetHost: "127.0.0.1", TargetPort: hop2Port, TCP: true, UDP: true, ForwardID: "hop1", AllowPrivate: true},
		{Port: hop2Port, TargetHost: "127.0.0.1", TargetPort: hop3Port, TCP: true, UDP: true, ForwardID: "hop2", AllowPrivate: true},
		{Port: hop3Port, TargetHost: "127.0.0.1", TargetPort: targetPort, TCP: true, UDP: true, ForwardID: "hop3", AllowPrivate: true},
	}
	if err := relayApplyAll(dir, nil, specs); err != nil {
		t.Fatal(err)
	}
	waitForwardListening(t, "hop1")
	waitForwardListening(t, "hop2")
	waitForwardListening(t, "hop3")

	var tok [32]byte
	if _, err := rand.Read(tok[:]); err != nil {
		t.Fatal(err)
	}
	if err := armRelayProbe("hop3", tok, 10*time.Second); err != nil {
		t.Fatal(err)
	}

	// 1. 挂载期间真实客户端连接必须原样回显，不被探针吞首包。
	userConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(hop1Port)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	wantMsg := []byte("real-business-payload-12345")
	if _, err := userConn.Write(wantMsg); err != nil {
		t.Fatal(err)
	}
	gotMsg := make([]byte, len(wantMsg))
	if _, err := io.ReadFull(userConn, gotMsg); err != nil {
		t.Fatal(err)
	}
	_ = userConn.Close()
	if !bytes.Equal(gotMsg, wantMsg) {
		t.Fatalf("user traffic corrupted: got %q want %q", gotMsg, wantMsg)
	}
	beforeProbe := externalPayloadBytes.Load()
	if beforeProbe != int64(len(wantMsg)) {
		t.Fatalf("expected external bytes %d, got %d", len(wantMsg), beforeProbe)
	}

	// 2. 执行 3 跳整链 TCP + UDP 探针：全链通过，且外部目标收到的载荷增量必须为 0。
	chainRes := executeProbe(context.Background(), probeRequest{
		ID:           "chain-1",
		Host:         "127.0.0.1",
		Port:         hop1Port,
		AllowPrivate: true,
		RunTCPing:    true,
		ChainToken:   hex.EncodeToString(tok[:]),
		ChainTCP:     true,
		ChainUDP:     true,
	})
	if chainRes.ChainTCP == nil || chainRes.ChainTCP.Status != "ok" || chainRes.ChainTCP.RTTMs < 1 || chainRes.ChainTCP.TargetDialMs < 1 {
		t.Fatalf("chain tcp failed: %+v", chainRes.ChainTCP)
	}
	if chainRes.ChainUDP == nil || chainRes.ChainUDP.Status != "ok" || chainRes.ChainUDP.RTTMs < 1 {
		t.Fatalf("chain udp failed: %+v", chainRes.ChainUDP)
	}
	time.Sleep(50 * time.Millisecond)
	if afterProbe := externalPayloadBytes.Load(); afterProbe != beforeProbe {
		t.Fatalf("probe leaked %d bytes to external target", afterProbe-beforeProbe)
	}

	// 3. 掐断第 2 跳（保留第 1 跳监听）：首跳 TCPing 仍通，但整链 ChainTCP 必须报红（绝不假绿）。
	if err := relayApplyAll(dir, nil, []relaySpec{specs[0], specs[2]}); err != nil {
		t.Fatal(err)
	}
	var tok2 [32]byte
	_, _ = rand.Read(tok2[:])
	if err := armRelayProbe("hop3", tok2, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	brokenRes := executeProbe(context.Background(), probeRequest{
		ID:           "chain-broken",
		Host:         "127.0.0.1",
		Port:         hop1Port,
		AllowPrivate: true,
		RunTCPing:    true,
		ChainToken:   hex.EncodeToString(tok2[:]),
		ChainTCP:     true,
	})
	if brokenRes.TCPing == nil || brokenRes.TCPing.Status != "ok" {
		t.Fatalf("hop1 tcping should still accept: %+v", brokenRes.TCPing)
	}
	if brokenRes.ChainTCP == nil || brokenRes.ChainTCP.Status != "error" {
		t.Fatalf("broken mid-hop chain must fail end-to-end, got %+v", brokenRes.ChainTCP)
	}
}

func TestChannelSyncAndProbeRPC(t *testing.T) {
	resetRelay(t.TempDir())
	resetRelayBytes()
	t.Cleanup(func() {
		resetRelay(t.TempDir())
		resetRelayBytes()
	})

	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	targetPort := targetLn.Addr().(*net.TCPAddr).Port
	fwdPort := freeLoopbackDualPort(t)

	var tok [32]byte
	_, _ = rand.Read(tok[:])
	tokHex := hex.EncodeToString(tok[:])

	s, _, _ := dialWithPanel(t, false, func(peer *panelHandle) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// 跳过初始 desired_req（若带 stats 先回 stats_ack）。
		for {
			m, err := peer.read(ctx)
			if err != nil {
				t.Errorf("read init: %v", err)
				return
			}
			if m.T == msgStats {
				var st struct {
					Batch string `json:"batch"`
				}
				_ = json.Unmarshal(m.D, &st)
				if st.Batch != "" {
					ackRaw, _ := json.Marshal(map[string]string{"batch": st.Batch})
					_ = peer.send(ctx, message{T: msgStatsAck, D: ackRaw})
				}
				continue
			}
			if m.T == msgDesiredReq {
				break
			}
		}

		// 1. sync_req 同步应用转发端口并确认监听状态。
		desiredJSON, _ := json.Marshal(map[string]any{
			"generation": 77,
			"serving":    false,
			"relays":     []any{},
			"forwards": []any{
				map[string]any{
					"id":            "prb-test-1",
					"port":          fwdPort,
					"target_host":   "127.0.0.1",
					"target_port":   targetPort,
					"tcp":           true,
					"udp":           true,
					"allow_private": true,
				},
			},
		})
		syncReq, _ := json.Marshal(map[string]any{
			"id":      "sync-1",
			"desired": json.RawMessage(desiredJSON),
		})
		if err := peer.send(ctx, message{T: msgSyncReq, D: syncReq}); err != nil {
			t.Errorf("send sync_req: %v", err)
			return
		}
		syncReply := readTyped(t, ctx, peer, msgSyncResp)
		if !strings.Contains(string(syncReply), `"ok":true`) || !strings.Contains(string(syncReply), `"generation":77`) {
			t.Errorf("unexpected sync_resp: %s", syncReply)
			return
		}

		// 2. probe_arm 挂载贯穿令牌。
		armReq, _ := json.Marshal(map[string]any{
			"id":         "arm-1",
			"forward_id": "prb-test-1",
			"token_hex":  tokHex,
			"ttl_ms":     8000,
		})
		if err := peer.send(ctx, message{T: msgProbeArm, D: armReq}); err != nil {
			t.Errorf("send probe_arm: %v", err)
			return
		}
		armReply := readTyped(t, ctx, peer, msgProbeArmResp)
		if !strings.Contains(string(armReply), `"ok":true`) {
			t.Errorf("unexpected probe_arm_resp: %s", armReply)
			return
		}

		// 3. probe_req 实测整链贯穿。
		pReq, _ := json.Marshal(probeRequest{
			ID:           "prb-rpc-1",
			Host:         "127.0.0.1",
			Port:         fwdPort,
			AllowPrivate: true,
			RunTCPing:    true,
			ChainToken:   tokHex,
			ChainTCP:     true,
			ChainUDP:     true,
		})
		if err := peer.send(ctx, message{T: msgProbeReq, D: pReq}); err != nil {
			t.Errorf("send probe_req: %v", err)
			return
		}
		pReply := readTyped(t, ctx, peer, msgProbeResp)
		var parsed probeResponse
		if err := json.Unmarshal(pReply, &parsed); err != nil {
			t.Errorf("unmarshal probe_resp: %v", err)
			return
		}
		if parsed.ChainTCP == nil || parsed.ChainTCP.Status != "ok" || parsed.ChainUDP == nil || parsed.ChainUDP.Status != "ok" {
			t.Errorf("unexpected probe_resp: %+v", parsed)
			return
		}
		_ = peer.conn.Close(websocket.StatusNormalClosure, "done")
	})

	if err := s.serve(context.Background()); err == nil {
		t.Fatal("expected close error")
	}
}

func readTyped(t *testing.T, ctx context.Context, peer *panelHandle, wantType string) json.RawMessage {
	t.Helper()
	for {
		msg, err := peer.read(ctx)
		if err != nil {
			t.Fatalf("waiting for %s: %v", wantType, err)
		}
		if msg.T == msgStats {
			var st struct {
				Batch string `json:"batch"`
			}
			_ = json.Unmarshal(msg.D, &st)
			if st.Batch != "" {
				ackRaw, _ := json.Marshal(map[string]string{"batch": st.Batch})
				_ = peer.send(ctx, message{T: msgStatsAck, D: ackRaw})
			}
			continue
		}
		if msg.T == wantType {
			return msg.D
		}
	}
}

func TestPeerServeAndBidirectionalProbe(t *testing.T) {
	resetRelay(t.TempDir())
	resetRelayBytes()
	t.Cleanup(func() {
		resetRelay(t.TempDir())
		resetRelayBytes()
	})

	var tok [32]byte
	_, _ = rand.Read(tok[:])
	tokHex := hex.EncodeToString(tok[:])

	var badTok [32]byte
	_, _ = rand.Read(badTok[:])
	badTokHex := hex.EncodeToString(badTok[:])

	s, _, _ := dialWithPanel(t, false, func(peer *panelHandle) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = readTyped(t, ctx, peer, msgDesiredReq)

		serveReqRaw, _ := json.Marshal(map[string]any{
			"id":          "peer-srv-1",
			"listen_host": "127.0.0.1",
			"port":        0,
			"token_hex":   tokHex,
			"ttl_ms":      15000,
		})
		if err := peer.send(ctx, message{T: msgPeerServeReq, D: serveReqRaw}); err != nil {
			t.Errorf("send peer_serve_req: %v", err)
			return
		}
		serveRespRaw := readTyped(t, ctx, peer, msgPeerServeResp)
		var serveResp struct {
			ID    string `json:"id"`
			OK    bool   `json:"ok"`
			Port  int    `json:"port"`
			UDPOK bool   `json:"udp_ok"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(serveRespRaw, &serveResp); err != nil || !serveResp.OK || serveResp.Port <= 0 || !serveResp.UDPOK {
			t.Errorf("unexpected peer_serve_resp: %s (%v)", string(serveRespRaw), err)
			return
		}

		// 错误令牌应无法完成双向测速握手。
		badProbe := executeProbe(ctx, probeRequest{
			ID:           "peer-bad",
			Host:         "127.0.0.1",
			Port:         serveResp.Port,
			AllowPrivate: true,
			RunTCPing:    true,
			PeerToken:    badTokHex,
			PeerUDP:      true,
			PeerSpeed:    true,
			PeerDir:      "both",
			PeerBytes:    64 << 10,
		})
		if badProbe.PeerUDP == nil || badProbe.PeerUDP.Status != "error" {
			t.Errorf("expected bad token UDP to fail, got %+v", badProbe.PeerUDP)
			return
		}
		if badProbe.PeerRecv == nil || badProbe.PeerRecv.Status != "error" {
			t.Errorf("expected bad token TCP stream to fail, got %+v", badProbe.PeerRecv)
			return
		}

		// 正确令牌执行 Ping + TCPing + UDP 往返 + 双向 512 KiB 流测速。
		goodReqRaw, _ := json.Marshal(probeRequest{
			ID:           "peer-good",
			Host:         "127.0.0.1",
			Port:         serveResp.Port,
			AllowPrivate: true,
			RunPing:      true,
			RunTCPing:    true,
			PeerToken:    tokHex,
			PeerUDP:      true,
			PeerSpeed:    true,
			PeerDir:      "both",
			PeerBytes:    512 << 10,
		})
		if err := peer.send(ctx, message{T: msgProbeReq, D: goodReqRaw}); err != nil {
			t.Errorf("send probe_req: %v", err)
			return
		}
		probeRespRaw := readTyped(t, ctx, peer, msgProbeResp)
		var pr probeResponse
		if err := json.Unmarshal(probeRespRaw, &pr); err != nil {
			t.Errorf("unmarshal probe_resp: %v", err)
			return
		}
		if pr.TCPing == nil || pr.TCPing.Status != "ok" {
			t.Errorf("tcping failed: %+v", pr.TCPing)
		}
		if pr.PeerUDP == nil || pr.PeerUDP.Status != "ok" || pr.PeerUDP.LossPct != 0 {
			t.Errorf("peer udp failed: %+v", pr.PeerUDP)
		}
		if pr.PeerSend == nil || pr.PeerSend.Status != "ok" || pr.PeerSend.Bytes != 512<<10 {
			t.Errorf("peer send failed: %+v", pr.PeerSend)
		}
		if pr.PeerRecv == nil || pr.PeerRecv.Status != "ok" || pr.PeerRecv.Bytes != 512<<10 {
			t.Errorf("peer recv failed: %+v", pr.PeerRecv)
		}

		// 验证 4 并发流 + 预热去慢启动 + 定长稳态采样 + 链内应用层 TCP RTT 探测。
		steadyProbe := executeProbe(ctx, probeRequest{
			ID:           "peer-steady-4",
			Host:         "127.0.0.1",
			Port:         serveResp.Port,
			AllowPrivate: true,
			PeerToken:    tokHex,
			PeerTCP:      true,
			PeerUDP:      true,
			PeerSpeed:    true,
			PeerDir:      "both",
			Streams:      4,
			WarmupMs:     80,
			DurationMs:   400,
		})
		if steadyProbe.PeerTCP == nil || steadyProbe.PeerTCP.Status != "ok" {
			t.Errorf("peer tcp failed: %+v", steadyProbe.PeerTCP)
		}
		if steadyProbe.PeerSend == nil || steadyProbe.PeerSend.Status != "ok" || steadyProbe.PeerSend.Streams != 4 || steadyProbe.PeerSend.Mbps <= 0 {
			t.Errorf("steady multi-stream send failed: %+v", steadyProbe.PeerSend)
		}
		if steadyProbe.PeerRecv == nil || steadyProbe.PeerRecv.Status != "ok" || steadyProbe.PeerRecv.Streams != 4 || steadyProbe.PeerRecv.Mbps <= 0 {
			t.Errorf("steady multi-stream recv failed: %+v", steadyProbe.PeerRecv)
		}

		// 发送 peer_stop 立即关闭端口。
		stopRaw, _ := json.Marshal(map[string]string{"id": "peer-srv-1"})
		_ = peer.send(ctx, message{T: msgPeerStop, D: stopRaw})
		time.Sleep(80 * time.Millisecond)
		if c, derr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(serveResp.Port)), 250*time.Millisecond); derr == nil {
			_ = c.Close()
			t.Errorf("peer port %d still open after peer_stop", serveResp.Port)
		}

		_ = peer.conn.Close(websocket.StatusNormalClosure, "done")
	})

	if err := s.serve(context.Background()); err == nil {
		t.Fatal("expected close error")
	}
}

func TestDirectPublicMultiStreamProbe(t *testing.T) {
	origGuard := probeURLGuardEnabled
	probeURLGuardEnabled = false
	t.Cleanup(func() { probeURLGuardEnabled = origGuard })

	payload := bytes.Repeat([]byte("A5Z9"), 16<<10) // 64 KiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/204" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 64; i++ {
			if _, err := w.Write(payload); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := executeProbe(ctx, probeRequest{
		ID:            "direct-pub-1",
		DirectURLTest: true,
		LatencyURL:    srv.URL + "/204",
		SpeedTest:     true,
		SpeedURL:      srv.URL + "/down",
		Streams:       4,
		WarmupMs:      80,
		DurationMs:    400,
	})
	if res.URLTest == nil || res.URLTest.Status != "ok" || res.URLTest.HTTPStatus != http.StatusNoContent {
		t.Fatalf("direct url test failed: %+v", res.URLTest)
	}
	if res.Speed == nil || res.Speed.Status != "ok" || res.Speed.Streams != 4 || res.Speed.Bytes <= 0 {
		t.Fatalf("direct multi-stream speed test failed: %+v", res.Speed)
	}
}

func TestDirectPublicSpeedFollowsCrossHostRedirectAndPeerStopClosesConns(t *testing.T) {
	origGuard := probeURLGuardEnabled
	probeURLGuardEnabled = false
	t.Cleanup(func() { probeURLGuardEnabled = origGuard })

	payload := bytes.Repeat([]byte("R3D1"), 16<<10)
	cdnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 32; i++ {
			if _, err := w.Write(payload); err != nil {
				return
			}
		}
	}))
	defer cdnSrv.Close()

	entrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/204" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, cdnSrv.URL+"/file.bin", http.StatusFound)
	}))
	defer entrySrv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := executeProbe(ctx, probeRequest{
		ID:            "direct-redir-1",
		DirectURLTest: true,
		LatencyURL:    entrySrv.URL + "/204",
		SpeedTest:     true,
		SpeedURL:      entrySrv.URL + "/go",
		Streams:       2,
		WarmupMs:      50,
		DurationMs:    400,
	})
	if res.Speed == nil || res.Speed.Status != "ok" || res.Speed.Bytes <= 0 {
		t.Fatalf("expected redirected speed test to succeed, got %+v", res.Speed)
	}

	// PeerToken 非空但 Host 为空应直接报探测目标地址为空。
	emptyRes := executeProbe(ctx, probeRequest{
		ID:        "peer-empty-host",
		PeerToken: strings.Repeat("aa", 32),
		PeerTCP:   true,
	})
	if emptyRes.Error == "" {
		t.Fatalf("expected top-level error for empty host with PeerToken, got %+v", emptyRes)
	}

	// peerServer.stop() 必须立刻关闭已接受的活跃测速连接。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var tok [32]byte
	_, _ = rand.Read(tok[:])
	ps := &peerServer{id: "stop-conn-test", token: tok, tcpLn: ln, conns: map[net.Conn]struct{}{}}
	go ps.serveTCP()
	defer ps.stop()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hdr := buildPeerTCPHeader('U', tok, 64<<20, 0)
	if _, err := c.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	readyBuf := make([]byte, len("NWDPEER_READY\n"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, readyBuf); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	ps.stop()
	_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
	one := make([]byte, 1)
	if _, err := c.Read(one); err == nil {
		t.Fatal("expected active peer connection to close immediately on stop()")
	}
}
