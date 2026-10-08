package agent

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"nowhere.local/agent/internal/keypin"
)

// nwdock-agent-v1 线格式。字段名、常量与派生必须与 panel 侧逐字一致，任何偏离都是 bug。
const (
	channelProtocol     = "nwdock-agent-v1"
	channelHKDFInfo     = "nwdock-agent-v1"
	channelPath         = "/api/agent/channel"
	channelReadLimit    = 16 << 20
	channelDialTimeout  = 30 * time.Second
	channelWriteTimeout = 30 * time.Second
	channelPingTimeout  = 20 * time.Second
	heartbeatInterval   = 15 * time.Second
	statsInterval       = time.Minute
)

// 面板以 close 4401 + reason 拒绝 client_auth；reason 为 unknown agent 时带安装令牌重试一次。
const channelCloseUnknownAgent = 4401

const (
	msgClientAuth = "client_auth"
	msgHeartbeat  = "heartbeat"
	msgStats      = "stats"
	msgDesiredReq = "desired_req"
	msgDesired    = "desired"
	msgQuota      = "quota"
)

// message 是握手后每个 binary 帧的明文：紧凑 JSON {"t":"<type>","d":<任意 JSON>}。
type message struct {
	T string          `json:"t"`
	D json.RawMessage `json:"d"`
}

type clientHello struct {
	V     int    `json:"v"`
	FP    string `json:"fp"`
	Eph   string `json:"eph"`
	Nonce string `json:"nonce"`
}

type serverHello struct {
	Pub   string `json:"pub"`
	Eph   string `json:"eph"`
	Nonce string `json:"nonce"`
	Sig   string `json:"sig"`
}

type inboxFrame struct {
	msg message
	err error
}

// session 是一条已握手的加密通道。写由 writeMu 串行化，读由 serve 内的单一 reader goroutine 驱动。
type session struct {
	cfg  Config
	conn *websocket.Conn

	gcmC2S cipher.AEAD
	gcmS2C cipher.AEAD

	writeMu sync.Mutex
	seqC2S  uint64
	seqS2C  uint64
}

// normalizeChannelURL 把 AGENT_PANEL_ENDPOINTS 的一项归一化成 ws(s)://host[:port]/api/agent/channel。
// https→wss、http→ws；wss/ws 直接拼路径；不带 scheme 的按 https 处理。
func normalizeChannelURL(raw string) string {
	endpoint := strings.TrimRight(strings.TrimSpace(raw), "/")
	switch {
	case endpoint == "":
		return ""
	case strings.HasPrefix(endpoint, "wss://"), strings.HasPrefix(endpoint, "ws://"):
		return endpoint + channelPath
	case strings.HasPrefix(endpoint, "https://"):
		return "wss://" + endpoint[len("https://"):] + channelPath
	case strings.HasPrefix(endpoint, "http://"):
		return "ws://" + endpoint[len("http://"):] + channelPath
	default:
		return "wss://" + endpoint + channelPath
	}
}

// channelHTTPBase 取文件下载（Authorization: AgentFile）用的 http(s) 基址，与 WS 端点同主机。
func channelHTTPBase(wsURL string) string {
	base := strings.TrimSuffix(wsURL, channelPath)
	switch {
	case strings.HasPrefix(base, "wss://"):
		return "https://" + base[len("wss://"):]
	case strings.HasPrefix(base, "ws://"):
		return "http://" + base[len("ws://"):]
	}
	return base
}

// frameNonce：0x00×4 ‖ uint64be(seq)，无 AAD。
func frameNonce(seq uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

func (s *session) seal(plaintext []byte) ([]byte, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	nonce := frameNonce(s.seqC2S)
	s.seqC2S++
	return s.gcmC2S.Seal(nil, nonce, plaintext, nil), nil
}

// open 用期望 seq 推 nonce：乱序或重放的帧过不了 GCM 认证。
func (s *session) open(ciphertext []byte) ([]byte, error) {
	nonce := frameNonce(s.seqS2C)
	plain, err := s.gcmS2C.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	s.seqS2C++
	return plain, nil
}

func (s *session) send(ctx context.Context, msg message) error {
	plain, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	sealed, err := s.seal(plain)
	if err != nil {
		return err
	}
	// 写超时即视为连接坏死：库会在 ctx 到期时关闭连接，上层走退避重连。
	writeCtx, cancel := context.WithTimeout(ctx, channelWriteTimeout)
	defer cancel()
	return s.conn.Write(writeCtx, websocket.MessageBinary, sealed)
}

func (s *session) readMessage(ctx context.Context) (message, error) {
	typ, data, err := s.conn.Read(ctx)
	if err != nil {
		return message{}, err
	}
	if typ != websocket.MessageBinary {
		return message{}, fmt.Errorf("channel: frame type %v", typ)
	}
	plain, err := s.open(data)
	if err != nil {
		return message{}, err
	}
	var msg message
	if err := json.Unmarshal(plain, &msg); err != nil {
		return message{}, err
	}
	return msg, nil
}

func (s *session) requestDesired(ctx context.Context) error {
	body, err := json.Marshal(map[string]string{"api": coreAPIAddr()})
	if err != nil {
		return err
	}
	return s.send(ctx, message{T: msgDesiredReq, D: body})
}

func (s *session) sendHeartbeat(ctx context.Context) error {
	core, coreVersion := runningCoreInfo()
	body, err := json.Marshal(map[string]any{
		"runtime":      s.cfg.Runtime,
		"version":      Version,
		"core":         string(core),
		"core_version": coreVersion,
		"generation":   appliedGeneration(s.cfg.DataDir),
		"error":        errorSummary(),
		"image":        s.cfg.Image,
	})
	if err != nil {
		return err
	}
	return s.send(ctx, message{T: msgHeartbeat, D: body})
}

func (s *session) ping(ctx context.Context) error {
	pingCtx, cancel := context.WithTimeout(ctx, channelPingTimeout)
	defer cancel()
	if err := s.conn.Ping(pingCtx); err != nil {
		return fmt.Errorf("channel ping: %w", err)
	}
	return nil
}

func (s *session) closeConn() {
	_ = s.conn.CloseNow()
}

// serve 驱动整条会话：先上报用量再要 desired（失联期间的字节先入账），
// 15s 心跳 + 保活 ping，60s stats，低水位时立刻再报一次。
// 收到 desired 或 quota 即应用。返回即连接断开，由 Run 走退避重连。
func (s *session) serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, s.closeConn)
	defer stop()
	defer s.closeConn()
	traffic.setConnected(true)
	defer traffic.setConnected(false)

	// 先把上一轮还没入账的用量送出，面板再开新的预支轮次。
	if err := reportStats(ctx, s); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	if err := s.requestDesired(ctx); err != nil {
		return err
	}
	inbox := make(chan inboxFrame, 8)
	readerCtx, cancelReader := context.WithCancel(ctx)
	defer cancelReader()
	go func() {
		for {
			msg, err := s.readMessage(readerCtx)
			select {
			case inbox <- inboxFrame{msg: msg, err: err}:
			case <-readerCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	var lastStats time.Time
	gotDesired := false
	retryDesired := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-traffic.wake:
			lastStats = time.Now()
			if err := reportStats(ctx, s); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
			}
		case <-heartbeat.C:
			if err := s.sendHeartbeat(ctx); err != nil {
				return err
			}
			if !gotDesired || retryDesired {
				if err := s.requestDesired(ctx); err != nil {
					return err
				}
			}
			if err := s.ping(ctx); err != nil {
				return err
			}
			if core, _ := runningCoreInfo(); core != "" && time.Since(lastStats) >= statsInterval {
				lastStats = time.Now()
				if err := reportStats(ctx, s); err != nil {
					fmt.Fprintln(os.Stderr, err.Error())
				}
			}
		case frame := <-inbox:
			if frame.err != nil {
				return frame.err
			}
			switch frame.msg.T {
			case msgQuota:
				if err := traffic.ApplySnapshot(frame.msg.D); err != nil {
					fmt.Fprintln(os.Stderr, err.Error())
				}
			case msgDesired:
				gotDesired = true
				if err := s.applyDesired(ctx, frame.msg.D); err != nil {
					setError(err)
					fmt.Fprintln(os.Stderr, err.Error())
					retryDesired = true
					continue
				}
				setError(nil)
				retryDesired = false
			}
		}
	}
}

// dialChannel 完成 WS 拨号与 nwdock-agent-v1 握手，首条加密帧带 client_auth。
// withToken 为 true 时在 client_auth 里带安装令牌（仅面板提示指纹未绑定后重试一次）。
func dialChannel(ctx context.Context, cfg Config, id *identity, withToken bool) (*session, error) {
	dialCtx, cancel := context.WithTimeout(ctx, channelDialTimeout)
	defer cancel()
	conn, res, err := websocket.Dial(dialCtx, cfg.Endpoints[0], nil)
	if err != nil {
		if res != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
			_ = res.Body.Close()
		}
		return nil, fmt.Errorf("channel dial %s: %w", cfg.Endpoints[0], err)
	}
	fp := keypin.Fingerprint(id.pub)
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	nonceC := make([]byte, 32)
	if _, err := rand.Read(nonceC); err != nil {
		conn.CloseNow()
		return nil, err
	}
	hello, err := json.Marshal(clientHello{
		V:     1,
		FP:    fp,
		Eph:   base64.StdEncoding.EncodeToString(ephPriv.PublicKey().Bytes()),
		Nonce: base64.StdEncoding.EncodeToString(nonceC),
	})
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	if err := conn.Write(dialCtx, websocket.MessageText, hello); err != nil {
		conn.CloseNow()
		return nil, fmt.Errorf("channel hello: %w", err)
	}
	typ, raw, err := conn.Read(dialCtx)
	if err != nil {
		conn.CloseNow()
		return nil, fmt.Errorf("channel hello: %w", err)
	}
	if typ != websocket.MessageText {
		conn.CloseNow()
		return nil, fmt.Errorf("channel: server hello frame type %v", typ)
	}
	var srv serverHello
	if err := json.Unmarshal(raw, &srv); err != nil {
		conn.CloseNow()
		return nil, fmt.Errorf("channel hello: %w", err)
	}
	panelPub, err := channelB64("pub", srv.Pub, 32)
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	ephS, err := channelB64("eph", srv.Eph, 32)
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	nonceS, err := channelB64("nonce", srv.Nonce, 32)
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	sig, err := channelB64("sig", srv.Sig, 64)
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	if err := keypin.Match(panelPub, cfg.KeyPin); err != nil {
		conn.CloseNow()
		return nil, err
	}
	ephC := ephPriv.PublicKey().Bytes()
	h := channelTranscript(fp, panelPub, ephC, ephS, nonceC, nonceS)
	if !ed25519.Verify(panelPub, h, sig) {
		conn.CloseNow()
		return nil, errors.New("channel: panel signature mismatch")
	}
	ephSrv, err := ecdh.X25519().NewPublicKey(ephS)
	if err != nil {
		conn.CloseNow()
		return nil, fmt.Errorf("channel hello: eph: %w", err)
	}
	shared, err := ephPriv.ECDH(ephSrv)
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	okm, err := hkdf.Key(sha256.New, shared, h, channelHKDFInfo, 64)
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	blockC2S, err := aes.NewCipher(okm[:32])
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	blockS2C, err := aes.NewCipher(okm[32:])
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	gcmC2S, err := cipher.NewGCM(blockC2S)
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	gcmS2C, err := cipher.NewGCM(blockS2C)
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	s := &session{cfg: cfg, conn: conn, gcmC2S: gcmC2S, gcmS2C: gcmS2C}
	conn.SetReadLimit(channelReadLimit)
	token := ""
	if withToken {
		token = cfg.Token
	}
	auth, err := json.Marshal(map[string]string{
		"pub":   base64.StdEncoding.EncodeToString(id.pub),
		"sig":   base64.StdEncoding.EncodeToString(ed25519.Sign(id.priv, h)),
		"token": token,
	})
	if err != nil {
		conn.CloseNow()
		return nil, err
	}
	if err := s.send(dialCtx, message{T: msgClientAuth, D: auth}); err != nil {
		conn.CloseNow()
		return nil, fmt.Errorf("channel auth: %w", err)
	}
	return s, nil
}

func channelB64(field, value string, want int) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("channel hello: %s: %w", field, err)
	}
	if len(raw) != want {
		return nil, fmt.Errorf("channel hello: %s must be %d bytes, got %d", field, want, len(raw))
	}
	return raw, nil
}

// channelTranscript：SHA256("nwdock-agent-v1" ‖ fp_ascii(64) ‖ panel_pub(32) ‖ eph_c(32) ‖ eph_s(32) ‖ nonce_c(32) ‖ nonce_s(32))。
func channelTranscript(fp string, panelPub, ephC, ephS, nonceC, nonceS []byte) []byte {
	h := sha256.New()
	h.Write([]byte(channelProtocol))
	h.Write([]byte(fp))
	h.Write(panelPub)
	h.Write(ephC)
	h.Write(ephS)
	h.Write(nonceC)
	h.Write(nonceS)
	return h.Sum(nil)
}

// unknownAgentClose 判断断开是否面板对 client_auth 的拒绝：close 4401 且 reason 提示指纹未绑定。
func unknownAgentClose(err error) bool {
	var closed websocket.CloseError
	if !errors.As(err, &closed) {
		return false
	}
	return closed.Code == channelCloseUnknownAgent &&
		strings.Contains(strings.ToLower(closed.Reason), "unknown agent")
}
