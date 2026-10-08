package agent

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"nowhere.local/agent/internal/keypin"
)

func testGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	gcm, err := cipher.NewGCM(mustAES(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return gcm
}

func mustAES(t *testing.T, key []byte) cipher.Block {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return block
}

func testSession(t *testing.T) *session {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	gcm := testGCM(t, key)
	return &session{gcmC2S: gcm, gcmS2C: gcm}
}

func TestChannelConstantsMatchSpec(t *testing.T) {
	if channelProtocol != "nwdock-agent-v1" || channelHKDFInfo != channelProtocol {
		t.Fatal("protocol/hkdf info constants")
	}
	if channelPath != "/api/agent/channel" {
		t.Fatal(channelPath)
	}
	for _, tc := range []struct{ got, want string }{
		{msgClientAuth, "client_auth"},
		{msgHeartbeat, "heartbeat"},
		{msgStats, "stats"},
		{msgDesiredReq, "desired_req"},
		{msgDesired, "desired"},
		{msgQuota, "quota"},
	} {
		if tc.got != tc.want {
			t.Fatalf("message type %q != %q", tc.got, tc.want)
		}
	}
	if heartbeatInterval != 15*time.Second || statsInterval != time.Minute {
		t.Fatal("intervals")
	}
	if channelCloseUnknownAgent != 4401 {
		t.Fatal("close code")
	}
}

func TestFrameNonceLayout(t *testing.T) {
	if !bytes.Equal(frameNonce(0), make([]byte, 12)) {
		t.Fatal("seq 0 nonce must be all zero")
	}
	nonce := frameNonce(1)
	if !bytes.Equal(nonce[:4], make([]byte, 4)) || nonce[11] != 1 {
		t.Fatalf("nonce layout %v", nonce)
	}
	nonce = frameNonce(1 << 40)
	if !bytes.Equal(nonce[:4], make([]byte, 4)) || nonce[6] != 1 || !bytes.Equal(nonce[7:], make([]byte, 5)) {
		t.Fatalf("big uint64be layout %v", nonce)
	}
}

func TestChannelFrameRoundTrip(t *testing.T) {
	s := testSession(t)
	first, err := s.seal([]byte(`{"t":"heartbeat","d":{"runtime":"service"}}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.seal([]byte(`{"t":"stats","d":{"counters":{"a":1}}}`))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s.open(first)
	if err != nil || !strings.Contains(string(plain), "heartbeat") {
		t.Fatalf("open first: %v %s", err, plain)
	}
	plain, err = s.open(second)
	if err != nil || !strings.Contains(string(plain), "stats") {
		t.Fatalf("open second: %v %s", err, plain)
	}
	// 重放/乱序帧的 nonce 与期望 seq 不符，必须过不了 GCM。
	if _, err := s.open(first); err == nil {
		t.Fatal("replayed frame must fail")
	}
	if _, err := s.open(second); err == nil {
		t.Fatal("reordered frame must fail")
	}
	// 篡改密文必须失败。
	fresh := testSession(t)
	sealed, err := fresh.seal([]byte(`{"t":"desired_req","d":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := fresh.open(sealed); err == nil {
		t.Fatal("tampered frame must fail")
	}
}

func TestChannelMessageEncode(t *testing.T) {
	s := testSession(t)
	body, err := json.Marshal(map[string]string{"api": "127.0.0.1:10085"})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.seal(mustJSON(t, message{T: msgDesiredReq, D: body}))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s.open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	var msg message
	if err := json.Unmarshal(plain, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.T != msgDesiredReq || !strings.Contains(string(msg.D), `"api":"127.0.0.1:10085"`) {
		t.Fatalf("msg %+v", msg)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestChannelTranscriptSpec(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	panelPub := bytes.Repeat([]byte{0x11}, 32)
	ephC := bytes.Repeat([]byte{0x22}, 32)
	ephS := bytes.Repeat([]byte{0x33}, 32)
	nonceC := bytes.Repeat([]byte{0x44}, 32)
	nonceS := bytes.Repeat([]byte{0x55}, 32)
	got := channelTranscript(fp, panelPub, ephC, ephS, nonceC, nonceS)
	concat := bytes.Join([][]byte{
		[]byte(channelProtocol), []byte(fp), panelPub, ephC, ephS, nonceC, nonceS,
	}, nil)
	want := sha256.Sum256(concat)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("transcript %x != %x", got, want[:])
	}
}

func TestNormalizeChannelURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://panel.example:8089", "wss://panel.example:8089/api/agent/channel"},
		{"https://panel.example/", "wss://panel.example/api/agent/channel"},
		{"http://10.0.0.2:8088", "ws://10.0.0.2:8088/api/agent/channel"},
		{"wss://cdn.example", "wss://cdn.example/api/agent/channel"},
		{"ws://cdn.example", "ws://cdn.example/api/agent/channel"},
		{"panel.example:8443", "wss://panel.example:8443/api/agent/channel"},
		{"  ", ""},
	} {
		if got := normalizeChannelURL(tc.in); got != tc.want {
			t.Fatalf("%q -> %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestChannelHTTPBase(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"wss://panel.example:8089/api/agent/channel", "https://panel.example:8089"},
		{"ws://10.0.0.2:8088/api/agent/channel", "http://10.0.0.2:8088"},
	} {
		if got := channelHTTPBase(tc.in); got != tc.want {
			t.Fatalf("%q -> %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnknownAgentClose(t *testing.T) {
	yes := websocket.CloseError{Code: 4401, Reason: "unknown agent"}
	if !unknownAgentClose(yes) {
		t.Fatal("4401 unknown agent must be detected")
	}
	if unknownAgentClose(websocket.CloseError{Code: 4401, Reason: "bad token"}) {
		t.Fatal("other 4401 reasons must not trigger token retry")
	}
	if unknownAgentClose(websocket.CloseError{Code: 4400, Reason: "unknown agent"}) {
		t.Fatal("wrong code must not match")
	}
	if unknownAgentClose(context.DeadlineExceeded) {
		t.Fatal("plain errors must not match")
	}
}

// serveChannelOnce 起一个按规范实现 panel 侧握手 + 首条 client_auth 解密的参考服务器。
func serveChannelOnce(t *testing.T, handler func(*websocket.Conn)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer conn.CloseNow()
		handler(conn)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestChannelHandshakeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	panelPub, panelPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var helloSeen = make(chan clientHello, 1)
	var authSeen = make(chan struct {
		Pub   string `json:"pub"`
		Sig   string `json:"sig"`
		Token string `json:"token"`
	}, 1)
	srv := serveChannelOnce(t, func(conn *websocket.Conn) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		typ, raw, err := conn.Read(ctx)
		if err != nil || typ != websocket.MessageText {
			t.Errorf("server hello read: %v", err)
			return
		}
		var hello clientHello
		if err := json.Unmarshal(raw, &hello); err != nil {
			t.Errorf("client hello: %v", err)
			return
		}
		helloSeen <- hello
		ephSrvPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Errorf("eph: %v", err)
			return
		}
		nonceS := make([]byte, 32)
		if _, err := rand.Read(nonceS); err != nil {
			t.Errorf("nonce: %v", err)
			return
		}
		ephC, err := base64.StdEncoding.DecodeString(hello.Eph)
		if err != nil {
			t.Errorf("eph b64: %v", err)
			return
		}
		nonceC, err := base64.StdEncoding.DecodeString(hello.Nonce)
		if err != nil {
			t.Errorf("nonce b64: %v", err)
			return
		}
		ephSrvPub := ephSrvPriv.PublicKey().Bytes()
		h := channelTranscript(hello.FP, panelPub, ephC, ephSrvPub, nonceC, nonceS)
		hello2, err := json.Marshal(serverHello{
			Pub:   base64.StdEncoding.EncodeToString(panelPub),
			Eph:   base64.StdEncoding.EncodeToString(ephSrvPub),
			Nonce: base64.StdEncoding.EncodeToString(nonceS),
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(panelPriv, h)),
		})
		if err != nil {
			t.Errorf("hello: %v", err)
			return
		}
		if err := conn.Write(ctx, websocket.MessageText, hello2); err != nil {
			t.Errorf("hello write: %v", err)
			return
		}
		ephCPub, err := ecdh.X25519().NewPublicKey(ephC)
		if err != nil {
			t.Errorf("eph pub: %v", err)
			return
		}
		shared, err := ephSrvPriv.ECDH(ephCPub)
		if err != nil {
			t.Errorf("ecdh: %v", err)
			return
		}
		okm, err := hkdf.Key(sha256.New, shared, h, channelHKDFInfo, 64)
		if err != nil {
			t.Errorf("hkdf: %v", err)
			return
		}
		gcmC2S := testGCM(t, okm[:32])
		gcmS2C := testGCM(t, okm[32:])
		typ, data, err := conn.Read(ctx)
		if err != nil || typ != websocket.MessageBinary {
			t.Errorf("auth read: %v", err)
			return
		}
		plain, err := gcmC2S.Open(nil, frameNonce(0), data, nil)
		if err != nil {
			t.Errorf("auth open: %v", err)
			return
		}
		var msg message
		if err := json.Unmarshal(plain, &msg); err != nil {
			t.Errorf("auth json: %v", err)
			return
		}
		if msg.T != "client_auth" {
			t.Errorf("first encrypted frame %q", msg.T)
			return
		}
		var auth struct {
			Pub   string `json:"pub"`
			Sig   string `json:"sig"`
			Token string `json:"token"`
		}
		if err := json.Unmarshal(msg.D, &auth); err != nil {
			t.Errorf("auth payload: %v", err)
			return
		}
		agentPub, err := base64.StdEncoding.DecodeString(auth.Pub)
		if err != nil {
			t.Errorf("agent pub: %v", err)
			return
		}
		agentSig, err := base64.StdEncoding.DecodeString(auth.Sig)
		if err != nil {
			t.Errorf("agent sig: %v", err)
			return
		}
		if !ed25519.Verify(agentPub, h, agentSig) {
			t.Errorf("agent signature over transcript must verify")
			return
		}
		// 回推一帧加密 desired，验证 agent 侧 open 与 seq。
		if hello.FP != keypin.Fingerprint(id.pub) {
			t.Errorf("hello fp %q", hello.FP)
		}
		authSeen <- auth
		payload := mustJSON(t, message{T: msgDesired, D: json.RawMessage(`{"generation":7,"serving":false}`)})
		sealed := gcmS2C.Seal(nil, frameNonce(0), payload, nil)
		if err := conn.Write(ctx, websocket.MessageBinary, sealed); err != nil {
			t.Errorf("desired write: %v", err)
			return
		}
		_, _, _ = conn.Read(ctx)
	})

	cfg := Config{
		Runtime:   "service",
		DataDir:   dir,
		Endpoints: []string{normalizeChannelURL(srv.URL)},
		KeyPin:    keypin.Fingerprint(panelPub),
		Token:     "install-token",
	}
	s, err := dialChannel(context.Background(), cfg, id, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.closeConn()
	select {
	case hello := <-helloSeen:
		if hello.V != 1 {
			t.Fatalf("hello v %d", hello.V)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client hello not received")
	}
	select {
	case auth := <-authSeen:
		if auth.Token != "" {
			t.Fatalf("token must be empty on first connect: %q", auth.Token)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client_auth not received")
	}
	msg, err := s.readMessage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if msg.T != msgDesired {
		t.Fatalf("frame %q", msg.T)
	}
	var payload struct {
		Generation int  `json:"generation"`
		Serving    bool `json:"serving"`
	}
	if err := json.Unmarshal(msg.D, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Generation != 7 || payload.Serving {
		t.Fatalf("payload %+v", payload)
	}
}

func TestChannelHandshakeTokenRetry(t *testing.T) {
	dir := t.TempDir()
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	panelPub, panelPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenSeen := make(chan string, 1)
	var auth struct {
		Token string `json:"token"`
	}
	srv := serveChannelOnce(t, func(conn *websocket.Conn) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, raw, err := conn.Read(ctx)
		if err != nil {
			t.Errorf("hello: %v", err)
			return
		}
		var hello clientHello
		if err := json.Unmarshal(raw, &hello); err != nil {
			t.Errorf("hello: %v", err)
			return
		}
		ephSrvPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Errorf("eph: %v", err)
			return
		}
		nonceS := make([]byte, 32)
		if _, err := rand.Read(nonceS); err != nil {
			t.Errorf("nonce: %v", err)
			return
		}
		ephC, _ := base64.StdEncoding.DecodeString(hello.Eph)
		nonceC, _ := base64.StdEncoding.DecodeString(hello.Nonce)
		h := channelTranscript(hello.FP, panelPub, ephC, ephSrvPriv.PublicKey().Bytes(), nonceC, nonceS)
		hello2, _ := json.Marshal(serverHello{
			Pub:   base64.StdEncoding.EncodeToString(panelPub),
			Eph:   base64.StdEncoding.EncodeToString(ephSrvPriv.PublicKey().Bytes()),
			Nonce: base64.StdEncoding.EncodeToString(nonceS),
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(panelPriv, h)),
		})
		if err := conn.Write(ctx, websocket.MessageText, hello2); err != nil {
			t.Errorf("hello write: %v", err)
			return
		}
		ephCPub, _ := ecdh.X25519().NewPublicKey(ephC)
		shared, err := ephSrvPriv.ECDH(ephCPub)
		if err != nil {
			t.Errorf("ecdh: %v", err)
			return
		}
		okm, err := hkdf.Key(sha256.New, shared, h, channelHKDFInfo, 64)
		if err != nil {
			t.Errorf("hkdf: %v", err)
			return
		}
		gcmC2S := testGCM(t, okm[:32])
		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Errorf("auth: %v", err)
			return
		}
		plain, err := gcmC2S.Open(nil, frameNonce(0), data, nil)
		if err != nil {
			t.Errorf("auth open: %v", err)
			return
		}
		var msg message
		if err := json.Unmarshal(plain, &msg); err != nil {
			t.Errorf("auth json: %v", err)
			return
		}
		if err := json.Unmarshal(msg.D, &auth); err != nil {
			t.Errorf("auth payload: %v", err)
			return
		}
		tokenSeen <- auth.Token
		_, _, _ = conn.Read(ctx)
	})
	cfg := Config{
		Runtime:   "service",
		DataDir:   dir,
		Endpoints: []string{normalizeChannelURL(srv.URL)},
		KeyPin:    keypin.Fingerprint(panelPub),
		Token:     "install-token",
	}
	s, err := dialChannel(context.Background(), cfg, id, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.closeConn()
	select {
	case got := <-tokenSeen:
		if got != "install-token" {
			t.Fatalf("token retry frame %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client_auth not received")
	}
}

func TestChannelHandshakePinMismatch(t *testing.T) {
	dir := t.TempDir()
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	panelPub, panelPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := serveChannelOnce(t, func(conn *websocket.Conn) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, raw, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var hello clientHello
		if err := json.Unmarshal(raw, &hello); err != nil {
			return
		}
		ephSrvPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return
		}
		nonceS := make([]byte, 32)
		_, _ = rand.Read(nonceS)
		ephC, _ := base64.StdEncoding.DecodeString(hello.Eph)
		nonceC, _ := base64.StdEncoding.DecodeString(hello.Nonce)
		h := channelTranscript(hello.FP, panelPub, ephC, ephSrvPriv.PublicKey().Bytes(), nonceC, nonceS)
		hello2, _ := json.Marshal(serverHello{
			Pub:   base64.StdEncoding.EncodeToString(panelPub),
			Eph:   base64.StdEncoding.EncodeToString(ephSrvPriv.PublicKey().Bytes()),
			Nonce: base64.StdEncoding.EncodeToString(nonceS),
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(panelPriv, h)),
		})
		_ = conn.Write(ctx, websocket.MessageText, hello2)
		_, _, _ = conn.Read(ctx)
	})
	cfg := Config{
		Runtime:   "service",
		DataDir:   dir,
		Endpoints: []string{normalizeChannelURL(srv.URL)},
		KeyPin:    strings.Repeat("0", 64),
	}
	if _, err := dialChannel(context.Background(), cfg, id, false); err == nil || !strings.Contains(err.Error(), "pin mismatch") {
		t.Fatalf("want pin mismatch, got %v", err)
	}
}

func TestChannelHandshakeBadSignature(t *testing.T) {
	dir := t.TempDir()
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	panelPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := serveChannelOnce(t, func(conn *websocket.Conn) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, raw, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var hello clientHello
		if err := json.Unmarshal(raw, &hello); err != nil {
			return
		}
		ephSrvPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return
		}
		nonceS := make([]byte, 32)
		_, _ = rand.Read(nonceS)
		ephC, _ := base64.StdEncoding.DecodeString(hello.Eph)
		nonceC, _ := base64.StdEncoding.DecodeString(hello.Nonce)
		h := channelTranscript(hello.FP, panelPub, ephC, ephSrvPriv.PublicKey().Bytes(), nonceC, nonceS)
		hello2, _ := json.Marshal(serverHello{
			Pub:   base64.StdEncoding.EncodeToString(panelPub),
			Eph:   base64.StdEncoding.EncodeToString(ephSrvPriv.PublicKey().Bytes()),
			Nonce: base64.StdEncoding.EncodeToString(nonceS),
			// 用别的密钥签名：agent 必须校验失败。
			Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(otherPriv, h)),
		})
		_ = conn.Write(ctx, websocket.MessageText, hello2)
		_, _, _ = conn.Read(ctx)
	})
	cfg := Config{
		Runtime:   "service",
		DataDir:   dir,
		Endpoints: []string{normalizeChannelURL(srv.URL)},
		KeyPin:    keypin.Fingerprint(panelPub),
	}
	if _, err := dialChannel(context.Background(), cfg, id, false); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want signature mismatch, got %v", err)
	}
}

// panelHandle 是参考面板侧的通道句柄：读 agent 帧、向 agent 写帧，双向 seq 各自从 0。
type panelHandle struct {
	conn     *websocket.Conn
	gcmC2S   cipher.AEAD
	gcmS2C   cipher.AEAD
	seqRead  uint64
	seqWrite uint64
}

func (p *panelHandle) read(ctx context.Context) (message, error) {
	typ, data, err := p.conn.Read(ctx)
	if err != nil {
		return message{}, err
	}
	if typ != websocket.MessageBinary {
		return message{}, fmt.Errorf("unexpected frame type %v", typ)
	}
	plain, err := p.gcmC2S.Open(nil, frameNonce(p.seqRead), data, nil)
	if err != nil {
		return message{}, err
	}
	p.seqRead++
	var msg message
	if err := json.Unmarshal(plain, &msg); err != nil {
		return message{}, err
	}
	return msg, nil
}

func (p *panelHandle) send(ctx context.Context, msg message) error {
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	sealed := p.gcmS2C.Seal(nil, frameNonce(p.seqWrite), raw, nil)
	p.seqWrite++
	return p.conn.Write(ctx, websocket.MessageBinary, sealed)
}

// dialWithPanel 起一个按规范实现握手的参考面板：完成握手、校验 client_auth，
// 再把 panelHandle 交给 handler（handler 在面板 goroutine 内运行，返回即关闭连接）。
// 返回 agent 会话、数据目录与面板看到的 client hello。
func dialWithPanel(t *testing.T, withToken bool, handler func(*panelHandle)) (*session, string, clientHello) {
	t.Helper()
	dir := t.TempDir()
	id, err := loadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	panelPub, panelPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		hello clientHello
		err   error
	}
	authDone := make(chan outcome, 1)
	srv := serveChannelOnce(t, func(conn *websocket.Conn) {
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, raw, err := conn.Read(ctx)
		if err != nil {
			authDone <- outcome{err: err}
			return
		}
		var hello clientHello
		if err := json.Unmarshal(raw, &hello); err != nil {
			authDone <- outcome{err: err}
			return
		}
		ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			authDone <- outcome{err: err}
			return
		}
		nonceS := make([]byte, 32)
		if _, err := rand.Read(nonceS); err != nil {
			authDone <- outcome{err: err}
			return
		}
		ephC, err := base64.StdEncoding.DecodeString(hello.Eph)
		if err != nil {
			authDone <- outcome{err: err}
			return
		}
		nonceC, err := base64.StdEncoding.DecodeString(hello.Nonce)
		if err != nil {
			authDone <- outcome{err: err}
			return
		}
		ephS := ephPriv.PublicKey().Bytes()
		h := channelTranscript(hello.FP, panelPub, ephC, ephS, nonceC, nonceS)
		hello2, err := json.Marshal(serverHello{
			Pub:   base64.StdEncoding.EncodeToString(panelPub),
			Eph:   base64.StdEncoding.EncodeToString(ephS),
			Nonce: base64.StdEncoding.EncodeToString(nonceS),
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(panelPriv, h)),
		})
		if err != nil {
			authDone <- outcome{err: err}
			return
		}
		if err := conn.Write(ctx, websocket.MessageText, hello2); err != nil {
			authDone <- outcome{err: err}
			return
		}
		ephCPub, err := ecdh.X25519().NewPublicKey(ephC)
		if err != nil {
			authDone <- outcome{err: err}
			return
		}
		shared, err := ephPriv.ECDH(ephCPub)
		if err != nil {
			authDone <- outcome{err: err}
			return
		}
		okm, err := hkdf.Key(sha256.New, shared, h, channelHKDFInfo, 64)
		if err != nil {
			authDone <- outcome{err: err}
			return
		}
		peer := &panelHandle{conn: conn, gcmC2S: testGCM(t, okm[:32]), gcmS2C: testGCM(t, okm[32:])}
		typ, data, err := conn.Read(ctx)
		if err != nil || typ != websocket.MessageBinary {
			authDone <- outcome{err: fmt.Errorf("auth frame: %v", err)}
			return
		}
		plain, err := peer.gcmC2S.Open(nil, frameNonce(peer.seqRead), data, nil)
		if err != nil {
			authDone <- outcome{err: err}
			return
		}
		peer.seqRead++
		var msg message
		if err := json.Unmarshal(plain, &msg); err != nil {
			authDone <- outcome{err: err}
			return
		}
		if msg.T != "client_auth" {
			authDone <- outcome{err: fmt.Errorf("first frame %q", msg.T)}
			return
		}
		var auth struct {
			Pub   string `json:"pub"`
			Sig   string `json:"sig"`
			Token string `json:"token"`
		}
		if err := json.Unmarshal(msg.D, &auth); err != nil {
			authDone <- outcome{err: err}
			return
		}
		agentPub, err := base64.StdEncoding.DecodeString(auth.Pub)
		if err != nil {
			authDone <- outcome{err: err}
			return
		}
		agentSig, err := base64.StdEncoding.DecodeString(auth.Sig)
		if err != nil {
			authDone <- outcome{err: err}
			return
		}
		if !ed25519.Verify(agentPub, h, agentSig) {
			authDone <- outcome{err: errors.New("agent signature mismatch")}
			return
		}
		authDone <- outcome{hello: hello}
		handler(peer)
	})
	cfg := Config{
		Runtime:   "service",
		DataDir:   dir,
		Endpoints: []string{normalizeChannelURL(srv.URL)},
		KeyPin:    keypin.Fingerprint(panelPub),
		Token:     "install-token",
	}
	s, err := dialChannel(context.Background(), cfg, id, withToken)
	if err != nil {
		t.Fatal(err)
	}
	var got clientHello
	select {
	case res := <-authDone:
		if res.err != nil {
			t.Fatalf("panel handshake: %v", res.err)
		}
		got = res.hello
	case <-time.After(5 * time.Second):
		t.Fatal("panel handshake timeout")
	}
	return s, dir, got
}

func TestChannelServeAppliesDesired(t *testing.T) {
	s, dir, _ := dialWithPanel(t, false, func(peer *panelHandle) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := peer.read(ctx)
		if err != nil {
			t.Errorf("desired_req: %v", err)
			return
		}
		if req.T != "desired_req" {
			t.Errorf("first frame %q", req.T)
			return
		}
		var api struct {
			API string `json:"api"`
		}
		if err := json.Unmarshal(req.D, &api); err != nil {
			t.Errorf("desired_req payload: %v", err)
			return
		}
		if api.API != "127.0.0.1:10085" {
			t.Errorf("api %q", api.API)
			return
		}
		payload := json.RawMessage(`{"generation":42,"serving":false}`)
		if err := peer.send(ctx, message{T: msgDesired, D: payload}); err != nil {
			t.Errorf("desired push: %v", err)
			return
		}
		// 给 agent 应用时间后关连接，serve 必须返回错误。
		time.Sleep(200 * time.Millisecond)
		_ = peer.conn.Close(websocket.StatusNormalClosure, "done")
	})
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.serve(context.Background()) }()
	select {
	case err := <-serveErr:
		if err == nil {
			t.Fatal("serve must return an error on close")
		}
		t.Logf("serve err: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return")
	}
	gen, err := os.ReadFile(filepath.Join(dir, "applied-generation"))
	if err != nil {
		t.Fatal(err)
	}
	if string(gen) != "42" {
		t.Fatalf("applied generation %q", gen)
	}
	if summary := errorSummary(); summary != "" {
		t.Fatalf("error summary %q", summary)
	}
}

func TestChannelMessageShapes(t *testing.T) {
	s, _, _ := dialWithPanel(t, false, func(peer *panelHandle) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		seen := map[string]map[string]any{}
		for i := 0; i < 3; i++ {
			msg, err := peer.read(ctx)
			if err != nil {
				t.Errorf("frame %d: %v", i, err)
				return
			}
			var payload map[string]any
			if err := json.Unmarshal(msg.D, &payload); err != nil {
				t.Errorf("frame %q payload: %v", msg.T, err)
				return
			}
			seen[msg.T] = payload
		}
		req, ok := seen["desired_req"]
		if !ok {
			t.Fatalf("frames %v", seen)
		}
		if got := req["api"]; got != "127.0.0.1:10085" {
			t.Fatalf("desired_req %v", req)
		}
		beat, ok := seen["heartbeat"]
		if !ok {
			t.Fatalf("frames %v", seen)
		}
		for _, key := range []string{"runtime", "version", "core", "core_version", "generation", "error", "image"} {
			if _, ok := beat[key]; !ok {
				t.Fatalf("heartbeat missing %q: %v", key, beat)
			}
		}
		if _, ok := beat["cert_not_after"]; ok {
			t.Fatal("cert_not_after must be gone")
		}
		if beat["runtime"] != "service" || beat["version"] != Version {
			t.Fatalf("heartbeat %v", beat)
		}
		stats, ok := seen["stats"]
		if !ok {
			t.Fatalf("frames %v", seen)
		}
		counters, ok := stats["counters"].(map[string]any)
		if !ok || counters["inbound>>>api"] != float64(3) {
			t.Fatalf("stats %v", stats)
		}
		_ = peer.conn.Close(websocket.StatusNormalClosure, "done")
	})
	if err := s.requestDesired(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.sendHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"counters": map[string]int64{"inbound>>>api": 3}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.send(context.Background(), message{T: msgStats, D: body}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
}
