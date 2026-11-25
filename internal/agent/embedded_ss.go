package agent

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/sockopt"
	C "github.com/metacubex/mihomo/constant"
	IN "github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	shadowsocks "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

// ssServiceGen 是一代只读的多用户 Shadowsocks 服务快照。
// sing-shadowsocks 的 MultiService.UpdateUsers 内部 map 无互斥锁，构造完成后发布到
// atomic.Pointer 只读不改，彻底规避并发收包与热更用户表之间的数据竞争。
type ssServiceGen struct {
	ctx     context.Context
	cancel  context.CancelFunc
	service shadowsocks.MultiService[string]
	users   map[string]string
}

type keptSSGen struct {
	cancel context.CancelFunc
	timer  *time.Timer
}

// ssTrackingHandler 包装 sing.ListenerHandler，把不经 HandleTCPConn 的特殊连接
// （如 Shadowsocks UoT / sing-mux）按 (inbound, user) 纳入 traffic.live 追踪，
// 确保吊销/超额/改密或关闭监听时立刻断开存量 UoT/Mux 会话。
type ssTrackingHandler struct {
	*sing.ListenerHandler
	owner *embeddedSSListener
}

func (h *ssTrackingHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	if h.ListenerHandler.IsSpecialFqdn(metadata.Destination.Fqdn) {
		user, _ := auth.UserFromContext[string](ctx)
		name := h.owner.Name()
		traffic.track(conn, name, user)
		defer traffic.detach(conn)
		if h.owner.closed.Load() || ctx.Err() != nil {
			_ = conn.Close()
			return net.ErrClosed
		}
		if cur := h.owner.gen.Load(); cur == nil || cur.users[user] == "" {
			_ = conn.Close()
			return net.ErrClosed
		}
	}
	return h.ListenerHandler.NewConnection(ctx, conn, metadata)
}

// embeddedSSListener 在不修改上游 clash-meta-nw 的前提下，基于依赖树内已有的
// sing-shadowsocks MultiService 托管单端口多用户 Shadowsocks（含经典 AEAD、2022、UDP 与 UoT）。
type embeddedSSListener struct {
	*IN.Base
	config  *IN.ShadowSocksOption
	tunnel  C.Tunnel
	handler *ssTrackingHandler

	gen    atomic.Pointer[ssServiceGen]
	closed atomic.Bool

	mu           sync.Mutex
	tcpListeners []net.Listener
	udpListeners []net.PacketConn
	keptSeq      uint64
	keptGens     map[uint64]*keptSSGen
}

var _ C.InboundListener = (*embeddedSSListener)(nil)

func newEmbeddedSSListener(opt *IN.ShadowSocksOption, users []sharedUser) (*embeddedSSListener, error) {
	if opt == nil {
		return nil, errors.New("nil shadowsocks option")
	}
	cp := *opt
	cp.Users = maps.Clone(opt.Users)
	base, err := IN.NewBase(&cp.BaseOption)
	if err != nil {
		return nil, err
	}
	l := &embeddedSSListener{
		Base:     base,
		config:   &cp,
		tunnel:   meterTunnel{},
		keptGens: map[uint64]*keptSSGen{},
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    l.tunnel,
		Type:      C.SHADOWSOCKS,
		Additions: base.Additions(),
		MuxOption: cp.MuxOption.Build(),
	})
	if err != nil {
		return nil, err
	}
	l.handler = &ssTrackingHandler{ListenerHandler: h, owner: l}
	gen, err := l.buildGen(users)
	if err != nil {
		return nil, err
	}
	l.gen.Store(gen)
	return l, nil
}

func (l *embeddedSSListener) buildGen(users []sharedUser) (*ssServiceGen, error) {
	udpTimeout := int64(sing.UDPTimeout.Seconds())
	userList := make([]string, 0, len(users))
	passList := make([]string, 0, len(users))
	userMap := make(map[string]string, len(users))
	for _, u := range users {
		if u.Email == "" || u.Secret == "" {
			return nil, errors.New("shadowsocks shared user email and secret are required")
		}
		if _, dup := userMap[u.Email]; dup {
			continue
		}
		userMap[u.Email] = u.Secret
		userList = append(userList, u.Email)
		passList = append(passList, u.Secret)
	}

	cipher := l.config.Cipher
	var svc shadowsocks.MultiService[string]
	switch {
	case common.Contains(shadowaead.List, cipher):
		ms, err := shadowaead.NewMultiService[string](cipher, udpTimeout, l.handler)
		if err != nil {
			return nil, err
		}
		if err := ms.UpdateUsersWithPasswords(userList, passList); err != nil {
			return nil, err
		}
		svc = ms
	case common.Contains(shadowaead_2022.List, cipher):
		ms, err := shadowaead_2022.NewMultiServiceWithPassword[string](cipher, l.config.Password, udpTimeout, l.handler, ntp.Now)
		if err != nil {
			if errors.Is(err, os.ErrInvalid) {
				return nil, fmt.Errorf("shadowsocks: unsupported multi-user cipher %q", cipher)
			}
			return nil, err
		}
		if err := ms.UpdateUsersWithPasswords(userList, passList); err != nil {
			return nil, err
		}
		svc = ms
	default:
		return nil, fmt.Errorf("shadowsocks: unsupported multi-user cipher %q", cipher)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &ssServiceGen{
		ctx:     ctx,
		cancel:  cancel,
		service: svc,
		users:   userMap,
	}, nil
}

func (l *embeddedSSListener) Config() C.InboundConfig {
	return l.config
}

func (l *embeddedSSListener) Address() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var addrs []string
	for _, lis := range l.tcpListeners {
		addrs = append(addrs, lis.Addr().String())
	}
	for _, pc := range l.udpListeners {
		addrs = append(addrs, pc.LocalAddr().String())
	}
	return strings.Join(addrs, ",")
}

// UpdateUsers 原地热更共享监听的用户表，不关闭底层 TCP/UDP 监听端口。
// 返回被移除或轮换了密钥的用户集合，供调用方只掐断这些用户的存量连接。
func (l *embeddedSSListener) UpdateUsers(users []sharedUser) (map[string]bool, error) {
	prev := l.gen.Load()
	if prev != nil && sameSSUsers(prev.users, users) {
		return nil, nil
	}
	next, err := l.buildGen(users)
	if err != nil {
		return nil, err
	}
	dropped := map[string]bool{}
	if prev != nil {
		for email, oldSecret := range prev.users {
			if newSecret, ok := next.users[email]; !ok || newSecret != oldSecret {
				dropped[email] = true
			}
		}
	}
	old := l.gen.Swap(next)
	if old != nil {
		if len(dropped) > 0 {
			// 有用户被吊销或改密：立即取消直接上一代及所有历史滞留代，释放全部旧 udpnat 会话。
			l.drainKeptGens()
			old.cancel()
		} else {
			// 仅新增用户：保留上一代上下文至 NAT 超时自然排空（或监听器关闭/后续吊销），存量 UDP 会话零抖动。
			l.keepGenUntilIdle(old.cancel)
		}
	}
	return dropped, nil
}

func (l *embeddedSSListener) keepGenUntilIdle(cancel context.CancelFunc) {
	l.mu.Lock()
	if l.closed.Load() {
		l.mu.Unlock()
		cancel()
		return
	}
	l.keptSeq++
	seq := l.keptSeq
	entry := &keptSSGen{cancel: cancel}
	entry.timer = time.AfterFunc(sing.UDPTimeout+5*time.Second, func() {
		l.mu.Lock()
		cur := l.keptGens[seq]
		if cur != nil {
			delete(l.keptGens, seq)
		}
		l.mu.Unlock()
		if cur != nil {
			cur.cancel()
		}
	})
	l.keptGens[seq] = entry
	l.mu.Unlock()
}

func (l *embeddedSSListener) drainKeptGens() {
	l.mu.Lock()
	if len(l.keptGens) == 0 {
		l.mu.Unlock()
		return
	}
	entries := make([]*keptSSGen, 0, len(l.keptGens))
	for seq, entry := range l.keptGens {
		entries = append(entries, entry)
		delete(l.keptGens, seq)
	}
	l.mu.Unlock()
	for _, entry := range entries {
		if entry.timer != nil {
			entry.timer.Stop()
		}
		entry.cancel()
	}
}

func sameSSUsers(have map[string]string, want []sharedUser) bool {
	seen := make(map[string]struct{}, len(want))
	for _, u := range want {
		if _, dup := seen[u.Email]; dup {
			continue
		}
		secret, ok := have[u.Email]
		if !ok || secret != u.Secret {
			return false
		}
		seen[u.Email] = struct{}{}
	}
	return len(seen) == len(have)
}

func (l *embeddedSSListener) Listen(tunnel C.Tunnel) error {
	if tunnel != nil && tunnel != l.tunnel {
		h, err := sing.NewListenerHandler(sing.ListenerConfig{
			Tunnel:    tunnel,
			Type:      C.SHADOWSOCKS,
			Additions: l.Additions(),
			MuxOption: l.config.MuxOption.Build(),
		})
		if err != nil {
			return err
		}
		l.tunnel = tunnel
		l.handler = &ssTrackingHandler{ListenerHandler: h, owner: l}
		prev := l.gen.Load()
		var users []sharedUser
		if prev != nil {
			for email, secret := range prev.users {
				users = append(users, sharedUser{Email: email, Secret: secret})
			}
			prev.cancel()
		}
		next, err := l.buildGen(users)
		if err != nil {
			return err
		}
		l.gen.Store(next)
	}

	lc := l.ListenConfig()
	success := false
	defer func() {
		if !success {
			_ = l.Close()
		}
	}()

	for _, addr := range strings.Split(l.RawAddress(), ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if l.config.UDP {
			ul, err := lc.ListenPacket(context.Background(), "udp", addr)
			if err != nil {
				return err
			}
			if err := sockopt.UDPReuseaddr(ul); err != nil {
				log.Warnln("Failed to Reuse UDP Address: %s", err)
			}
			l.mu.Lock()
			l.udpListeners = append(l.udpListeners, ul)
			l.mu.Unlock()
			go l.serveUDP(ul)
		}

		tl, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return err
		}
		l.mu.Lock()
		l.tcpListeners = append(l.tcpListeners, tl)
		l.mu.Unlock()
		go l.serveTCP(tl)
	}

	success = true
	log.Infoln("ShadowSocks[%s] multi-user proxy listening at: %s", l.Name(), l.Address())
	return nil
}

func (l *embeddedSSListener) serveTCP(tl net.Listener) {
	for {
		c, err := tl.Accept()
		if err != nil {
			if l.closed.Load() {
				return
			}
			continue
		}
		go l.handleConn(c)
	}
}

func (l *embeddedSSListener) handleConn(conn net.Conn) {
	gen := l.gen.Load()
	if gen == nil {
		_ = conn.Close()
		return
	}
	err := gen.service.NewConnection(gen.ctx, conn, M.Metadata{
		Protocol: "shadowsocks",
		Source:   M.SocksaddrFromNet(conn.RemoteAddr()),
	})
	if err != nil {
		_ = conn.Close()
	}
}

func (l *embeddedSSListener) serveUDP(ul net.PacketConn) {
	conn := bufio.NewPacketConn(ul)
	gen0 := l.gen.Load()
	if gen0 == nil {
		return
	}
	rwOptions := network.NewReadWaitOptions(conn, gen0.service)
	readWaiter, isReadWaiter := bufio.CreatePacketReadWaiter(conn)
	if isReadWaiter {
		readWaiter.InitializeReadWaiter(rwOptions)
	}
	inAddr := ul.LocalAddr()
	for {
		var (
			buff *buf.Buffer
			dest M.Socksaddr
			err  error
		)
		if isReadWaiter {
			buff, dest, err = readWaiter.WaitReadPacket()
		} else {
			buff = rwOptions.NewPacketBuffer()
			dest, err = conn.ReadPacket(buff)
			if buff != nil {
				rwOptions.PostReturn(buff)
			}
		}
		if err != nil {
			if buff != nil {
				buff.Release()
			}
			if l.closed.Load() {
				return
			}
			continue
		}
		gen := l.gen.Load()
		if gen == nil {
			buff.Release()
			continue
		}
		ctx := sing.WithInAddr(gen.ctx, inAddr)
		if err := gen.service.NewPacket(ctx, conn, buff, M.Metadata{
			Protocol: "shadowsocks",
			Source:   dest,
		}); err != nil {
			buff.Release()
		}
	}
}

func (l *embeddedSSListener) Close() error {
	l.closed.Store(true)
	if cur := l.gen.Load(); cur != nil {
		cur.cancel()
	}
	l.drainKeptGens()
	l.mu.Lock()
	tcps := l.tcpListeners
	l.tcpListeners = nil
	udps := l.udpListeners
	l.udpListeners = nil
	l.mu.Unlock()

	var retErr error
	for _, lis := range tcps {
		if err := lis.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = err
		}
	}
	for _, pc := range udps {
		if err := pc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = err
		}
	}
	return retErr
}
