package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/observable"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	IN "github.com/metacubex/mihomo/listener/inbound"
	mihomolog "github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

const (
	embedBindRetryBudget = 500 * time.Millisecond
	relayBindRetryBudget = 500 * time.Millisecond
)

var bindRetryDelays = []time.Duration{
	10 * time.Millisecond,
	20 * time.Millisecond,
	40 * time.Millisecond,
	80 * time.Millisecond,
	100 * time.Millisecond,
}

func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "address already in use")
}

// retryOnAddrInUse 在端口刚释放出现瞬时 EADDRINUSE 时做有界退避重试；
// 预算耗尽或遇到非占用错误立即返回，避免误配大量冲突端口时拖慢整批应用。
func retryOnAddrInUse(budget *time.Duration, fn func() error) error {
	err := fn()
	if err == nil || budget == nil || *budget <= 0 || !isAddrInUse(err) {
		return err
	}
	for _, d := range bindRetryDelays {
		if *budget <= 0 {
			break
		}
		wait := d
		if wait > *budget {
			wait = *budget
		}
		*budget -= wait
		time.Sleep(wait)
		err = fn()
		if err == nil || !isAddrInUse(err) {
			return err
		}
	}
	return err
}

func listenInboundWithRetry(build func() (C.InboundListener, error), budget *time.Duration) (C.InboundListener, error) {
	var opened C.InboundListener
	err := retryOnAddrInUse(budget, func() error {
		lis, err := build()
		if err != nil {
			return err
		}
		if err := lis.Listen(meterTunnel{}); err != nil {
			closeInboundListener(lis)
			return err
		}
		opened = lis
		return nil
	})
	if err != nil {
		return nil, err
	}
	return opened, nil
}

// embeddedRuntime 把 clash-meta-nw 跑在 agent 进程里。监听器由本进程持有，
// 交给 meterTunnel 计数；出站、规则和 DNS 仍由 executor.ApplyConfig 更新。
type embeddedRuntime struct {
	version   string
	running   atomic.Bool
	listeners map[string]C.InboundListener
	logSub    observable.Subscription[mihomolog.Event]
}

func newEmbeddedRuntime() *embeddedRuntime {
	return &embeddedRuntime{
		version:   C.Version,
		listeners: map[string]C.InboundListener{},
	}
}

func (e *embeddedRuntime) Kind() coreKind { return coreMihomo }

func (e *embeddedRuntime) Version() string {
	if e.version == "" {
		return C.Version
	}
	return e.version
}

func (e *embeddedRuntime) Running() bool { return e.running.Load() }

func (e *embeddedRuntime) Test(_ context.Context, configPath, dir string) error {
	C.SetHomeDir(dir)
	cfg, err := parseMihomoFile(configPath)
	if err != nil {
		return err
	}
	return cfg.Close()
}

func (e *embeddedRuntime) Start(ctx context.Context, configPath, dir string) error {
	return e.StartShared(ctx, configPath, dir, nil)
}

func (e *embeddedRuntime) StartShared(ctx context.Context, configPath, dir string, shared []sharedDesired) error {
	// mihomo 自身仍打印到 stdout；这里订阅 observable 只是把事件收入日志环供面板查看。
	if e.logSub != nil {
		mihomolog.UnSubscribe(e.logSub)
		e.logSub = nil
	}
	e.logSub = mihomolog.Subscribe()
	go e.captureLogs(e.logSub)
	if err := e.Apply(ctx, configPath, dir, nil, "", shared, true, false); err != nil {
		e.Stop()
		return err
	}
	return nil
}

// captureLogs 消费 mihomo 日志事件入环；UnSubscribe 关闭通道后函数退出。
func (e *embeddedRuntime) captureLogs(sub observable.Subscription[mihomolog.Event]) {
	for ev := range sub {
		logs.append(time.Now(), string(coreMihomo), mihomologLevel(ev.LogLevel), ev.Payload)
	}
}

// mihomologLevel 把 mihomo 的级别映射成与面板一致的词汇。
func mihomologLevel(level mihomolog.LogLevel) string {
	switch level.String() {
	case "debug", "info", "warning", "error":
		return level.String()
	default:
		return "info"
	}
}

// ApplySharedOnly 在核心配置、证书与 geo 均未变化时，尝试仅原地热更已运行的
// 共享 Shadowsocks 多用户监听器；不触碰 config.Parse / executor.ApplyConfig，
// 避免仅转发/入口变更或 SS 用户增删时引发整核堆峰与既有出站断连。
func (e *embeddedRuntime) ApplySharedOnly(shared []sharedDesired) bool {
	if !e.running.Load() {
		return false
	}
	sharedSS := make(map[string]sharedDesired, len(shared))
	for _, item := range shared {
		if item.Protocol == "shadowsocks" && item.Tag != "" {
			sharedSS[item.Tag] = item
		}
	}
	activeSSCount := 0
	for name, lis := range e.listeners {
		if _, isSS := lis.(*embeddedSSListener); isSS {
			if _, ok := sharedSS[name]; !ok {
				return false
			}
			activeSSCount++
		}
	}
	if activeSSCount != len(sharedSS) {
		return false
	}
	for name, spec := range sharedSS {
		oldSS, ok := e.listeners[name].(*embeddedSSListener)
		if !ok {
			return false
		}
		dropped, err := oldSS.UpdateUsers(spec.Users)
		if err != nil {
			return false
		}
		traffic.closeInboundUsers(name, dropped)
	}
	return true
}

func (e *embeddedRuntime) Apply(_ context.Context, configPath, dir string, _ map[string][]byte, _ string, shared []sharedDesired, geoChanged, filesChanged bool) error {
	C.SetHomeDir(dir)
	if geoChanged {
		// geo 资产有变（内容更新或大小写孪生清理）时清掉核内匹配缓存：
		// singleflight 只按类别名缓存，不清会把旧文件的内容留到进程重启。
		geodata.ClearGeoSiteCache()
		geodata.ClearGeoIPCache()
	}
	cfg, err := parseMihomoFile(configPath)
	if err != nil {
		return err
	}
	listeners := cfg.Listeners
	cfg.Listeners = map[string]C.InboundListener{}
	if err := applyMihomo(cfg); err != nil {
		_ = cfg.Close()
		return err
	}
	sharedSS := make(map[string]sharedDesired, len(shared))
	for _, item := range shared {
		if item.Protocol == "shadowsocks" && item.Tag != "" {
			sharedSS[item.Tag] = item
		}
	}
	// 两阶段切换监听器：先识别可复用条目并关闭全部待删/换名/改配/换证旧监听，
	// 再打开新监听，避免同端口换 tag（如 nw2↔nw3、换用户/协议）或互换端口时报 address already in use。
	reuse := make(map[string]bool, len(e.listeners))
	for name, old := range e.listeners {
		lis, exists := listeners[name]
		if !exists {
			continue
		}
		if _, isSharedSS := sharedSS[name]; isSharedSS {
			if ssOpt, ok := lis.Config().(*IN.ShadowSocksOption); ok {
				if oldSS, ok := old.(*embeddedSSListener); ok && oldSS.Config() != nil && oldSS.Config().Equal(ssOpt) {
					reuse[name] = true
				}
				continue
			}
		}
		_, oldWasSharedSS := old.(*embeddedSSListener)
		if !oldWasSharedSS && !filesChanged && old.Config() != nil && lis.Config() != nil && old.Config().Equal(lis.Config()) {
			reuse[name] = true
		}
	}
	for name, old := range e.listeners {
		if reuse[name] {
			continue
		}
		traffic.closeInbound(name)
		closeInboundListener(old)
		delete(e.listeners, name)
	}
	retryBudget := embedBindRetryBudget
	rollbackOpened := func(next map[string]C.InboundListener) {
		for n, opened := range next {
			if opened != e.listeners[n] {
				closeInboundListener(opened)
			}
		}
	}
	next := map[string]C.InboundListener{}
	for name, lis := range listeners {
		old := e.listeners[name]
		if spec, isSharedSS := sharedSS[name]; isSharedSS {
			if ssOpt, ok := lis.Config().(*IN.ShadowSocksOption); ok {
				if reuse[name] {
					oldSS := old.(*embeddedSSListener)
					dropped, err := oldSS.UpdateUsers(spec.Users)
					if err != nil {
						rollbackOpened(next)
						return fmt.Errorf("update users %s: %w", name, err)
					}
					traffic.closeInboundUsers(name, dropped)
					next[name] = oldSS
					continue
				}
				multiLis, err := listenInboundWithRetry(func() (C.InboundListener, error) {
					return newEmbeddedSSListener(ssOpt, spec.Users)
				}, &retryBudget)
				if err != nil {
					rollbackOpened(next)
					return fmt.Errorf("listen %s: %w", name, err)
				}
				next[name] = multiLis
				continue
			}
		}
		if reuse[name] {
			next[name] = old
			continue
		}
		targetLis := lis
		opened, err := listenInboundWithRetry(func() (C.InboundListener, error) {
			return targetLis, nil
		}, &retryBudget)
		if err != nil {
			rollbackOpened(next)
			return fmt.Errorf("listen %s: %w", name, err)
		}
		next[name] = opened
	}
	e.listeners = next
	e.running.Store(true)
	e.version = C.Version
	return nil
}

func (e *embeddedRuntime) Stop() {
	wasRunning := e.running.Swap(false)
	// 先把隧道切到 Suspend 挡住新连接，避免关监听瞬间在途流量进入路由匹配。
	tunnel.OnSuspend()
	if e.logSub != nil {
		mihomolog.UnSubscribe(e.logSub)
		e.logSub = nil
	}
	for name, lis := range e.listeners {
		traffic.closeInbound(name)
		closeInboundListener(lis)
	}
	e.listeners = map[string]C.InboundListener{}
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		_ = c.Close()
		return true
	})
	// 释放全局业务 proxies/rules/sniffer 与 geo 匹配缓存，切到 xray/sing-box 或整机停服后
	// 不把旧出站协议栈和几十 MiB GeoSite/GeoIP 索引留在进程堆里；保留最小内置 REJECT 占位
	// （DIRECT/REJECT/GLOBAL）避免已越过 isHandle 的在途 TCP/UDP 协程拿到 nil proxy 触发空指针 panic。
	// 不调 executor.Shutdown 以免触碰 iptables 或磁盘 cache.db。
	reject := adapter.NewProxy(outbound.NewReject())
	tunnel.UpdateProxies(map[string]C.Proxy{
		"DIRECT": reject,
		"REJECT": reject,
		"GLOBAL": reject,
	}, nil)
	tunnel.UpdateRules(nil, nil, nil)
	tunnel.UpdateSniffer(nil)
	geodata.ClearGeoSiteCache()
	geodata.ClearGeoIPCache()
	if wasRunning {
		debug.FreeOSMemory()
	}
}

func closeInboundListener(lis C.InboundListener) {
	if lis == nil {
		return
	}
	defer func() { _ = recover() }()
	_ = lis.Close()
}

func (e *embeddedRuntime) Counters(context.Context) (map[string]int64, error) {
	return traffic.counters(), nil
}

func parseMihomoFile(path string) (*config.Config, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Parse(buf)
	if err != nil {
		return nil, fmt.Errorf("mihomo test: %w", err)
	}
	return cfg, nil
}

func applyMihomo(cfg *config.Config) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("mihomo apply: %v", rec)
		}
	}()
	executor.ApplyConfig(cfg, true)
	return nil
}

// absolutizeMihomo 把成对的证书相对路径改成数据目录下的绝对路径。
// 只有 private-key、没有 certificate 的字段是密钥正文（WireGuard），不改。
func absolutizeMihomo(configRaw []byte, dir string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(configRaw, &doc); err != nil {
		return nil, err
	}
	if err := walkMihomoPaths(doc, dir); err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}

func walkMihomoPaths(node any, dir string) error {
	switch item := node.(type) {
	case map[string]any:
		cert, _ := item["certificate"].(string)
		key, _ := item["private-key"].(string)
		if cert != "" && key != "" {
			for _, field := range []string{"certificate", "private-key"} {
				value, _ := item[field].(string)
				if value == "" || filepath.IsAbs(value) {
					continue
				}
				abs, err := safeJoin(dir, value)
				if err != nil {
					return err
				}
				item[field] = abs
			}
		}
		for _, child := range item {
			if err := walkMihomoPaths(child, dir); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range item {
			if err := walkMihomoPaths(child, dir); err != nil {
				return err
			}
		}
	}
	return nil
}
