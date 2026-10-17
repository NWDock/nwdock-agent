package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// embeddedRuntime 把 clash-meta-nw 跑在 agent 进程里。监听器由本进程持有，
// 交给 meterTunnel 计数；出站、规则和 DNS 仍由 executor.ApplyConfig 更新。
type embeddedRuntime struct {
	version   string
	running   bool
	listeners map[string]C.InboundListener
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

func (e *embeddedRuntime) Running() bool { return e.running }

func (e *embeddedRuntime) Test(_ context.Context, configPath, dir string) error {
	C.SetHomeDir(dir)
	_, err := parseMihomoFile(configPath)
	return err
}

func (e *embeddedRuntime) Start(ctx context.Context, configPath, dir string) error {
	if err := e.Apply(ctx, configPath, dir, nil, "", nil, true, false); err != nil {
		e.Stop()
		return err
	}
	return nil
}

func (e *embeddedRuntime) Apply(_ context.Context, configPath, dir string, _ map[string][]byte, _ string, _ []sharedDesired, geoChanged, _ bool) error {
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
		return err
	}
	next := map[string]C.InboundListener{}
	for name, lis := range listeners {
		old := e.listeners[name]
		if old != nil && old.Config() != nil && lis.Config() != nil && old.Config().Equal(lis.Config()) {
			next[name] = old
			continue
		}
		if old != nil {
			traffic.closeInbound(name)
			_ = old.Close()
		}
		if err := lis.Listen(meterTunnel{}); err != nil {
			_ = lis.Close()
			return fmt.Errorf("listen %s: %w", name, err)
		}
		next[name] = lis
	}
	for name, old := range e.listeners {
		if _, ok := next[name]; ok {
			continue
		}
		traffic.closeInbound(name)
		_ = old.Close()
	}
	e.listeners = next
	e.running = true
	e.version = C.Version
	return nil
}

func (e *embeddedRuntime) Stop() {
	for name, lis := range e.listeners {
		traffic.closeInbound(name)
		_ = lis.Close()
	}
	e.listeners = map[string]C.InboundListener{}
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		_ = c.Close()
		return true
	})
	e.running = false
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
