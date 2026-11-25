package agent

import (
	"context"
	"errors"
	"fmt"
	"math"
	mathrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"nowhere.local/agent/internal/envfile"
)

// Version 由构建期 -ldflags -X nowhere.local/agent/internal/agent.Version=<tag> 注入，
// 未注入时心跳上报 0.0.0。必须是 var：链接器 -X 只对变量生效。
var Version = "0.0.0"

type Config struct {
	Runtime    string
	DataDir    string
	Endpoints  []string
	KeyPin     string
	Token      string
	Image      string
	XrayBin    string
	SingboxBin string
	XrayAPI    string
	// MemoryLimit 是进程软内存上限，单位字节。0 表示不设，只在显式 off 时出现。
	MemoryLimit int64
	// NowhereEnv 是校验通过的 Nowhere 3.4 运行时调优变量（来自 agent.conf 或进程环境）。
	NowhereEnv map[string]string
	// NowhereMemoryProfile 是生效的 Nowhere 3.4 QUIC 内存档位（显式优先，否则按 MemoryLimit 推导）。
	NowhereMemoryProfile string

	fromFile   bool
	noteMihomo bool
}

// LoadConfig reads the process environment. Existing variables win over files
// already loaded into the environment.
func LoadConfig(envDir string) (Config, error) {
	var envKeys []string
	for _, entry := range os.Environ() {
		if key, _, ok := strings.Cut(entry, "="); ok {
			envKeys = append(envKeys, key)
		}
	}
	return buildConfig(envDir, func(primary string, aliases ...string) string {
		value, _ := envfile.First(primary, aliases...)
		return value
	}, func(key string) bool {
		value, ok := os.LookupEnv(key)
		return ok && value != ""
	}, envKeys)
}

// LoadConfigFile reads path as the only source of agent settings. The process
// environment is ignored and then cleared of agent keys so child processes
// do not inherit them. mode must be 0600 or 0400.
func LoadConfigFile(path string) (Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Config{}, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return Config{}, err
	}
	if !info.Mode().IsRegular() {
		return Config{}, fmt.Errorf("%s: 不是普通文件", abs)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 && perm != 0o400 {
		return Config{}, fmt.Errorf("%s: 权限必须是 0600 或 0400", abs)
	}
	values, err := envfile.Read(abs)
	if err != nil {
		return Config{}, err
	}
	fileKeys := make([]string, 0, len(values))
	for key := range values {
		fileKeys = append(fileKeys, key)
	}
	cfg, err := buildConfig(filepath.Dir(abs), func(primary string, aliases ...string) string {
		value, _ := envfile.Lookup(values, primary, aliases...)
		return value
	}, func(key string) bool {
		value, ok := values[key]
		return ok && value != ""
	}, fileKeys)
	if err != nil {
		return Config{}, err
	}
	cfg.fromFile = true
	scrubAgentEnv()
	ApplyFileRuntime(cfg)
	return cfg, nil
}

func buildConfig(base string, pick func(primary string, aliases ...string) string, set func(string) bool, sourceKeys []string) (Config, error) {
	dataDir := pick("AGENT_DATA_DIR", "DATA_DIR")
	keyPin := pick("AGENT_PANEL_KEYPIN")
	token := pick("AGENT_ENROLL_TOKEN", "NOWHERE_ENROLL_TOKEN")
	image := pick("AGENT_IMAGE_TAG", "IMAGE_TAG")
	endpoints := pick("AGENT_PANEL_ENDPOINTS", "PANEL_ENDPOINTS")
	if keyPin == "" {
		for _, old := range []string{"AGENT_PANEL_SPKI_PIN", "PANEL_SPKI_PIN"} {
			if set(old) {
				return Config{}, fmt.Errorf("%s 已改名 AGENT_PANEL_KEYPIN，请改成面板身份公钥指纹（keypin hex）", old)
			}
		}
	}
	cfg := Config{
		Runtime:    pick("AGENT_RUNTIME"),
		DataDir:    dataDir,
		KeyPin:     keyPin,
		Token:      token,
		Image:      image,
		XrayBin:    pick("AGENT_XRAY_BIN", "XRAY_BIN"),
		SingboxBin: pick("AGENT_SINGBOX_BIN", "SINGBOX_BIN"),
		XrayAPI:    pick("AGENT_XRAY_API_ADDR", "XRAY_API_ADDR"),
		noteMihomo: pick("AGENT_MIHOMO_BIN", "MIHOMO_BIN") != "",
	}
	limit, err := parseMemoryLimit(pick("AGENT_MEMORY_LIMIT"))
	if err != nil {
		return Config{}, err
	}
	cfg.MemoryLimit = limit
	nowhereEnv, err := parseNowhereEnv(pick, sourceKeys)
	if err != nil {
		return Config{}, err
	}
	cfg.NowhereEnv = nowhereEnv
	if prof := nowhereEnv[nowhereEnvMemoryProfile]; prof != "" {
		cfg.NowhereMemoryProfile = prof
	} else {
		cfg.NowhereMemoryProfile = defaultNowhereMemoryProfile(limit)
	}
	if cfg.Runtime != "service" && cfg.Runtime != "docker" {
		return Config{}, errors.New("AGENT_RUNTIME must be service or docker")
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	// 核心进程以 DataDir 为工作目录启动，相对路径会让配置路径指错目录，这里统一转绝对。
	// env 文件在上一级时，相对路径对着那份文件，而不是当前工作目录。
	// -config 时相对路径对着配置文件所在目录。
	if base == "" {
		base = "."
	}
	if !filepath.IsAbs(cfg.DataDir) {
		if abs, err := filepath.Abs(filepath.Join(base, cfg.DataDir)); err == nil {
			cfg.DataDir = abs
		}
	} else if abs, err := filepath.Abs(cfg.DataDir); err == nil {
		cfg.DataDir = abs
	}
	for _, part := range strings.Split(endpoints, ",") {
		if ws := normalizeChannelURL(part); ws != "" {
			cfg.Endpoints = append(cfg.Endpoints, ws)
		}
	}
	if len(cfg.Endpoints) == 0 || cfg.KeyPin == "" {
		return Config{}, errors.New("AGENT_PANEL_ENDPOINTS and AGENT_PANEL_KEYPIN are required")
	}
	return cfg, nil
}

// defaultMemoryLimit 是内嵌核心长跑时的软上限。Go 按 GOGC=100 会把约一倍空闲堆
// 留在进程里；设上限后 GC 提前跑，空闲堆不再按流量峰值一直留着。
const defaultMemoryLimit = 768 << 20

// minMemoryLimit 挡住小到会让 GC 持续抢转发的值。
const minMemoryLimit = 64 << 20

// parseMemoryLimit 解析 AGENT_MEMORY_LIMIT。空字符串用缺省；off 表示不设。
// 后缀与 GOMEMLIMIT 相同：B、KiB、MiB、GiB、TiB，以及纯字节数。不接受 MB。
func parseMemoryLimit(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultMemoryLimit, nil
	}
	if strings.EqualFold(raw, "off") {
		return 0, nil
	}
	n, ok := parseByteCount(raw)
	if !ok || n < minMemoryLimit {
		return 0, fmt.Errorf("AGENT_MEMORY_LIMIT 必须是至少 64MiB 的字节数（如 768MiB），或 off")
	}
	return n, nil
}

// parseByteCount 对齐 runtime.parseByteCount：^[0-9]+(([KMGT]i)?B)?$。
func parseByteCount(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	last := s[len(s)-1]
	if last >= '0' && last <= '9' {
		n, err := strconv.ParseInt(s, 10, 64)
		return n, err == nil && n >= 0
	}
	if last != 'B' || len(s) < 2 {
		return 0, false
	}
	if c := s[len(s)-2]; c >= '0' && c <= '9' {
		n, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
		return n, err == nil && n >= 0
	} else if c != 'i' {
		return 0, false
	}
	if len(s) < 4 {
		return 0, false
	}
	power := 0
	switch s[len(s)-3] {
	case 'K':
		power = 1
	case 'M':
		power = 2
	case 'G':
		power = 3
	case 'T':
		power = 4
	default:
		return 0, false
	}
	m := uint64(1)
	for i := 0; i < power; i++ {
		m *= 1024
	}
	n, err := strconv.ParseInt(s[:len(s)-3], 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	un := uint64(n)
	if un > math.MaxUint64/m {
		return 0, false
	}
	un *= m
	if un > uint64(math.MaxInt64) {
		return 0, false
	}
	return int64(un), true
}

// Nowhere 3.4 运行时调优变量白名单，口径与 third_party/clash-meta-nw/transport/nowhere/core/runtime 对齐。
const (
	nowhereEnvMemoryProfile = "NOW_TRANSPORT_MEMORY_PROFILE"
	nowhereEnvMaxPortalIdle = 1023
	nowhereEnvMaxQUICQueue  = int64(^uint32(0))
	nowhereEnvMaxInt        = int64(^uint(0) >> 1)
)

var nowhereEnvKeys = []string{
	nowhereEnvMemoryProfile,
	"NOW_TCP_DATA_BUF_SIZE",
	"NOW_TCP_DIAL_TIMEOUT",
	"NOW_UDP_DIAL_TIMEOUT",
	"NOW_HANDSHAKE_TIMEOUT",
	"NOW_FLOW_SETUP_TIMEOUT",
	"NOW_TCP_READ_TIMEOUT",
	"NOW_UDP_IDLE_TIMEOUT",
	"NOW_QUIC_UDP_QUEUE_BYTES",
	"NOW_SHUTDOWN_TIMEOUT",
	"NOW_SERVICE_COOLDOWN",
	"NOW_EGRESS_TLS_POOL_MAX",
	"NOW_PORTAL_TLS_IDLE_MAX",
	"NOW_MORPH_TCP_PRELUDE",
	"NOW_MORPH_UDP_PRELUDE",
}

// defaultNowhereMemoryProfile 在未显式指定 NOW_TRANSPORT_MEMORY_PROFILE 时，
// 按 AGENT_MEMORY_LIMIT 推导匹配的 Nowhere 3.4 QUIC 窗口档位，避免 32MiB 默认窗口顶穿软上限。
func defaultNowhereMemoryProfile(limit int64) string {
	if limit <= 0 || limit > (1<<30) {
		return "throughput"
	}
	if limit <= (512 << 20) {
		return "memory"
	}
	return "balanced"
}

func parseNowhereEnv(pick func(primary string, aliases ...string) string, sourceKeys []string) (map[string]string, error) {
	var unknown []string
	for _, key := range sourceKeys {
		if strings.HasPrefix(key, "NOW_") && !slices.Contains(nowhereEnvKeys, key) {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		unknown = slices.Compact(unknown)
		return nil, fmt.Errorf("unknown NOW_* setting: %s", strings.Join(unknown, ", "))
	}
	out := map[string]string{}
	for _, key := range nowhereEnvKeys {
		raw := strings.TrimSpace(pick(key))
		if raw == "" {
			continue
		}
		if err := validateNowhereEnvValue(key, raw); err != nil {
			return nil, err
		}
		out[key] = raw
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func validateNowhereEnvValue(key, value string) error {
	switch key {
	case nowhereEnvMemoryProfile:
		switch value {
		case "memory", "balanced", "throughput":
			return nil
		default:
			return fmt.Errorf("%s must be memory, balanced or throughput", key)
		}
	case "NOW_MORPH_TCP_PRELUDE", "NOW_MORPH_UDP_PRELUDE":
		// 注意：NOW_MORPH_TCP_PRELUDE=fade 仅适用于 nw3；存量 nw2 载体只接受 low7 / full8
		// （留空时各自走默认：nw3=fade、nw2=full8）。
		switch value {
		case "fade", "full8", "low7":
			return nil
		default:
			return fmt.Errorf("%s must be fade, full8 or low7", key)
		}
	case "NOW_TCP_DATA_BUF_SIZE", "NOW_EGRESS_TLS_POOL_MAX":
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 1 || n > nowhereEnvMaxInt {
			return fmt.Errorf("%s: invalid integer", key)
		}
		return nil
	case "NOW_QUIC_UDP_QUEUE_BYTES":
		queueMax := nowhereEnvMaxQUICQueue
		if nowhereEnvMaxInt < queueMax {
			queueMax = nowhereEnvMaxInt
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 1 || n > queueMax {
			return fmt.Errorf("%s: invalid integer", key)
		}
		return nil
	case "NOW_PORTAL_TLS_IDLE_MAX":
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 1 || n > nowhereEnvMaxPortalIdle {
			return fmt.Errorf("%s: invalid integer", key)
		}
		return nil
	default:
		d, err := time.ParseDuration(value)
		if err != nil || d <= 0 {
			return fmt.Errorf("%s: invalid duration", key)
		}
		return nil
	}
}

func applyNowhereEnv(cfg Config) {
	for _, key := range nowhereEnvKeys {
		if value, ok := cfg.NowhereEnv[key]; ok && value != "" {
			_ = os.Setenv(key, value)
		} else {
			// 未在生效配置中指定的白名单变量统一清掉（含空字符串占位与旧值残留），
			// 防止 Nowhere 3.4 runtime.Load 拒收空值并保证多次应用幂等。
			_ = os.Unsetenv(key)
		}
	}
	profile := cfg.NowhereMemoryProfile
	if profile == "" {
		profile = defaultNowhereMemoryProfile(cfg.MemoryLimit)
	}
	_ = os.Setenv(nowhereEnvMemoryProfile, profile)
	source := "auto"
	if cfg.NowhereEnv[nowhereEnvMemoryProfile] != "" {
		source = "config"
	}
	logf(levelInfo, "nowhere memory profile %s (%s)", profile, source)
}

// scrubAgentEnv drops agent and NOW_* settings from the process environment so
// -config mode stays strictly file-driven and core subprocesses cannot see them.
func scrubAgentEnv() {
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if ok && (strings.HasPrefix(key, "AGENT_") || strings.HasPrefix(key, "NOW_")) {
			os.Unsetenv(key)
		}
	}
	for _, key := range []string{
		"DATA_DIR",
		"PANEL_ENDPOINTS",
		"PANEL_SPKI_PIN",
		"NOWHERE_ENROLL_TOKEN",
		"IMAGE_TAG",
		"XRAY_BIN",
		"XRAY_API_ADDR",
		"SINGBOX_BIN",
		"MIHOMO_BIN",
	} {
		os.Unsetenv(key)
	}
}

// Run 建立并维持 nwdock-agent-v1 加密通道：desired 推送驱动配置应用，
// 15s 心跳、60s stats；断开走退避 + jitter + endpoint 轮转重连。
func Run(ctx context.Context, cfg Config) error {
	applyMemoryLimit(ctx, cfg.MemoryLimit)
	applyNowhereEnv(cfg)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	id, err := loadOrCreateIdentity(cfg.DataDir)
	if err != nil {
		return err
	}
	// 转发引擎与通道、核心都解耦：先按磁盘上最后一份清单把入口端口听起来，
	// 面板连上后由 desired 驱动增删；面板失联也不影响转发。
	relayInit(cfg.DataDir)
	defer relayStop()
	backoff := time.Second
	tokenRetried := false
	if cfg.fromFile {
		if cfg.noteMihomo {
			logf(levelWarning, "AGENT_MIHOMO_BIN 已忽略：mihomo 由 agent 内置")
		}
	} else if bin, _ := envfile.First("AGENT_MIHOMO_BIN", "MIHOMO_BIN"); bin != "" {
		logf(levelWarning, "AGENT_MIHOMO_BIN 已忽略：mihomo 由 agent 内置")
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		ch, err := dialChannel(ctx, cfg, id, tokenRetried)
		if err == nil {
			err = ch.serve(ctx)
		}
		if ctx.Err() != nil {
			return nil
		}
		logf(levelWarning, "%s", err.Error())
		// 面板以 4401 unknown agent 提示指纹未绑定：带安装令牌重试一次（防抖），之后照常退避。
		if !tokenRetried && cfg.Token != "" && unknownAgentClose(err) {
			tokenRetried = true
			if !sleep(ctx, jitter(time.Second)) {
				return nil
			}
			continue
		}
		if !sleep(ctx, jitter(backoff)) {
			return nil
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
		cfg.Endpoints = append(cfg.Endpoints[1:], cfg.Endpoints[0])
	}
}

// heapReleaseEvery 是检查空闲堆的间隔。FreeOSMemory 会触发一次 GC，不能跟心跳走。
const heapReleaseEvery = 5 * time.Minute

// heapReleaseMin 是值得归还的最小空闲量。小于它就留给运行时自己收。
const heapReleaseMin = 128 << 20

// applyMemoryLimit 设置进程软内存上限，并周期把多出来的空闲堆还给系统。
// limit 为 0 表示不设上限，归还仍会做。上限不含栈和堆外内存。
func applyMemoryLimit(ctx context.Context, limit int64) {
	if limit > 0 {
		debug.SetMemoryLimit(limit)
		logf(levelInfo, "memory limit %dMiB", limit>>20)
	}
	go releaseIdleHeap(ctx)
}

// releaseIdleHeap 在空闲堆明显多过在用堆时归还。流量高峰留下的页否则会一直占着 RSS。
func releaseIdleHeap(ctx context.Context) {
	ticker := time.NewTicker(heapReleaseEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if !shouldReleaseHeap(ms.HeapInuse, ms.HeapIdle, ms.HeapReleased) {
				continue
			}
			debug.FreeOSMemory()
			logf(levelInfo, "released idle heap")
		}
	}
}

// shouldReleaseHeap 在可归还的空闲堆达到 128MiB 且多于在用堆时返回 true。
// HeapReleased 已还给系统，不重复计算。
func shouldReleaseHeap(inuse, idle, released uint64) bool {
	if idle < released {
		return false
	}
	reclaimable := idle - released
	return reclaimable >= heapReleaseMin && reclaimable > inuse
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d/2 + time.Duration(mathrand.Int64N(int64(d/2)+1))
}
