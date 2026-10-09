package agent

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"os"
	"path/filepath"
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

	fromFile   bool
	noteMihomo bool
}

// LoadConfig reads the process environment. Existing variables win over files
// already loaded into the environment.
func LoadConfig(envDir string) (Config, error) {
	return buildConfig(envDir, func(primary string, aliases ...string) string {
		value, _ := envfile.First(primary, aliases...)
		return value
	}, func(key string) bool {
		value, ok := os.LookupEnv(key)
		return ok && value != ""
	})
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
	cfg, err := buildConfig(filepath.Dir(abs), func(primary string, aliases ...string) string {
		value, _ := envfile.Lookup(values, primary, aliases...)
		return value
	}, func(key string) bool {
		value, ok := values[key]
		return ok && value != ""
	})
	if err != nil {
		return Config{}, err
	}
	cfg.fromFile = true
	scrubAgentEnv()
	ApplyFileRuntime(cfg)
	return cfg, nil
}

func buildConfig(base string, pick func(primary string, aliases ...string) string, set func(string) bool) (Config, error) {
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

// scrubAgentEnv drops agent settings from the process environment so a core
// subprocess started with os.Environ cannot see them.
func scrubAgentEnv() {
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if ok && strings.HasPrefix(key, "AGENT_") {
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
			fmt.Fprintln(os.Stderr, "AGENT_MIHOMO_BIN 已忽略：mihomo 由 agent 内置")
		}
	} else if bin, _ := envfile.First("AGENT_MIHOMO_BIN", "MIHOMO_BIN"); bin != "" {
		fmt.Fprintln(os.Stderr, "AGENT_MIHOMO_BIN 已忽略：mihomo 由 agent 内置")
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
		fmt.Fprintln(os.Stderr, err.Error())
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
