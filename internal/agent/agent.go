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
	Runtime   string
	DataDir   string
	Endpoints []string
	KeyPin    string
	Token     string
	Image     string
}

func LoadConfig(envDir string) (Config, error) {
	dataDir, _ := envfile.First("AGENT_DATA_DIR", "DATA_DIR")
	keyPin, _ := envfile.First("AGENT_PANEL_KEYPIN")
	token, _ := envfile.First("AGENT_ENROLL_TOKEN", "NOWHERE_ENROLL_TOKEN")
	image, _ := envfile.First("AGENT_IMAGE_TAG", "IMAGE_TAG")
	endpoints, _ := envfile.First("AGENT_PANEL_ENDPOINTS", "PANEL_ENDPOINTS")
	if keyPin == "" {
		for _, old := range []string{"AGENT_PANEL_SPKI_PIN", "PANEL_SPKI_PIN"} {
			if value, ok := os.LookupEnv(old); ok && value != "" {
				return Config{}, fmt.Errorf("%s 已改名 AGENT_PANEL_KEYPIN，请改成面板身份公钥指纹（keypin hex）", old)
			}
		}
	}
	cfg := Config{
		Runtime: os.Getenv("AGENT_RUNTIME"),
		DataDir: dataDir,
		KeyPin:  keyPin,
		Token:   token,
		Image:   image,
	}
	if cfg.Runtime != "service" && cfg.Runtime != "docker" {
		return Config{}, errors.New("AGENT_RUNTIME must be service or docker")
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	// 核心进程以 DataDir 为工作目录启动，相对路径会让配置路径指错目录，这里统一转绝对。
	// env 文件在上一级时，相对路径对着那份文件，而不是当前工作目录。
	base := envDir
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
	backoff := time.Second
	tokenRetried := false
	go mihomoStatsLoop(ctx)
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
