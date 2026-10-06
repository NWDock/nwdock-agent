package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nowhere.local/agent/internal/certpin"
	"nowhere.local/agent/internal/envfile"
)

const Version = "0.0.0"

type Config struct {
	Runtime   string
	DataDir   string
	Endpoints []string
	Pin       string
	Token     string
	Image     string
}

func LoadConfig(envDir string) (Config, error) {
	dataDir, _ := envfile.First("AGENT_DATA_DIR", "DATA_DIR")
	pin, _ := envfile.First("AGENT_PANEL_SPKI_PIN", "PANEL_SPKI_PIN")
	token, _ := envfile.First("AGENT_ENROLL_TOKEN", "NOWHERE_ENROLL_TOKEN")
	image, _ := envfile.First("AGENT_IMAGE_TAG", "IMAGE_TAG")
	endpoints, _ := envfile.First("AGENT_PANEL_ENDPOINTS", "PANEL_ENDPOINTS")
	cfg := Config{
		Runtime: os.Getenv("AGENT_RUNTIME"),
		DataDir: dataDir,
		Pin:     pin,
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
		part = strings.TrimSpace(part)
		if part != "" {
			cfg.Endpoints = append(cfg.Endpoints, strings.TrimRight(part, "/"))
		}
	}
	if len(cfg.Endpoints) == 0 || cfg.Pin == "" {
		return Config{}, errors.New("AGENT_PANEL_ENDPOINTS and AGENT_PANEL_SPKI_PIN are required")
	}
	return cfg, nil
}

func Run(ctx context.Context, cfg Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	backoff := time.Second
	var lastStats time.Time
	go mihomoStatsLoop(ctx)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := beat(ctx, cfg); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			if !sleep(ctx, jitter(backoff)) {
				return nil
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			cfg.Endpoints = append(cfg.Endpoints[1:], cfg.Endpoints[0])
			continue
		}
		if err := syncConfig(ctx, cfg); err != nil {
			setError(err)
			fmt.Fprintln(os.Stderr, err.Error())
			if !sleep(ctx, jitter(backoff)) {
				return nil
			}
			continue
		}
		setError(nil)
		backoff = time.Second
		if core, _ := runningCoreInfo(); core != "" && time.Since(lastStats) >= time.Minute {
			lastStats = time.Now()
			if err := reportStats(ctx, cfg); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
			}
		}
		if !sleep(ctx, 15*time.Second) {
			return nil
		}
	}
}

func beat(ctx context.Context, cfg Config) error {
	cert, err := ensureCert(ctx, cfg)
	if err != nil {
		return err
	}
	core, coreVersion := runningCoreInfo()
	payload := map[string]any{
		"runtime": cfg.Runtime, "version": Version,
		"core": string(core), "core_version": coreVersion,
		"generation": appliedGeneration(cfg.DataDir),
		"error":      errorSummary(),
		"image":      cfg.Image,
	}
	if notAfter := clientCertNotAfter(cfg.DataDir); !notAfter.IsZero() {
		payload["cert_not_after"] = notAfter.UTC().Format(time.RFC3339)
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoints[0]+"/api/agent/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := httpClient(cfg.Pin, cert).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("heartbeat status %d", res.StatusCode)
	}
	return nil
}

const renewWindow = 30 * 24 * time.Hour

func ensureCert(ctx context.Context, cfg Config) (tls.Certificate, error) {
	certPath := filepath.Join(cfg.DataDir, "agent.crt")
	keyPath := filepath.Join(cfg.DataDir, "agent.key")
	pair, loadErr := tls.LoadX509KeyPair(certPath, keyPath)
	if loadErr == nil {
		if leaf, parseErr := x509.ParseCertificate(pair.Certificate[0]); parseErr == nil {
			remaining := time.Until(leaf.NotAfter)
			if remaining > renewWindow {
				return pair, nil
			}
			if remaining > 0 {
				renewed, renewErr := renewCertificate(ctx, cfg, pair, certPath, keyPath)
				if renewErr != nil {
					fmt.Fprintln(os.Stderr, "renew:", renewErr.Error())
					return pair, nil
				}
				return renewed, nil
			}
		}
	}
	if cfg.Token == "" {
		if loadErr == nil {
			return pair, nil
		}
		return tls.Certificate{}, errors.New("missing client certificate")
	}
	return enrollCertificate(ctx, cfg, certPath, keyPath)
}

// renewCertificate 用现有客户端证书走 mTLS 换一张同公钥的新证书：SPKI 指纹不变，节点身份不变。
func renewCertificate(ctx context.Context, cfg Config, auth tls.Certificate, certPath, keyPath string) (tls.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoints[0]+"/api/agent/renew", nil)
	if err != nil {
		return tls.Certificate{}, err
	}
	res, err := httpClient(cfg.Pin, auth).Do(req)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer res.Body.Close()
	return writeIssuedCertificate(res, certPath, keyPath)
}

func enrollCertificate(ctx context.Context, cfg Config, certPath, keyPath string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.CertificateRequest{Subject: pkixName()}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	payload, _ := json.Marshal(map[string]string{
		"token": cfg.Token,
		"csr":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoints[0]+"/api/agent/enroll", bytes.NewReader(payload))
	if err != nil {
		return tls.Certificate{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := httpClient(cfg.Pin, tls.Certificate{}).Do(req)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer res.Body.Close()
	// 面板拒绝（令牌用掉/失效）时不能动磁盘上已有的 agent.key。
	if res.StatusCode != http.StatusOK {
		return tls.Certificate{}, fmt.Errorf("certificate issue status %d", res.StatusCode)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return writeIssuedCertificate(res, certPath, keyPath)
}

func writeIssuedCertificate(res *http.Response, certPath, keyPath string) (tls.Certificate, error) {
	respBody, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return tls.Certificate{}, fmt.Errorf("certificate issue status %d", res.StatusCode)
	}
	var parsed struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, []byte(parsed.Certificate), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if _, err := os.Stat(keyPath); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func pkixName() pkix.Name {
	return pkix.Name{CommonName: "nowhere-agent"}
}

func httpClient(pin string, cert tls.Certificate) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("panel certificate pin mismatch")
			}
			return certpin.Match(rawCerts[0], pin)
		},
	}
	if len(cert.Certificate) > 0 {
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
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
