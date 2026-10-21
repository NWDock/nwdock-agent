package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const wgcfKind = "wgcf"

var wgcfTagPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// wgcfIdentity 是一台机器上某个出口 tag 的 WARP 身份。私钥只留在数据目录，不回传面板。
type wgcfIdentity struct {
	PrivateKey    string   `json:"private_key"`
	PublicKey     string   `json:"public_key"`
	DeviceID      string   `json:"device_id"`
	Token         string   `json:"token"`
	PeerPublicKey string   `json:"peer_public_key"`
	Endpoint      string   `json:"endpoint"`
	Port          int      `json:"port"`
	Addresses     []string `json:"addresses"`
	Reserved      []int    `json:"reserved"`
}

type wgcfAPI struct {
	base   string
	client *http.Client
}

var wgcfLive = wgcfAPI{
	base: "https://api.cloudflareclient.com",
	client: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			// Cloudflare 对非常规 TLS 指纹回 403/1020；与 wgcf 一样钉在 TLS 1.2，并且直连，不走环境代理。
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: false,
			Proxy:             nil,
		},
	},
}

type wgcfAPIVersion struct {
	path   string
	header string
}

var wgcfAPIVersions = []wgcfAPIVersion{
	{path: "v0a1922", header: "a-6.3-1922"},
	{path: "v0a2158", header: "a-6.10-2158"},
}

// materializeWGCF 把面板写下的 wgcf 占位换成该核心的 WireGuard。没有占位时原样返回。
// 同一 tag 已有身份文件就复用，不重复注册。
func materializeWGCF(ctx context.Context, dir string, kind coreKind, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return raw, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	changed := false
	switch kind {
	case coreMihomo:
		next, ok, err := fillWGCFList(ctx, dir, doc["proxies"], "type", "name", mihomoWireGuard)
		if err != nil {
			return nil, err
		}
		if ok {
			doc["proxies"] = next
			changed = true
		}
	case coreXray:
		next, ok, err := fillWGCFList(ctx, dir, doc["outbounds"], "protocol", "tag", xrayWireGuard)
		if err != nil {
			return nil, err
		}
		if ok {
			doc["outbounds"] = next
			changed = true
		}
	case coreSingbox:
		next, extra, ok, err := pullSingboxWGCF(ctx, dir, doc["outbounds"])
		if err != nil {
			return nil, err
		}
		if ok {
			merged, err := appendRawArray(doc["endpoints"], extra)
			if err != nil {
				return nil, err
			}
			doc["outbounds"] = next
			doc["endpoints"] = merged
			changed = true
		}
	default:
		return raw, nil
	}
	if !changed {
		return raw, nil
	}
	return json.Marshal(doc)
}

func fillWGCFList(ctx context.Context, dir string, raw json.RawMessage, kindKey, tagKey string, build func(string, wgcfIdentity) (any, error)) (json.RawMessage, bool, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(raw) == "null" {
		return raw, false, nil
	}
	items, err := decodeRawArray(raw)
	if err != nil {
		return nil, false, err
	}
	changed := false
	for i, item := range items {
		kind, tag, ok, err := peekWGCF(item, kindKey, tagKey)
		if err != nil {
			return nil, false, err
		}
		if !ok || kind != wgcfKind {
			continue
		}
		id, err := ensureWGCF(ctx, dir, tag)
		if err != nil {
			return nil, false, err
		}
		built, err := build(tag, id)
		if err != nil {
			return nil, false, err
		}
		encoded, err := json.Marshal(built)
		if err != nil {
			return nil, false, err
		}
		items[i] = encoded
		changed = true
	}
	if !changed {
		return raw, false, nil
	}
	next, err := json.Marshal(items)
	return next, true, err
}

func pullSingboxWGCF(ctx context.Context, dir string, raw json.RawMessage) (json.RawMessage, []json.RawMessage, bool, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(raw) == "null" {
		return raw, nil, false, nil
	}
	items, err := decodeRawArray(raw)
	if err != nil {
		return nil, nil, false, err
	}
	kept := make([]json.RawMessage, 0, len(items))
	var extra []json.RawMessage
	for _, item := range items {
		kind, tag, ok, err := peekWGCF(item, "type", "tag")
		if err != nil {
			return nil, nil, false, err
		}
		if !ok || kind != wgcfKind {
			kept = append(kept, item)
			continue
		}
		id, err := ensureWGCF(ctx, dir, tag)
		if err != nil {
			return nil, nil, false, err
		}
		built, err := singboxWireGuard(tag, id)
		if err != nil {
			return nil, nil, false, err
		}
		encoded, err := json.Marshal(built)
		if err != nil {
			return nil, nil, false, err
		}
		extra = append(extra, encoded)
	}
	if len(extra) == 0 {
		return raw, nil, false, nil
	}
	next, err := json.Marshal(kept)
	if err != nil {
		return nil, nil, false, err
	}
	return next, extra, true, nil
}

func peekWGCF(item json.RawMessage, kindKey, tagKey string) (kind, tag string, ok bool, err error) {
	var peek map[string]json.RawMessage
	if err = json.Unmarshal(item, &peek); err != nil {
		return "", "", false, err
	}
	kindRaw, found := peek[kindKey]
	if !found {
		return "", "", false, nil
	}
	if err = json.Unmarshal(kindRaw, &kind); err != nil {
		return "", "", false, nil
	}
	if kind != wgcfKind {
		return kind, "", true, nil
	}
	if err = json.Unmarshal(peek[tagKey], &tag); err != nil || !wgcfTagPattern.MatchString(tag) {
		return "", "", false, fmt.Errorf("wgcf outbound tag is invalid")
	}
	return kind, tag, true, nil
}

func decodeRawArray(raw json.RawMessage) ([]json.RawMessage, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func appendRawArray(existing json.RawMessage, extra []json.RawMessage) (json.RawMessage, error) {
	var items []json.RawMessage
	if len(bytes.TrimSpace(existing)) > 0 && string(existing) != "null" {
		if err := json.Unmarshal(existing, &items); err != nil {
			return nil, err
		}
	}
	items = append(items, extra...)
	return json.Marshal(items)
}

// errWGCFEndpointStale 表示身份文件里的出口地址带端口。旧版本把注册响应的 v4/v6
// （形如 162.159.192.2:0）原样存下，端口信息已经丢失，只能换一个身份重注册。
var errWGCFEndpointStale = errors.New("wgcf endpoint carries a port")

// 同一 tag 已有身份文件就复用，不重复注册；旧格式（endpoint 带端口）视为过期重注册。
func ensureWGCF(ctx context.Context, dir, tag string) (wgcfIdentity, error) {
	id, err := loadWGCF(dir, tag)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errWGCFEndpointStale) {
		return wgcfIdentity{}, err
	}
	privateKey, publicKey, err := newWGCFKey()
	if err != nil {
		return wgcfIdentity{}, err
	}
	remote, err := wgcfLive.register(ctx, publicKey)
	if err != nil {
		return wgcfIdentity{}, err
	}
	remote.PrivateKey = privateKey
	remote.PublicKey = publicKey
	if err := remote.validate(); err != nil {
		return wgcfIdentity{}, err
	}
	if err := saveWGCF(dir, tag, remote); err != nil {
		return wgcfIdentity{}, err
	}
	return remote, nil
}

func wgcfPath(dir, tag string) (string, error) {
	if !wgcfTagPattern.MatchString(tag) {
		return "", fmt.Errorf("wgcf outbound tag is invalid")
	}
	return filepath.Join(dir, "wgcf", tag+".json"), nil
}

func loadWGCF(dir, tag string) (wgcfIdentity, error) {
	path, err := wgcfPath(dir, tag)
	if err != nil {
		return wgcfIdentity{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return wgcfIdentity{}, err
	}
	var id wgcfIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		return wgcfIdentity{}, fmt.Errorf("wgcf identity %s is unreadable", tag)
	}
	if err := id.validate(); err != nil {
		return wgcfIdentity{}, fmt.Errorf("wgcf identity %s is unreadable: %w", tag, err)
	}
	return id, nil
}

func saveWGCF(dir, tag string, id wgcfIdentity) error {
	path, err := wgcfPath(dir, tag)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(id)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Chmod(path, 0o600)
}

func (id wgcfIdentity) validate() error {
	if _, err := decodeWGKey(id.PrivateKey); err != nil {
		return err
	}
	if _, err := decodeWGKey(id.PeerPublicKey); err != nil {
		return err
	}
	if id.Endpoint == "" || id.Port < 1 || id.Port > 65535 {
		return errors.New("wgcf endpoint")
	}
	if !bareWGCFHost(id.Endpoint) {
		return errWGCFEndpointStale
	}
	if len(id.Addresses) == 0 || len(id.Reserved) != 3 {
		return errors.New("wgcf identity")
	}
	for _, item := range id.Reserved {
		if item < 0 || item > 255 {
			return errors.New("wgcf reserved")
		}
	}
	for _, item := range id.Addresses {
		if _, err := netip.ParsePrefix(item); err != nil {
			return err
		}
	}
	return nil
}

func newWGCFKey() (privateKey, publicKey string, err error) {
	var private [32]byte
	if _, err = rand.Read(private[:]); err != nil {
		return "", "", err
	}
	private[0] &= 248
	private[31] = (private[31] & 127) | 64
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(private[:]), base64.StdEncoding.EncodeToString(public), nil
}

func decodeWGKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(value, "="))
	}
	if err != nil || len(raw) != 32 {
		return nil, errors.New("wgcf key")
	}
	return raw, nil
}

func (api wgcfAPI) register(ctx context.Context, publicKey string) (wgcfIdentity, error) {
	body, err := json.Marshal(map[string]string{
		"key":        publicKey,
		"install_id": "",
		"fcm_token":  "",
		"tos":        time.Now().Format("2006-01-02T15:04:05.000-07:00"),
		"model":      "PC",
		"locale":     "en_US",
		"type":       "Android",
	})
	if err != nil {
		return wgcfIdentity{}, err
	}
	var last error
	for _, version := range wgcfAPIVersions {
		id, retry, err := api.registerOnce(ctx, version, body)
		if err == nil {
			return id, nil
		}
		last = err
		if !retry {
			return wgcfIdentity{}, err
		}
	}
	if last == nil {
		last = errors.New("wgcf register failed")
	}
	return wgcfIdentity{}, last
}

func (api wgcfAPI) registerOnce(ctx context.Context, version wgcfAPIVersion, body []byte) (wgcfIdentity, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(api.base, "/")+"/"+version.path+"/reg", bytes.NewReader(body))
	if err != nil {
		return wgcfIdentity{}, false, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", version.header)
	res, err := api.client.Do(req)
	if err != nil {
		return wgcfIdentity{}, false, fmt.Errorf("wgcf register: %w", err)
	}
	defer res.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return wgcfIdentity{}, false, fmt.Errorf("wgcf register: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return wgcfIdentity{}, res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusNotFound, wgcfStatusError(res.StatusCode, payload)
	}
	id, err := parseWGCFRegistration(payload)
	if err != nil {
		return wgcfIdentity{}, false, err
	}
	return id, false, nil
}

func wgcfStatusError(status int, payload []byte) error {
	var body struct {
		Errno int `json:"errno"`
	}
	if json.Unmarshal(payload, &body) == nil && body.Errno != 0 {
		return fmt.Errorf("wgcf register: status %d errno %d", status, body.Errno)
	}
	return fmt.Errorf("wgcf register: status %d", status)
}

type wgcfRegistration struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4    string `json:"v4"`
				V6    string `json:"v6"`
				Host  string `json:"host"`
				Ports []int  `json:"ports"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func parseWGCFRegistration(payload []byte) (wgcfIdentity, error) {
	var body wgcfRegistration
	if err := json.Unmarshal(payload, &body); err != nil {
		return wgcfIdentity{}, fmt.Errorf("wgcf register: response")
	}
	if len(body.Config.Peers) == 0 {
		return wgcfIdentity{}, fmt.Errorf("wgcf register: response")
	}
	peer := body.Config.Peers[0]
	peerKey, err := decodeWGKey(peer.PublicKey)
	if err != nil {
		return wgcfIdentity{}, fmt.Errorf("wgcf register: response")
	}
	reserved, err := decodeReserved(body.Config.ClientID)
	if err != nil {
		return wgcfIdentity{}, err
	}
	endpoint, port, err := warpEndpoint(peer.Endpoint.V4, peer.Endpoint.V6, peer.Endpoint.Host, peer.Endpoint.Ports)
	if err != nil {
		return wgcfIdentity{}, err
	}
	addresses, err := localPrefixes(body.Config.Interface.Addresses.V4, body.Config.Interface.Addresses.V6)
	if err != nil || len(addresses) == 0 {
		return wgcfIdentity{}, fmt.Errorf("wgcf register: response")
	}
	return wgcfIdentity{
		DeviceID:      body.ID,
		Token:         body.Token,
		PeerPublicKey: base64.StdEncoding.EncodeToString(peerKey),
		Endpoint:      endpoint,
		Port:          port,
		Addresses:     addresses,
		Reserved:      reserved,
	}, nil
}

// warpEndpoint 从注册响应里取出口主机与端口。Cloudflare 的 v4/v6 字段自带端口
// （常见是 162.159.192.2:0），host 字段是 engage.cloudflareclient.com:2408；
// 三者都要拆掉端口，端口为 0 时回落到 ports 里的 2408。
func warpEndpoint(v4, v6, host string, ports []int) (string, int, error) {
	for _, value := range []string{v4, v6, host} {
		name, port, ok := splitWGCEndpoint(value)
		if !ok {
			continue
		}
		if port == 0 {
			port = warpPort(ports)
		}
		if !bareWGCFHost(name) {
			continue
		}
		return name, port, nil
	}
	return "", 0, fmt.Errorf("wgcf register: response")
}

func splitWGCEndpoint(value string) (string, int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, false
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = value[1 : len(value)-1]
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return value, 0, true
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 || host == "" {
		return "", 0, false
	}
	return host, port, true
}

func bareWGCFHost(value string) bool {
	if _, err := netip.ParseAddr(value); err == nil {
		return true
	}
	if value == "" || len(value) > 253 || strings.Contains(value, ":") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return strings.Contains(value, ".")
}

func decodeReserved(clientID string) ([]int, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(clientID))
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(clientID), "="))
	}
	if err != nil || len(raw) != 3 {
		return nil, fmt.Errorf("wgcf register: response")
	}
	return []int{int(raw[0]), int(raw[1]), int(raw[2])}, nil
}

func warpPort(ports []int) int {
	for _, port := range ports {
		if port == 2408 {
			return 2408
		}
	}
	if len(ports) > 0 && ports[0] > 0 && ports[0] <= 65535 {
		return ports[0]
	}
	return 2408
}

func localPrefixes(v4, v6 string) ([]string, error) {
	var out []string
	for _, item := range []struct {
		value string
		bits  int
	}{{v4, 32}, {v6, 128}} {
		value := strings.TrimSpace(item.value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, err
			}
			out = append(out, prefix.String())
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, err
		}
		bits := item.bits
		if addr.BitLen() != bits {
			bits = addr.BitLen()
		}
		out = append(out, netip.PrefixFrom(addr, bits).String())
	}
	return out, nil
}

func hostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func mihomoWireGuard(tag string, id wgcfIdentity) (any, error) {
	proxy := map[string]any{
		"name":                 tag,
		"type":                 "wireguard",
		"private-key":          id.PrivateKey,
		"server":               id.Endpoint,
		"port":                 id.Port,
		"public-key":           id.PeerPublicKey,
		"reserved":             id.Reserved,
		"mtu":                  1280,
		"udp":                  true,
		"persistent-keepalive": 25,
	}
	for _, item := range id.Addresses {
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, err
		}
		if prefix.Addr().Is4() {
			proxy["ip"] = prefix.String()
		} else {
			proxy["ipv6"] = prefix.String()
		}
	}
	return proxy, nil
}

func xrayWireGuard(tag string, id wgcfIdentity) (any, error) {
	return map[string]any{
		"tag":      tag,
		"protocol": "wireguard",
		"settings": map[string]any{
			"secretKey":   id.PrivateKey,
			"address":     id.Addresses,
			"mtu":         1280,
			"reserved":    id.Reserved,
			"noKernelTun": true,
			"peers": []any{map[string]any{
				"publicKey":  id.PeerPublicKey,
				"endpoint":   hostPort(id.Endpoint, id.Port),
				"keepAlive":  25,
				"allowedIPs": []string{"0.0.0.0/0", "::/0"},
			}},
		},
	}, nil
}

func singboxWireGuard(tag string, id wgcfIdentity) (any, error) {
	return map[string]any{
		"type":        "wireguard",
		"tag":         tag,
		"mtu":         1280,
		"address":     id.Addresses,
		"private_key": id.PrivateKey,
		"peers": []any{map[string]any{
			"address":                       id.Endpoint,
			"port":                          id.Port,
			"public_key":                    id.PeerPublicKey,
			"allowed_ips":                   []string{"0.0.0.0/0", "::/0"},
			"persistent_keepalive_interval": 25,
			"reserved":                      id.Reserved,
		}},
	}, nil
}
