package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type coreProc struct {
	mu           sync.Mutex
	cmd          *exec.Cmd
	core         coreKind
	version      string
	generation   int
	loaded       bool
	applied      map[string][]byte
	skeleton     string
	appliedUsers map[string]map[string]string
	usersLoaded  bool
}

var proc coreProc

type desiredFile struct {
	Path string `json:"path"`
	PEM  string `json:"pem"`
	Mode string `json:"mode"`
}

// assetMaxBytes 是单个资产（.dat 规则数据库 / .srs 规则集）下载上限；常用 geosite.dat 在 10–15MB 量级。
const assetMaxBytes int64 = 64 << 20

type geoDesired struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type ruleSetDesired struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// validAssetName 只接受两类资产：xray/mihomo 的 .dat 与 sing-box 的 <tag>.srs 规则集。
func validAssetName(name string) bool {
	if name == "geoip.dat" || name == "geosite.dat" {
		return true
	}
	tag, ok := strings.CutSuffix(name, ".srs")
	if !ok {
		return false
	}
	for i, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0:
		default:
			return false
		}
	}
	return len(tag) > 0 && len(tag) <= 32
}

// assetSidecar 侧车 hash 名：旧 .dat 保持 geo-<name>.sha256；带子目录的 .srs 把 / 归一为 _。
func assetSidecar(name string) string {
	return filepath.Join(".", "geo-"+strings.ReplaceAll(name, "/", "_")+".sha256")
}

// syncAssets 让本地资产与面板清单一致；返回是否有文件更新（核心只在启动时加载 geo/规则集，需重启）。
func syncAssets(ctx context.Context, cfg Config, cert tls.Certificate, entries []geoDesired) (bool, error) {
	changed := false
	for _, entry := range entries {
		if !validAssetName(entry.Name) {
			return changed, fmt.Errorf("asset name %q", entry.Name)
		}
		want := strings.ToLower(strings.TrimSpace(entry.SHA256))
		if want == "" {
			return changed, fmt.Errorf("asset %s missing sha256", entry.Name)
		}
		if have, err := os.ReadFile(filepath.Join(cfg.DataDir, assetSidecar(entry.Name))); err == nil && strings.TrimSpace(string(have)) == want {
			continue
		}
		data, err := fetchAsset(ctx, cfg, cert, entry.Name)
		if err != nil {
			return changed, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != want {
			return changed, fmt.Errorf("asset %s sha256 mismatch", entry.Name)
		}
		target := filepath.Join(cfg.DataDir, filepath.FromSlash(entry.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return changed, err
		}
		tmp := target + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return changed, err
		}
		if err := os.Rename(tmp, target); err != nil {
			return changed, err
		}
		if err := os.WriteFile(filepath.Join(cfg.DataDir, assetSidecar(entry.Name)), []byte(want+"\n"), 0o644); err != nil {
			return changed, err
		}
		changed = true
		fmt.Println("geo", entry.Name)
	}
	return changed, nil
}

func assetFetchPath(name string) string {
	if strings.HasSuffix(name, ".srs") {
		return "/api/agent/rule-sets/" + name
	}
	return "/api/agent/geo/" + name
}

func fetchAsset(ctx context.Context, cfg Config, cert tls.Certificate, name string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Endpoints[0]+assetFetchPath(name), nil)
	if err != nil {
		return nil, err
	}
	res, err := httpClient(cfg.Pin, cert).Do(req)
	if err != nil {
		return nil, fmt.Errorf("asset fetch: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("asset fetch status %d", res.StatusCode)
	}
	return io.ReadAll(io.LimitReader(res.Body, assetMaxBytes))
}

// coreEnv 给 xray 注入资产目录：xray 找 .dat 只看 XRAY_LOCATION_ASSET 和可执行文件目录，不看 cwd。
func coreEnv(kind coreKind, dir string) []string {
	env := os.Environ()
	if kind == coreXray {
		env = append(env, "XRAY_LOCATION_ASSET="+dir)
	}
	return env
}

func syncConfig(ctx context.Context, cfg Config) error {
	api := coreAPIAddr()
	cert, err := tls.LoadX509KeyPair(filepath.Join(cfg.DataDir, "agent.crt"), filepath.Join(cfg.DataDir, "agent.key"))
	if err != nil {
		return err
	}
	res, err := httpNew(ctx, cfg.Endpoints[0]+"/api/agent/desired?api="+api, cert, cfg.Pin)
	if err != nil {
		return err
	}
	if res.status != 200 {
		return fmt.Errorf("desired status %d", res.status)
	}
	var body struct {
		Generation int              `json:"generation"`
		Serving    bool             `json:"serving"`
		Core       string           `json:"core"`
		Config     json.RawMessage  `json:"config"`
		Files      []desiredFile    `json:"files"`
		Shared     []sharedDesired  `json:"shared"`
		Geo        []geoDesired     `json:"geo"`
		RuleSets   []ruleSetDesired `json:"rule_sets"`
	}
	if err := json.Unmarshal(res.body, &body); err != nil {
		return err
	}
	want := normalizeCore(body.Core)
	proc.mu.Lock()
	defer proc.mu.Unlock()
	if !proc.loaded {
		raw, err := os.ReadFile(filepath.Join(cfg.DataDir, "applied-generation"))
		if err == nil {
			proc.generation, _ = strconv.Atoi(string(bytes.TrimSpace(raw)))
		}
		raw, err = os.ReadFile(filepath.Join(cfg.DataDir, "applied-skeleton"))
		if err == nil {
			proc.skeleton = string(bytes.TrimSpace(raw))
		}
		proc.loaded = true
	}
	if body.Generation == proc.generation && runningLocked() == body.Serving && (!body.Serving || proc.core == want) {
		return nil
	}
	if !body.Serving {
		stopLocked()
		proc.applied = nil
		proc.skeleton = ""
		_ = os.Remove(filepath.Join(cfg.DataDir, "applied-skeleton"))
		clearAppliedUsers(cfg.DataDir)
		clearAppliedCore(cfg.DataDir)
		return writeGeneration(cfg.DataDir, body.Generation)
	}
	bin := coreBin(want)
	if bin == "" {
		return fmt.Errorf("%s is required", coreBinEnv(want))
	}
	assets := make([]geoDesired, 0, len(body.Geo)+len(body.RuleSets))
	assets = append(assets, body.Geo...)
	for _, item := range body.RuleSets {
		assets = append(assets, geoDesired{Name: item.Name, SHA256: item.SHA256})
	}
	geoChanged, err := syncAssets(ctx, cfg, cert, assets)
	if err != nil {
		return err
	}
	switching := proc.cmd != nil && proc.core != want
	if switching {
		if err := reportStatsLocked(ctx, cfg); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
		}
	}
	rendered, changed, err := stageConfig(ctx, cfg.DataDir, want, bin, body.Config, body.Files)
	if err != nil {
		if switching {
			fmt.Fprintf(os.Stderr, "degraded: keeping %s: %s\n", proc.core, err.Error())
		}
		return err
	}
	var raws map[string][]byte
	var skel string
	if want == coreXray {
		raws, err = inboundRaws(rendered)
		if err != nil {
			return err
		}
		skel, err = skeleton(rendered)
		if err != nil {
			return err
		}
	}
	current := filepath.Join(cfg.DataDir, coreConfigName(want))
	switch {
	case switching:
		stopLocked()
		if err := bootWithRollback(ctx, cfg, api, bin, want, current, raws, skel, body.Shared); err != nil {
			return err
		}
		fmt.Println("switch", want)
	case proc.cmd == nil:
		if err := bootWithRollback(ctx, cfg, api, bin, want, current, raws, skel, body.Shared); err != nil {
			return err
		}
	default:
		plan := sameCorePlan(want, proc.skeleton != skel)
		if geoChanged {
			// 核心只在启动时加载 geo 数据文件，文件有变必须整进程重启。
			plan = planRestart
		}
		switch plan {
		case planHot:
			readded, err := diffLocked(ctx, bin, api, cfg.DataDir, raws, changed)
			if err != nil {
				return err
			}
			appliedUsers := appliedUsersLocked(cfg.DataDir)
			for tag := range readded {
				delete(appliedUsers, tag)
			}
			if err := reconcileUsers(ctx, bin, api, cfg.DataDir, body.Shared); err != nil {
				return err
			}
			proc.applied = raws
		case planReload:
			abs, err := filepath.Abs(current)
			if err != nil {
				return err
			}
			if err := reloadMihomo(ctx, api, abs); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				if err := restartLocked(ctx, cfg, api, bin, want, current, raws, skel, body.Shared); err != nil {
					return err
				}
			} else {
				fmt.Println("reload")
			}
		default:
			if err := restartLocked(ctx, cfg, api, bin, want, current, raws, skel, body.Shared); err != nil {
				return err
			}
		}
	}
	return writeGeneration(cfg.DataDir, body.Generation)
}

func stageConfig(ctx context.Context, dir string, kind coreKind, bin string, raw json.RawMessage, files []desiredFile) ([]byte, bool, error) {
	changed, restore, err := writeFiles(dir, files)
	if err != nil {
		return nil, false, err
	}
	rendered, err := absolutizeCerts(raw, dir)
	if err != nil {
		restore()
		return nil, false, err
	}
	next := filepath.Join(dir, coreStagingName(kind))
	if err := os.WriteFile(next, rendered, 0o600); err != nil {
		restore()
		return nil, false, err
	}
	test := exec.CommandContext(ctx, bin, coreTestArgs(kind, next, dir)...)
	test.Dir = dir
	test.Env = coreEnv(kind, dir)
	if out, err := test.CombinedOutput(); err != nil {
		restore()
		_ = os.Remove(next)
		return nil, false, cmdFail(string(kind)+" test", out, err)
	}
	final := filepath.Join(dir, coreConfigName(kind))
	if prevData, err := os.ReadFile(final); err == nil {
		_ = os.WriteFile(final+".prev", prevData, 0o600)
	}
	if err := os.Rename(next, final); err != nil {
		return nil, false, err
	}
	return rendered, changed, nil
}

func bootLocked(ctx context.Context, cfg Config, api, bin string, kind coreKind, current string, raws map[string][]byte, skel string, shared []sharedDesired) error {
	if err := startLocked(ctx, kind, bin, current, cfg.DataDir); err != nil {
		return err
	}
	if err := writeAppliedCore(cfg.DataDir, kind); err != nil {
		return err
	}
	if kind != coreXray {
		proc.applied = nil
		proc.skeleton = ""
		_ = os.Remove(filepath.Join(cfg.DataDir, "applied-skeleton"))
		clearAppliedUsers(cfg.DataDir)
		return nil
	}
	if err := writeSkeleton(cfg.DataDir, skel); err != nil {
		return err
	}
	resetAppliedUsersLocked()
	if err := reconcileUsers(ctx, bin, api, cfg.DataDir, shared); err != nil {
		return err
	}
	proc.applied = raws
	return nil
}

func bootWithRollback(ctx context.Context, cfg Config, api, bin string, kind coreKind, current string, raws map[string][]byte, skel string, shared []sharedDesired) error {
	err := bootLocked(ctx, cfg, api, bin, kind, current, raws, skel, shared)
	if err == nil {
		_ = os.Remove(current + ".prev")
		return nil
	}
	prevData, rerr := os.ReadFile(current + ".prev")
	if rerr != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "degraded: %s start failed (%v), rolling back to previous config\n", kind, err)
	if werr := os.WriteFile(current, prevData, 0o600); werr != nil {
		return fmt.Errorf("%v; restore previous config: %w", err, werr)
	}
	var prevRaws map[string][]byte
	if kind == coreXray {
		prevRaws, rerr = inboundRaws(prevData)
		if rerr != nil {
			return fmt.Errorf("%v; parse previous config: %w", err, rerr)
		}
	}
	if retryErr := bootLocked(ctx, cfg, api, bin, kind, current, prevRaws, "", shared); retryErr != nil {
		return fmt.Errorf("%v; rollback start: %w", err, retryErr)
	}
	return fmt.Errorf("%s start failed, rolled back to previous config: %w", kind, err)
}

func restartLocked(ctx context.Context, cfg Config, api, bin string, kind coreKind, current string, raws map[string][]byte, skel string, shared []sharedDesired) error {
	if err := reportStatsLocked(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	stopLocked()
	if err := bootWithRollback(ctx, cfg, api, bin, kind, current, raws, skel, shared); err != nil {
		return err
	}
	fmt.Println("restart")
	return nil
}

func httpNew(ctx context.Context, url string, cert tls.Certificate, pin string) (*pinnedResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := httpClient(pin, cert).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return &pinnedResponse{status: res.StatusCode, body: body}, nil
}

type pinnedResponse struct {
	status int
	body   []byte
}

func (r *pinnedResponse) Close() error { return nil }

func startLocked(ctx context.Context, kind coreKind, bin, config, dir string) error {
	cmd := exec.Command(bin, coreRunArgs(kind, config, dir)...)
	cmd.Dir = dir
	cmd.Env = coreEnv(kind, dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	proc.cmd = cmd
	proc.core = kind
	proc.version = probeVersion(ctx, bin, kind)
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err := <-waitErr:
		proc.mu.Lock()
		if proc.cmd == cmd {
			proc.cmd = nil
			proc.core = ""
			proc.version = ""
		}
		proc.mu.Unlock()
		if err != nil {
			return fmt.Errorf("%s exited: %s", kind, err.Error())
		}
		return fmt.Errorf("%s exited immediately", kind)
	case <-time.After(2 * time.Second):
	}
	go func() {
		<-waitErr
		proc.mu.Lock()
		if proc.cmd == cmd {
			proc.cmd = nil
			proc.core = ""
			proc.version = ""
		}
		proc.mu.Unlock()
	}()
	return nil
}

func runningLocked() bool {
	return proc.cmd != nil
}

func runningCoreInfo() (coreKind, string) {
	proc.mu.Lock()
	defer proc.mu.Unlock()
	if proc.cmd == nil {
		return "", ""
	}
	return proc.core, proc.version
}

func stopLocked() {
	if proc.cmd != nil && proc.cmd.Process != nil {
		_ = proc.cmd.Process.Kill()
		proc.cmd = nil
	}
	proc.core = ""
	proc.version = ""
}

func diffLocked(ctx context.Context, bin, api, dir string, want map[string][]byte, reload bool) (map[string]bool, error) {
	out, err := exec.CommandContext(ctx, bin, "api", "lsi", "--server", api, "-isOnlyTags=true").CombinedOutput()
	if err != nil {
		return nil, cmdFail("list inbounds", out, err)
	}
	reapplied := map[string]bool{}
	have := map[string]bool{}
	for _, tag := range tagsFrom(out) {
		have[tag] = true
	}
	for tag := range have {
		if tag == "api" {
			continue
		}
		if _, ok := want[tag]; !ok {
			if out, err := exec.CommandContext(ctx, bin, "api", "rmi", "--server", api, tag).CombinedOutput(); err != nil {
				return nil, cmdFail("remove "+tag, out, err)
			}
			reapplied[tag] = true
			fmt.Println("rmi", tag)
		}
	}
	for tag, raw := range want {
		if !safeTag(tag) {
			return nil, errors.New("tag")
		}
		if have[tag] && !reload && bytes.Equal(proc.applied[tag], raw) {
			continue
		}
		if have[tag] {
			if out, err := exec.CommandContext(ctx, bin, "api", "rmi", "--server", api, tag).CombinedOutput(); err != nil {
				return nil, cmdFail("remove "+tag, out, err)
			}
			fmt.Println("rmi", tag)
		}
		file := filepath.Join(dir, "inbound-"+tag+".json")
		wrapped, err := json.Marshal(map[string]any{"inbounds": []json.RawMessage{raw}})
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(file, wrapped, 0o600); err != nil {
			return nil, err
		}
		add := exec.CommandContext(ctx, bin, "api", "adi", "--server", api, file)
		add.Dir = dir
		out, err := add.CombinedOutput()
		_ = os.Remove(file)
		if err != nil {
			return nil, cmdFail("add "+tag, out, err)
		}
		reapplied[tag] = true
		fmt.Println("adi", tag)
	}
	return reapplied, nil
}

func tagsFrom(raw []byte) []string {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	var tags []string
	var walk func(any)
	walk = func(v any) {
		switch item := v.(type) {
		case map[string]any:
			if tag, ok := item["tag"].(string); ok {
				tags = append(tags, tag)
			}
			for _, child := range item {
				walk(child)
			}
		case []any:
			for _, child := range item {
				walk(child)
			}
		}
	}
	walk(doc)
	return tags
}

func writeGeneration(dir string, generation int) error {
	if err := os.WriteFile(filepath.Join(dir, "applied-generation"), []byte(strconv.Itoa(generation)), 0o600); err != nil {
		return err
	}
	proc.generation = generation
	return nil
}

func writeSkeleton(dir, skel string) error {
	if err := os.WriteFile(filepath.Join(dir, "applied-skeleton"), []byte(skel), 0o600); err != nil {
		return err
	}
	proc.skeleton = skel
	return nil
}

func skeleton(rendered []byte) (string, error) {
	var doc map[string]any
	if err := json.Unmarshal(rendered, &doc); err != nil {
		return "", err
	}
	inbounds, _ := doc["inbounds"].([]any)
	keep := make([]any, 0, len(inbounds))
	for _, item := range inbounds {
		inbound, _ := item.(map[string]any)
		if inbound == nil {
			return "", errors.New("inbound")
		}
		if tag, _ := inbound["tag"].(string); tag == "api" {
			keep = append(keep, item)
		}
	}
	if _, ok := doc["inbounds"]; ok {
		doc["inbounds"] = keep
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:]), nil
}

func writeFiles(dir string, files []desiredFile) (bool, func(), error) {
	type snap struct {
		path    string
		data    []byte
		mode    os.FileMode
		existed bool
	}
	var snaps []snap
	changed := false
	restore := func() {
		for i := len(snaps) - 1; i >= 0; i-- {
			item := snaps[i]
			if !item.existed {
				_ = os.Remove(item.path)
				continue
			}
			_ = os.WriteFile(item.path, item.data, item.mode)
		}
	}
	for _, file := range files {
		if file.Mode != "0644" && file.Mode != "0600" {
			restore()
			return false, nil, errors.New("file mode")
		}
		path, err := safeJoin(dir, file.Path)
		if err != nil {
			restore()
			return false, nil, err
		}
		mode := os.FileMode(0o600)
		if file.Mode == "0644" {
			mode = 0o644
		}
		item := snap{path: path, mode: mode}
		prev, err := os.ReadFile(path)
		if err == nil {
			info, statErr := os.Stat(path)
			item.existed = true
			item.data = prev
			if statErr == nil {
				item.mode = info.Mode().Perm()
			}
			if !bytes.Equal(prev, []byte(file.PEM)) {
				changed = true
			}
		} else if os.IsNotExist(err) {
			changed = true
		} else {
			restore()
			return false, nil, err
		}
		snaps = append(snaps, item)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			restore()
			return false, nil, err
		}
		if err := os.WriteFile(path, []byte(file.PEM), mode); err != nil {
			restore()
			return false, nil, err
		}
	}
	return changed, restore, nil
}

func safeJoin(root, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, `\`) {
		return "", errors.New("path")
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("path")
	}
	full := filepath.Join(root, clean)
	back, err := filepath.Rel(root, full)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(os.PathSeparator)) {
		return "", errors.New("path")
	}
	return full, nil
}

func absolutizeCerts(config []byte, dir string) ([]byte, error) {
	if len(bytes.TrimSpace(config)) == 0 {
		return nil, errors.New("config")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(config, &doc); err != nil {
		return nil, err
	}
	rawInbounds, ok := doc["inbounds"]
	if !ok {
		return config, nil
	}
	var inbounds []map[string]any
	if err := json.Unmarshal(rawInbounds, &inbounds); err != nil {
		return nil, err
	}
	for _, inbound := range inbounds {
		settings, _ := inbound["settings"].(map[string]any)
		stream, _ := inbound["streamSettings"].(map[string]any)
		var tlsSettings map[string]any
		if stream != nil {
			tlsSettings, _ = stream["tlsSettings"].(map[string]any)
		}
		for _, holder := range []map[string]any{settings, tlsSettings} {
			if holder == nil {
				continue
			}
			certs, _ := holder["certificates"].([]any)
			for _, item := range certs {
				cert, _ := item.(map[string]any)
				if cert == nil {
					return nil, errors.New("certificate")
				}
				for _, key := range []string{"certificateFile", "keyFile"} {
					value, _ := cert[key].(string)
					if value == "" {
						return nil, errors.New("certificate")
					}
					abs, err := safeJoin(dir, value)
					if err != nil {
						return nil, err
					}
					cert[key] = abs
				}
			}
		}
	}
	encoded, err := json.Marshal(inbounds)
	if err != nil {
		return nil, err
	}
	doc["inbounds"] = encoded
	return json.Marshal(doc)
}

func inboundRaws(config []byte) (map[string][]byte, error) {
	var doc struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &doc); err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, raw := range doc.Inbounds {
		var item struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, err
		}
		if item.Tag == "" || item.Tag == "api" {
			continue
		}
		out[item.Tag] = append([]byte(nil), raw...)
	}
	return out, nil
}

func safeTag(tag string) bool {
	if tag == "" || len(tag) > 64 {
		return false
	}
	for _, r := range tag {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func safeOut(out []byte) string {
	text := string(bytes.TrimSpace(out))
	lower := strings.ToLower(text)
	if strings.Contains(text, "PRIVATE") || strings.Contains(lower, "password") || strings.Contains(lower, "begin ") {
		return "rejected"
	}
	if len(text) > 200 {
		text = text[:200]
	}
	return text
}

// cmdFail 把命令失败写成可核对的一行。标准输出为空时回退到进程错误；两边都有且不重复时拼在一起。
// 输出与错误都先过 safeOut，密钥类原文不会进日志或心跳。
func cmdFail(prefix string, out []byte, err error) error {
	detail := safeOut(out)
	if err != nil {
		reason := safeOut([]byte(err.Error()))
		switch {
		case detail == "":
			detail = reason
		case reason != "" && reason != detail && !strings.Contains(detail, reason):
			detail += ": " + reason
		}
	}
	if detail == "" {
		detail = "failed"
	}
	return fmt.Errorf("%s: %s", prefix, detail)
}

func Shutdown() {
	proc.mu.Lock()
	defer proc.mu.Unlock()
	stopLocked()
}
