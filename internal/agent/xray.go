package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	rt           coreRuntime
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
	Token  string `json:"token"`
}

type ruleSetDesired struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Token  string `json:"token"`
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
func syncAssets(ctx context.Context, cfg Config, entries []geoDesired) (bool, error) {
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
		data, err := fetchAsset(ctx, cfg, entry)
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
		return "/api/agent/files/rule-sets/" + name
	}
	return "/api/agent/files/geo/" + name
}

// assetClient 复用连接；大 geo 文件放宽超时，sha256 校验仍兜底。
var assetClient = &http.Client{Timeout: 5 * time.Minute}

func fetchAsset(ctx context.Context, cfg Config, entry geoDesired) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, channelHTTPBase(cfg.Endpoints[0])+assetFetchPath(entry.Name), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "AgentFile "+entry.Token)
	res, err := assetClient.Do(req)
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

// applyDesired 应用面板经加密通道推送的 desired 载荷（现 desired 端点响应原样）。
func (s *session) applyDesired(ctx context.Context, raw json.RawMessage) error {
	api := coreAPIAddr()
	var body struct {
		Generation int              `json:"generation"`
		Serving    bool             `json:"serving"`
		Core       string           `json:"core"`
		Config     json.RawMessage  `json:"config"`
		Files      []desiredFile    `json:"files"`
		Shared     []sharedDesired  `json:"shared"`
		Geo        []geoDesired     `json:"geo"`
		RuleSets   []ruleSetDesired `json:"rule_sets"`
		Quota      json.RawMessage  `json:"quota"`
		Relays     []relaySpec      `json:"relays"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return err
	}
	// 入口转发与核心完全解耦：清单无条件下发，无论 serving 与核心状态如何都先应用；
	// 之后核心重启、换核或配置失败都不影响已建立的入口转发。
	relayApply(s.cfg.DataDir, body.Relays)
	if len(body.Quota) > 0 && string(body.Quota) != "null" {
		if err := traffic.ApplySnapshot(body.Quota); err != nil {
			return err
		}
	}
	want := normalizeCore(body.Core)
	proc.mu.Lock()
	defer proc.mu.Unlock()
	if !proc.loaded {
		raw, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "applied-generation"))
		if err == nil {
			proc.generation, _ = strconv.Atoi(string(bytes.TrimSpace(raw)))
		}
		raw, err = os.ReadFile(filepath.Join(s.cfg.DataDir, "applied-skeleton"))
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
		_ = os.Remove(filepath.Join(s.cfg.DataDir, "applied-skeleton"))
		clearAppliedUsers(s.cfg.DataDir)
		clearAppliedCore(s.cfg.DataDir)
		return writeGeneration(s.cfg.DataDir, body.Generation)
	}
	var bin string
	if want != coreMihomo {
		bin = coreBin(want)
		if bin == "" {
			return fmt.Errorf("%s is required", coreBinEnv(want))
		}
	}
	assets := make([]geoDesired, 0, len(body.Geo)+len(body.RuleSets))
	assets = append(assets, body.Geo...)
	for _, item := range body.RuleSets {
		assets = append(assets, geoDesired{Name: item.Name, SHA256: item.SHA256, Token: item.Token})
	}
	geoChanged, err := syncAssets(ctx, s.cfg, assets)
	if err != nil {
		return err
	}
	switching := runningLocked() && proc.core != want
	if switching {
		if err := reportStatsLocked(ctx, s); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
		}
	}
	filled, err := materializeWGCF(ctx, s.cfg.DataDir, want, body.Config)
	if err != nil {
		if switching {
			fmt.Fprintf(os.Stderr, "degraded: keeping %s: %s\n", proc.core, err.Error())
		}
		return err
	}
	rendered, changed, err := stageConfig(ctx, s.cfg.DataDir, want, bin, filled, body.Files)
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
	current := filepath.Join(s.cfg.DataDir, coreConfigName(want))
	switch {
	case switching:
		stopLocked()
		if err := bootWithRollback(ctx, s.cfg, api, bin, want, current, raws, skel, body.Shared); err != nil {
			return err
		}
		fmt.Println("switch", want)
	case !runningLocked():
		if err := bootWithRollback(ctx, s.cfg, api, bin, want, current, raws, skel, body.Shared); err != nil {
			return err
		}
	default:
		plan := sameCorePlan(want, proc.skeleton != skel)
		if geoChanged && want != coreMihomo {
			// 外部核心只在启动时加载 geo 数据文件，文件有变必须整进程重启。
			// 内置 clash-meta-nw 重新 Parse 并套用即可。
			plan = planRestart
		}
		switch plan {
		case planRestart:
			if err := restartLocked(ctx, s, s.cfg, api, bin, want, current, raws, skel, body.Shared); err != nil {
				return err
			}
		default:
			if proc.rt == nil {
				return errors.New("core is not running")
			}
			if err := proc.rt.Apply(ctx, current, s.cfg.DataDir, raws, skel, body.Shared, geoChanged, changed); err != nil {
				if !errors.Is(err, errNeedRestart) && want != coreMihomo {
					return err
				}
				fmt.Fprintln(os.Stderr, err.Error())
				if err := restartLocked(ctx, s, s.cfg, api, bin, want, current, raws, skel, body.Shared); err != nil {
					return err
				}
			} else if plan == planReload {
				fmt.Println("reload")
			}
		}
	}
	return writeGeneration(s.cfg.DataDir, body.Generation)
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
	if kind == coreMihomo {
		abs, err := absolutizeMihomo(rendered, dir)
		if err != nil {
			restore()
			return nil, false, err
		}
		rendered = abs
	}
	next := filepath.Join(dir, coreStagingName(kind))
	if err := os.WriteFile(next, rendered, 0o600); err != nil {
		restore()
		return nil, false, err
	}
	if err := testCoreConfig(ctx, kind, bin, next, dir); err != nil {
		restore()
		_ = os.Remove(next)
		return nil, false, err
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

func restartLocked(ctx context.Context, s *session, cfg Config, api, bin string, kind coreKind, current string, raws map[string][]byte, skel string, shared []sharedDesired) error {
	if err := reportStatsLocked(ctx, s); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	stopLocked()
	if err := bootWithRollback(ctx, cfg, api, bin, kind, current, raws, skel, shared); err != nil {
		return err
	}
	fmt.Println("restart")
	return nil
}

func testCoreConfig(ctx context.Context, kind coreKind, bin, config, dir string) error {
	if kind == coreMihomo {
		return newEmbeddedRuntime().Test(ctx, config, dir)
	}
	return newExecRuntime(kind, bin, coreAPIAddr()).Test(ctx, config, dir)
}

func startLocked(ctx context.Context, kind coreKind, bin, config, dir string) error {
	var rt coreRuntime
	var err error
	if kind == coreMihomo {
		rt = newEmbeddedRuntime()
		err = rt.Start(ctx, config, dir)
	} else {
		rt = newExecRuntime(kind, bin, coreAPIAddr())
		err = rt.Start(ctx, config, dir)
	}
	if err != nil {
		if rt != nil {
			rt.Stop()
		}
		return err
	}
	proc.rt = rt
	proc.core = kind
	proc.version = rt.Version()
	return nil
}

func runningLocked() bool {
	return proc.rt != nil && proc.rt.Running()
}

func runningCoreInfo() (coreKind, string) {
	proc.mu.Lock()
	defer proc.mu.Unlock()
	if proc.rt == nil || !proc.rt.Running() {
		return "", ""
	}
	return proc.core, proc.version
}

func stopLocked() {
	if proc.rt != nil {
		proc.rt.Stop()
		proc.rt = nil
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
	relayStop()
}
