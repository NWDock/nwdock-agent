package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSkeletonIgnoresBusinessInbounds(t *testing.T) {
	a := []byte(`{"log":{"level":"warn"},"inbounds":[{"port":10085,"tag":"api"},{"listen":"0.0.0.0","port":20000,"tag":"nw-a-20000"}],"routing":{"rules":[]}}`)
	b := []byte(`{"routing":{"rules":[]},"inbounds":[{"tag":"nw-b-30000","port":30000},{"tag":"api","port":10085}],"log":{"level":"warn"}}`)
	sa, err := skeleton(a)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := skeleton(b)
	if err != nil {
		t.Fatal(err)
	}
	if sa != sb {
		t.Fatal("business inbounds and key order must not affect skeleton")
	}
	if len(sa) != 64 {
		t.Fatal(sa)
	}
}

func TestSkeletonDetectsSkeletonChange(t *testing.T) {
	base := []byte(`{"inbounds":[{"tag":"api","port":10085}],"routing":{"rules":[]}}`)
	changed := []byte(`{"inbounds":[{"tag":"api","port":10085}],"routing":{"rules":[{"type":"field","outboundTag":"block"}]}}`)
	sb, err := skeleton(base)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := skeleton(changed)
	if err != nil {
		t.Fatal(err)
	}
	if sb == sc {
		t.Fatal("routing change must change skeleton")
	}
}

func TestSkeletonRejectsBadJSON(t *testing.T) {
	if _, err := skeleton([]byte(`{`)); err == nil {
		t.Fatal("expected error")
	}
	if _, err := skeleton([]byte(`{"inbounds":["x"]}`)); err == nil {
		t.Fatal("expected inbound error")
	}
}

func TestAbsolutizeCerts(t *testing.T) {
	config := []byte(`{"inbounds":[
		{"tag":"nw-a-20000","settings":{"certificates":[{"certificateFile":"certs/c1/fullchain.pem","keyFile":"certs/c1/key.pem"}]}},
		{"tag":"sh-vless-20001","streamSettings":{"tlsSettings":{"certificates":[{"certificateFile":"certs/c1/fullchain.pem","keyFile":"certs/c1/key.pem"}]}}},
		{"tag":"sh-ss-20002"}
	]}`)
	out, err := absolutizeCerts(config, "/data")
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{"/data/certs/c1/fullchain.pem", "/data/certs/c1/key.pem"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in %s", want, text)
		}
	}
	if strings.Contains(text, `"certificateFile": "certs/`) {
		t.Fatalf("relative certificate path left in %s", text)
	}
}

func TestAbsolutizeMihomo(t *testing.T) {
	const wgKey = "oI/4kH8vN2pQ6sT0uW4yA8cE1gJ5mL9nR3bD7fH0iK="
	config := []byte(`{"listeners":[{"name":"nw","certificate":"certs/n/fullchain.pem","private-key":"certs/n/key.pem"}],"proxies":[{"name":"warp","type":"wireguard","private-key":"` + wgKey + `"}]}`)
	out, err := absolutizeMihomo(config, "/data")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Listeners []struct {
			Certificate string `json:"certificate"`
			PrivateKey  string `json:"private-key"`
		} `json:"listeners"`
		Proxies []struct {
			Type       string `json:"type"`
			PrivateKey string `json:"private-key"`
		} `json:"proxies"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Listeners) != 1 || len(doc.Proxies) != 1 {
		t.Fatalf("%s", out)
	}
	if doc.Listeners[0].Certificate != "/data/certs/n/fullchain.pem" || doc.Listeners[0].PrivateKey != "/data/certs/n/key.pem" {
		t.Fatalf("listener certs: %+v", doc.Listeners[0])
	}
	if doc.Proxies[0].Type != "wireguard" || doc.Proxies[0].PrivateKey != wgKey {
		t.Fatalf("wireguard key changed: %s", doc.Proxies[0].PrivateKey)
	}
}

type fakeCoreRuntime struct{ running bool }

func (f *fakeCoreRuntime) Kind() coreKind { return coreXray }
func (f *fakeCoreRuntime) Test(context.Context, string, string) error {
	return nil
}
func (f *fakeCoreRuntime) Start(context.Context, string, string) error {
	f.running = true
	return nil
}
func (f *fakeCoreRuntime) Apply(context.Context, string, string, map[string][]byte, string, []sharedDesired, bool, bool) error {
	return nil
}
func (f *fakeCoreRuntime) Stop()           { f.running = false }
func (f *fakeCoreRuntime) Running() bool   { return f.running }
func (f *fakeCoreRuntime) Version() string { return "test" }
func (f *fakeCoreRuntime) Counters(context.Context) (map[string]int64, error) {
	return nil, nil
}

// 核心启动时刻的记录与清理：startLocked 成功后有值（心跳据此发 core_started_at），
// stopLocked 与意外退出善后（exec.go 清 core/version）后必须回到零值。
func TestCoreStartedAtLifecycle(t *testing.T) {
	resetProc := func(rt coreRuntime, startedAt time.Time) {
		proc.mu.Lock()
		proc.rt, proc.core, proc.version, proc.startedAt = rt, "", "", time.Time{}
		if rt != nil {
			proc.core, proc.version = coreXray, rt.Version()
		}
		proc.startedAt = startedAt
		proc.mu.Unlock()
	}
	resetProc(nil, time.Time{})
	defer resetProc(nil, time.Time{})

	if got := runningCoreStartedAt(); !got.IsZero() {
		t.Fatalf("not running must be zero, got %v", got)
	}

	booted := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	resetProc(&fakeCoreRuntime{running: true}, booted)
	got := runningCoreStartedAt()
	if got.IsZero() || !got.Equal(booted) {
		t.Fatalf("running: want %v got %v", booted, got)
	}

	stopLocked()
	if !runningCoreStartedAt().IsZero() {
		t.Fatal("stopLocked must clear startedAt")
	}

	resetProc(&fakeCoreRuntime{running: false}, booted)
	if got := runningCoreStartedAt(); !got.IsZero() {
		t.Fatalf("crashed core must be zero, got %v", got)
	}
}

func TestWriteFilesSkipsUnchangedWrite(t *testing.T) {
	dir := t.TempDir()
	files := []desiredFile{{Path: "certs/a.pem", Mode: "0644", PEM: "cert-v1"}}
	changed, _, err := writeFiles(dir, files)
	if err != nil || !changed {
		t.Fatalf("first writeFiles: changed=%v err=%v", changed, err)
	}
	target := filepath.Join(dir, "certs/a.pem")
	past := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(target, past, past); err != nil {
		t.Fatal(err)
	}

	// 内容与权限均未变时，不得触发写盘，避免惊动证书文件监听。
	changed, _, err = writeFiles(dir, files)
	if err != nil || changed {
		t.Fatalf("unchanged writeFiles: changed=%v err=%v", changed, err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(past) {
		t.Fatalf("unchanged file must not be rewritten: mtime=%v want=%v", info.ModTime(), past)
	}

	// 内容变化时正常写盘并返回 changed=true。
	changed, _, err = writeFiles(dir, []desiredFile{{Path: "certs/a.pem", Mode: "0644", PEM: "cert-v2"}})
	if err != nil || !changed {
		t.Fatalf("updated writeFiles: changed=%v err=%v", changed, err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "cert-v2" {
		t.Fatalf("updated content=%q err=%v", data, err)
	}
}

func TestStageConfigSkipsUnchangedTest(t *testing.T) {
	dir := t.TempDir()
	raw := json.RawMessage(`{"log-level":"silent","rules":["MATCH,DIRECT"]}`)
	rendered, err := absolutizeMihomo(raw, dir)
	if err != nil {
		t.Fatal(err)
	}
	// 当 prevBytes 与渲染后字节完全一致且文件未变时，skipUnchangedTest=true 必须直接短路，
	// 不写 staging 文件也不触发核心 test。
	got, changed, err := stageConfig(context.Background(), dir, coreMihomo, "", raw, nil, rendered, true, true)
	if err != nil || changed {
		t.Fatalf("stageConfig unchanged: changed=%v err=%v", changed, err)
	}
	if string(got) != string(rendered) {
		t.Fatalf("rendered mismatch: got %s want %s", got, rendered)
	}
	if _, err := os.Stat(filepath.Join(dir, coreStagingName(coreMihomo))); !os.IsNotExist(err) {
		t.Fatalf("expected staging file not written on unchanged short-circuit, stat err=%v", err)
	}
}

// 回归：端口在同一次 desired 变更里从核心入站让给入口/独立转发时，
// applyDesired 必须在核心释放端口后立刻重试失败转发，不等下一次 15s 心跳。
func TestApplyDesiredCoreToRelayPortHandoff(t *testing.T) {
	dir := t.TempDir()
	resetRelay(dir)
	resetTraffic()
	t.Cleanup(func() {
		Shutdown()
		resetTraffic()
		proc.mu.Lock()
		proc.generation = 0
		proc.loaded = false
		proc.lastDesired = nil
		proc.mu.Unlock()
	})
	proc.mu.Lock()
	proc.rt = nil
	proc.core = ""
	proc.version = ""
	proc.generation = 0
	proc.loaded = false
	proc.mu.Unlock()

	portP := freeDualPort(t)
	portQ := freeDualPort(t)
	sink := echoSink(t)
	s := &session{cfg: Config{Runtime: "service", DataDir: dir}}

	mkMihomo := func(port int) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{
			"log-level":"silent",
			"find-process-mode":"off",
			"listeners":[{"name":"nw-%d","type":"nowhere","listen":"0.0.0.0","port":%d,"password":"%s","alpn":["nw3"],"net":"udp","morph":true}],
			"rules":["MATCH,DIRECT"]
		}`, port, port, trafficTestPassword))
	}

	// 世代 1：核心占着 portP（UDP）。
	d1, err := json.Marshal(desiredBody{
		Generation: 1,
		Serving:    true,
		Core:       "mihomo",
		Config:     mkMihomo(portP),
		Forwards:   []forwardDesired{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.applyDesired(context.Background(), d1); err != nil {
		t.Fatalf("applyDesired gen 1: %v", err)
	}

	// 世代 2：核心改听 portQ，同时独立转发接管 portP（TCP+UDP）。
	// relayApplyAll 先执行会短暂撞上核心占着的 portP，核心切换完成后必须立即自愈。
	d2, err := json.Marshal(desiredBody{
		Generation: 2,
		Serving:    true,
		Core:       "mihomo",
		Config:     mkMihomo(portQ),
		Forwards: []forwardDesired{{
			ID:           "fwd-handoff",
			Port:         portP,
			TargetHost:   "127.0.0.1",
			TargetPort:   sink,
			TCP:          true,
			UDP:          true,
			AllowPrivate: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.applyDesired(context.Background(), d2); err != nil {
		t.Fatalf("applyDesired gen 2: %v", err)
	}

	// 直接检查引擎状态（不借助 relayHeartbeatStates 内的重试），必须已经监听成功。
	relayEng.mu.Lock()
	h := relayEng.handles[relayForwardKey("fwd-handoff")]
	if h == nil || h.err != "" {
		relayEng.mu.Unlock()
		t.Fatalf("expected forward on port %d recovered immediately after core handoff, got %+v", portP, h)
	}
	relayEng.mu.Unlock()

	// 世代 3：整机停服（serving=false），同时把核心刚释放的 portQ 交给入口转发。
	d3, err := json.Marshal(desiredBody{
		Generation: 3,
		Serving:    false,
		Core:       "mihomo",
		Relays:     []relaySpec{{Port: portQ, TargetHost: "127.0.0.1", TargetPort: sink, TCP: true, UDP: true}},
		Forwards:   []forwardDesired{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.applyDesired(context.Background(), d3); err != nil {
		t.Fatalf("applyDesired gen 3: %v", err)
	}

	relayEng.mu.Lock()
	h2 := relayEng.handles[relayPortKey(portQ)]
	if h2 == nil || h2.err != "" {
		relayEng.mu.Unlock()
		t.Fatalf("expected legacy relay on port %d recovered immediately after core stop, got %+v", portQ, h2)
	}
	relayEng.mu.Unlock()
}

// 回归：execRuntime.Stop() 必须等被杀子进程真正退出回收 FD 再返回，避免重启立刻抢绑端口失败。
func TestExecRuntimeStopWaitsForProcessExit(t *testing.T) {
	cmd := exec.Command("sh", "-c", "sleep 30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sh sleep: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	rt := &execRuntime{kind: coreXray, cmd: cmd, done: done}
	rt.Stop()

	select {
	case <-done:
	default:
		t.Fatal("execRuntime.Stop returned before child process exited")
	}
	if rt.Running() {
		t.Fatal("execRuntime.Running must be false after Stop")
	}
}
