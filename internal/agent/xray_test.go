package agent

import (
	"context"
	"encoding/json"
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
