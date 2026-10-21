package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterializeWGCFRegistersOnce(t *testing.T) {
	_, peer, err := newWGCFKey()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{
		"id": "dev-1",
		"token": "token-1",
		"config": {
			"client_id": "AQID",
			"peers": [{
				"public_key": "` + peer + `",
				"endpoint": {"v4": "162.159.192.1:0", "v6": "[2606:4700:d0::a29f:c001]:0", "host": "engage.cloudflareclient.com:2408", "ports": [2408, 500]}
			}],
			"interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8f3a::1"}}
		}
	}`)
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		if r.URL.Path == "/v0a1922/reg" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errno":1020}`))
			return
		}
		if r.Header.Get("CF-Client-Version") != "a-6.10-2158" || r.Header.Get("User-Agent") != "okhttp/3.12.1" {
			t.Errorf("headers %v", r.Header)
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	saved := wgcfLive
	t.Cleanup(func() { wgcfLive = saved })
	wgcfLive = wgcfAPI{base: srv.URL, client: srv.Client()}

	dir := t.TempDir()
	ctx := context.Background()
	original := json.RawMessage(`{"proxies":[{"name":"direct","type":"direct","udp":true},{"name":"warp","type":"wgcf"}],"rules":["MATCH,warp"]}`)
	out, err := materializeWGCF(ctx, dir, coreMihomo, original)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{
		`"type":"wireguard"`,
		`"server":"162.159.192.1"`,
		`"ip":"172.16.0.2/32"`,
		`"ipv6":"2606:4700:110:8f3a::1/128"`,
		`"reserved":[1,2,3]`,
		`MATCH,warp`,
		`"name":"direct"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in %s", want, text)
		}
	}
	if strings.Contains(text, `"type":"wgcf"`) {
		t.Fatalf("placeholder left in %s", text)
	}
	if len(hits) != 2 || hits[0] != "/v0a1922/reg" || hits[1] != "/v0a2158/reg" {
		t.Fatalf("hits %v", hits)
	}
	info, err := os.Stat(filepath.Join(dir, "wgcf", "warp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "wgcf", "warp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"token":"token-1"`) || !strings.Contains(text, `"private-key":"`) {
		t.Fatal("identity or proxy missing key material")
	}
	if !strings.Contains(string(raw), `"endpoint":"162.159.192.1"`) || strings.Contains(string(raw), `"endpoint":"162.159.192.1:0"`) {
		t.Fatalf("endpoint kept its port: %s", raw)
	}

	again, err := materializeWGCF(ctx, dir, coreMihomo, original)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != text {
		t.Fatalf("second pass changed config")
	}
	if len(hits) != 2 {
		t.Fatalf("registered again: %v", hits)
	}

	xrayIn := json.RawMessage(`{"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"wgcf","tag":"warp"}]}`)
	xrayOut, err := materializeWGCF(ctx, dir, coreXray, xrayIn)
	if err != nil {
		t.Fatal(err)
	}
	xrayText := string(xrayOut)
	if !strings.Contains(xrayText, `"protocol":"wireguard"`) || !strings.Contains(xrayText, `"noKernelTun":true`) || !strings.Contains(xrayText, `"endpoint":"162.159.192.1:2408"`) {
		t.Fatalf("%s", xrayText)
	}
	if !strings.Contains(xrayText, `{"protocol":"freedom","tag":"direct"}`) {
		t.Fatalf("sibling outbound rewritten: %s", xrayText)
	}

	singIn := json.RawMessage(`{"outbounds":[{"type":"direct","tag":"direct"},{"type":"wgcf","tag":"warp"}]}`)
	singOut, err := materializeWGCF(ctx, dir, coreSingbox, singIn)
	if err != nil {
		t.Fatal(err)
	}
	singText := string(singOut)
	if !strings.Contains(singText, `"endpoints":[`) || !strings.Contains(singText, `"private_key"`) || strings.Contains(singText, `"type":"wgcf"`) {
		t.Fatalf("%s", singText)
	}
	if !strings.Contains(singText, `{"type":"direct","tag":"direct"}`) {
		t.Fatalf("sibling outbound rewritten: %s", singText)
	}
	if !strings.Contains(singText, `"address":"162.159.192.1"`) || !strings.Contains(singText, `"port":2408`) {
		t.Fatalf("sing-box peer endpoint is wrong: %s", singText)
	}
	if len(hits) != 2 {
		t.Fatalf("registered again: %v", hits)
	}

	untouched := json.RawMessage(`{"outbounds":[{"protocol":"freedom","tag":"direct"}]}`)
	same, err := materializeWGCF(ctx, dir, coreXray, untouched)
	if err != nil {
		t.Fatal(err)
	}
	if string(same) != string(untouched) {
		t.Fatalf("rewrote config without wgcf: %s", same)
	}

	// 旧版本把 v4 原样存成 162.159.192.1:0；加载时应判过期并换新身份重新注册。
	legacy := strings.Replace(string(raw), `"endpoint":"162.159.192.1"`, `"endpoint":"162.159.192.1:0"`, 1)
	if legacy == string(raw) {
		t.Fatal("failed to build legacy identity")
	}
	if err := os.WriteFile(filepath.Join(dir, "wgcf", "warp.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	renewed, err := materializeWGCF(ctx, dir, coreMihomo, original)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 4 {
		t.Fatalf("legacy identity was not re-registered: %v", hits)
	}
	if !strings.Contains(string(renewed), `"server":"162.159.192.1"`) {
		t.Fatalf("renewed identity is wrong: %s", renewed)
	}
	if after, err := os.ReadFile(filepath.Join(dir, "wgcf", "warp.json")); err != nil || strings.Contains(string(after), `:0"`) {
		t.Fatalf("legacy identity was not rewritten: %s", after)
	}

	if err := os.WriteFile(filepath.Join(dir, "wgcf", "warp.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := materializeWGCF(ctx, dir, coreMihomo, original); err == nil {
		t.Fatal("expected unreadable identity to fail")
	}
	if len(hits) != 4 {
		t.Fatalf("corrupt identity registered again: %v", hits)
	}
}

func TestWarpEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		v4, v6   string
		host     string
		ports    []int
		want     string
		wantPort int
		wantErr  bool
	}{
		{"v4 带端口", "162.159.192.2:0", "[2606:4700:d0::a29f:c002]:0", "engage.cloudflareclient.com:2408", []int{2408, 500}, "162.159.192.2", 2408, false},
		{"只有 v6", "", "[2606:4700:d0::a29f:c002]:0", "", []int{500, 2408}, "2606:4700:d0::a29f:c002", 2408, false},
		{"回落到 host", "", "", "engage.cloudflareclient.com:2408", nil, "engage.cloudflareclient.com", 2408, false},
		{"全空", "", "", "", []int{2408}, "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := warpEndpoint(tt.v4, tt.v6, tt.host, tt.ports)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q %d", host, port)
				}
				return
			}
			if err != nil || host != tt.want || port != tt.wantPort {
				t.Fatalf("got %q %d %v, want %q %d", host, port, err, tt.want, tt.wantPort)
			}
		})
	}
}
