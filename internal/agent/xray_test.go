package agent

import (
	"encoding/json"
	"strings"
	"testing"
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
