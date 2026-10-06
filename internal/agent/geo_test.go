package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func testAgentConfig(dir string) Config {
	return Config{DataDir: dir, Endpoints: []string{"https://panel.invalid"}, Pin: "test-pin"}
}

func TestCoreEnvXrayAsset(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	env := coreEnv(coreXray, "/data")
	found := false
	for _, item := range env {
		if item == "XRAY_LOCATION_ASSET=/data" {
			found = true
		}
	}
	if !found {
		t.Fatal("XRAY_LOCATION_ASSET missing")
	}
	if env = coreEnv(coreMihomo, "/data"); len(env) != len(os.Environ()) {
		t.Fatal("mihomo must not get asset env")
	}
	if assetMaxBytes != 64<<20 {
		t.Fatal("asset download limit")
	}
}

func TestSyncAssetsSkipAndReject(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := testAgentConfig(dir)
	cert := tls.Certificate{}

	// 名单外的名字直接拒绝。
	if _, err := syncAssets(ctx, cfg, cert, []geoDesired{{Name: "evil.dat", SHA256: "abc"}}); err == nil {
		t.Fatal("expected error")
	}
	// 空 sha256 拒绝。
	if _, err := syncAssets(ctx, cfg, cert, []geoDesired{{Name: "geoip.dat", SHA256: ""}}); err == nil {
		t.Fatal("expected error")
	}

	// 侧车 hash 一致时跳过，不发网络请求。
	payload := []byte("geoip-bytes")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geo-geoip.dat.sha256"), []byte(digest+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if changed, err := syncAssets(ctx, cfg, cert, []geoDesired{{Name: "geoip.dat", SHA256: digest}}); err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
}

func TestValidAssetName(t *testing.T) {
	for _, ok := range []string{"geoip.dat", "geosite.dat", "cn.srs", "category-ads-all.srs", "a.srs", "0ab-1.srs"} {
		if !validAssetName(ok) {
			t.Fatalf("%s should be valid", ok)
		}
	}
	for _, bad := range []string{"evil.dat", "geo.dat", ".srs", "-cn.srs", "CN.srs", "cn_srs", "cn.SRS", "../evil.srs", "rule-sets/cn.srs", "cn.tar", ""} {
		if validAssetName(bad) {
			t.Fatalf("%s should be invalid", bad)
		}
	}
}

func TestAssetURLRouting(t *testing.T) {
	if got := assetFetchPath("geoip.dat"); got != "/api/agent/geo/geoip.dat" {
		t.Fatalf(".dat path %q", got)
	}
	if got := assetFetchPath("cn.srs"); got != "/api/agent/rule-sets/cn.srs" {
		t.Fatalf(".srs path %q", got)
	}
}
