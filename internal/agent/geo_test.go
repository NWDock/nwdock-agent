package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func testAgentConfig(dir string) Config {
	return Config{DataDir: dir, Endpoints: []string{"wss://panel.invalid/api/agent/channel"}, KeyPin: "test-pin"}
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

	// 名单外的名字直接拒绝。
	if _, err := syncAssets(ctx, cfg, []geoDesired{{Name: "evil.dat", SHA256: "abc"}}); err == nil {
		t.Fatal("expected error")
	}
	// 空 sha256 拒绝。
	if _, err := syncAssets(ctx, cfg, []geoDesired{{Name: "geoip.dat", SHA256: ""}}); err == nil {
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
	if changed, err := syncAssets(ctx, cfg, []geoDesired{{Name: "geoip.dat", SHA256: digest}}); err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
}

func TestSyncAssetsDropsCaseTwins(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := testAgentConfig(dir)

	// 面板已下发 geosite.dat（侧车命中，不发网络请求）。
	payload := []byte("geosite-bytes")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("geosite.dat", string(payload))
	write("geo-geosite.dat.sha256", digest+"\n")
	// 陈旧大写孪生（核自行下载的 MetaCubeX 版）+ .srs 异体 + 清单外文件。
	write("GeoSite.dat", "stale-metacubex")
	write("CN.srs", "stale-twin")
	write("cn.srs", "srs-bytes")
	write("geo-cn.srs.sha256", "unused")
	write("config.yaml", "keep-me")

	changed, err := syncAssets(ctx, cfg, []geoDesired{
		{Name: "geosite.dat", SHA256: digest},
		{Name: "cn.srs", SHA256: "unused"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("twin removal must report change")
	}
	for _, gone := range []string{"GeoSite.dat", "CN.srs"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s must be removed", gone)
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "geosite.dat")); err != nil || !bytes.Equal(data, payload) {
		t.Fatal("delivered file must stay intact")
	}
	if data, err := os.ReadFile(filepath.Join(dir, "config.yaml")); err != nil || string(data) != "keep-me" {
		t.Fatal("unmanaged files must not be touched")
	}
}

func TestSyncAssetsSelfHealMissingFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := testAgentConfig(dir)

	// 侧车命中但文件缺失：必须重拉而不是静默跳过（测试环境无面板，拉取必失败）。
	payload := []byte("geoip-bytes")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, "geo-geoip.dat.sha256"), []byte(digest+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := syncAssets(ctx, cfg, []geoDesired{{Name: "geoip.dat", SHA256: digest}}); err == nil {
		t.Fatal("missing file must trigger re-fetch")
	}
}

func TestValidAssetName(t *testing.T) {
	for _, ok := range []string{"geoip.dat", "geosite.dat", "ASN.mmdb", "cn.srs", "category-ads-all.srs", "a.srs", "0ab-1.srs"} {
		if !validAssetName(ok) {
			t.Fatalf("%s should be valid", ok)
		}
	}
	for _, bad := range []string{"evil.dat", "geo.dat", "asn.mmdb", ".srs", "-cn.srs", "CN.srs", "cn_srs", "cn.SRS", "../evil.srs", "rule-sets/cn.srs", "cn.tar", ""} {
		if validAssetName(bad) {
			t.Fatalf("%s should be invalid", bad)
		}
	}
}

func TestAssetURLRouting(t *testing.T) {
	if got := assetFetchPath("geoip.dat"); got != "/api/agent/files/geo/geoip.dat" {
		t.Fatalf(".dat path %q", got)
	}
	if got := assetFetchPath("cn.srs"); got != "/api/agent/files/rule-sets/cn.srs" {
		t.Fatalf(".srs path %q", got)
	}
}
