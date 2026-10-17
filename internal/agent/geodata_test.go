package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/memconservative"
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"

	"google.golang.org/protobuf/proto"
)

// writeGeoSiteDat 造一份最小 geosite.dat：CN（Verify 要查）+ china-list（只放一个域名）。
func writeGeoSiteDat(t *testing.T, dir, name, chinaListDomain string) {
	t.Helper()
	list := &router.GeoSiteList{Entry: []*router.GeoSite{
		{CountryCode: "CN", Domain: []*router.Domain{{Type: router.Domain_Full, Value: "cn.example"}}},
		{CountryCode: "china-list", Domain: []*router.Domain{{Type: router.Domain_Full, Value: chinaListDomain}}},
	}}
	raw, err := proto.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// 孪生清理后 embedded Apply 靠 ClearGeoSiteCache 让核重读文件；
// singleflight 带 StoreResult，不清缓存会一直服务旧文件内容。
func TestGeoSiteMatcherReloadsAfterCacheClear(t *testing.T) {
	dir := t.TempDir()
	writeGeoSiteDat(t, dir, "geosite.dat", "a.com")
	C.SetHomeDir(dir)
	if err := geodata.InitGeoSite(); err != nil {
		t.Fatal(err)
	}
	matcher, err := geodata.LoadGeoSiteMatcher("china-list")
	if err != nil {
		t.Fatal(err)
	}
	if !matcher.ApplyDomain("a.com") {
		t.Fatal("a.com should match initially")
	}

	writeGeoSiteDat(t, dir, "geosite.dat", "b.com")
	stale, err := geodata.LoadGeoSiteMatcher("china-list")
	if err != nil {
		t.Fatal(err)
	}
	if !stale.ApplyDomain("a.com") {
		t.Fatal("singleflight cache should still serve old content")
	}

	geodata.ClearGeoSiteCache()
	fresh, err := geodata.LoadGeoSiteMatcher("china-list")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.ApplyDomain("a.com") || !fresh.ApplyDomain("b.com") {
		t.Fatal("cache clear must reload from file")
	}
	geodata.ClearGeoSiteCache()
}
