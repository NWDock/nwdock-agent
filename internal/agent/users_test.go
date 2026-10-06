package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestUserJSON(t *testing.T) {
	uuid := "11111111-2222-3333-4444-555555555555"

	vless := sharedDesired{Tag: "sh-vless-20001", Protocol: "vless", Flow: "xtls-rprx-vision"}
	user := userJSON(vless, "sub1", uuid)
	if user["email"] != "sub1" || user["level"] != 1 || user["id"] != uuid {
		t.Fatalf("vless: %v", user)
	}
	if user["flow"] != "xtls-rprx-vision" {
		t.Fatalf("vless user must carry flow: %v", user)
	}
	if _, ok := user["password"]; ok {
		t.Fatalf("vless must not carry password: %v", user)
	}
	if _, ok := userJSON(sharedDesired{Protocol: "vless"}, "sub1", uuid)["flow"]; ok {
		t.Fatal("vless without flow must not carry flow key")
	}

	trojan := userJSON(sharedDesired{Protocol: "trojan"}, "sub1", "pw")
	if trojan["email"] != "sub1" || trojan["level"] != 1 || trojan["password"] != "pw" {
		t.Fatalf("trojan: %v", trojan)
	}
	if _, ok := trojan["id"]; ok {
		t.Fatalf("trojan must not carry id: %v", trojan)
	}
	if _, ok := trojan["method"]; ok {
		t.Fatalf("trojan must not carry method: %v", trojan)
	}

	ss := userJSON(sharedDesired{Protocol: "shadowsocks"}, "sub1", "pw")
	if ss["email"] != "sub1" || ss["level"] != 1 || ss["password"] != "pw" {
		t.Fatalf("shadowsocks: %v", ss)
	}
	if ss["method"] != "aes-256-gcm" {
		t.Fatalf("shadowsocks method must default to aes-256-gcm: %v", ss)
	}
	if _, ok := ss["id"]; ok {
		t.Fatalf("shadowsocks must not carry id: %v", ss)
	}
	explicit := userJSON(sharedDesired{Protocol: "shadowsocks", Method: "chacha20-poly1305"}, "sub1", "pw")
	if explicit["method"] != "chacha20-poly1305" {
		t.Fatalf("explicit method must win: %v", explicit)
	}
}

func TestUserFile(t *testing.T) {
	vless := sharedDesired{Tag: "sh-vless-20001", Protocol: "vless", Flow: "xtls-rprx-vision"}
	raw, err := userFile(vless, "sh-vless-20001", []map[string]any{userJSON(vless, "sub1", "11111111-2222-3333-4444-555555555555")})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Settings struct {
				Decryption string           `json:"decryption"`
				Method     string           `json:"method"`
				Password   string           `json:"password"`
				Clients    []map[string]any `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Inbounds) != 1 {
		t.Fatalf("inbounds: %d", len(doc.Inbounds))
	}
	inbound := doc.Inbounds[0]
	if inbound.Tag != "sh-vless-20001" || inbound.Protocol != "vless" || inbound.Listen != "127.0.0.1" || inbound.Port == 0 {
		t.Fatalf("%+v", inbound)
	}
	if inbound.Settings.Decryption != "none" {
		t.Fatalf("vless needs decryption none: %s", raw)
	}
	if len(inbound.Settings.Clients) != 1 || inbound.Settings.Clients[0]["email"] != "sub1" {
		t.Fatalf("clients: %v", inbound.Settings.Clients)
	}

	ssDefault := sharedDesired{Protocol: "shadowsocks"}
	raw, err = userFile(ssDefault, "sh-ss-20002", []map[string]any{userJSON(ssDefault, "sub2", "pw")})
	if err != nil {
		t.Fatal(err)
	}
	var ss struct {
		Inbounds []struct {
			Protocol string         `json:"protocol"`
			Settings map[string]any `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &ss); err != nil {
		t.Fatal(err)
	}
	settings := ss.Inbounds[0].Settings
	if ss.Inbounds[0].Protocol != "shadowsocks" {
		t.Fatalf("protocol: %s", raw)
	}
	if settings["method"] != "aes-256-gcm" {
		t.Fatalf("shadowsocks inbound needs default method: %s", raw)
	}
	if _, ok := settings["password"]; ok {
		t.Fatalf("non-2022 shadowsocks must not carry server key field: %s", raw)
	}

	ss2022 := sharedDesired{Protocol: "shadowsocks", Method: "2022-blake3-aes-256-gcm"}
	raw, err = userFile(ss2022, "sh-ss-20003", []map[string]any{userJSON(ss2022, "sub3", "psk")})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &ss); err != nil {
		t.Fatal(err)
	}
	settings = ss.Inbounds[0].Settings
	if settings["method"] != "2022-blake3-aes-256-gcm" {
		t.Fatalf("2022 method must pass through: %s", raw)
	}
	password, ok := settings["password"]
	if !ok || password != "" {
		t.Fatalf("2022 shadowsocks needs empty server key field: %s", raw)
	}
}

func TestUserStamp(t *testing.T) {
	item := sharedDesired{Tag: "sh-vless-20001", Protocol: "vless", Flow: "xtls-rprx-vision"}
	want := "vless\x00\x00xtls-rprx-vision\x00uuid1"
	if got := userStamp(sharedUser{Email: "sub1", Secret: "uuid1"}, item); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDiffUsers(t *testing.T) {
	item := sharedDesired{Tag: "sh-ss-20002", Protocol: "shadowsocks", Method: "aes-256-gcm", Users: []sharedUser{
		{Email: "same", Secret: "y"},
		{Email: "changed", Secret: "new"},
		{Email: "fresh", Secret: "z"},
	}}
	have := map[string]string{
		"gone":    "x",
		"same":    userStamp(item.Users[0], item),
		"changed": userStamp(sharedUser{Email: "changed", Secret: "old"}, item),
	}
	drop, add := diffUsers(have, item)
	if len(drop) != 1 || drop[0] != "gone" {
		t.Fatalf("drop: %v", drop)
	}
	var added []string
	for _, user := range add {
		added = append(added, user.Email)
	}
	sort.Strings(added)
	if !reflect.DeepEqual(added, []string{"changed", "fresh"}) {
		t.Fatalf("add: %v", added)
	}

	// method 变化：同一 email 也必须重加。
	methodChange := sharedDesired{Tag: "sh-ss-20002", Protocol: "shadowsocks", Method: "aes-256-gcm", Users: []sharedUser{{Email: "sub1", Secret: "pw"}}}
	have = map[string]string{"sub1": userStamp(methodChange.Users[0], methodChange)}
	methodChange.Method = "chacha20-poly1305"
	drop, add = diffUsers(have, methodChange)
	if len(drop) != 0 || len(add) != 1 || add[0].Email != "sub1" {
		t.Fatalf("method change must re-add: drop %v add %v", drop, add)
	}

	// flow 变化：同一 email 也必须重加。
	vless := sharedDesired{Tag: "sh-vless-20001", Protocol: "vless", Users: []sharedUser{{Email: "sub1", Secret: "uuid"}}}
	have = map[string]string{"sub1": userStamp(vless.Users[0], vless)}
	vless.Flow = "xtls-rprx-vision"
	drop, add = diffUsers(have, vless)
	if len(drop) != 0 || len(add) != 1 || add[0].Email != "sub1" {
		t.Fatalf("flow change must re-add: drop %v add %v", drop, add)
	}

	drop, add = diffUsers(map[string]string{}, item)
	if len(drop) != 0 || len(add) != len(item.Users) {
		t.Fatalf("cold start: drop %v add %v", drop, add)
	}
	steady := sharedDesired{Tag: "sh-ss-20002", Protocol: "shadowsocks", Method: "aes-256-gcm", Users: []sharedUser{{Email: "same", Secret: "y"}}}
	drop, add = diffUsers(map[string]string{"same": userStamp(steady.Users[0], steady)}, steady)
	if len(drop) != 0 || len(add) != 0 {
		t.Fatalf("steady state: drop %v add %v", drop, add)
	}
}

func TestReconcileUsersRejectsUnknownProtocols(t *testing.T) {
	dir := t.TempDir()
	clearAppliedUsers(dir)
	for _, protocol := range []string{"vmess", "ss2022", ""} {
		shared := []sharedDesired{{
			Tag:      "sh-x-20001",
			Protocol: protocol,
			Users:    []sharedUser{{Email: "sub1", Secret: "pw"}},
		}}
		err := reconcileUsers(context.Background(), filepath.Join(dir, "missing-bin"), "127.0.0.1:1", dir, shared)
		if err == nil || !strings.Contains(err.Error(), "shared protocol") {
			t.Fatalf("%q: expected whitelist rejection, got %v", protocol, err)
		}
	}
	if applied := loadAppliedUsers(dir); len(applied) != 0 {
		t.Fatalf("rejected reconcile must not touch applied users: %v", applied)
	}
}

const fakeCoreScript = `#!/bin/sh
log="$FAKE_CORE_LOG"
if [ "$1/$2" = "api/rmu" ]; then
	shift 5
	tag="$1"
	shift
	echo "rmu $tag $*" >> "$log"
	echo "Removed $# user(s) in total."
elif [ "$1/$2" = "api/adu" ]; then
	echo "adu" >> "$log"
	cat "$5" >> "$log"
	echo >> "$log"
	n=$(grep -o '"email"' "$5" | wc -l)
	echo "Added ${n} user(s) in total."
else
	echo "unexpected invocation: $*" >> "$log"
	exit 1
fi
`

func writeFakeCore(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "fake-core.sh")
	if err := os.WriteFile(bin, []byte(fakeCoreScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestReconcileUsersLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	log := filepath.Join(dir, "api.log")
	clearAppliedUsers(dir)
	t.Setenv("FAKE_CORE_LOG", log)
	bin := writeFakeCore(t, dir)
	api := "127.0.0.1:10085"
	run := func(shared []sharedDesired) string {
		t.Helper()
		if err := reconcileUsers(ctx, bin, api, dir, shared); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(log); err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}

	vless := sharedDesired{Tag: "sh-vless-20001", Protocol: "vless", Flow: "xtls-rprx-vision",
		Users: []sharedUser{{Email: "sub1", Secret: "11111111-2222-3333-4444-555555555555"}}}
	ss := sharedDesired{Tag: "sh-ss-20002", Protocol: "shadowsocks",
		Users: []sharedUser{{Email: "sub2", Secret: "pw"}}}

	first := run([]sharedDesired{vless, ss})
	if strings.Contains(first, "rmu ") {
		t.Fatalf("cold start must not remove users: %s", first)
	}
	if strings.Count(first, "adu") != 2 {
		t.Fatalf("cold start must add both inbounds: %s", first)
	}
	if !strings.Contains(first, `"flow":"xtls-rprx-vision"`) {
		t.Fatalf("vless payload must carry flow: %s", first)
	}
	if !strings.Contains(first, `"method":"aes-256-gcm"`) {
		t.Fatalf("shadowsocks payload must carry default method: %s", first)
	}
	applied := loadAppliedUsers(dir)
	want := map[string]map[string]string{
		"sh-vless-20001": {"sub1": userStamp(vless.Users[0], vless)},
		"sh-ss-20002":    {"sub2": userStamp(ss.Users[0], ss)},
	}
	if !reflect.DeepEqual(applied, want) {
		t.Fatalf("applied users: got %v want %v", applied, want)
	}

	ss.Method = "chacha20-poly1305"
	second := run([]sharedDesired{vless, ss})
	if !strings.Contains(second, `"method":"chacha20-poly1305"`) {
		t.Fatalf("method change must re-add with new method: %s", second)
	}
	if strings.Contains(second, "rmu ") {
		t.Fatalf("method change must re-add in place, not drop: %s", second)
	}

	vless.Flow = ""
	third := run([]sharedDesired{vless, ss})
	if strings.Contains(third, `"flow"`) {
		t.Fatalf("cleared flow must disappear from payload: %s", third)
	}
	if strings.Contains(third, "rmu ") {
		t.Fatalf("flow change must re-add in place, not drop: %s", third)
	}

	vless.Users = nil
	fourth := run([]sharedDesired{vless, ss})
	if !strings.Contains(fourth, "rmu sh-vless-20001 sub1") {
		t.Fatalf("removed user must be dropped: %s", fourth)
	}

	err := reconcileUsers(ctx, bin, api, dir, []sharedDesired{{
		Tag: "sh-vmess-20003", Protocol: "vmess",
		Users: []sharedUser{{Email: "sub3", Secret: "pw"}},
	}})
	if err == nil || !strings.Contains(err.Error(), `shared protocol "vmess"`) {
		t.Fatalf("vmess must be rejected by whitelist, got %v", err)
	}

	// 冷启动 + shadowsocks 2022 方法：先移除 bootstrap，再正常加用户。
	clearAppliedUsers(dir)
	ss2022 := sharedDesired{Tag: "sh-ss22-20004", Protocol: "shadowsocks", Method: "2022-blake3-aes-256-gcm",
		Users: []sharedUser{{Email: "sub4", Secret: "psk"}}}
	fifth := run([]sharedDesired{ss2022})
	if !strings.Contains(fifth, "rmu sh-ss22-20004 bootstrap") {
		t.Fatalf("2022 method cold start must remove bootstrap: %s", fifth)
	}
	if !strings.Contains(fifth, `"method":"2022-blake3-aes-256-gcm"`) {
		t.Fatalf("2022 payload must carry method: %s", fifth)
	}
}

func TestAppliedUsersRoundTrip(t *testing.T) {
	dir := t.TempDir()
	applied := map[string]map[string]string{"sh-vless-20001": {"sub1": "uuid1", "sub2": "uuid2"}}
	if err := saveAppliedUsers(dir, applied); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "applied-users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatal(info.Mode())
	}
	loaded := loadAppliedUsers(dir)
	if !reflect.DeepEqual(loaded, applied) {
		t.Fatalf("%v", loaded)
	}
	if got := loadAppliedUsers(filepath.Join(dir, "missing")); len(got) != 0 {
		t.Fatalf("missing file: %v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "applied-users.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadAppliedUsers(dir); len(got) != 0 {
		t.Fatalf("corrupt file: %v", got)
	}
}

func TestReportedCount(t *testing.T) {
	cases := []struct {
		out string
		n   int
		ok  bool
	}{
		{"add user: sub1\nresult: ok\nAdded 1 user(s) in total.\n", 1, true},
		{"Removed 0 user(s) in total.\n", 0, true},
		{"processing inbound: x\nRemoved 12 user(s) in total.\n", 12, true},
		{"failed to build config: boom\n", 0, false},
	}
	for _, c := range cases {
		n, ok := reportedCount([]byte(c.out))
		if n != c.n || ok != c.ok {
			t.Fatalf("%q: got %d %v", c.out, n, ok)
		}
	}
}
