package agent

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeCore(t *testing.T) {
	cases := []struct {
		in   string
		want coreKind
	}{
		{"", coreXray},
		{"xray", coreXray},
		{"mihomo", coreMihomo},
		{"singbox", coreSingbox},
		{"SingBox", coreXray},
		{"garbage", coreXray},
	}
	for _, c := range cases {
		if got := normalizeCore(c.in); got != c.want {
			t.Fatalf("%q: got %s want %s", c.in, got, c.want)
		}
	}
}

func TestCoreBinFromEnv(t *testing.T) {
	t.Setenv("AGENT_XRAY_BIN", "")
	t.Setenv("AGENT_MIHOMO_BIN", "")
	t.Setenv("AGENT_SINGBOX_BIN", "")
	t.Setenv("XRAY_BIN", "/opt/xray")
	t.Setenv("MIHOMO_BIN", "/opt/mihomo")
	t.Setenv("SINGBOX_BIN", "/opt/sing-box")
	for _, c := range []struct {
		kind coreKind
		env  string
		bin  string
	}{
		{coreXray, "AGENT_XRAY_BIN", "/opt/xray"},
		{coreMihomo, "AGENT_MIHOMO_BIN", "/opt/mihomo"},
		{coreSingbox, "AGENT_SINGBOX_BIN", "/opt/sing-box"},
	} {
		if got := coreBin(c.kind); got != c.bin {
			t.Fatalf("%s bin: got %q want %q", c.kind, got, c.bin)
		}
		if got := coreBinEnv(c.kind); got != c.env {
			t.Fatalf("%s env: got %q want %q", c.kind, got, c.env)
		}
	}
	t.Setenv("AGENT_XRAY_BIN", "/opt/agent-xray")
	if got := coreBin(coreXray); got != "/opt/agent-xray" {
		t.Fatalf("new name must win, got %q", got)
	}
	t.Setenv("AGENT_MIHOMO_BIN", "")
	t.Setenv("MIHOMO_BIN", "")
	if got := coreBin(coreMihomo); got != "" {
		t.Fatalf("missing mihomo bin must stay empty, got %q", got)
	}
}

func TestCoreAPIAddr(t *testing.T) {
	t.Setenv("AGENT_XRAY_API_ADDR", "")
	t.Setenv("XRAY_API_ADDR", "")
	if got := coreAPIAddr(); got != "127.0.0.1:10085" {
		t.Fatal(got)
	}
	t.Setenv("XRAY_API_ADDR", "127.0.0.1:19090")
	if got := coreAPIAddr(); got != "127.0.0.1:19090" {
		t.Fatal(got)
	}
}

func TestCoreConfigNames(t *testing.T) {
	for _, c := range []struct {
		kind    coreKind
		config  string
		staging string
	}{
		{coreXray, "config.json", "config.next.json"},
		{coreMihomo, "config.yaml", "config.next.yaml"},
		{coreSingbox, "singbox.json", "singbox.next.json"},
	} {
		if got := coreConfigName(c.kind); got != c.config {
			t.Fatalf("%s config: got %q want %q", c.kind, got, c.config)
		}
		if got := coreStagingName(c.kind); got != c.staging {
			t.Fatalf("%s staging: got %q want %q", c.kind, got, c.staging)
		}
	}
}

func TestCoreCommands(t *testing.T) {
	for _, c := range []struct {
		kind    coreKind
		test    []string
		run     []string
		version []string
	}{
		{coreXray,
			[]string{"run", "-test", "-c", "/d/config.next.json"},
			[]string{"run", "-c", "/d/config.json"},
			[]string{"version"}},
		{coreMihomo,
			[]string{"-d", "/d", "-t", "-f", "/d/config.next.yaml"},
			[]string{"-d", "/d", "-f", "/d/config.yaml"},
			[]string{"-v"}},
		{coreSingbox,
			[]string{"check", "-c", "/d/singbox.next.json"},
			[]string{"run", "-c", "/d/singbox.json"},
			[]string{"version"}},
	} {
		config := "/d/" + coreConfigName(c.kind)
		staging := "/d/" + coreStagingName(c.kind)
		if got := coreTestArgs(c.kind, staging, "/d"); !reflect.DeepEqual(got, c.test) {
			t.Fatalf("%s test args: got %v want %v", c.kind, got, c.test)
		}
		if got := coreRunArgs(c.kind, config, "/d"); !reflect.DeepEqual(got, c.run) {
			t.Fatalf("%s run args: got %v want %v", c.kind, got, c.run)
		}
		if got := coreVersionArgs(c.kind); !reflect.DeepEqual(got, c.version) {
			t.Fatalf("%s version args: got %v want %v", c.kind, got, c.version)
		}
	}
}

func TestSameCorePlan(t *testing.T) {
	for _, c := range []struct {
		kind            coreKind
		skeletonChanged bool
		want            corePlan
	}{
		{coreXray, false, planHot},
		{coreXray, true, planRestart},
		{coreMihomo, false, planReload},
		{coreMihomo, true, planReload},
		{coreSingbox, false, planRestart},
		{coreSingbox, true, planRestart},
	} {
		if got := sameCorePlan(c.kind, c.skeletonChanged); got != c.want {
			t.Fatalf("%s changed=%v: got %d want %d", c.kind, c.skeletonChanged, got, c.want)
		}
	}
}

func TestCmdFail(t *testing.T) {
	secret := "s3cret-value"
	cases := []struct {
		name   string
		out    string
		err    error
		want   string
		absent string
	}{
		{
			name: "empty output keeps exec error",
			err:  errors.New("fork/exec /opt/sing-box: no such file or directory"),
			want: "singbox test: fork/exec /opt/sing-box: no such file or directory",
		},
		{
			name: "keeps check text and exit status",
			out:  "parse error at line 1",
			err:  errors.New("exit status 1"),
			want: "singbox test: parse error at line 1: exit status 1",
		},
		{
			name:   "password redacted",
			out:    "password: " + secret,
			err:    errors.New("exit status 1"),
			want:   "singbox test: rejected: exit status 1",
			absent: secret,
		},
		{
			name: "blank output and blank error",
			want: "singbox test: failed",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cmdFail("singbox test", []byte(c.out), c.err).Error()
			if got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
			if c.absent != "" && strings.Contains(got, c.absent) {
				t.Fatalf("secret leaked: %q", got)
			}
		})
	}
}

func TestAppliedCorePersistence(t *testing.T) {
	dir := t.TempDir()
	if err := writeAppliedCore(dir, coreMihomo); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "applied-core")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "mihomo" {
		t.Fatalf("content: %q", raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatal(info.Mode())
	}
	clearAppliedCore(dir)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("applied-core must be removed: %v", err)
	}
}
