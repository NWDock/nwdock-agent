package envfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	body := strings.Join([]string{
		"# comment",
		"",
		"export NOWHERE_ENVFILE_PLAIN=plain",
		`NOWHERE_ENVFILE_QUOTED="a b\n"`,
		"NOWHERE_ENVFILE_SINGLE='keep $dollar'",
		"NOWHERE_ENVFILE_URL=postgres://change-me@db.example:5432/nowhere?sslmode=disable",
		"NOWHERE_ENVFILE_EMPTY=",
		"NOWHERE_ENVFILE_DUP=first",
		"NOWHERE_ENVFILE_DUP=second",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := []string{
		"NOWHERE_ENVFILE_PLAIN",
		"NOWHERE_ENVFILE_QUOTED",
		"NOWHERE_ENVFILE_SINGLE",
		"NOWHERE_ENVFILE_URL",
		"NOWHERE_ENVFILE_EMPTY",
		"NOWHERE_ENVFILE_DUP",
		"NOWHERE_ENVFILE_KEEP",
	}
	for _, key := range keys {
		restoreEnv(t, key)
	}
	t.Setenv("NOWHERE_ENVFILE_KEEP", "shell")
	if err := os.WriteFile(path, []byte(body+"\nNOWHERE_ENVFILE_KEEP=file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	assertEnv(t, "NOWHERE_ENVFILE_PLAIN", "plain")
	assertEnv(t, "NOWHERE_ENVFILE_QUOTED", "a b\n")
	assertEnv(t, "NOWHERE_ENVFILE_SINGLE", "keep $dollar")
	assertEnv(t, "NOWHERE_ENVFILE_URL", "postgres://change-me@db.example:5432/nowhere?sslmode=disable")
	assertEnv(t, "NOWHERE_ENVFILE_EMPTY", "")
	assertEnv(t, "NOWHERE_ENVFILE_DUP", "second")
	assertEnv(t, "NOWHERE_ENVFILE_KEEP", "shell")
}

func TestExampleFile(t *testing.T) {
	loadExample(t, filepath.Join("..", "..", ".env.agent.example"))
	assertEnv(t, "AGENT_RUNTIME", "service")
	assertEnv(t, "AGENT_DATA_DIR", "./data")
}

func loadExample(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("example line without equals")
		}
		restoreEnv(t, strings.TrimSpace(key))
	}
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func TestReadLeavesEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.conf")
	body := "NOWHERE_ENVFILE_FILE=from-file\nNOWHERE_ENVFILE_ONLY_ENV=from-file\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	restoreEnv(t, "NOWHERE_ENVFILE_FILE")
	restoreEnv(t, "NOWHERE_ENVFILE_ONLY_ENV")
	t.Setenv("NOWHERE_ENVFILE_FILE", "from-env")
	values, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if values["NOWHERE_ENVFILE_FILE"] != "from-file" || values["NOWHERE_ENVFILE_ONLY_ENV"] != "from-file" {
		t.Fatal(values)
	}
	assertEnv(t, "NOWHERE_ENVFILE_FILE", "from-env")
	if _, ok := os.LookupEnv("NOWHERE_ENVFILE_ONLY_ENV"); ok {
		t.Fatal("Read changed the environment")
	}
}

func TestReadMissing(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadMissing(t *testing.T) {
	if err := Load(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatal(err)
	}
}

func TestLoadInvalidDoesNotApply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	secret := "NOWHERE_ENVFILE_SECRET=super-secret\nNOT A LINE\n"
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	restoreEnv(t, "NOWHERE_ENVFILE_SECRET")
	err := Load(path)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv("NOWHERE_ENVFILE_SECRET"); ok {
		t.Fatal("invalid file changed the environment")
	}
}

func restoreEnv(t *testing.T, key string) {
	t.Helper()
	prev, ok := os.LookupEnv(key)
	t.Cleanup(func() {
		if ok {
			os.Setenv(key, prev)
		} else {
			os.Unsetenv(key)
		}
	})
	os.Unsetenv(key)
}

func assertEnv(t *testing.T, key, want string) {
	t.Helper()
	got, ok := os.LookupEnv(key)
	if !ok || got != want {
		t.Fatalf("%s = %q, ok=%v", key, got, ok)
	}
}

func TestLoadProjectPrefersWorkingDir(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.panel"), []byte("NOWHERE_ENVFILE_PARENT=parent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, ".env.panel"), []byte("NOWHERE_ENVFILE_PARENT=here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restoreEnv(t, "NOWHERE_ENVFILE_PARENT")
	t.Chdir(sub)
	dir, legacy, err := LoadProject(".env.panel", ".env")
	if err != nil {
		t.Fatal(err)
	}
	if dir != "." || legacy {
		t.Fatalf("dir=%q legacy=%v", dir, legacy)
	}
	assertEnv(t, "NOWHERE_ENVFILE_PARENT", "here")
}

func TestLoadProjectParentAndLegacy(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("NOWHERE_ENVFILE_LEGACY=old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restoreEnv(t, "NOWHERE_ENVFILE_LEGACY")
	t.Chdir(sub)
	dir, legacy, err := LoadProject(".env.panel", ".env")
	if err != nil {
		t.Fatal(err)
	}
	if dir != ".." || !legacy {
		t.Fatalf("dir=%q legacy=%v", dir, legacy)
	}
	assertEnv(t, "NOWHERE_ENVFILE_LEGACY", "old")
	if got := Against("..", "./data"); got == "./data" || !filepath.IsAbs(got) {
		t.Fatal(got)
	}
	want, err := filepath.Abs(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	if Against("..", "./data") != want {
		t.Fatalf("against %s want %s", Against("..", "./data"), want)
	}
	if Against(".", "./data") != "./data" || Against("..", "/var/lib/data") != "/var/lib/data" {
		t.Fatal("absolute and cwd paths must stay")
	}
}
