package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeJoin(t *testing.T) {
	dir := t.TempDir()
	if _, err := safeJoin(dir, "../x"); err == nil {
		t.Fatal("parent")
	}
	if _, err := safeJoin(dir, "/etc/passwd"); err == nil {
		t.Fatal("absolute")
	}
	got, err := safeJoin(dir, "certs/a/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, filepath.Join("certs", "a", "key.pem")) {
		t.Fatal(got)
	}
}

func TestWriteFilesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	changed, restore, err := writeFiles(dir, []desiredFile{{
		Path: "certs/a/key.pem", PEM: "secret\n", Mode: "0600",
	}})
	if err != nil || !changed || restore == nil {
		t.Fatal(err, changed)
	}
	info, err := os.Stat(filepath.Join(dir, "certs", "a", "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatal(info.Mode())
	}
	changed, _, err = writeFiles(dir, []desiredFile{{
		Path: "certs/a/key.pem", PEM: "secret\n", Mode: "0600",
	}})
	if err != nil || changed {
		t.Fatal(err, changed)
	}
	if _, _, err := writeFiles(dir, []desiredFile{{Path: "../x", PEM: "no", Mode: "0600"}}); err == nil {
		t.Fatal("expected path error")
	}
}
