package agent

import (
	"strings"
	"testing"
	"time"
)

func TestLogRingCapacityAndSnapshot(t *testing.T) {
	r := &logRing{}
	for i := 0; i < logRingMaxLines+50; i++ {
		r.append(time.Now(), "agent", "info", strings.Repeat("x", 8))
	}
	lines, truncated := r.snapshot(10)
	if len(lines) != 10 {
		t.Fatalf("snapshot 10: got %d", len(lines))
	}
	if !truncated {
		t.Fatal("want truncated=true")
	}
	lines, truncated = r.snapshot(logRingMaxLines)
	if len(lines) != logRingMaxLines {
		t.Fatalf("snapshot all: got %d", len(lines))
	}
	if truncated {
		t.Fatal("want truncated=false")
	}
	lines, _ = r.snapshot(0)
	if len(lines) != logRingMaxLines {
		t.Fatalf("snapshot 0 应取全部: got %d", len(lines))
	}
}

func TestClipLogLineKeepsRunes(t *testing.T) {
	text := strings.Repeat("好", 3000)
	clipped := clipLogLine(text)
	if len(clipped) <= logRingLineLimit {
		t.Fatalf("want >%d bytes", logRingLineLimit)
	}
	if !strings.HasPrefix(text, strings.TrimSuffix(clipped, "…")) {
		t.Fatal("截断后不是原文前缀")
	}
}

func TestStripANSI(t *testing.T) {
	cases := []struct{ in, want string }{
		{"\x1b[36mINFO\x1b[0m[0000] inbound started", "INFO[0000] inbound started"},
		{"\x1b[1;31mERRO\x1b[0m[0000] listen failed", "ERRO[0000] listen failed"},
		{"\x1b]8;;https://example.com\x07链接\x1b]8;;\x07", "链接"},
		{"普通日志 info", "普通日志 info"},
		{"\x1bXescaped", "escaped"},
	}
	for _, c := range cases {
		if got := stripANSI(c.in); got != c.want {
			t.Errorf("stripANSI(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLogRingStripsANSI(t *testing.T) {
	r := &logRing{}
	r.append(time.Now(), "singbox", "info", "\x1b[36mINFO\x1b[0m[0000] started")
	lines, _ := r.snapshot(1)
	if len(lines) != 1 || lines[0].Text != "INFO[0000] started" {
		t.Fatalf("入环未清洗 ANSI: %#v", lines)
	}
}

func TestScrubLogLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"password=change-me token=abc", "password=[redacted] token=[redacted]"},
		{"keep normal line", "keep normal line"},
		{"-----BEGIN PRIVATE KEY-----", "[redacted]"},
		{"api_key: sk-1234", "api_key=[redacted]"},
	}
	for _, c := range cases {
		if got := scrubLogLine(c.in); got != c.want {
			t.Errorf("scrub(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSetLogLevelFilter(t *testing.T) {
	defer setLogLevel("info")
	if !setLogLevel("warning") {
		t.Fatal("warning 应被接受")
	}
	r := &logRing{}
	r.append(time.Now(), "agent", "debug", "d")
	r.append(time.Now(), "agent", "info", "i")
	r.append(time.Now(), "agent", "warning", "w")
	logsBackup := logs
	logs = r
	defer func() { logs = logsBackup }()
	logf(levelDebug, "hidden")
	logf(levelWarning, "shown")
	lines, _ := r.snapshot(10)
	if len(lines) != 4 {
		t.Fatalf("want 4 lines (append 2 + logf warning 1 + logf debug 0), got %d", len(lines))
	}
	if lines[3].Text != "shown" {
		t.Fatalf("want shown, got %q", lines[3].Text)
	}
	if setLogLevel("nope") {
		t.Fatal("非法级别应被拒绝")
	}
	if !setLogLevel("debug") || !setLogLevel("info") || !setLogLevel("error") {
		t.Fatal("合法级别应被接受")
	}
}

func TestCoreLogLevel(t *testing.T) {
	cases := map[string]string{
		"2026/10/19 12:00:00 [Warning] failed":    "warning",
		"[Error] listen tcp":                      "error",
		"INFO[0000] inbound started":              "info",
		"WARN something":                          "warning",
		"plain output":                            "info",
		"\x1b[36mINFO\x1b[0m[0000] started":       "info",
		"\x1b[33mWARN\x1b[0m[0000] slow":          "warning",
		"\x1b[31mERRO\x1b[0m[0000] listen failed": "error",
	}
	for in, want := range cases {
		if got := coreLogLevel(in); got != want {
			t.Errorf("coreLogLevel(%q) = %q, want %q", in, got, want)
		}
	}
}
