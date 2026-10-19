package agent

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// agent 自身日志：无级别之前是零散 fmt.Print，现在统一走 logf——
// 低于当前级别的丢弃，其余写 stderr（journald/docker 路径不变）并入环形缓冲，
// 供面板经 log_req 拉取。级别词汇与面板下发的日志级别一致。
const (
	levelDebug = iota
	levelInfo
	levelWarning
	levelError
)

var logLevelNames = map[string]int{
	"debug":   levelDebug,
	"info":    levelInfo,
	"warning": levelWarning,
	"error":   levelError,
}

// procLogLevel 进程级日志级别；启动到首个 desired 之间保持 info，不丢启动诊断。
var procLogLevel atomic.Int32

func init() {
	procLogLevel.Store(int32(levelInfo))
}

// setLogLevel 按名字切换级别；非法值返回 false，保持原级别。
func setLogLevel(name string) bool {
	lv, ok := logLevelNames[name]
	if !ok {
		return false
	}
	procLogLevel.Store(int32(lv))
	return true
}

func logLevelName(level int) string {
	for name, lv := range logLevelNames {
		if lv == level {
			return name
		}
	}
	return "info"
}

func logf(level int, format string, args ...any) {
	if int32(level) < procLogLevel.Load() {
		return
	}
	text := scrubLogLine(fmt.Sprintf(format, args...))
	fmt.Fprintln(os.Stderr, text)
	logs.appendRaw(time.Now(), "agent", logLevelName(level), text)
}

const (
	logRingMaxLines  = 500
	logRingLineLimit = 2048
)

type logLine struct {
	Time   string `json:"time"`
	Source string `json:"source"`
	Level  string `json:"level"`
	Text   string `json:"text"`
}

// logRing 是定长环形缓冲：agent 自身与核心输出共用，只留最近若干行，
// 内存占用有界；snapshot 返回尾 tail 行并告知缓冲里是否还有更早的行。
type logRing struct {
	mu    sync.Mutex
	lines []logLine
}

var logs = &logRing{}

func (r *logRing) append(at time.Time, source, level, text string) {
	r.appendRaw(at, source, level, scrubLogLine(text))
}

// ansiEscapeRE 匹配终端控制序列：CSI（ESC[...）、OSC（ESC]...BEL/ST）与双字节转义。
// 只处理 ESC，避免把 UTF-8 多字节序列里的 0x9b 当控制符删掉。
var ansiEscapeRE = regexp.MustCompile("\x1b(?:\\[[0-?]*[ -/]*[@-~]|\\][^\x07\x1b]*(?:\x07|\x1b\\\\)|[@-_])")

// stripANSI 去掉核心输出里的颜色等控制码；没有 ESC 的行原样返回。
func stripANSI(text string) string {
	if !strings.Contains(text, "\x1b") {
		return text
	}
	return ansiEscapeRE.ReplaceAllString(text, "")
}

// appendRaw 入环前清掉终端控制码并按字节截断；调用方已脱敏时走这里。
func (r *logRing) appendRaw(at time.Time, source, level, text string) {
	text = clipLogLine(stripANSI(text))
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, logLine{Time: at.UTC().Format(time.RFC3339), Source: source, Level: level, Text: text})
	if len(r.lines) > logRingMaxLines {
		r.lines = append(r.lines[:0], r.lines[len(r.lines)-logRingMaxLines:]...)
	}
}

func (r *logRing) snapshot(tail int) ([]logLine, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := len(r.lines)
	if tail <= 0 || tail > total {
		tail = total
	}
	out := make([]logLine, tail)
	copy(out, r.lines[total-tail:])
	return out, tail < total
}

// clipLogLine 按字节上限截断且不切断 UTF-8 rune。
func clipLogLine(text string) string {
	if len(text) <= logRingLineLimit {
		return text
	}
	cut := logRingLineLimit
	for cut > 0 && (text[cut]&0xC0) == 0x80 {
		cut--
	}
	return text[:cut] + "…"
}

// logSecretRE 匹配键值形式的密钥片段；口令/令牌一律不得出服务端（红线 #5），
// 口径与 xray.go safeOut 一致：宁可丢信息也不放密钥。
var logSecretRE = regexp.MustCompile(`(?i)(pass(?:word|wd|phrase)?|secret|token|api[_-]?key|user[_-]?key|private[_-]?key)\s*[=:]\s*("[^"]*"|\S+)`)

func scrubLogLine(text string) string {
	if strings.Contains(text, "PRIVATE KEY") {
		return "[redacted]"
	}
	return logSecretRE.ReplaceAllString(text, "$1=[redacted]")
}

// coreLogLevel 试探解析核心输出行自带的级别标记（xray 的 [Info]/[Warning]，
// sing-box 的行首 INFO/WARN）；认不出来按 info 收。
func coreLogLevel(line string) string {
	line = stripANSI(line)
	switch {
	case strings.Contains(line, "[Debug]"), strings.HasPrefix(line, "DEBUG"):
		return "debug"
	case strings.Contains(line, "[Warning]"), strings.Contains(line, "[Warn]"),
		strings.HasPrefix(line, "WARN"), strings.HasPrefix(line, "WARNING"):
		return "warning"
	case strings.Contains(line, "[Error]"), strings.HasPrefix(line, "ERROR"), strings.HasPrefix(line, "ERRO"):
		return "error"
	default:
		return "info"
	}
}
