package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// execRuntime 监管 xray 或 sing-box 子进程。热路径只覆盖 xray 的 adi/rmi；
// 骨架或 geo 变化返回 errNeedRestart，由调用方整进程重启。
type execRuntime struct {
	kind    coreKind
	bin     string
	api     string
	version string

	mu  sync.Mutex
	cmd *exec.Cmd
}

func newExecRuntime(kind coreKind, bin, api string) *execRuntime {
	return &execRuntime{kind: kind, bin: bin, api: api}
}

func (e *execRuntime) Kind() coreKind { return e.kind }

func (e *execRuntime) Version() string { return e.version }

func (e *execRuntime) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cmd != nil
}

func (e *execRuntime) Test(ctx context.Context, configPath, dir string) error {
	test := exec.CommandContext(ctx, e.bin, coreTestArgs(e.kind, configPath, dir)...)
	test.Dir = dir
	test.Env = coreEnv(e.kind, dir)
	out, err := test.CombinedOutput()
	if err != nil {
		return cmdFail(string(e.kind)+" test", out, err)
	}
	return nil
}

func (e *execRuntime) Start(ctx context.Context, configPath, dir string) error {
	cmd := exec.Command(e.bin, coreRunArgs(e.kind, configPath, dir)...)
	cmd.Dir = dir
	cmd.Env = coreEnv(e.kind, dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// 核心输出逐行 tee：原样写回进程输出（journald/docker 路径不变），同时入日志环供面板查看。
	// 管道在核心退出时 EOF，两个 goroutine 自然收场。
	go teeCoreOutput(e.kind, "stdout", os.Stdout, stdout)
	go teeCoreOutput(e.kind, "stderr", os.Stderr, stderr)
	e.mu.Lock()
	e.cmd = cmd
	e.mu.Unlock()
	e.version = probeVersion(ctx, e.bin, e.kind)
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err := <-waitErr:
		e.mu.Lock()
		if e.cmd == cmd {
			e.cmd = nil
		}
		e.mu.Unlock()
		if err != nil {
			return fmt.Errorf("%s exited: %s", e.kind, err.Error())
		}
		return fmt.Errorf("%s exited immediately", e.kind)
	case <-time.After(2 * time.Second):
	}
	go func() {
		<-waitErr
		e.mu.Lock()
		same := e.cmd == cmd
		if same {
			e.cmd = nil
		}
		e.mu.Unlock()
		if !same {
			return
		}
		proc.mu.Lock()
		if proc.rt == e {
			proc.core = ""
			proc.version = ""
			proc.startedAt = time.Time{}
		}
		proc.mu.Unlock()
	}()
	return nil
}

func (e *execRuntime) Stop() {
	e.mu.Lock()
	cmd := e.cmd
	e.cmd = nil
	e.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

// teeCoreOutput 逐行接管核心 stdout/stderr：透传回进程标准输出（service/docker 日志路径不变），
// 并按行内级别标记入日志环。核心被杀时管道 EOF，函数返回。
func teeCoreOutput(kind coreKind, stream string, dst io.Writer, src io.Reader) {
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		fmt.Fprintln(dst, line)
		logs.append(time.Now(), string(kind), coreLogLevel(line), line)
	}
}

func (e *execRuntime) Apply(ctx context.Context, configPath, dir string, raws map[string][]byte, skel string, shared []sharedDesired, geoChanged, filesChanged bool) error {
	if e.kind != coreXray || geoChanged || sameCorePlan(e.kind, proc.skeleton != skel) != planHot {
		return errNeedRestart
	}
	readded, err := diffLocked(ctx, e.bin, e.api, dir, raws, filesChanged)
	if err != nil {
		return err
	}
	appliedUsers := appliedUsersLocked(dir)
	for tag := range readded {
		delete(appliedUsers, tag)
	}
	if err := reconcileUsers(ctx, e.bin, e.api, dir, shared); err != nil {
		return err
	}
	proc.applied = raws
	return nil
}

func (e *execRuntime) Counters(ctx context.Context) (map[string]int64, error) {
	if e.kind == coreSingbox {
		return collectSingboxStats(ctx, e.api)
	}
	if e.bin == "" {
		return nil, errors.New("AGENT_XRAY_BIN is required")
	}
	return collectStats(ctx, e.bin, e.api)
}
