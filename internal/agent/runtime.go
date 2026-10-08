package agent

import (
	"context"
	"errors"
)

// errNeedRestart 表示这次变更热更新做不到，调用方应停掉后按上一份配置回滚启动。
var errNeedRestart = errors.New("core restart")

// coreRuntime 是一台机器上的数据面。同一时刻只有一个实现在跑。
// mihomo 用进程内的 clash-meta-nw；xray 与 sing-box 仍是外部可执行文件。
type coreRuntime interface {
	Kind() coreKind
	Test(ctx context.Context, configPath, dir string) error
	Start(ctx context.Context, configPath, dir string) error
	// Apply 热应用已经写好的配置。做不到时返回 errNeedRestart。
	Apply(ctx context.Context, configPath, dir string, raws map[string][]byte, skel string, shared []sharedDesired, geoChanged, filesChanged bool) error
	Stop()
	Running() bool
	Version() string
	Counters(ctx context.Context) (map[string]int64, error)
}
