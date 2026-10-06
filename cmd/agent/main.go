package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"nowhere.local/agent/internal/agent"
	"nowhere.local/agent/internal/envfile"
)

func main() {
	envDir, legacy, err := envfile.LoadProject(".env.agent", ".env")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	if envDir == ".." {
		fmt.Fprintln(os.Stderr, "仍在用上一级目录的环境文件")
	}
	if legacy {
		fmt.Fprintln(os.Stderr, "仍在用旧的单一 .env")
	}
	cfg, err := agent.LoadConfig(envDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer agent.Shutdown()
	if err := agent.Run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
