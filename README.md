# nwdock-agent

节点管控。控制面板在另一个仓库。

```bash
go run ./cmd/agent
```

在本目录执行。环境文件先找本目录的 `.env.agent`，没有再看上一级。

只含本程序的镜像：

```bash
docker build -f deploy/Dockerfile.source -t nwdock-agent .
```

三个核心不在本仓库。目标机要把核心打进同一张镜像时，在放好 `nowhere-agent`、`xray`、`mihomo`、`sing-box` 的目录执行：

```bash
docker build -f <本仓库>/deploy/Dockerfile -t nowhere-agent:local .
```

推送 `v` 开头的 tag（如 `v0.1.0`）才发布。Actions 用 `Dockerfile.source` 编镜像，推到 `ghcr.io/nwdock/nwdock-agent:<tag>`。二进制挂到该 tag 的 GitHub Release。`main` 上的提交不触发。三个核心不在这张镜像里。
