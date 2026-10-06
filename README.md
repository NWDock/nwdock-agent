# nwdock-agent

节点管控。控制面板在另一个仓库。

```bash
go run ./cmd/agent
```

在本目录执行。环境文件先找本目录的 `.env.agent`，没有再看上一级。

发布镜像在构建时编入三个核心，版本在 `deploy/cores.versions`。默认 `geoip.dat` / `geosite.dat` 来自 Loyalsoldier `v2ray-rules-dat` 的 `GEO_TAG`，放在 `/usr/share/nowhere/`。数据目录里还没有这两份文件时，启动时复制过去。面板之后下发的文件仍会覆盖。

```bash
set -a
. ./deploy/cores.versions
set +a
docker build -f deploy/Dockerfile.source \
  --build-arg "XRAY_TAG=${XRAY_TAG}" \
  --build-arg "MIHOMO_TAG=${MIHOMO_TAG}" \
  --build-arg "SINGBOX_TAG=${SINGBOX_TAG}" \
  --build-arg "GEO_TAG=${GEO_TAG}" \
  -t nwdock-agent .
```

已经准备好四个二进制、不想在镜像里编译时，在那个目录执行：

```bash
docker build -f <本仓库>/deploy/Dockerfile -t nowhere-agent:local .
```

推送 `v` 开头的 tag（如 `v1.0.1`）才发布。Actions 并行编出三个核心，再打三张镜像，每张只有一个核心：

- `ghcr.io/nwdock/nwdock-agent:<tag>-xray`
- `ghcr.io/nwdock/nwdock-agent:<tag>-mihomo`
- `ghcr.io/nwdock/nwdock-agent:<tag>-singbox`

二进制挂到该 tag 的 GitHub Release。`main` 上的提交不触发。sing-box 的 `.srs` 不在镜像里。
