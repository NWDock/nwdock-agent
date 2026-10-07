# nwdock-agent

节点管控。主动连接面板的 `/api/agent/channel`（出站 WebSocket，应用层加密）。控制面板在 [nwdock-panel](https://github.com/NWDock/nwdock-panel)。

## 配置

```bash
cp .env.agent.example .env.agent
```

进程先读本目录的 `.env.agent`，没有再读上一级。`AGENT_RUNTIME` 只能是 `service` 或 `docker`。

- `AGENT_PANEL_ENDPOINTS`：面板地址，如 `https://panel.example` 或 `http://127.0.0.1:8088`。不用写路径，进程会补成 `/api/agent/channel`。多个地址用逗号分隔。
- `AGENT_PANEL_KEYPIN`：面板 stdout 里 `panel identity` 的指纹。
- `AGENT_ENROLL_TOKEN`：只在身份还没绑定的时候需要。登记完成后从环境文件删掉。

身份私钥在数据目录的 `agent-identity.key`（`0600`）。删掉它等于取消登记，下次要新的安装令牌。

## 运行

在本目录执行。本机需要已经有选中的核心。

```bash
go run ./cmd/agent
```

systemd 单元是 [`deploy/nowhere-agent.service`](./deploy/nowhere-agent.service)。面板地址、指纹和安装令牌放在 `/etc/nowhere/agent.env`，不要写进单元文件。

## 镜像

核心和 geo 的版本钉在 [`deploy/cores.versions`](./deploy/cores.versions)。`geoip.dat` / `geosite.dat` 来自 Loyalsoldier `v2ray-rules-dat`，放在 `/usr/share/nowhere/`。数据目录里还没有这两份文件时，启动时复制过去；面板之后下发的文件会覆盖。sing-box 的 `.srs` 不在镜像里，由面板下发。

本地打一张三个核心都在里面的镜像，标签与 compose 一致：

```bash
set -a
. ./deploy/cores.versions
set +a
docker build -f deploy/Dockerfile.source \
  --build-arg "XRAY_TAG=${XRAY_TAG}" \
  --build-arg "MIHOMO_TAG=${MIHOMO_TAG}" \
  --build-arg "SINGBOX_TAG=${SINGBOX_TAG}" \
  --build-arg "GEO_TAG=${GEO_TAG}" \
  -t nowhere-agent:local .
docker compose -f deploy/docker-compose.yml up -d
```

`nowhere-agent`、`xray`、`mihomo`、`sing-box` 四个文件已经在当前目录、不想在镜像里编译时，用 [`deploy/Dockerfile`](./deploy/Dockerfile)。它只复制这四个文件，不含 geo：

```bash
docker build -f <本仓库>/deploy/Dockerfile -t nowhere-agent:local .
```

必须 `network_mode: host`。不要写 `ports`，不要 `privileged`。能力只有 `NET_BIND_SERVICE`。

## 发布

推送 `v` 开头的 tag（如 `v1.0.0`）才发布。Actions 并行编出三个核心，再打三张镜像，每张只有一个核心：

- `ghcr.io/nwdock/nwdock-agent:xray` 和 `ghcr.io/nwdock/nwdock-agent:<tag>-xray`
- `ghcr.io/nwdock/nwdock-agent:mihomo` 和 `ghcr.io/nwdock/nwdock-agent:<tag>-mihomo`
- `ghcr.io/nwdock/nwdock-agent:singbox` 和 `ghcr.io/nwdock/nwdock-agent:<tag>-singbox`

二进制 `nowhere-agent` 挂到该 tag 的 GitHub Release。`main` 上的提交不触发。用发布镜像时，compose 里只保留这张镜像实际带的那个核心。发布镜像不走上面两个本地 Dockerfile。
