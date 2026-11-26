# nwdock-agent

节点管控。主动连接面板的 `/api/agent/channel`（出站 WebSocket，应用层加密）。控制面板在 [nwdock-panel](https://github.com/NWDock/nwdock-panel)。

## 安装

两条都落在 `/opt/nwd-agent/`。

### 服务

[`deploy/install-service.sh`](./deploy/install-service.sh)。systemd 单元是 [`deploy/nwd-agent.service`](./deploy/nwd-agent.service)，OpenRC 脚本是 [`deploy/nwd-agent.initd`](./deploy/nwd-agent.initd)，都放在 `/opt/nwd-agent/`。执行 `/opt/nwd-agent/bin/agent -config /opt/nwd-agent/agent.conf`，只认这份文件，不看进程环境。示例是 [`deploy/agent.conf.example`](./deploy/agent.conf.example)。

### Docker

[`deploy/install.sh`](./deploy/install.sh) 写出的就是 [`deploy/docker-compose.yml`](./deploy/docker-compose.yml) 和 `/opt/nwd-agent/agent.conf`。compose 拉取 `ghcr.io/nwdock/nwdock-agent:latest`。要 xray 或 sing-box 时把 `image` 换成 `:xray` 或 `:singbox`。必须 `network_mode: host`。不要写 `ports`，不要 `privileged`。能力只有 `NET_BIND_SERVICE`。配置只读挂载。文件里写 `AGENT_RUNTIME=docker`，核心路径用镜像内的 `/usr/local/bin/xray` 和 `/usr/local/bin/sing-box`。数据目录是 `/opt/nwd-agent/data`。入口执行 `/usr/local/bin/agent -config /opt/nwd-agent/agent.conf`。

`geoip.dat` / `geosite.dat` 来自 Loyalsoldier `v2ray-rules-dat`，放在 `/usr/share/nowhere/`。数据目录里还没有这两份文件时，启动时复制过去；面板之后下发的文件会覆盖。sing-box 的 `.srs` 不在镜像里，由面板下发。

## 配置

```bash
cp .env.agent.example .env.agent
```

本目录 `.env.agent` 走环境变量。进程先读本目录的 `.env.agent`，没有再读上一级。服务和 Docker 安装不读这个文件，只读 `agent.conf`。`AGENT_RUNTIME` 只能是 `service` 或 `docker`。

- `AGENT_PANEL_ENDPOINTS`：面板地址，如 `https://panel.example` 或 `http://127.0.0.1:8088`。不用写路径，进程会补成 `/api/agent/channel`。多个地址用逗号分隔。
- `AGENT_PANEL_KEYPIN`：面板 stdout 里 `panel identity` 的指纹。
- `AGENT_ENROLL_TOKEN`：只在身份还没绑定的时候需要。登记完成后从环境文件删掉。
- `AGENT_MEMORY_LIMIT`：本进程软内存上限，缺省 `768MiB`。`off` 关闭。xray 与 sing-box 是外部进程，不受这项管。
- `NOW_TRANSPORT_MEMORY_PROFILE`：Nowhere 3.5 QUIC 窗口档位（`memory` / `balanced` / `throughput`）。留空时按 `AGENT_MEMORY_LIMIT` 自动选择：`≤512MiB` 选 `memory`（Conn 16 MiB / Send 8 MiB），`≤1GiB`（含默认 `768MiB`）选 `balanced`（Conn/Send 16 MiB，上游默认是 `throughput` 32 MiB），`>1GiB` 或 `off` 选 `throughput`。高带宽高延迟（大 BDP）节点如需 32 MiB 窗口可显式设为 `throughput` 或调高/关闭 `AGENT_MEMORY_LIMIT`。其余 Nowhere 3.5 官方 `NOW_*` 调优项同样支持经 `agent.conf` / 环境变量透传并在启动期校验；未知 `NOW_*` 键直接拒启（fail-closed）；`NOW_MORPH_TCP_PRELUDE=fade` 仅适用于 nw3，存量 nw2 节点仅接受 `low7`/`full8` 或留空走各栈默认。

身份私钥在数据目录的 `agent-identity.key`（`0600`）。删掉它等于取消登记，下次要新的安装令牌。

## 本地开发

在本目录执行。默认数据面是编进进程的 clash-meta-nw（`third_party/clash-meta-nw`，与 [`deploy/cores.versions`](./deploy/cores.versions) 的 `MIHOMO_TAG` 同一 tag，已对齐 Nowhere 3.5，支持 `nw3` Morph `grade: full|core`、`cipher: chacha|aes` 与 `NOW_*` 运行时调优）。构建和测试都要 `GOWORK=off`。选 xray 或 sing-box 时，本机还要有对应的可执行文件。`AGENT_MIHOMO_BIN` 会被忽略。

```bash
GOWORK=off go run ./cmd/agent
```

本地打一张镜像。clash-meta-nw 在 agent 里面，xray 和 sing-box 仍是镜像里的二进制：

```bash
set -a
. ./deploy/cores.versions
set +a
docker build -f deploy/Dockerfile.source \
  --build-arg "XRAY_TAG=${XRAY_TAG}" \
  --build-arg "MIHOMO_TAG=${MIHOMO_TAG}" \
  --build-arg "SINGBOX_TAG=${SINGBOX_TAG}" \
  --build-arg "GEO_TAG=${GEO_TAG}" \
  -t nwdock-agent:local .
```

`agent`、`xray`、`sing-box` 三个文件已经在当前目录、不想在镜像里编译时，用 [`deploy/Dockerfile`](./deploy/Dockerfile)。它只复制这三个文件，不含 geo。mihomo 不需要单独的二进制：

```bash
docker build -f deploy/Dockerfile -t nwdock-agent:local .
```
