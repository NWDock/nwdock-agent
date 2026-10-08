#!/usr/bin/env bash
# 与 panel/internal/panel/install-agent.sh 必须逐字相同。对照：scripts/check-embedded-copies.sh
# 由面板安装命令以环境变量调用。NWDOCK_INSTALL_PREFIX 只用于测试，把文件写到该目录下。
set -euo pipefail

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

require() {
  local name=$1 value=$2
  if [[ -z "$value" || "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    die "缺少 ${name}"
  fi
}

require AGENT_PANEL_ENDPOINTS "${AGENT_PANEL_ENDPOINTS:-}"
require AGENT_PANEL_KEYPIN "${AGENT_PANEL_KEYPIN:-}"
require AGENT_ENROLL_TOKEN "${AGENT_ENROLL_TOKEN:-}"
require AGENT_CORE "${AGENT_CORE:-}"

if [[ ! "$AGENT_PANEL_ENDPOINTS" =~ ^https?://(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9._-]+)(:[0-9]{1,5})?$ ]]; then
  die "AGENT_PANEL_ENDPOINTS 必须是 http(s)://主机[:端口]"
fi
if [[ -n "${BASH_REMATCH[2]:-}" ]]; then
  port=${BASH_REMATCH[2]#:}
  if (( port > 65535 )); then
    die "AGENT_PANEL_ENDPOINTS 必须是 http(s)://主机[:端口]"
  fi
fi
if [[ ! "$AGENT_PANEL_KEYPIN" =~ ^[0-9a-fA-F]{64}$ ]]; then
  die "AGENT_PANEL_KEYPIN 必须是 64 位十六进制"
fi
if [[ ! "$AGENT_ENROLL_TOKEN" =~ ^[0-9a-fA-F]{64}$ ]]; then
  die "AGENT_ENROLL_TOKEN 必须是 64 位十六进制"
fi

case "$AGENT_CORE" in
  clash-meta-nw|mihomo) image=ghcr.io/nwdock/nwdock-agent:latest ;;
  xray) image=ghcr.io/nwdock/nwdock-agent:xray ;;
  singbox) image=ghcr.io/nwdock/nwdock-agent:singbox ;;
  *) die "AGENT_CORE 只能是 clash-meta-nw、xray 或 singbox" ;;
esac

prefix=${NWDOCK_INSTALL_PREFIX:-}
if [[ -n "$prefix" ]]; then
  if [[ ! "$prefix" =~ ^/[-A-Za-z0-9._/]+$ ]]; then
    die "NWDOCK_INSTALL_PREFIX 无效"
  fi
elif [[ "$(id -u)" -ne 0 ]]; then
  die "需要 root"
fi

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  die "需要 docker compose"
fi

etc_dir="${prefix}/etc/nowhere"
data_dir="${prefix}/var/lib/nowhere-agent"
env_file="${etc_dir}/agent.env"
compose="${etc_dir}/docker-compose.yml"

install -d -m 0700 "$etc_dir" "$data_dir"
umask 077
{
  printf 'AGENT_RUNTIME=docker\n'
  printf 'AGENT_DATA_DIR=/var/lib/nowhere-agent\n'
  printf 'AGENT_PANEL_ENDPOINTS=%s\n' "$AGENT_PANEL_ENDPOINTS"
  printf 'AGENT_PANEL_KEYPIN=%s\n' "$AGENT_PANEL_KEYPIN"
  printf 'AGENT_ENROLL_TOKEN=%s\n' "$AGENT_ENROLL_TOKEN"
} >"$env_file"
chmod 0600 "$env_file"

cat >"$compose" <<EOF
services:
  agent:
    image: ${image}
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_BIND_SERVICE
    env_file:
      - ${env_file}
    volumes:
      - ${data_dir}:/var/lib/nowhere-agent
EOF
chmod 0600 "$compose"

exec docker compose -f "$compose" up -d
