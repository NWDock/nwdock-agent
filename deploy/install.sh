#!/bin/sh
# 与 panel/internal/panel/install-agent.sh 必须逐字相同。对照：scripts/check-embedded-copies.sh
# 四个 AGENT_* 都有时直接用。缺了则用两个参数向面板领取指纹和核心，不核销令牌。
# NWDOCK_INSTALL_PREFIX 只用于测试，把文件写到该目录下。
set -eu

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

nl='
'
cr=$(printf '\r')
tab=$(printf '\t')

require() {
  local name value
  name=$1
  value=$2
  if [ -z "$value" ]; then
    die "缺少 ${name}"
  fi
  case "$value" in
    *"$nl"*|*"$cr"*) die "缺少 ${name}" ;;
  esac
}

valid_hex64() {
  case "$1" in
    ""|*[!0-9a-fA-F]*) return 1 ;;
  esac
  [ "${#1}" -eq 64 ]
}

valid_endpoint() {
  local ep rest port host p
  ep=$1
  case "$ep" in
    http://*) rest=${ep#http://} ;;
    https://*) rest=${ep#https://} ;;
    *) return 1 ;;
  esac
  case "$rest" in
    ""|*/*|*" "*|*"$nl"*|*"$cr"*|*"$tab"*) return 1 ;;
  esac
  port=
  case "$rest" in
    \[*\]:*)
      host=${rest#\[}
      port=${host#*\]:}
      host=${host%%\]:*}
      [ -n "$port" ] || return 1
      case "$host" in
        ""|*[!0-9a-fA-F:.]*) return 1 ;;
      esac
      ;;
    \[*\])
      host=${rest#\[}
      host=${host%\]}
      case "$host" in
        ""|*[!0-9a-fA-F:.]*) return 1 ;;
      esac
      ;;
    *:*)
      host=${rest%:*}
      port=${rest##*:}
      [ -n "$port" ] || return 1
      case "$host" in
        ""|*[!A-Za-z0-9._-]*) return 1 ;;
      esac
      ;;
    *)
      host=$rest
      case "$host" in
        ""|*[!A-Za-z0-9._-]*) return 1 ;;
      esac
      ;;
  esac
  if [ -n "$port" ]; then
    case "$port" in
      *[!0-9]*) return 1 ;;
      ?|??|???|????|?????) ;;
      *) return 1 ;;
    esac
    p=$port
    while [ "$p" != "${p#0}" ]; do
      p=${p#0}
    done
    [ -n "$p" ] || p=0
    if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
      return 1
    fi
  fi
  return 0
}

valid_prefix() {
  case "$1" in
    /*?*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *[!A-Za-z0-9._/-]*) return 1 ;;
  esac
  return 0
}

load_install_spec() {
  local endpoint token payload spec keypin core
  endpoint=$1
  token=$2
  if [ -z "$endpoint" ] || [ -z "$token" ]; then
    require AGENT_PANEL_ENDPOINTS "${AGENT_PANEL_ENDPOINTS:-}"
    require AGENT_PANEL_KEYPIN "${AGENT_PANEL_KEYPIN:-}"
    require AGENT_ENROLL_TOKEN "${AGENT_ENROLL_TOKEN:-}"
    require AGENT_CORE "${AGENT_CORE:-}"
    return 0
  fi
  if [ "$token" = "-" ]; then
    if ! IFS= read -r token && [ -z "$token" ]; then
      token=""
    fi
    token=${token%"$cr"}
  fi
  valid_endpoint "$endpoint" || die "AGENT_PANEL_ENDPOINTS 必须是 http(s)://主机[:端口]"
  valid_hex64 "$token" || die "AGENT_ENROLL_TOKEN 必须是 64 位十六进制"
  command -v curl >/dev/null 2>&1 || die "需要 curl"
  payload=$(printf '{"token":"%s"}' "$token")
  spec=$(curl -fsSL --max-time 30 -X POST -H "Content-Type: application/json" --data "$payload" "${endpoint}/api/agent/install-spec") || die "无法读取安装参数"
  spec=$(printf '%s' "$spec" | tr -d '\r')
  case "$spec" in
    *"$nl"*|*"$tab"*) die "无法读取安装参数" ;;
  esac
  keypin=${spec%% *}
  core=${spec#* }
  if [ "$core" = "$spec" ] || [ -z "$core" ]; then
    die "无法读取安装参数"
  fi
  case "$core" in
    *" "*) die "无法读取安装参数" ;;
  esac
  valid_hex64 "$keypin" || die "无法读取安装参数"
  case "$core" in
    clash-meta-nw|mihomo|xray|singbox) ;;
    *) die "无法读取安装参数" ;;
  esac
  AGENT_PANEL_ENDPOINTS=$endpoint
  AGENT_PANEL_KEYPIN=$keypin
  AGENT_ENROLL_TOKEN=$token
  AGENT_CORE=$core
  export AGENT_PANEL_ENDPOINTS AGENT_PANEL_KEYPIN AGENT_ENROLL_TOKEN AGENT_CORE
}

if [ -z "${AGENT_PANEL_ENDPOINTS:-}" ] || [ -z "${AGENT_PANEL_KEYPIN:-}" ] || [ -z "${AGENT_ENROLL_TOKEN:-}" ] || [ -z "${AGENT_CORE:-}" ]; then
  load_install_spec "${1:-}" "${2:-}"
fi

require AGENT_PANEL_ENDPOINTS "${AGENT_PANEL_ENDPOINTS:-}"
require AGENT_PANEL_KEYPIN "${AGENT_PANEL_KEYPIN:-}"
require AGENT_ENROLL_TOKEN "${AGENT_ENROLL_TOKEN:-}"
require AGENT_CORE "${AGENT_CORE:-}"

valid_endpoint "$AGENT_PANEL_ENDPOINTS" || die "AGENT_PANEL_ENDPOINTS 必须是 http(s)://主机[:端口]"
valid_hex64 "$AGENT_PANEL_KEYPIN" || die "AGENT_PANEL_KEYPIN 必须是 64 位十六进制"
valid_hex64 "$AGENT_ENROLL_TOKEN" || die "AGENT_ENROLL_TOKEN 必须是 64 位十六进制"

case "$AGENT_CORE" in
  clash-meta-nw|mihomo) image=ghcr.io/nwdock/nwdock-agent:latest ;;
  xray) image=ghcr.io/nwdock/nwdock-agent:xray ;;
  singbox) image=ghcr.io/nwdock/nwdock-agent:singbox ;;
  *) die "AGENT_CORE 只能是 clash-meta-nw、xray 或 singbox" ;;
esac

prefix=${NWDOCK_INSTALL_PREFIX:-}
if [ -n "$prefix" ]; then
  valid_prefix "$prefix" || die "NWDOCK_INSTALL_PREFIX 无效"
elif [ "$(id -u)" -ne 0 ]; then
  die "需要 root"
fi

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  die "需要 docker compose"
fi

root_dir="${prefix}/opt/nwd-agent"
data_dir="${root_dir}/data"
conf_file="${root_dir}/agent.conf"
compose="${root_dir}/docker-compose.yml"

extra_conf=""
if [ -f "$conf_file" ]; then
  extra_conf=$(grep -Ev '^[[:space:]]*(AGENT_RUNTIME|AGENT_DATA_DIR|AGENT_PANEL_ENDPOINTS|AGENT_PANEL_KEYPIN|AGENT_ENROLL_TOKEN|AGENT_XRAY_BIN|AGENT_XRAY_API_ADDR|AGENT_SINGBOX_BIN)=' "$conf_file" || true)
fi

install -d -m 0700 "$root_dir" "$data_dir"
umask 077
{
  printf 'AGENT_RUNTIME=docker\n'
  printf 'AGENT_DATA_DIR=/opt/nwd-agent/data\n'
  printf 'AGENT_PANEL_ENDPOINTS=%s\n' "$AGENT_PANEL_ENDPOINTS"
  printf 'AGENT_PANEL_KEYPIN=%s\n' "$AGENT_PANEL_KEYPIN"
  printf 'AGENT_ENROLL_TOKEN=%s\n' "$AGENT_ENROLL_TOKEN"
  printf 'AGENT_XRAY_BIN=/usr/local/bin/xray\n'
  printf 'AGENT_XRAY_API_ADDR=127.0.0.1:10085\n'
  printf 'AGENT_SINGBOX_BIN=/usr/local/bin/sing-box\n'
  if [ -n "$extra_conf" ]; then
    printf '%s\n' "$extra_conf"
  fi
} >"$conf_file"
chmod 0600 "$conf_file"

cat >"$compose" <<EOF
name: nwd-agent
services:
  agent:
    image: ${image}
    container_name: nwd-agent
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_BIND_SERVICE
    entrypoint: ["/bin/sh", "-c"]
    command:
      - mkdir -p /opt/nwd-agent/data; if [ ! -f /opt/nwd-agent/data/geoip.dat ] && [ -f /usr/share/nowhere/geoip.dat ]; then cp /usr/share/nowhere/geoip.dat /opt/nwd-agent/data/geoip.dat; fi; if [ ! -f /opt/nwd-agent/data/geosite.dat ] && [ -f /usr/share/nowhere/geosite.dat ]; then cp /usr/share/nowhere/geosite.dat /opt/nwd-agent/data/geosite.dat; fi; exec /usr/local/bin/agent -config /opt/nwd-agent/agent.conf
    volumes:
      - ${data_dir}:/opt/nwd-agent/data
      - ${conf_file}:/opt/nwd-agent/agent.conf:ro
EOF
chmod 0600 "$compose"

exec docker compose -f "$compose" up -d --force-recreate
