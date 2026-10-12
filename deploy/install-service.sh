#!/bin/sh
# 与 panel/internal/panel/install-service.sh 必须逐字相同。对照：scripts/check-embedded-copies.sh
# 由面板安装命令以环境变量调用。NWDOCK_INSTALL_PREFIX、NWDOCK_*_API、NWDOCK_*_URL 只用于测试。
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

valid_tag() {
  local rest
  case "$1" in
    v*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *..*) return 1 ;;
  esac
  rest=${1#v}
  [ -n "$rest" ] || return 1
  case "$rest" in
    *[!0-9A-Za-z._-]*) return 1 ;;
  esac
  return 0
}

valid_http_url() {
  case "$1" in
    *"$nl"*|*"$cr"*|*"$tab"*|*" "*|*..*) return 1 ;;
    http://*|https://*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    http://|https://) return 1 ;;
  esac
  return 0
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
    \[*\):*)
      host=${rest#\[}
      host=${host%%\]:*}
      port=${rest##*:}
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
    if [ "$p" -gt 65535 ]; then
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

os_release_file() {
  if [ -n "${NWDOCK_OS_RELEASE:-}" ]; then
    printf '%s\n' "$NWDOCK_OS_RELEASE"
  else
    printf '%s\n' /etc/os-release
  fi
}

os_field() {
  local file
  file=$(os_release_file)
  if [ ! -f "$file" ]; then
    return 0
  fi
  sed -n "s/^${1}=//p" "$file" | head -n 1 | tr -d "\"'\r"
}

os_blob() {
  local id like
  id=$(os_field ID)
  like=$(os_field ID_LIKE)
  printf '%s %s' "$id" "$like"
}

pkg_family() {
  local blob
  blob=$(os_blob)
  case "$blob" in
    *alpine*) printf '%s\n' apk; return ;;
  esac
  case "$blob" in
    *debian*|*ubuntu*) printf '%s\n' apt; return ;;
  esac
  case "$blob" in
    *fedora*|*rhel*|*centos*|*rocky*|*almalinux*|*amzn*) printf '%s\n' dnf; return ;;
  esac
  case " $blob " in
    *" ol "*) printf '%s\n' dnf; return ;;
  esac
  case " $blob " in
    *" arch "*|*" archlinux "*) printf '%s\n' pacman; return ;;
  esac
  case "$blob" in
    *opensuse*|*sles*|*suse*) printf '%s\n' zypper; return ;;
  esac
  if command -v apt-get >/dev/null 2>&1; then
    printf '%s\n' apt
    return
  fi
  if command -v apk >/dev/null 2>&1; then
    printf '%s\n' apk
    return
  fi
  if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    printf '%s\n' dnf
    return
  fi
  if command -v pacman >/dev/null 2>&1; then
    printf '%s\n' pacman
    return
  fi
  if command -v zypper >/dev/null 2>&1; then
    printf '%s\n' zypper
    return
  fi
  return 0
}

pkg_install() {
  local family id
  if [ -n "${NWDOCK_PKG_INSTALL:-}" ]; then
    "$NWDOCK_PKG_INSTALL" "$@" || return 1
    return 0
  fi
  if [ -n "$prefix" ]; then
    return 1
  fi
  family=$(pkg_family)
  case "$family" in
    apt)
      DEBIAN_FRONTEND=noninteractive apt-get update || return 1
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" || return 1
      ;;
    apk)
      apk add --no-cache "$@" || return 1
      ;;
    dnf)
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y "$@" || return 1
      elif command -v yum >/dev/null 2>&1; then
        yum install -y "$@" || return 1
      else
        return 1
      fi
      ;;
    pacman)
      pacman -Sy --noconfirm --needed "$@" || return 1
      ;;
    zypper)
      zypper --non-interactive install --no-recommends "$@" || return 1
      ;;
    *)
      id=$(os_field ID)
      [ -n "$id" ] || id=unknown
      die "无法安装 $*（未知发行版 ${id}）"
      ;;
  esac
}

need_cmd() {
  local cmd
  cmd=$1
  shift
  if command -v "$cmd" >/dev/null 2>&1; then
    return 0
  fi
  if [ "$#" -eq 0 ]; then
    die "需要 ${cmd}"
  fi
  pkg_install "$@" || die "需要 ${cmd}"
  command -v "$cmd" >/dev/null 2>&1 || die "需要 ${cmd}"
}

ensure_tools() {
  if ! command -v curl >/dev/null 2>&1; then
    pkg_install curl ca-certificates || die "需要 curl"
    command -v curl >/dev/null 2>&1 || die "需要 curl"
  fi
  if ! command -v sha256sum >/dev/null 2>&1; then
    pkg_install coreutils || die "需要 sha256sum"
    command -v sha256sum >/dev/null 2>&1 || die "需要 sha256sum"
  fi
  if ! command -v install >/dev/null 2>&1; then
    pkg_install coreutils || die "需要 install"
    command -v install >/dev/null 2>&1 || die "需要 install"
  fi
  if [ "$AGENT_CORE" = xray ] && ! command -v unzip >/dev/null 2>&1; then
    pkg_install unzip || die "需要 unzip"
    command -v unzip >/dev/null 2>&1 || die "需要 unzip"
  fi
  if [ "$AGENT_CORE" = singbox ] && ! command -v tar >/dev/null 2>&1; then
    pkg_install tar || die "需要 tar"
    command -v tar >/dev/null 2>&1 || die "需要 tar"
  fi
}

detect_init() {
  if [ -n "${NWDOCK_INIT:-}" ]; then
    case "$NWDOCK_INIT" in
      systemd|openrc) printf '%s\n' "$NWDOCK_INIT"; return ;;
      *) die "NWDOCK_INIT 无效" ;;
    esac
  fi
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    printf '%s\n' systemd
    return
  fi
  if command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
    printf '%s\n' openrc
    return
  fi
  die "需要 systemd 或 OpenRC"
}

enable_openrc() {
  install -m 0755 "$initd" /etc/init.d/nwd-agent
  if ! rc-update show default 2>/dev/null | grep -q nwd-agent; then
    rc-update add nwd-agent default
  fi
  if ! rc-service nwd-agent status >/dev/null 2>&1; then
    rc-service nwd-agent start
  fi
}

pick_asset() {
  local file asset flat needle rest chunk digest url
  file=$1
  asset=$2
  flat=$(tr -d '\n' <"$file")
  needle='"name": "'"$asset"'"'
  rest=${flat#*"$needle"}
  if [ "$rest" = "$flat" ]; then
    needle='"name":"'"$asset"'"'
    rest=${flat#*"$needle"}
  fi
  if [ "$rest" = "$flat" ]; then
    die "发布里没有 ${asset}"
  fi
  chunk=${rest%%'"name":'*}
  digest=$(printf '%s\n' "$chunk" | sed -n 's/.*sha256:\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n 1)
  url=$(printf '%s\n' "$chunk" | sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
  if [ -z "$digest" ] || [ -z "$url" ]; then
    die "发布里没有 ${asset} 的校验和"
  fi
  printf '%s\n%s\n' "$digest" "$url"
}

release_tag() {
  local file flat tag
  file=$1
  flat=$(tr -d '\n' <"$file")
  tag=$(printf '%s\n' "$flat" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\(v[0-9A-Za-z._-]*\)".*/\1/p' | head -n 1)
  valid_tag "$tag" || die "发布标签无效"
  printf '%s\n' "$tag"
}

url_host() {
  local u
  u=$1
  u=${u#http://}
  u=${u#https://}
  u=${u%%/*}
  printf '%s\n' "$u"
}

accept_download_url() {
  local repo tag asset url api expected host api_host
  repo=$1
  tag=$2
  asset=$3
  url=$4
  api=$5
  case "$url" in
    *"$nl"*|*"$cr"*|*@*|*".."*|*"?"*|*"#"*) die "下载地址无效" ;;
  esac
  expected="https://github.com/ohmycggk/${repo}/releases/download/${tag}/${asset}"
  if [ "$url" = "$expected" ]; then
    return 0
  fi
  case "$api" in
    ""|https://api.github.com/*) die "下载地址无效" ;;
  esac
  case "$url" in
    http://*|https://*) ;;
    *) die "下载地址无效" ;;
  esac
  case "$url" in
    */"$asset") ;;
    *) die "下载地址无效" ;;
  esac
  host=$(url_host "$url")
  api_host=$(url_host "$api")
  if [ "$host" != "$api_host" ]; then
    die "下载地址无效"
  fi
}

verify_sha256() {
  local file digest sum
  file=$1
  digest=$2
  valid_hex64 "$digest" || die "校验和无效"
  sum=$(sha256sum "$file") || die "校验和不符"
  sum=${sum%% *}
  sum=$(printf '%s' "$sum" | tr 'A-F' 'a-f')
  digest=$(printf '%s' "$digest" | tr 'A-F' 'a-f')
  if [ "$sum" != "$digest" ]; then
    die "校验和不符"
  fi
}

download() {
  local url dest label
  url=$1
  dest=$2
  label=$3
  curl -fsSL -H "Accept: application/vnd.github+json" -H "User-Agent: nwdock-install" -o "$dest" "$url" || die "下载 ${label} 失败"
}

env_value() {
  case "$1" in
    NWDOCK_XRAY_API) printf '%s' "${NWDOCK_XRAY_API:-}" ;;
    NWDOCK_XRAY_URL) printf '%s' "${NWDOCK_XRAY_URL:-}" ;;
    NWDOCK_XRAY_SHA256) printf '%s' "${NWDOCK_XRAY_SHA256:-}" ;;
    NWDOCK_SINGBOX_API) printf '%s' "${NWDOCK_SINGBOX_API:-}" ;;
    NWDOCK_SINGBOX_URL) printf '%s' "${NWDOCK_SINGBOX_URL:-}" ;;
    NWDOCK_SINGBOX_SHA256) printf '%s' "${NWDOCK_SINGBOX_SHA256:-}" ;;
    *) die "下载地址无效" ;;
  esac
}

fetch_archive() {
  local repo asset version api_env url_env sha_env dest url digest api tag
  repo=$1
  asset=$2
  version=$3
  api_env=$4
  url_env=$5
  sha_env=$6
  dest=$7
  url=$(env_value "$url_env")
  if [ -n "$url" ]; then
    digest=$(env_value "$sha_env")
    if [ -z "$digest" ]; then
      die "缺少 ${sha_env}"
    fi
    valid_http_url "$url" || die "下载地址无效"
    download "$url" "$dest" "$asset"
    verify_sha256 "$dest" "$digest"
    return 0
  fi
  if [ -n "$version" ]; then
    valid_tag "$version" || die "${repo} 版本无效"
  fi
  api=$(env_value "$api_env")
  if [ -n "$api" ]; then
    valid_http_url "$api" || die "下载地址无效"
  elif [ -n "$version" ]; then
    api="https://api.github.com/repos/ohmycggk/${repo}/releases/tags/${version}"
  else
    api="https://api.github.com/repos/ohmycggk/${repo}/releases/latest"
  fi
  download "$api" "$tmp/release.json" "$repo"
  tag=$(release_tag "$tmp/release.json")
  if [ -n "$version" ] && [ -z "$(env_value "$api_env")" ] && [ "$tag" != "$version" ]; then
    die "发布标签不符"
  fi
  if [ "$repo" = sing-box ]; then
    asset="sing-box-${tag}-linux-amd64-v1.tar.gz"
  fi
  pick_asset "$tmp/release.json" "$asset" >"$tmp/picked"
  digest=$(head -n 1 "$tmp/picked")
  url=$(sed -n '2p' "$tmp/picked")
  accept_download_url "$repo" "$tag" "$asset" "$url" "$api"
  download "$url" "$dest" "$asset"
  verify_sha256 "$dest" "$digest"
  if [ "$repo" = sing-box ]; then
    printf '%s\n' "$tag"
  fi
}

reject_entries() {
  local entry
  entry=$1
  case "$entry" in
    /*|*".."*|*"$nl"*|*"$cr"*) die "压缩包路径无效" ;;
  esac
}

read_entries() {
  local found_name list found entry
  found_name=$1
  list=$2
  found=0
  while IFS= read -r entry || [ -n "$entry" ]; do
    [ -n "$entry" ] || continue
    reject_entries "$entry"
    if [ "$entry" = "$found_name" ]; then
      found=1
    fi
  done <"$list"
  if [ "$found" -ne 1 ]; then
    return 1
  fi
  return 0
}

extract_xray() {
  local zip dest
  zip=$1
  dest=$2
  unzip -Z1 "$zip" >"$tmp/entries" || die "压缩包路径无效"
  read_entries xray "$tmp/entries" || die "压缩包里没有 xray"
  unzip -p "$zip" xray >"$dest"
}

extract_singbox() {
  local archive dest member count
  archive=$1
  dest=$2
  tar -tzf "$archive" >"$tmp/entries" || die "压缩包路径无效"
  member=${SINGBOX_MEMBER:-}
  if [ -z "$member" ]; then
    member=$(grep -E '^sing-box-v[0-9A-Za-z._-]+-linux-amd64-v1/sing-box$' "$tmp/entries" || true)
    count=$(printf '%s\n' "$member" | grep -c . || true)
    if [ "$count" -ne 1 ]; then
      die "压缩包里没有 sing-box"
    fi
  fi
  read_entries "$member" "$tmp/entries" || die "压缩包里没有 sing-box"
  tar -xOzf "$archive" "$member" >"$dest"
}

require AGENT_PANEL_ENDPOINTS "${AGENT_PANEL_ENDPOINTS:-}"
require AGENT_PANEL_KEYPIN "${AGENT_PANEL_KEYPIN:-}"
require AGENT_ENROLL_TOKEN "${AGENT_ENROLL_TOKEN:-}"
require AGENT_CORE "${AGENT_CORE:-}"

valid_endpoint "$AGENT_PANEL_ENDPOINTS" || die "AGENT_PANEL_ENDPOINTS 必须是 http(s)://主机[:端口]"
valid_hex64 "$AGENT_PANEL_KEYPIN" || die "AGENT_PANEL_KEYPIN 必须是 64 位十六进制"
valid_hex64 "$AGENT_ENROLL_TOKEN" || die "AGENT_ENROLL_TOKEN 必须是 64 位十六进制"

case "$AGENT_CORE" in
  clash-meta-nw|mihomo|xray|singbox) ;;
  *) die "AGENT_CORE 只能是 clash-meta-nw、xray 或 singbox" ;;
esac

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
  die "只支持 Linux x86_64"
fi

prefix=${NWDOCK_INSTALL_PREFIX:-}
if [ -n "$prefix" ]; then
  valid_prefix "$prefix" || die "NWDOCK_INSTALL_PREFIX 无效"
elif [ "$(id -u)" -ne 0 ]; then
  die "需要 root"
fi

if [ -n "${AGENT_VERSION:-}" ]; then
  valid_tag "$AGENT_VERSION" || die "AGENT_VERSION 无效"
fi

ensure_tools

release_base=${NWDOCK_RELEASE_BASE:-}
if [ -z "$release_base" ]; then
  if [ -n "${AGENT_VERSION:-}" ]; then
    release_base="https://github.com/NWDock/nwdock-agent/releases/download/${AGENT_VERSION}"
  else
    release_base="https://github.com/NWDock/nwdock-agent/releases/latest/download"
  fi
fi
valid_http_url "$release_base" || die "下载地址无效"
release_base=${release_base%/}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

download "${release_base}/SHA256SUMS" "$tmp/SHA256SUMS" "agent 校验和"
download "${release_base}/agent" "$tmp/agent" "agent"
agent_sum=$(awk '$2=="agent" || $2=="*agent" {print $1; found=1; exit} END {if (!found) exit 1}' "$tmp/SHA256SUMS") || die "校验和里没有 agent"
verify_sha256 "$tmp/agent" "$agent_sum"

core_bin=""
case "$AGENT_CORE" in
  xray)
    fetch_archive "Xray-core" "Xray-linux-amd64.zip" "${XRAY_VERSION:-}" NWDOCK_XRAY_API NWDOCK_XRAY_URL NWDOCK_XRAY_SHA256 "$tmp/xray.zip" >/dev/null
    extract_xray "$tmp/xray.zip" "$tmp/xray"
    core_bin=xray
    ;;
  singbox)
    if [ -n "${NWDOCK_SINGBOX_URL:-}" ]; then
      fetch_archive "sing-box" "sing-box.tar.gz" "${SINGBOX_VERSION:-}" NWDOCK_SINGBOX_API NWDOCK_SINGBOX_URL NWDOCK_SINGBOX_SHA256 "$tmp/sing-box.tar.gz" >/dev/null
    else
      sb_tag=$(fetch_archive "sing-box" "sing-box.tar.gz" "${SINGBOX_VERSION:-}" NWDOCK_SINGBOX_API NWDOCK_SINGBOX_URL NWDOCK_SINGBOX_SHA256 "$tmp/sing-box.tar.gz")
      SINGBOX_MEMBER="sing-box-${sb_tag}-linux-amd64-v1/sing-box"
    fi
    extract_singbox "$tmp/sing-box.tar.gz" "$tmp/sing-box"
    core_bin=sing-box
    ;;
esac

root_dir="${prefix}/opt/nwd-agent"
bin_dir="${root_dir}/bin"
data_dir="${root_dir}/data"
conf_file="${root_dir}/agent.conf"
unit="${root_dir}/nwd-agent.service"
initd="${root_dir}/nwd-agent.initd"

install -d -m 0700 "$root_dir" "$data_dir"
install -d -m 0755 "$bin_dir"
install -m 0755 "$tmp/agent" "${bin_dir}/agent"
if [ -n "$core_bin" ]; then
  install -m 0755 "$tmp/$core_bin" "${bin_dir}/$core_bin"
fi

cat >"$unit" <<'UNIT'
[Unit]
Description=NWDock agent

[Service]
ExecStart=/opt/nwd-agent/bin/agent -config /opt/nwd-agent/agent.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$unit"

cat >"$initd" <<'INITD'
#!/sbin/openrc-run

name="nwd-agent"
description="NWDock agent"
supervisor=supervise-daemon
command="/opt/nwd-agent/bin/agent"
command_args="-config /opt/nwd-agent/agent.conf"
pidfile="/run/${RC_SVCNAME}.pid"
respawn_delay=2
respawn_max=0

depend() {
	need net
}
INITD
chmod 0644 "$initd"

umask 077
{
  printf 'AGENT_RUNTIME=service\n'
  printf 'AGENT_DATA_DIR=/opt/nwd-agent/data\n'
  printf 'AGENT_PANEL_ENDPOINTS=%s\n' "$AGENT_PANEL_ENDPOINTS"
  printf 'AGENT_PANEL_KEYPIN=%s\n' "$AGENT_PANEL_KEYPIN"
  printf 'AGENT_ENROLL_TOKEN=%s\n' "$AGENT_ENROLL_TOKEN"
  if [ "$AGENT_CORE" = xray ]; then
    printf 'AGENT_XRAY_BIN=/opt/nwd-agent/bin/xray\n'
    printf 'AGENT_XRAY_API_ADDR=127.0.0.1:10085\n'
  elif [ "$AGENT_CORE" = singbox ]; then
    printf 'AGENT_SINGBOX_BIN=/opt/nwd-agent/bin/sing-box\n'
  fi
} >"$conf_file"
chmod 0600 "$conf_file"

if [ -z "$prefix" ]; then
  init=$(detect_init)
  case "$init" in
    systemd)
      systemctl daemon-reload
      systemctl enable --now /opt/nwd-agent/nwd-agent.service
      ;;
    openrc)
      enable_openrc
      ;;
  esac
fi
