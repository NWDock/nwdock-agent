#!/usr/bin/env bash
# 与 panel/internal/panel/install-service.sh 必须逐字相同。对照：scripts/check-embedded-copies.sh
# 由面板安装命令以环境变量调用。NWDOCK_INSTALL_PREFIX、NWDOCK_*_API、NWDOCK_*_URL 只用于测试。
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
  clash-meta-nw|mihomo|xray|singbox) ;;
  *) die "AGENT_CORE 只能是 clash-meta-nw、xray 或 singbox" ;;
esac

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  die "只支持 Linux x86_64"
fi

prefix=${NWDOCK_INSTALL_PREFIX:-}
if [[ -n "$prefix" ]]; then
  if [[ ! "$prefix" =~ ^/[-A-Za-z0-9._/]+$ ]]; then
    die "NWDOCK_INSTALL_PREFIX 无效"
  fi
elif [[ "$(id -u)" -ne 0 ]]; then
  die "需要 root"
fi

command -v curl >/dev/null 2>&1 || die "需要 curl"
command -v sha256sum >/dev/null 2>&1 || die "需要 sha256sum"
command -v install >/dev/null 2>&1 || die "需要 install"
if [[ "$AGENT_CORE" == xray ]]; then
  command -v unzip >/dev/null 2>&1 || die "需要 unzip"
fi
if [[ "$AGENT_CORE" == singbox ]]; then
  command -v tar >/dev/null 2>&1 || die "需要 tar"
fi
if [[ -z "$prefix" ]] && ! command -v systemctl >/dev/null 2>&1; then
  die "需要 systemd"
fi

# 发布接口把 digest 和 browser_download_url 放在资产 name 之后。测试夹具保持这个顺序。
pick_asset() {
  local file=$1 asset=$2 flat needle rest chunk digest url
  flat=$(tr -d '\n' <"$file")
  needle='"name": "'"$asset"'"'
  rest=${flat#*"$needle"}
  if [[ "$rest" == "$flat" ]]; then
    needle='"name":"'"$asset"'"'
    rest=${flat#*"$needle"}
  fi
  if [[ "$rest" == "$flat" ]]; then
    die "发布里没有 ${asset}"
  fi
  chunk=${rest%%'"name":'*}
  digest=$(printf '%s' "$chunk" | grep -oE -m 1 'sha256:[0-9a-fA-F]{64}' | cut -d: -f2 || true)
  url=$(printf '%s' "$chunk" | grep -oE -m 1 '"browser_download_url":[[:space:]]*"https?://[^"]+"' | sed -E 's/.*"browser_download_url":[[:space:]]*"([^"]+)".*/\1/' || true)
  if [[ -z "$digest" || -z "$url" ]]; then
    die "发布里没有 ${asset} 的校验和"
  fi
  printf '%s\n%s\n' "$digest" "$url"
}

release_tag() {
  local file=$1 flat tag
  flat=$(tr -d '\n' <"$file")
  tag=$(printf '%s' "$flat" | grep -oE -m 1 '"tag_name":[[:space:]]*"v[0-9A-Za-z._-]+"' | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/' || true)
  if [[ ! "$tag" =~ ^v[0-9A-Za-z._-]+$ || "$tag" == *..* ]]; then
    die "发布标签无效"
  fi
  printf '%s\n' "$tag"
}

url_host() {
  local u=$1
  u=${u#http://}
  u=${u#https://}
  u=${u%%/*}
  printf '%s\n' "$u"
}

accept_download_url() {
  local repo=$1 tag=$2 asset=$3 url=$4 api=$5
  local expected host api_host
  if [[ "$url" == *$'\n'* || "$url" == *$'\r'* || "$url" == *"@"* || "$url" == *".."* || "$url" == *"?"* || "$url" == *"#"* ]]; then
    die "下载地址无效"
  fi
  expected="https://github.com/ohmycggk/${repo}/releases/download/${tag}/${asset}"
  if [[ "$url" == "$expected" ]]; then
    return 0
  fi
  if [[ -z "$api" || "$api" == https://api.github.com/* ]]; then
    die "下载地址无效"
  fi
  if [[ ! "$url" =~ ^https?:// || "$url" != */"$asset" ]]; then
    die "下载地址无效"
  fi
  host=$(url_host "$url")
  api_host=$(url_host "$api")
  if [[ "$host" != "$api_host" ]]; then
    die "下载地址无效"
  fi
}

verify_sha256() {
  local file=$1 digest=$2 sum
  if [[ ! "$digest" =~ ^[0-9a-fA-F]{64}$ ]]; then
    die "校验和无效"
  fi
  sum=$(sha256sum "$file" | awk '{print $1}')
  if [[ "${sum,,}" != "${digest,,}" ]]; then
    die "校验和不符"
  fi
}

download() {
  local url=$1 dest=$2 label=$3
  curl -fsSL -H "Accept: application/vnd.github+json" -H "User-Agent: nwdock-install" -o "$dest" "$url" || die "下载 ${label} 失败"
}

fetch_archive() {
  local repo=$1 asset=$2 version=$3 api_env=$4 url_env=$5 sha_env=$6 dest=$7
  local api url digest tag
  if [[ -n "${!url_env:-}" ]]; then
    url=${!url_env}
    digest=${!sha_env:-}
    if [[ -z "$digest" ]]; then
      die "缺少 ${sha_env}"
    fi
    if [[ ! "$url" =~ ^https?://[^[:space:]]+$ || "$url" == *..* ]]; then
      die "下载地址无效"
    fi
    download "$url" "$dest" "$asset"
    verify_sha256 "$dest" "$digest"
    return 0
  fi
  if [[ -n "$version" ]]; then
    if [[ ! "$version" =~ ^v[0-9A-Za-z._-]+$ || "$version" == *..* ]]; then
      die "${repo} 版本无效"
    fi
  fi
  if [[ -n "${!api_env:-}" ]]; then
    api=${!api_env}
    if [[ ! "$api" =~ ^https?://[^[:space:]]+$ || "$api" == *..* ]]; then
      die "下载地址无效"
    fi
  elif [[ -n "$version" ]]; then
    api="https://api.github.com/repos/ohmycggk/${repo}/releases/tags/${version}"
  else
    api="https://api.github.com/repos/ohmycggk/${repo}/releases/latest"
  fi
  download "$api" "$tmp/release.json" "$repo"
  tag=$(release_tag "$tmp/release.json")
  if [[ -n "$version" && -z "${!api_env:-}" && "$tag" != "$version" ]]; then
    die "发布标签不符"
  fi
  if [[ "$repo" == sing-box ]]; then
    asset="sing-box-${tag}-linux-amd64-v1.tar.gz"
  fi
  {
    read -r digest
    read -r url
  } < <(pick_asset "$tmp/release.json" "$asset")
  accept_download_url "$repo" "$tag" "$asset" "$url" "$api"
  download "$url" "$dest" "$asset"
  verify_sha256 "$dest" "$digest"
  if [[ "$repo" == sing-box ]]; then
    printf '%s\n' "$tag"
  fi
}

reject_entries() {
  local entry
  for entry in "$@"; do
    if [[ "$entry" == /* || "$entry" == *..* || "$entry" == *$'\n'* || "$entry" == *$'\r'* ]]; then
      die "压缩包路径无效"
    fi
  done
}

extract_xray() {
  local zip=$1 dest=$2 entry found=0
  local -a entries=()
  mapfile -t entries < <(unzip -Z1 "$zip")
  reject_entries "${entries[@]}"
  for entry in "${entries[@]}"; do
    if [[ "$entry" == xray ]]; then
      found=1
    fi
  done
  if [[ "$found" -ne 1 ]]; then
    die "压缩包里没有 xray"
  fi
  unzip -p "$zip" xray >"$dest"
}

extract_singbox() {
  local archive=$1 dest=$2 member entry found=0
  local -a entries=()
  mapfile -t entries < <(tar -tzf "$archive")
  reject_entries "${entries[@]}"
  if [[ -n "${SINGBOX_MEMBER:-}" ]]; then
    member=$SINGBOX_MEMBER
  else
    member=$(printf '%s\n' "${entries[@]}" | grep -E '^sing-box-v[0-9A-Za-z._-]+-linux-amd64-v1/sing-box$' || true)
    if [[ "$(printf '%s\n' "$member" | grep -c .)" -ne 1 ]]; then
      die "压缩包里没有 sing-box"
    fi
  fi
  for entry in "${entries[@]}"; do
    if [[ "$entry" == "$member" ]]; then
      found=1
    fi
  done
  if [[ "$found" -ne 1 ]]; then
    die "压缩包里没有 sing-box"
  fi
  tar -xOzf "$archive" "$member" >"$dest"
}

release_base=${NWDOCK_RELEASE_BASE:-}
if [[ -z "$release_base" ]]; then
  if [[ -n "${AGENT_VERSION:-}" ]]; then
    if [[ ! "$AGENT_VERSION" =~ ^v[0-9A-Za-z._-]+$ || "$AGENT_VERSION" == *..* ]]; then
      die "AGENT_VERSION 无效"
    fi
    release_base="https://github.com/NWDock/nwdock-agent/releases/download/${AGENT_VERSION}"
  else
    release_base="https://github.com/NWDock/nwdock-agent/releases/latest/download"
  fi
fi
if [[ ! "$release_base" =~ ^https?://[^[:space:]]+$ || "$release_base" == *..* ]]; then
  die "下载地址无效"
fi
release_base=${release_base%/}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

download "${release_base}/SHA256SUMS" "$tmp/SHA256SUMS" "nowhere-agent 校验和"
download "${release_base}/nowhere-agent" "$tmp/nowhere-agent" "nowhere-agent"
agent_sum=$(awk '$2=="nowhere-agent" || $2=="*nowhere-agent" {print $1; found=1; exit} END {if (!found) exit 1}' "$tmp/SHA256SUMS") || die "校验和里没有 nowhere-agent"
verify_sha256 "$tmp/nowhere-agent" "$agent_sum"

core_bin=""
case "$AGENT_CORE" in
  xray)
    fetch_archive "Xray-core" "Xray-linux-amd64.zip" "${XRAY_VERSION:-}" NWDOCK_XRAY_API NWDOCK_XRAY_URL NWDOCK_XRAY_SHA256 "$tmp/xray.zip" >/dev/null
    extract_xray "$tmp/xray.zip" "$tmp/xray"
    core_bin=xray
    ;;
  singbox)
    if [[ -n "${NWDOCK_SINGBOX_URL:-}" ]]; then
      fetch_archive "sing-box" "sing-box.tar.gz" "${SINGBOX_VERSION:-}" NWDOCK_SINGBOX_API NWDOCK_SINGBOX_URL NWDOCK_SINGBOX_SHA256 "$tmp/sing-box.tar.gz" >/dev/null
    else
      sb_tag=$(fetch_archive "sing-box" "sing-box.tar.gz" "${SINGBOX_VERSION:-}" NWDOCK_SINGBOX_API NWDOCK_SINGBOX_URL NWDOCK_SINGBOX_SHA256 "$tmp/sing-box.tar.gz")
      SINGBOX_MEMBER="sing-box-${sb_tag}-linux-amd64-v1/sing-box"
    fi
    extract_singbox "$tmp/sing-box.tar.gz" "$tmp/sing-box"
    core_bin=sing-box
    ;;
esac

if [[ -z "$prefix" ]] && systemctl is-active --quiet nowhere-agent; then
  systemctl stop nowhere-agent
fi

bin_dir="${prefix}/usr/local/bin"
unit_dir="${prefix}/etc/systemd/system"
etc_dir="${prefix}/etc/nowhere"
data_dir="${prefix}/var/lib/nowhere-agent"
conf_file="${etc_dir}/agent.conf"
unit="${unit_dir}/nowhere-agent.service"

install -d -m 0755 "$bin_dir" "$unit_dir"
install -d -m 0700 "$etc_dir" "$data_dir"
install -m 0755 "$tmp/nowhere-agent" "${bin_dir}/nowhere-agent"
if [[ -n "$core_bin" ]]; then
  install -m 0755 "$tmp/$core_bin" "${bin_dir}/$core_bin"
fi

cat >"$unit" <<'UNIT'
[Unit]
Description=Nowhere node agent

[Service]
ExecStart=/usr/local/bin/nowhere-agent -config /etc/nowhere/agent.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$unit"

umask 077
{
  printf 'AGENT_RUNTIME=service\n'
  printf 'AGENT_DATA_DIR=/var/lib/nowhere-agent\n'
  printf 'AGENT_PANEL_ENDPOINTS=%s\n' "$AGENT_PANEL_ENDPOINTS"
  printf 'AGENT_PANEL_KEYPIN=%s\n' "$AGENT_PANEL_KEYPIN"
  printf 'AGENT_ENROLL_TOKEN=%s\n' "$AGENT_ENROLL_TOKEN"
  if [[ "$AGENT_CORE" == xray ]]; then
    printf 'AGENT_XRAY_BIN=/usr/local/bin/xray\n'
    printf 'AGENT_XRAY_API_ADDR=127.0.0.1:10085\n'
  elif [[ "$AGENT_CORE" == singbox ]]; then
    printf 'AGENT_SINGBOX_BIN=/usr/local/bin/sing-box\n'
  fi
} >"$conf_file"
chmod 0600 "$conf_file"
rm -f "${etc_dir}/agent.env"

if [[ -z "$prefix" ]]; then
  systemctl daemon-reload
  systemctl enable --now nowhere-agent
fi
