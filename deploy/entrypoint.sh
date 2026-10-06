#!/bin/sh
set -eu
dest="${AGENT_DATA_DIR:-/var/lib/nowhere-agent}"
src=/usr/share/nowhere
mkdir -p "$dest"
for name in geoip.dat geosite.dat; do
  if [ ! -f "$dest/$name" ] && [ -f "$src/$name" ]; then
    cp "$src/$name" "$dest/$name"
  fi
done
exec /usr/local/bin/nowhere-agent
