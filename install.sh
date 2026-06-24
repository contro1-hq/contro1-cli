#!/usr/bin/env sh
# Install the contro1 CLI on macOS or Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/contro1-hq/contro1-cli/main/install.sh | sh
#
# Env:
#   CONTRO1_VERSION   pin a version (e.g. v0.1.0); default: latest
#   CONTRO1_INSTALL_DIR  install dir; default: /usr/local/bin (falls back to ~/.local/bin)
set -eu

REPO="contro1-hq/contro1-cli"
BIN="contro1"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux) os=linux ;;
  darwin) os=darwin ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

version="${CONTRO1_VERSION:-}"
if [ -z "$version" ]; then
  version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
fi
if [ -z "$version" ]; then
  echo "could not determine latest version; set CONTRO1_VERSION" >&2; exit 1
fi
ver_no_v=${version#v}

asset="${BIN}_${ver_no_v}_${os}_${arch}.tar.gz"
url="https://github.com/${REPO}/releases/download/${version}/${asset}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading $url"
curl -fsSL "$url" -o "$tmp/$asset"
tar -xzf "$tmp/$asset" -C "$tmp"

dir="${CONTRO1_INSTALL_DIR:-/usr/local/bin}"
if [ ! -w "$dir" ] 2>/dev/null && [ -z "${CONTRO1_INSTALL_DIR:-}" ]; then
  if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
      echo "Installing to $dir (sudo)"
      sudo install -m 0755 "$tmp/$BIN" "$dir/$BIN"
      echo "Installed: $("$dir/$BIN" --version 2>/dev/null || echo "$dir/$BIN")"
      exit 0
    fi
    dir="$HOME/.local/bin"
    mkdir -p "$dir"
    echo "No write access to /usr/local/bin; installing to $dir (ensure it is on your PATH)"
  fi
fi
mkdir -p "$dir"
install -m 0755 "$tmp/$BIN" "$dir/$BIN"
echo "Installed contro1 to $dir/$BIN"
"$dir/$BIN" --version 2>/dev/null || true
