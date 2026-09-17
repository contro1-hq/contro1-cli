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

# Where to install:
#   1. CONTRO1_INSTALL_DIR when set.
#   2. Where contro1 already is, when that place is writable: updating in place
#      means an old copy can never sit earlier on PATH and shadow the new one.
#   3. /usr/local/bin, through sudo only when sudo can actually ask someone (a
#      terminal) or needs no password. Piped from an agent with no terminal, a
#      sudo prompt would wait forever for a password nobody can type.
#   4. Otherwise ~/.local/bin, no privileges needed.
dir="${CONTRO1_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  existing=$(command -v "$BIN" 2>/dev/null || true)
  if [ -n "$existing" ] && [ -w "$(dirname "$existing")" ]; then
    dir=$(dirname "$existing")
  fi
fi
if [ -z "$dir" ]; then
  dir=/usr/local/bin
  if [ ! -w "$dir" ] && [ "$(id -u)" -ne 0 ]; then
    can_sudo=""
    if command -v sudo >/dev/null 2>&1; then
      if sudo -n true 2>/dev/null; then
        can_sudo=yes
      elif (: </dev/tty) 2>/dev/null; then
        can_sudo=tty
      fi
    fi
    if [ -n "$can_sudo" ]; then
      echo "Installing to $dir (sudo)"
      if [ "$can_sudo" = tty ]; then
        sudo install -m 0755 "$tmp/$BIN" "$dir/$BIN" </dev/tty
      else
        sudo -n install -m 0755 "$tmp/$BIN" "$dir/$BIN"
      fi
      echo "Installed: $("$dir/$BIN" --version 2>/dev/null || echo "$dir/$BIN")"
      exit 0
    fi
    dir="$HOME/.local/bin"
    echo "No terminal for a sudo password; installing to $dir instead (no privileges needed)"
  fi
fi
mkdir -p "$dir"
install -m 0755 "$tmp/$BIN" "$dir/$BIN"
echo "Installed contro1 to $dir/$BIN"
"$dir/$BIN" --version 2>/dev/null || true
found=$(command -v "$BIN" 2>/dev/null || true)
if [ -n "$found" ] && [ "$found" != "$dir/$BIN" ]; then
  echo "Note: $found comes first on your PATH and is not the copy just installed. Remove it or put $dir first."
fi
