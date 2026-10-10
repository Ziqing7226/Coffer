#!/bin/sh
# GitCoffer installer: downloads the latest release (or GITCOFFER_VERSION),
# verifies the archive against the published checksums, and installs the
# two binaries into your bin directory. No root, no administrator rights.
#
#   curl -fsSL https://raw.githubusercontent.com/Ziqing7226/GitCoffer/main/scripts/install.sh | sh
#
# Override the destination with GITCOFFER_BIN and the version with
# GITCOFFER_VERSION (a tag like v1.0.0-rc.2; default: latest release).

set -eu

REPO="Ziqing7226/GitCoffer"
BIN_DIR="${GITCOFFER_BIN:-$HOME/.local/bin}"
VERSION="${GITCOFFER_VERSION:-latest}"

say() { printf '%s\n' "$*"; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || { say "error: '$1' is required but not installed"; exit 1; }
}

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$1"
    else
        say "error: need curl or wget"; exit 1
    fi
}

fetch_file() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        say "error: need curl or wget"; exit 1
    fi
}

os=$(uname -s)
arch=$(uname -m)
case "$os" in
    Linux*) os_name="linux" ;;
    Darwin*) os_name="darwin" ;;
    *) say "error: unsupported OS '$os' — download from https://github.com/$REPO/releases"; exit 1 ;;
esac
case "$arch" in
    x86_64|amd64) arch_name="amd64" ;;
    aarch64|arm64) arch_name="arm64" ;;
    *) say "error: unsupported architecture '$arch'"; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
    need_cmd "grep"
    VERSION=$(fetch "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
    [ -n "$VERSION" ] || { say "error: could not determine the latest release"; exit 1; }
fi

archive="gitcoffer-${VERSION#v}-${os_name}-${arch_name}.tar.gz"
base="https://github.com/$REPO/releases/download/$VERSION"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

say "Downloading $archive"
fetch_file "$base/$archive" "$tmp/$archive"
fetch_file "$base/checksums.txt" "$tmp/checksums.txt"

# Integrity: the archive must match its published sha256.
cd "$tmp"
want=$(grep "$archive" checksums.txt | cut -d' ' -f1)
[ -n "$want" ] || { say "error: checksums.txt has no entry for $archive"; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$archive" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "$archive" | cut -d' ' -f1)
else
    say "error: need sha256sum or shasum to verify the download"; exit 1
fi
[ "$want" = "$got" ] || { say "error: checksum mismatch for $archive (want $want, got $got)"; exit 1; }
say "Checksum OK"

mkdir -p "$BIN_DIR"
tar -xzf "$archive"
mv "${archive%.tar.gz}/gitcoffer" "${archive%.tar.gz}/git-remote-coffer" "$BIN_DIR/"
chmod +x "$BIN_DIR/gitcoffer" "$BIN_DIR/git-remote-coffer"

say "Installed: $($BIN_DIR/gitcoffer version)"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) say "Note: $BIN_DIR is not on your PATH — add it to your shell profile:"
       say "  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
