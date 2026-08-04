#!/bin/sh
# stallwatch installer — https://github.com/varbees/stallwatch
#
# Usage:
#   curl -fsSL https://antharmaya.com/tools/stallwatch/install.sh | sh
#
# Environment:
#   STALLWATCH_VERSION   install a specific tag (default: latest release)
#   STALLWATCH_BIN_DIR   install location (default: ~/.local/bin)
#
# Installs two static binaries into your home directory. No sudo, no package
# manager, nothing written outside BIN_DIR. Every download is checksum-verified
# against the SHA256SUMS published with the release.
#
# Everything is wrapped in main() and only called on the very last line, so a
# connection that drops mid-transfer leaves a partial script that does nothing
# rather than a half-defined one that runs.

set -eu

REPO="varbees/stallwatch"

say() { printf '%s\n' "$*"; }
err() { printf 'error: %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || err "this installer needs '$1', which is not on your PATH"
}

detect_target() {
    os="$(uname -s)"
    [ "$os" = "Linux" ] || err "stallwatch reads Linux kernel pressure files (/proc/pressure) and cannot run on $os"

    arch="$(uname -m)"
    case "$arch" in
        x86_64 | amd64)  echo "x86_64-unknown-linux-musl"  ;;
        aarch64 | arm64) echo "aarch64-unknown-linux-musl" ;;
        *) err "no prebuilt binary for $arch — build from source: cargo install stallwatch" ;;
    esac
}

latest_version() {
    # Ask GitHub for the newest release tag. Parsed with sed rather than jq so
    # the installer keeps working on a machine with nothing extra installed.
    curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' \
        | head -n 1
}

verify_checksum() {
    # $1 = file to check, $2 = SHA256SUMS, $3 = name as listed in SHA256SUMS
    expected="$(sed -n "s/^\([0-9a-f]\{64\}\)  *$3\$/\1/p" "$2" | head -n 1)"
    [ -n "$expected" ] || err "$3 is not listed in SHA256SUMS — refusing to install an unverified binary"

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$1" | cut -d' ' -f1)"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$1" | cut -d' ' -f1)"
    else
        err "no sha256sum or shasum available to verify the download"
    fi

    [ "$actual" = "$expected" ] || err "checksum mismatch for $3
  expected $expected
  got      $actual
This download does not match what was published. Not installing."
}

main() {
    need curl
    need tar

    target="$(detect_target)"
    bin_dir="${STALLWATCH_BIN_DIR:-$HOME/.local/bin}"

    version="${STALLWATCH_VERSION:-$(latest_version)}"
    [ -n "$version" ] || err "could not determine the latest release — set STALLWATCH_VERSION=v0.1.0 to pin one"

    # Tag is v-prefixed; the artifact names are not.
    bare="${version#v}"
    tarball="stallwatch-${bare}-${target}.tar.gz"
    base="https://github.com/$REPO/releases/download/$version"

    say "stallwatch $version  ($target)"

    tmp="$(mktemp -d)"
    # Clean up on any exit path, including a failed download.
    trap 'rm -rf "$tmp"' EXIT INT TERM

    say "  downloading…"
    curl -fsSL "$base/$tarball"    -o "$tmp/$tarball" || err "could not download $tarball
Check that $version has a release for $target: https://github.com/$REPO/releases"
    curl -fsSL "$base/SHA256SUMS"  -o "$tmp/SHA256SUMS" || err "could not download SHA256SUMS"

    say "  verifying checksum…"
    verify_checksum "$tmp/$tarball" "$tmp/SHA256SUMS" "$tarball"

    tar -xzf "$tmp/$tarball" -C "$tmp"
    extracted="$tmp/stallwatch-${bare}-${target}"

    mkdir -p "$bin_dir"
    install -m 755 "$extracted/stallwatch"  "$bin_dir/stallwatch"
    install -m 755 "$extracted/stallwatchd" "$bin_dir/stallwatchd"

    say "  installed to $bin_dir"
    say ""

    # A tool nobody can run is not installed. Say so plainly.
    case ":$PATH:" in
        *":$bin_dir:"*) say "Run: stallwatch" ;;
        *)
            say "$bin_dir is not on your PATH. Add it:"
            say "    echo 'export PATH=\"\$PATH:$bin_dir\"' >> ~/.profile"
            say ""
            say "Or run it directly: $bin_dir/stallwatch"
            ;;
    esac

    # PSI is a kernel build option. Finding out now beats finding out from an
    # empty report that looks like "nothing is wrong".
    if [ ! -e /proc/pressure ]; then
        say ""
        say "Note: this kernel exposes no /proc/pressure, so stallwatch cannot see"
        say "stalls. It needs CONFIG_PSI=y, and on kernels built with"
        say "CONFIG_PSI_DEFAULT_DISABLED=y also 'psi=1' on the kernel command line."
    fi
}

main "$@"
