#!/bin/sh
# Raincoat build-and-install script.
#
# Works two ways:
#   from a checkout:  ./install.sh
#   one-liner:        curl -fsSL https://raw.githubusercontent.com/zachgenius/raincoat/master/install.sh | sh
#
# It installs the build dependencies with your package manager (asking sudo where needed),
# builds with CMake, and installs to /usr/local (override with --prefix or PREFIX=).
#
#   ./install.sh [--prefix <dir>] [--no-deps] [--no-install]
#     --prefix <dir>  install prefix (default /usr/local; PREFIX env var also works)
#     --no-deps       skip the package-manager dependency step
#     --no-install    build only; leave the binary in ./build/raincoat
set -eu

REPO_URL="https://github.com/zachgenius/raincoat.git"
PREFIX="${PREFIX:-/usr/local}"
DO_DEPS=1
DO_INSTALL=1

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)     PREFIX="$2"; shift 2 ;;
        --prefix=*)   PREFIX="${1#--prefix=}"; shift ;;
        --no-deps)    DO_DEPS=0; shift ;;
        --no-install) DO_INSTALL=0; shift ;;
        -h|--help)    sed -n '2,15p' "$0" 2>/dev/null || true; exit 0 ;;
        *) echo "install.sh: unknown option: $1" >&2; exit 2 ;;
    esac
done

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Re-run a command with sudo only when we are not already root.
as_root() {
    if [ "$(id -u)" = "0" ]; then "$@"; else sudo "$@"; fi
}

OS="$(uname -s)"

# --- 1. Dependencies --------------------------------------------------------
install_deps() {
    case "$OS" in
    Linux)
        if command -v apt-get >/dev/null 2>&1; then
            say "Installing dependencies (apt): bubblewrap cmake g++ libssl-dev libgtest-dev"
            as_root apt-get install -y bubblewrap cmake g++ libssl-dev libgtest-dev
        elif command -v dnf >/dev/null 2>&1; then
            say "Installing dependencies (dnf): bubblewrap cmake gcc-c++ openssl-devel gtest-devel"
            as_root dnf install -y bubblewrap cmake gcc-c++ openssl-devel gtest-devel
        elif command -v pacman >/dev/null 2>&1; then
            say "Installing dependencies (pacman): bubblewrap cmake gcc openssl gtest"
            as_root pacman -S --needed --noconfirm bubblewrap cmake gcc openssl gtest
        else
            fail "no supported package manager found (apt/dnf/pacman); install bubblewrap, cmake, a C++17 compiler, OpenSSL and GoogleTest dev packages manually, then re-run with --no-deps"
        fi
        ;;
    Darwin)
        command -v brew >/dev/null 2>&1 || fail "Homebrew not found — install it from https://brew.sh, or install cmake/openssl@3/googletest manually and re-run with --no-deps"
        say "Installing dependencies (brew): cmake openssl@3 googletest"
        brew install cmake openssl@3 googletest
        # The sandbox itself is Apple's built-in Seatbelt — nothing else to install.
        ;;
    *)
        fail "unsupported platform: $OS (Raincoat targets Linux and macOS)"
        ;;
    esac
}
[ "$DO_DEPS" = "1" ] && install_deps

# --- 2. Sources -------------------------------------------------------------
# When piped via curl there is no checkout — clone into a temp dir first.
if [ -f CMakeLists.txt ] && grep -q '^project(raincoat' CMakeLists.txt 2>/dev/null; then
    SRC_DIR="$(pwd)"
else
    SRC_DIR="$(mktemp -d "${TMPDIR:-/tmp}/raincoat-src.XXXXXX")"
    trap 'rm -rf "$SRC_DIR"' EXIT
    say "Cloning $REPO_URL"
    command -v git >/dev/null 2>&1 || fail "git not found"
    git clone --depth 1 "$REPO_URL" "$SRC_DIR"
fi

# --- 3. Build ---------------------------------------------------------------
# A dedicated build dir so running this from a dev checkout never reconfigures ./build.
BUILD_DIR="$SRC_DIR/build-release"
say "Building in $BUILD_DIR"
CMAKE_ARGS="-DCMAKE_BUILD_TYPE=Release"
if [ "$OS" = "Darwin" ]; then
    # Homebrew's openssl@3 is keg-only; point find_package(OpenSSL) at it.
    CMAKE_ARGS="$CMAKE_ARGS -DCMAKE_PREFIX_PATH=$(brew --prefix openssl@3)"
fi
# shellcheck disable=SC2086
cmake -S "$SRC_DIR" -B "$BUILD_DIR" $CMAKE_ARGS
cmake --build "$BUILD_DIR" -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

if [ "$DO_INSTALL" = "0" ]; then
    say "Build done: $BUILD_DIR/raincoat (skipping install as requested)"
    exit 0
fi

# --- 4. Install -------------------------------------------------------------
say "Installing to $PREFIX"
if mkdir -p "$PREFIX" 2>/dev/null && [ -w "$PREFIX" ]; then
    cmake --install "$BUILD_DIR" --prefix "$PREFIX"
else
    as_root cmake --install "$BUILD_DIR" --prefix "$PREFIX"
fi

say "Installed: $PREFIX/bin/raincoat"
say "Checking the host with 'raincoat doctor':"
"$PREFIX/bin/raincoat" doctor || true
