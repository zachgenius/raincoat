# Installing and building Raincoat

Raincoat is a C++17 project built with CMake (≥ 3.16). Building needs a C/C++ toolchain,
**OpenSSL** (the egress bridge terminates HTTPS via OpenSSL), and **GoogleTest** (the test
suite is built by default). The runtime dependency is per-platform: **bubblewrap** on Linux;
on macOS the sandbox is Apple's built-in Seatbelt, so there is nothing extra to install.

## Quick install (one-liner)

```sh
curl -fsSL https://raw.githubusercontent.com/zachgenius/raincoat/master/install.sh | sh
```

The script installs the build dependencies with your package manager (apt/dnf/pacman/brew),
builds, installs to `/usr/local`, and runs `raincoat doctor`. From a checkout, run
`./install.sh` — flags: `--prefix <dir>` (or `PREFIX=`), `--no-deps` (skip the package
manager), `--no-install` (build only). The rest of this document is the same thing by hand.

## 1. Install the dependencies

**Linux**

```sh
# Ubuntu/Debian
sudo apt install bubblewrap cmake g++ libssl-dev libgtest-dev
# Fedora
sudo dnf install bubblewrap cmake gcc-c++ openssl-devel gtest-devel
# Arch
sudo pacman -S bubblewrap cmake gcc openssl gtest
```

Optional: [`pasta`](https://passt.top/) (package `passt` on all three) enables the
isolated-netns egress jail; without it the egress bridge falls back to the shared host
network namespace (`raincoat doctor` reports which you have).

**macOS**

```sh
xcode-select --install                    # compiler toolchain (skip if Xcode/CLT is installed)
brew install cmake openssl@3 googletest
```

Apple's Seatbelt (`sandbox_init` / `sandbox-exec`) ships with macOS — nothing to install for
the sandbox itself.

## 2. Build

```sh
git clone https://github.com/zachgenius/raincoat.git
cd raincoat
cmake -S . -B build
cmake --build build -j
```

On macOS, point CMake at Homebrew's keg-only `openssl@3` when configuring:

```sh
cmake -S . -B build -DCMAKE_PREFIX_PATH="$(brew --prefix openssl@3)"
cmake --build build -j
```

The binary lands at `./build/raincoat`. CMake selects the sandbox backend at configure time:
bubblewrap on Linux, Seatbelt on macOS (where it also builds the `rc_interpose.dylib`
identity interposer next to the binary). See
[`MACOS.md`](MACOS.md#building-and-running-on-macos) for macOS specifics.

## 3. Install

`sudo cmake --install build` installs to `/usr/local` (`bin/raincoat`, plus
`lib/raincoat/rc_interpose.dylib` on macOS). Pass `--prefix <dir>` to install elsewhere.

## 4. Check your host

`raincoat doctor` verifies that everything Raincoat needs is present and working — bwrap is
installed and executable, user namespaces are available, and a `bwrap ... true` smoke test
succeeds. It exits non-zero if the host is unusable.

```
$ raincoat doctor
Raincoat doctor
===============
  [ OK ] bubblewrap (bwrap) found: /usr/bin/bwrap
  [ OK ] bwrap version: bubblewrap 0.11.0
  [ OK ] user namespaces available: yes
  [ OK ] bwrap smoke test (`bwrap ... true`): passed
  [ OK ] egress network jail: available (pasta) /usr/bin/pasta

Result: PASS — host is usable. bwrap is present and the smoke test passed.
```

The `egress network jail` line is informational, never a `[FAIL]`: if neither `pasta` nor
`slirp4netns` is installed it reads `[INFO] … unavailable` and the egress bridge simply falls
back to the shared host network namespace (see
[Egress bridge](../README.md#egress-bridge-endpoint-indirection)).

On macOS, `doctor` is Seatbelt-aware instead: it checks that `sandbox-exec` is present, runs a
real SBPL smoke test, and always prints the honest Seatbelt-deprecation warning (see
[`MACOS.md`](MACOS.md)). No pasta helper is needed there — the egress firewall is
kernel-level.

### The bubblewrap dependency (Linux)

Raincoat does not sandbox anything itself — it builds an argument vector and hands it to
`bwrap`. Bubblewrap must be installed and functional; `raincoat doctor` checks this. If bwrap is
missing, Raincoat tells you how to install it and exits without running your command:

```
Error: bubblewrap / bwrap was not found.

Install it with your package manager, for example:
  Ubuntu/Debian: sudo apt install bubblewrap
  Fedora: sudo dnf install bubblewrap
  Arch: sudo pacman -S bubblewrap

Then run:
  raincoat doctor
```

## Running the tests

```sh
ctest --test-dir build --output-on-failure
```

CMake compiles the platform-appropriate suites (the bwrap/seccomp tests on Linux, the Seatbelt
SBPL suite on macOS), and integration tests that actually invoke `bwrap` skip gracefully on
hosts without it.

## Packaging

Packaging sources live in [`packaging/`](../packaging/):

- **Homebrew** — [`packaging/homebrew/raincoat.rb`](../packaging/homebrew/raincoat.rb), ready
  for a `zachgenius/homebrew-raincoat` tap (`brew install zachgenius/raincoat/raincoat`).
- **AUR** — [`packaging/aur/PKGBUILD`](../packaging/aur/PKGBUILD), a `raincoat-git` VCS
  package.
- **deb / rpm** — `cpack -G DEB` / `cpack -G RPM` from the build dir produces installable
  packages with the right runtime dependencies (`bubblewrap`, recommends `passt`).
