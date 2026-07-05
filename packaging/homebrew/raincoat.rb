# Homebrew formula for Raincoat.
#
# To publish: create a tap repo (github.com/zachgenius/homebrew-raincoat), copy this file
# into its Formula/ directory, and users install with:
#   brew install zachgenius/raincoat/raincoat
#
# TODO before publishing a versioned (non-HEAD) release: tag v0.1.0, then switch `url` to
#   url "https://github.com/zachgenius/raincoat/archive/refs/tags/v0.1.0.tar.gz"
#   sha256 "<sha256 of that tarball>"
class Raincoat < Formula
  desc "Lightweight privacy sandbox for nosy CLI tools and AI agents"
  homepage "https://github.com/zachgenius/raincoat"
  url "https://github.com/zachgenius/raincoat.git", branch: "master"
  version "0.1.0"
  head "https://github.com/zachgenius/raincoat.git", branch: "master"

  depends_on "cmake" => :build
  depends_on "googletest" => :build
  depends_on "openssl@3"

  # The sandbox itself is Apple's built-in Seatbelt on macOS. On Linux the runtime
  # dependency is bubblewrap, which is not in homebrew-core — get it from your distro.

  def install
    # openssl@3 is keg-only; point find_package(OpenSSL) at it explicitly.
    system "cmake", "-S", ".", "-B", "build",
           "-DCMAKE_PREFIX_PATH=#{Formula["openssl@3"].opt_prefix}",
           *std_cmake_args
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"
    # cmake --install places rc_interpose.dylib in #{lib}/raincoat/ on macOS; the raincoat
    # binary resolves it via ../lib/raincoat/ relative to its own (realpath'd) location.
  end

  test do
    assert_match "raincoat", shell_output("#{bin}/raincoat --version")
    # doctor exercises the real backend (Seatbelt smoke test on macOS, bwrap probe on Linux);
    # it may legitimately fail in a sandboxed CI runner, so only check it executes.
    system "#{bin}/raincoat", "doctor" if OS.mac?
  end
end
