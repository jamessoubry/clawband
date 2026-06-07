#!/usr/bin/env bash
# gen-formula.sh — emit the Homebrew formula for a given version + binary SHA256s.
# Usage: gen-formula.sh <version> <sha_macos_arm64> <sha_macos_x86_64> <sha_linux_x86_64>
# Prints the formula to stdout. Used by the release workflow to bump the tap.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "Usage: $0 <version> <sha_macos_arm64> <sha_macos_x86_64> <sha_linux_x86_64>" >&2
  exit 1
fi

VERSION="$1"
SHA_MAC_ARM="$2"
SHA_MAC_X86="$3"
SHA_LINUX_X86="$4"
BASE="https://github.com/jamessoubry/clawband/releases/download/v${VERSION}"

cat <<EOF
# typed: false
# frozen_string_literal: true

# Homebrew formula for clawband — a PreToolUse hook for Claude Code that
# blocks destructive shell commands before they execute.
class Clawband < Formula
  desc "PreToolUse hook for Claude Code that blocks destructive shell commands"
  homepage "https://github.com/jamessoubry/clawband"
  version "${VERSION}"
  license "MIT"

  on_macos do
    on_arm do
      url "${BASE}/clawband-macos-arm64"
      sha256 "${SHA_MAC_ARM}"
    end
    on_intel do
      url "${BASE}/clawband-macos-x86_64"
      sha256 "${SHA_MAC_X86}"
    end
  end

  on_linux do
    on_intel do
      url "${BASE}/clawband-linux-x86_64"
      sha256 "${SHA_LINUX_X86}"
    end
  end

  def install
    # The downloaded asset is a bare binary named per-platform; install as "clawband".
    bin.install Dir["clawband-*"].first => "clawband"
  end

  def caveats
    <<~CAVEAT
      clawband is installed, but it is not yet wired into Claude Code.

      Run:

        clawband install   # registers the PreToolUse hook + seeds ~/.clawband/
        clawband verify    # confirm it's active

      Then run /hooks in Claude Code (or restart) to activate.
      See: https://github.com/jamessoubry/clawband#installation
    CAVEAT
  end

  test do
    assert_match "clawband v#{version}", shell_output("#{bin}/clawband --version")
  end
end
EOF
