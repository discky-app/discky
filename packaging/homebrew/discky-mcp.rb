# Homebrew formula stub for discky-mcp.
#
# Untestable until the repository is public: the tarball URL and sha256 below do not
# exist yet.
# Covers the MCP server only; Discky.app is built with `cargo xtask install` (see README).
# TODO: fill sha256 after the first tag (v0.1.0).
class DisckyMcp < Formula
  desc "MCP server that lets AI agents find and safely clear disk space on macOS"
  homepage "https://github.com/alxgol/discky"
  url "https://github.com/alxgol/discky/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "TODO: fill after first tag"
  license "MIT"

  depends_on "rust" => :build
  depends_on :macos

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/discky-mcp")
  end

  test do
    assert_match "Discky MCP server", shell_output("#{bin}/discky-mcp --help")
  end
end
