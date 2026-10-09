class Coffer < Formula
  desc "Encrypted git remote that lives on your own disk"
  homepage "https://github.com/Ziqing7226/Coffer"
  url "https://github.com/Ziqing7226/Coffer/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "fill-in-at-submission-from-the-release-source-archive"
  license "MIT"

  livecheck do
    url :stable
    strategy :github_latest
  end

  depends_on "go" => :build

  def install
    ldflags = "-s -w -X main.version=v#{version}"
    system "go", "build", "-trimpath", "-ldflags", ldflags, "-o", bin/"coffer", "./cmd/coffer"
    system "go", "build", "-trimpath", "-ldflags", ldflags, "-o", bin/"git-remote-coffer", "./cmd/git-remote-coffer"
  end

  test do
    assert_match "coffer", shell_output("#{bin}/coffer version")
    output = shell_output("git ls-remote coffer::#{testpath}/nope.coffer 2>&1", 128)
    assert_match "not a coffer vault", output
  end
end
