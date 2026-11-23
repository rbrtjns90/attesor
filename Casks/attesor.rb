cask "attesor" do
  version "0.1.0"
  sha256 "392716c080ee073086ab8cae94c71a76329aaffa699b126bdb00e8ae21b15a0a"

  url "https://github.com/rbrtjns90/attesor/releases/download/v#{version}/Attesor-v#{version}.dmg"
  name "Attesor"
  desc "Run x86-64 Linux programs on Apple Silicon"
  homepage "https://github.com/rbrtjns90/attesor"

  depends_on cask: "xquartz"
  depends_on arch: :arm64

  app "Attesor.app"

  zap trash: "~/Library/Application Support/Attesor"
end
