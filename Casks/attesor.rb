cask "attesor" do
  version "0.1.0"
  sha256 :no_check   # set to the DMG sha256 from SHA256SUMS at release time

  url "https://github.com/rbrtjns90/attesor/releases/download/v#{version}/Attesor-v#{version}.dmg"
  name "Attesor"
  desc "Run x86-64 Linux programs on Apple Silicon"
  homepage "https://github.com/rbrtjns90/attesor"

  depends_on cask: "xquartz"
  depends_on arch: :arm64

  app "Attesor.app"

  zap trash: "~/Library/Application Support/Attesor"
end
