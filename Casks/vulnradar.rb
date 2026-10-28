# Copy this into a homebrew-tap repo at Casks/vulnradar.rb, then users run:
#   brew install --cask sauravchamoli17/tap/vulnradar
cask "vulnradar" do
  version "1.0.3"
  sha256 "6956dbb5aeee12a80f4a8fbc67dbf9ca7f620b141faa5805fd4e669a80a86ecc"

  url "https://github.com/sauravchamoli17/vulnradar/releases/download/v#{version}/VulnRadar.app.zip"
  name "Vulnerability Radar"
  desc "Tells you which of your projects the latest CVEs actually affect"
  homepage "https://github.com/sauravchamoli17/vulnradar"

  depends_on :macos

  app "VulnRadar.app"

  # The build is ad-hoc signed, so strip the quarantine flag on install.
  postflight do
    system_command "/usr/bin/xattr",
                   args: ["-dr", "com.apple.quarantine", "#{appdir}/VulnRadar.app"],
                   sudo: false
  end

  zap trash: [
    "~/.claude/vuln-radar",
    "~/Library/LaunchAgents/dev.local.vulnradar.scan.plist",
    "~/Library/Preferences/dev.local.vulnradar.plist",
  ]
end
