# Copy this into a homebrew-tap repo at Casks/vulnradar.rb, then users run:
#   brew install --cask sauravchamoli17/tap/vulnradar
cask "vulnradar" do
  version "1.0.4"
  sha256 "e48602643ae35485c5d09e7195b34c5230d2db382388cc13151fbebb3e9ee9c2"

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
