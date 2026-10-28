# Copy this into a homebrew-tap repo at Casks/vulnradar.rb, then users run:
#   brew install --cask sauravchamoli17/tap/vulnradar
cask "vulnradar" do
  version "1.0.0"
  sha256 "d582d63a89caef974f133c35aaf93ebd5bbdaed7efd65ddb0c6293c53b8021a3"

  url "https://github.com/sauravchamoli17/vulnradar/releases/download/v#{version}/VulnRadar.app.zip"
  name "Vulnerability Radar"
  desc "Tells you which of your projects the latest CVEs actually affect"
  homepage "https://github.com/sauravchamoli17/vulnradar"

  app "VulnRadar.app"

  # The build is ad-hoc signed, so strip the quarantine flag on install.
  postflight do
    system_command "/usr/bin/xattr",
                   args: ["-dr", "com.apple.quarantine", "#{appdir}/VulnRadar.app"],
                   sudo: false
  end

  zap trash: [
    "~/Library/Preferences/dev.local.vulnradar.plist",
    "~/Library/LaunchAgents/dev.local.vulnradar.scan.plist",
    "~/.claude/vuln-radar",
  ]
end
