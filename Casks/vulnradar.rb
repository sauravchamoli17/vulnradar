# Copy this into a homebrew-tap repo at Casks/vulnradar.rb, then users run:
#   brew install --cask <your-github-user>/tap/vulnradar
cask "vulnradar" do
  version "1.0.0"
  sha256 "REPLACE_WITH_SHA_FROM_THE_RELEASE"

  url "https://github.com/<your-github-user>/vulnradar/releases/download/v#{version}/VulnRadar.app.zip"
  name "Vulnerability Radar"
  desc "Tells you which of your projects the latest CVEs actually affect"
  homepage "https://github.com/<your-github-user>/vulnradar"

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
