# Copy this into a homebrew-tap repo at Casks/vulnradar.rb, then users run:
#   brew install --cask sauravchamoli17/tap/vulnradar
cask "vulnradar" do
  version "1.0.2"
  sha256 "35fd1105e50151b242bc953d28b9932f37cd4f6956c7befc013ada5709873f36"

  url "https://github.com/sauravchamoli17/vulnradar/releases/download/v#{version}/VulnRadar.app.zip"
  name "Vulnerability Radar"
  desc "Tells you which of your projects the latest CVEs actually affect"
  homepage "https://github.com/sauravchamoli17/vulnradar"

  depends_on :macos

  app "VulnRadar.app"

  # The build is ad-hoc signed, so strip the quarantine flag on install.
  # `appdir` is not in scope inside this block and there is no {{appdir}} token, so the
  # app is reached by changing into it instead of naming its full path.
  postflight_steps do
    run "/usr/bin/xattr",
        args:  ["-dr", "com.apple.quarantine", "."],
        chdir: "VulnRadar.app"
  end

  zap trash: [
    "~/.claude/vuln-radar",
    "~/Library/LaunchAgents/dev.local.vulnradar.scan.plist",
    "~/Library/Preferences/dev.local.vulnradar.plist",
  ]
end
