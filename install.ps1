# Install the contro1 CLI on Windows.
#
#   irm https://raw.githubusercontent.com/contro1-hq/contro1-cli/main/install.ps1 | iex
#
# Env:
#   CONTRO1_VERSION       pin a version (e.g. v0.1.0); default: latest
#   CONTRO1_INSTALL_DIR   install dir; default: %LOCALAPPDATA%\Programs\contro1
$ErrorActionPreference = "Stop"

$repo = "contro1-hq/contro1-cli"
$bin = "contro1"

$arch = if ([Environment]::Is64BitOperatingSystem) {
  if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
} else { throw "unsupported architecture" }

$version = $env:CONTRO1_VERSION
if (-not $version) {
  $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{ "User-Agent" = "contro1-install" }
  $version = $rel.tag_name
}
if (-not $version) { throw "could not determine latest version; set CONTRO1_VERSION" }
$verNoV = $version.TrimStart("v")

$asset = "{0}_{1}_windows_{2}.zip" -f $bin, $verNoV, $arch
$url = "https://github.com/$repo/releases/download/$version/$asset"

$tmp = Join-Path $env:TEMP ("contro1-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "Downloading $url"
  Invoke-WebRequest -Uri $url -OutFile (Join-Path $tmp $asset)
  Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath $tmp -Force

  $dir = $env:CONTRO1_INSTALL_DIR
  if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA "Programs\contro1" }
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  Copy-Item -Path (Join-Path $tmp "$bin.exe") -Destination (Join-Path $dir "$bin.exe") -Force

  # Add to the user PATH if missing.
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if ($userPath -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
    Write-Host "Added $dir to your user PATH (restart the terminal to pick it up)."
  }
  Write-Host "Installed contro1 to $dir\$bin.exe"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
