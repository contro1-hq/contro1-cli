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
  $target = Join-Path $dir "$bin.exe"
  try {
    Copy-Item -Path (Join-Path $tmp "$bin.exe") -Destination $target -Force
  } catch {
    # WHY: Windows will not replace an .exe that is running, and every open
    # Claude Code window runs `contro1 mcp serve`. The raw error ("being used
    # by another process") named a file, not the cause or the way out. The
    # file is never renamed aside: the running copies are named instead.
    $running = @(Get-Process -Name $bin -ErrorAction SilentlyContinue)
    if ($running.Count -eq 0 -or $_.Exception -isnot [System.IO.IOException]) { throw }
    # Only the copies run from this file hold it. The Contro1 service runs
    # its own copy and must not be listed, or stopped, as the cause.
    $holding = @($running | Where-Object { $_.Path -eq $target })
    if ($holding.Count -gt 0) { $running = $holding }
    Write-Host ""
    Write-Host "contro1 is running, so $target cannot be replaced." -ForegroundColor Yellow
    Write-Host "Usually it is the Contro1 MCP server that Claude Code, Codex or Cursor started, or contro1 in another terminal:"
    $lines = @{}
    try {
      Get-CimInstance Win32_Process -Filter "Name='$bin.exe'" -ErrorAction Stop |
        ForEach-Object { $lines[[int]$_.ProcessId] = $_.CommandLine }
    } catch {}
    foreach ($p in $running) {
      $what = $lines[[int]$p.Id]
      if (-not $what) { $what = $p.Path }
      if (-not $what) { $what = "$bin.exe" }
      Write-Host ("  PID {0}  {1}" -f $p.Id, $what)
    }
    Write-Host ""
    Write-Host "Close Claude Code, Codex and Cursor, or stop these processes:"
    Write-Host ("  Get-Process $bin | Where-Object Path -eq '{0}' | Stop-Process" -f ($target -replace "'", "''"))
    Write-Host "Then run the installer again."
    # `exit` would close the window this was piped into with `| iex`; the
    # non-zero result is carried in $LASTEXITCODE there instead.
    $global:LASTEXITCODE = 1
    if ($PSCommandPath) { exit 1 }
    return
  }

  # Add to the user PATH if missing.
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if ($userPath -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$dir", "User")
    Write-Host "Added $dir to your user PATH (restart the terminal to pick it up)."
  }
  Write-Host "Installed contro1 to $dir\$bin.exe"
  $global:LASTEXITCODE = 0
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
