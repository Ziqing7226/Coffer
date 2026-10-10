# GitCoffer installer for Windows PowerShell: downloads the latest release
# (or GITCOFFER_VERSION), verifies the archive against the published
# checksums, and installs the two executables into your bin directory.
# No administrator rights needed.
#
#   irm https://raw.githubusercontent.com/Ziqing7226/GitCoffer/main/scripts/install.ps1 | iex
#
# Override the destination with GITCOFFER_BIN and the version with
# GITCOFFER_VERSION (a tag like v1.0.0-rc.2; default: latest release).

$ErrorActionPreference = "Stop"

$Repo = "Ziqing7226/GitCoffer"
$BinDir = if ($env:GITCOFFER_BIN) { $env:GITCOFFER_BIN } else { "$HOME\.local\bin" }
$Version = if ($env:GITCOFFER_VERSION) { $env:GITCOFFER_VERSION } else { "latest" }

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }

if ($Version -eq "latest") {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $rel.tag_name
}

$archive = "gitcoffer-$($Version.TrimStart('v'))-windows-$arch.zip"
$base = "https://github.com/$Repo/releases/download/$Version"
$tmp = New-Item -ItemType Directory -Path (Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid()))
try {
    Write-Host "Downloading $archive"
    Invoke-WebRequest -Uri "$base/$archive" -OutFile "$tmp/$archive"
    Invoke-WebRequest -Uri "$base/checksums.txt" -OutFile "$tmp/checksums.txt"

    # Integrity: the archive must match its published sha256.
    $want = (Select-String -Path "$tmp/checksums.txt" -Pattern $archive).Line.Split(" ")[0]
    if (-not $want) { throw "checksums.txt has no entry for $archive" }
    $got = (Get-FileHash -Algorithm SHA256 "$tmp/$archive").Hash.ToLower()
    if ($want -ne $got) { throw "checksum mismatch for $archive (want $want, got $got)" }
    Write-Host "Checksum OK"

    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    Expand-Archive -Path "$tmp/$archive" -DestinationPath $tmp -Force
    Copy-Item "$tmp/gitcoffer-$($Version.TrimStart('v'))-windows-$arch/gitcoffer.exe" $BinDir -Force
    Copy-Item "$tmp/gitcoffer-$($Version.TrimStart('v'))-windows-$arch/git-remote-coffer.exe" $BinDir -Force

    Write-Host "Installed: $(& (Join-Path $BinDir 'gitcoffer.exe') version)"
    if (($env:PATH -split ';') -notcontains $BinDir) {
        Write-Host "Note: $BinDir is not on your PATH - add it to your environment:"
        Write-Host "  [Environment]::SetEnvironmentVariable('PATH', `$env:PATH + ';$BinDir', 'User')"
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
