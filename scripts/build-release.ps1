$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'use-project-temp.ps1')

$version = (Get-Content (Join-Path $projectRoot 'VERSION') -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') {
    throw "VERSION must use x.y.z format, got '$version'"
}

$goExe = Join-Path $projectRoot '.tools/go/bin/go.exe'
if (-not (Test-Path -LiteralPath $goExe)) {
    $goExe = 'go'
}

$releaseDir = Join-Path $projectRoot 'temp/releases'
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

foreach ($target in @(
    @{ GOOS = 'linux'; GOARCH = 'amd64'; Suffix = '' },
    @{ GOOS = 'linux'; GOARCH = 'arm64'; Suffix = '' },
    @{ GOOS = 'windows'; GOARCH = 'amd64'; Suffix = '.exe' }
)) {
    $env:GOOS = $target.GOOS
    $env:GOARCH = $target.GOARCH
    $env:CGO_ENABLED = '0'
    $platform = "$($target.GOOS)-$($target.GOARCH)"

    foreach ($program in @(
        @{ Name = 'aries-server'; Package = './cmd/server'; Ldflags = "-s -w -X aries.local/aries/internal/kernel.BuildVersion=$version" },
        @{ Name = 'ariesctl'; Package = './cmd/cli'; Ldflags = '-s -w' }
    )) {
        $name = "$($program.Name)-v$version-$platform$($target.Suffix)"
        $destination = Join-Path $releaseDir $name
        & $goExe build -trimpath -ldflags $program.Ldflags -o $destination $program.Package
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed for $name"
        }
    }
}

Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue

$checksumPath = Join-Path $releaseDir 'SHA256SUMS.txt'
Remove-Item -LiteralPath $checksumPath -Force -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath $releaseDir -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object Name | ForEach-Object {
    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $($_.Name)" | Add-Content -LiteralPath $checksumPath -Encoding ascii
}

Write-Output "Built version $version release assets in $releaseDir"
