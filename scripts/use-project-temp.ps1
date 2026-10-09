$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$tempRoot = Join-Path $projectRoot 'temp'
$paths = @{
    TEMP       = Join-Path $tempRoot 'windows-user-temp'
    TMP        = Join-Path $tempRoot 'windows-user-temp'
    TMPDIR     = Join-Path $tempRoot 'windows-user-temp'
    GOCACHE    = Join-Path $tempRoot 'go-cache'
    GOPATH     = Join-Path $tempRoot 'go-path'
    GOMODCACHE = Join-Path $tempRoot 'go-mod-cache'
    GOTMPDIR   = Join-Path $tempRoot 'go-tmp'
}

foreach ($path in $paths.Values) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

foreach ($name in $paths.Keys) {
    Set-Item -Path "Env:$name" -Value $paths[$name]
}
