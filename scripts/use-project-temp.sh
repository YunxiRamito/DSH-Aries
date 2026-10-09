#!/bin/sh

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temp_root="$project_root/temp"

export TEMP="$temp_root/unix-user-temp"
export TMP="$temp_root/unix-user-temp"
export TMPDIR="$temp_root/unix-user-temp"
export GOCACHE="$temp_root/go-cache"
export GOPATH="$temp_root/go-path"
export GOMODCACHE="$temp_root/go-mod-cache"
export GOTMPDIR="$temp_root/go-tmp"

mkdir -p "$TEMP" "$GOCACHE" "$GOPATH" "$GOMODCACHE" "$GOTMPDIR"
