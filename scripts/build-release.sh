#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$project_root/scripts/use-project-temp.sh"

version=$(tr -d '\r\n' < "$project_root/VERSION")
case "$version" in
  ''|*[!0-9.]*|.*|*.) echo "VERSION must use x.y.z format" >&2; exit 1 ;;
esac

release_dir="$project_root/temp/releases"
mkdir -p "$release_dir"
rm -f "$release_dir"/aries-server-* "$release_dir"/ariesctl-* "$release_dir/SHA256SUMS.txt"

for target in linux-amd64 linux-arm64 windows-amd64; do
  goos=${target%-*}
  goarch=${target#*-}
  suffix=
  [ "$goos" = windows ] && suffix=.exe
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath \
    -ldflags "-s -w -X aries.local/aries/internal/kernel.BuildVersion=$version" \
    -o "$release_dir/aries-server-v$version-$target$suffix" ./cmd/server
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath \
    -ldflags '-s -w' \
    -o "$release_dir/ariesctl-v$version-$target$suffix" ./cmd/cli
done

(
  cd "$release_dir"
  find . -maxdepth 1 -type f ! -name SHA256SUMS.txt -print | sort | while IFS= read -r file; do
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "${file#./}"
    else
      shasum -a 256 "${file#./}"
    fi
  done > SHA256SUMS.txt
)

printf 'Built version %s release assets in %s\n' "$version" "$release_dir"
