#!/usr/bin/env bash
#
# Rebuild every test fixture under tests/samples/ from the sources in src/.
#
# All builds use -trimpath so NO local filesystem paths leak into the
# committed binaries (the embedded source paths become module-relative, e.g.
# "gobin.test/basic/main.go").
#
# Fixtures are version-suffixed: <prog>_go<minor>_<goos>_<goarch>[_stripped].
# The Go minor version maps to a moduledata layout the parser must detect:
#   go121 -> V3,  go124 -> V3 (no epclntab),  go126 -> V4,  go127 -> V5.
#
# Toolchains (install once):
#   go install golang.org/dl/go1.16.15@latest && go1.16.15 download
#   go install golang.org/dl/go1.19.13@latest && go1.19.13 download
#   go install golang.org/dl/go1.21.13@latest && go1.21.13 download
#   go install golang.org/dl/go1.24.13@latest && go1.24.13 download
#   go install golang.org/dl/gotip@latest      && gotip download   # 1.27 dev
#   (go1.26 is the system `go`)
set -euo pipefail

cd "$(dirname "$0")"
OUT="$(pwd)"
SRC="$OUT/src"

# Toolchain binary for a minor-version tag (portable to bash 3.2 / macOS).
go_for() {
  case "$1" in
    go116) echo "$HOME/go/bin/go1.16.15" ;;
    go119) echo "$HOME/go/bin/go1.19.13" ;;
    go121) echo "$HOME/go/bin/go1.21.13" ;;
    go124) echo "$HOME/go/bin/go1.24.13" ;;
    go126) echo "go" ;;
    go127) echo "$HOME/go/bin/gotip" ;;
    *) echo "unknown go tag: $1" >&2; return 1 ;;
  esac
}

build() {  # build <gotag> <srcdir> <outprefix> <goos> <goarch> <suffix> <ldflags> [env...]
  local tag=$1 srcdir=$2 prefix=$3 goos=$4 goarch=$5 suffix=$6 ldflags=$7; shift 7
  local go; go="$(go_for "$tag")"
  local name="${prefix}_${tag}_${goos}_${goarch}${suffix}"
  [[ "$goos" == "windows" ]] && name="${name}.exe"
  echo "  $name"
  # GOTOOLCHAIN=local pins the build to the invoked toolchain — without it Go
  # would auto-download a newer toolchain to satisfy a higher go.mod directive,
  # silently defeating the version matrix.
  ( cd "$SRC/$srcdir" && env "$@" GOTOOLCHAIN=local CGO_ENABLED=0 \
      GOOS="$goos" GOARCH="$goarch" \
      "$go" build -trimpath ${ldflags:+-ldflags="$ldflags"} -o "$OUT/$name" . )
}

echo "Removing old fixtures…"
find "$OUT" -maxdepth 1 -type f \( -name 'basic_*' -o -name 'minimal_*' \) \
  -not -name '*.sh' -not -name '*.md' -delete

echo "Building basic (all versions × native/elf/pe)…"
# Pre-1.18 toolchains (Go116/Go118 magic, V2 moduledata): native + cross.
for tag in go116 go119; do
  build "$tag" basic basic darwin  arm64 "" ""
  build "$tag" basic basic linux   amd64 "" ""
  build "$tag" basic basic windows amd64 "" ""
done
for tag in go121 go124 go126 go127; do
  build "$tag" basic basic darwin arm64 ""         ""
  build "$tag" basic basic linux  amd64 ""         ""
done
# PE + stripped coverage on the two anchor versions.
for tag in go126 go127; do
  build "$tag" basic basic windows amd64 ""         ""
  build "$tag" basic basic darwin  arm64 "_stripped" "-s -w"
  build "$tag" basic basic windows amd64 "_stripped" "-s -w"
done

echo "Building minimal…"
build go126 minimal minimal darwin arm64 ""         ""
build go126 minimal minimal darwin arm64 "_stripped" "-s -w"

echo "Building embed (go:embed assets)…"
for tag in go126 go127; do
  build "$tag" embed embed darwin arm64 ""         ""
  build "$tag" embed embed linux  amd64 ""         ""
done
build go126 embed embed darwin arm64 "_stripped" "-s -w"

echo "Building plugin (-buildmode=plugin, native darwin + CGO → chained fixups)…"
( cd "$SRC/plugin" && env GOTOOLCHAIN=local CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
    go build -trimpath -buildmode=plugin -o "$OUT/plugin_go126_darwin_arm64.so" . )
echo "  plugin_go126_darwin_arm64.so"

echo "Building cover (basic source + -cover, needs >=1.20)…"
( cd "$SRC/basic" && env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -cover -o "$OUT/cover_go126_linux_amd64" . )
echo "  cover_go126_linux_amd64"

echo "Building fips (basic source + GOFIPS140, needs >=1.24)…"
for tag in go124 go126 go127; do
  build "$tag" basic fips darwin arm64 "" "" GOFIPS140=v1.0.0
done

echo "Building wasm (basic source, wasip1)…"
for tag in go126 go127; do
  build "$tag" basic basic wasip1 wasm "" ""
done

echo "Done. $(find "$OUT" -maxdepth 1 -type f \( -name 'basic_*' -o -name 'minimal_*' \) | wc -l | tr -d ' ') fixtures."
