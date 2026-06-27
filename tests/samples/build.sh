#!/usr/bin/env bash
#
# Rebuild every test fixture under tests/samples/ from the sources in src/.
#
# ONE script for the whole corpus. It runs on a linux/amd64 host and is largely
# self-contained: it downloads each released Go toolchain from go.dev on demand
# — no system Go and no container engine. (The single exception is the
# unreleased go127/V5 fixture, built via a gotip tree the caller bootstraps; see
# the gotip note below.) A linux host is used because the pre-1.16 toolchains
# have no darwin/arm64 build (and crash under qemu user-emulation), while every
# modern format (Mach-O / PE / Wasm) cross-compiles cleanly from linux. The cgo
# harness needs a host C compiler (gcc), which a linux/amd64 box has.
#
# The primary fixture program (`src/basic/main.go`) compiles unchanged on every
# Go release from 1.2 onward, so a single program anchors uniform assertions
# across the whole version matrix. Additional harnesses exercise advanced,
# extractable features (see src/): `types` (the full type-descriptor zoo),
# `generics` (type parameters, >=1.18), `cgo` (a CGO build), plus `embed`,
# `minimal`, and `plugin`.
#
# Fixtures are named  <prog>_go<minor>_<goos>_<goarch>[_variant][.exe].
# The integration suite's `mod matrix` discovers them by filename, so editing
# the matrix below automatically extends test coverage.
#
# Usage:
#   ./build.sh                 # build the whole matrix
#   ./build.sh go12 go126      # only these version tags
#   ./build.sh --list          # print the planned fixture set and exit
#
# One fixture is NOT produced here: plugin_go126_darwin_arm64.so. A Go plugin
# needs CGO and -buildmode=plugin, and a darwin/arm64 plugin requires a darwin
# C toolchain (for the Mach-O chained-fixup test). Build it on a mac with:
#   ( cd src/plugin && CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
#       go build -trimpath -buildmode=plugin -o ../../plugin_go126_darwin_arm64.so . )
#
set -uo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT_DIR:-$SELF_DIR}"
SRC="$SELF_DIR/src"
CACHE="${GO_DL_CACHE:-${TMPDIR:-/tmp}/gobin-toolchains}"
WORK="$CACHE/work"
DL_BASE="https://go.dev/dl"

mkdir -p "$OUT" "$CACHE" "$WORK"

# ---------------------------------------------------------------------------
# Version matrix: tag -> full toolchain version. Every tag is built as
# linux/amd64 (the backbone that exercises the version-gated parsing).
#
# Why each version earns a slot (parser-relevant boundaries):
#   go12  1.2.2   Go12 pclntab; pre-moduledata, pre-types, pre-funcID
#   go14  1.4.3   last pre-moduledata
#   go15  1.5.4   moduledata (V1) introduced; pre-types (typelinks []*_type)
#   go17  1.7.6   +types/etypes, typelinks []int32, typemap
#   go18  1.8.7   +textsectmap, ptab, pluginpath, pkghashes
#   go19  1.9.7   V1 tail without hasmain/bad
#   go110 1.10.8  +hasmain, +bad
#   go112 1.12.17 _func gains funcID
#   go115 1.15.15 last Go12-pclntab release
#   go116 1.16.15 new pcHeader (magic Go116); moduledata V2
#   go117 1.17.13 last Go116-magic
#   go118 1.18.10 magic Go118; _func +flag; moduledata V3; generics
#   go120 1.20.14 magic Go120; _func +startLine; +covctrs
#   go121 1.21.13 +inittasks; wasip1
#   go123 1.23.12 interior V3 sample
#   go124 1.24.13 GOFIPS140 available
#   go125 1.25.11 interior V3 sample
#   go126 1.26.4  moduledata V4 (+epclntab); newest stable anchor
# ---------------------------------------------------------------------------
# go127 (moduledata V5) is the unreleased 1.27 dev tree, built via gotip; it is
# skipped automatically when $HOME/sdk/gotip is absent.
VERSIONS=(
  "go12:1.2.2"   "go14:1.4.3"   "go15:1.5.4"   "go17:1.7.6"   "go18:1.8.7"
  "go19:1.9.7"   "go110:1.10.8" "go112:1.12.17" "go115:1.15.15"
  "go116:1.16.15" "go117:1.17.13" "go118:1.18.10" "go120:1.20.14"
  "go121:1.21.13" "go123:1.23.12" "go124:1.24.13" "go125:1.25.11" "go126:1.26.4"
  "go127:tip"
)

# Anchor versions that get cross-compiled format variants. Mach-O/PE build from
# any toolchain; darwin/arm64 needs >= 1.16; wasip1 needs >= 1.21.
FORMAT_ANCHORS=("go116" "go120" "go124" "go126" "go127")
WASIP1_ANCHORS=("go121" "go124" "go126" "go127")
# Versions that get a `types` harness (the type system arrived in Go 1.7).
TYPES_VERSIONS=("go17" "go110" "go116" "go120" "go126")
# Versions that get a `generics` harness (type parameters arrived in Go 1.18).
GENERICS_VERSIONS=("go118" "go120" "go124" "go126")
# Versions that get a `cgo` harness (linux/amd64, CGO_ENABLED=1 + host gcc).
CGO_VERSIONS=("go116" "go126")

# Minor version of a tag/full-version string ("1.9.7" -> 9, "go116" -> 16).
# The unreleased tip toolchain (Go 1.27 dev) maps to a large sentinel so all the
# ">= N" feature gates treat it as newest.
minor_of() {
  [[ "$1" == "tip" || "$1" == "go127" ]] && { echo 99; return; }
  local v="${1#go1}"; v="${v#1.}"; echo "${v%%.*}"
}
in_list() { local x=$1; shift; local e; for e in "$@"; do [[ "$e" == "$x" ]] && return 0; done; return 1; }

list_only=0; SELECT=()
for a in "$@"; do
  case "$a" in --list) list_only=1 ;; *) SELECT+=("$a") ;; esac
done
selected() {
  [[ ${#SELECT[@]} -eq 0 ]] && return 0
  local t; for t in "${SELECT[@]}"; do [[ "$t" == "$1" ]] && return 0; done; return 1
}

# Download + extract a toolchain into the cache (idempotent); echo its GOROOT.
fetch_toolchain() {  # fetch_toolchain <full-version>
  local v="$1"
  # Go 1.27 is unreleased: use a gotip tree the caller bootstrapped into
  # $HOME/sdk/gotip (`go install golang.org/dl/gotip@latest && gotip download`).
  if [[ "$v" == "tip" ]]; then
    [[ -x "$HOME/sdk/gotip/bin/go" ]] && echo "$HOME/sdk/gotip" || return 1
    return 0
  fi
  local root="$CACHE/go$v"
  if [[ ! -x "$root/go/bin/go" ]]; then
    local tgz="$CACHE/go$v.linux-amd64.tar.gz"
    [[ -s "$tgz" ]] || { echo "  ↓ go$v" >&2; curl -fsSL -o "$tgz" "$DL_BASE/go$v.linux-amd64.tar.gz" || return 1; }
    mkdir -p "$root"; tar -C "$root" -xzf "$tgz" || return 1
  fi
  [[ -x "$root/go/bin/go" ]] && echo "$root/go"
}

ok=0; fail=()
# build <tag> <ver> <prog> <goos> <goarch> <variant> [build args / KEY=VAL env]…
build() {
  local tag=$1 ver=$2 prog=$3 goos=$4 goarch=$5 variant=$6; shift 6
  local m; m="$(minor_of "$ver")"
  local name="${prog}_${tag}_${goos}_${goarch}${variant}"
  [[ "$goos" == "windows" ]] && name="${name}.exe"
  if [[ $list_only -eq 1 ]]; then echo "  $name"; return 0; fi

  local goroot; goroot="$(fetch_toolchain "$ver")"
  if [[ -z "$goroot" ]]; then echo "  !! $name: no go$ver toolchain"; fail+=("$name"); return 0; fi

  local bdir="$WORK/$prog"
  # Keep build-host paths out of the committed fixtures. The `-trimpath` build
  # flag exists from Go 1.13; Go 1.4-1.12 predate it but their gc compiler
  # accepts `-gcflags=-trimpath=<dir>`, which strips the build dir so embedded
  # source paths reduce to "main.go" (the fixture programs are pure Go, so no
  # `-asmflags` is needed). Only Go 1.2's `6g` has neither and embeds the
  # (fixed, build-cache) path — a single fixture, by necessity.
  local flags=()
  if [[ "$m" -ge 13 ]]; then
    flags+=("-trimpath")
  elif [[ "$m" -ge 4 ]]; then
    flags+=("-gcflags=-trimpath=$bdir")
  fi
  # GOTOOLCHAIN=local (>=1.21) pins the build to the invoked toolchain.
  local pin=(); [[ "$m" -ge 21 ]] && pin+=("GOTOOLCHAIN=local")

  local args=() envs=() a
  for a in "$@"; do
    if [[ "$a" == *=* && "$a" != -* ]]; then envs+=("$a"); else args+=("$a"); fi
  done

  # Copy the whole program dir (so go:embed assets travel with main.go), but
  # drop go.mod — every build runs in GOPATH mode (GO111MODULE=off) and a stray
  # module file would only confuse the older toolchains.
  rm -rf "$bdir"; mkdir -p "$bdir"
  cp -r "$SRC/$prog/." "$bdir/"; rm -f "$bdir/go.mod"
  echo "  $name"
  # Hardcoded defaults come first; per-call envs (e.g. CGO_ENABLED=1) override.
  if ( cd "$bdir" && env \
        GOROOT="$goroot" GOPATH="$CACHE/gopath" GOCACHE="$CACHE/gocache" \
        GO111MODULE=off CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        "${pin[@]}" "${envs[@]}" \
        "$goroot/bin/go" build "${flags[@]}" "${args[@]}" -o "$OUT/$name" main.go ) \
      && [[ -s "$OUT/$name" ]]; then
    ok=$((ok + 1))
  else
    echo "    !! build failed"; rm -f "$OUT/$name"; fail+=("$name")
  fi
}

[[ $list_only -eq 0 ]] && echo "Building fixtures into $OUT (linux host, go.dev toolchains)…"

for entry in "${VERSIONS[@]}"; do
  tag="${entry%%:*}"; ver="${entry##*:}"; m="$(minor_of "$ver")"
  selected "$tag" || continue

  # Backbone: every version as linux/amd64.
  build "$tag" "$ver" basic linux amd64 ""

  # Format variants on anchor versions.
  if in_list "$tag" "${FORMAT_ANCHORS[@]}"; then
    [[ "$m" -ge 16 ]] && build "$tag" "$ver" basic darwin arm64 ""
    build "$tag" "$ver" basic windows amd64 ""
  fi
  in_list "$tag" "${WASIP1_ANCHORS[@]}" && build "$tag" "$ver" basic wasip1 wasm ""

  # Advanced-feature harnesses.
  in_list "$tag" "${TYPES_VERSIONS[@]}"    && build "$tag" "$ver" types    linux amd64 ""
  in_list "$tag" "${GENERICS_VERSIONS[@]}" && build "$tag" "$ver" generics linux amd64 ""
  in_list "$tag" "${CGO_VERSIONS[@]}"      && build "$tag" "$ver" cgo      linux amd64 "" CGO_ENABLED=1

  # Feature / stripped variants.
  case "$tag" in
    go110) build "$tag" "$ver" basic linux amd64 "_stripped" -ldflags "-s -w" ;;  # stripped legacy
    go116) build "$tag" "$ver" basic linux amd64 "_stripped" -ldflags "-s -w" ;;
    go124) build "$tag" "$ver" embed linux amd64 ""
           build "$tag" "$ver" basic linux amd64 "_fips" GOFIPS140=v1.0.0 ;;
    go126) build "$tag" "$ver" basic   darwin  arm64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" basic   windows amd64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" basic   linux   amd64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" minimal darwin  arm64 ""
           build "$tag" "$ver" minimal darwin  arm64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" embed   darwin  arm64 ""
           build "$tag" "$ver" embed   linux   amd64 ""
           build "$tag" "$ver" embed   darwin  arm64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" basic   linux   amd64 "_cover" -cover
           build "$tag" "$ver" basic   darwin  arm64 "_fips" GOFIPS140=v1.0.0 ;;
    go127) build "$tag" "$ver" basic   darwin  arm64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" basic   windows amd64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" types   linux   amd64 ""
           build "$tag" "$ver" generics linux  amd64 "" ;;
  esac
done

if [[ $list_only -eq 1 ]]; then exit 0; fi
echo "Done. Built $ok fixtures into $OUT."
if [[ ${#fail[@]} -gt 0 ]]; then printf 'Failed:\n'; printf '  %s\n' "${fail[@]}"; fi
