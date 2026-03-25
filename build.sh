#!/usr/bin/env sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_DIR=${BIN_DIR:-"$ROOT_DIR/bin"}
GO_CMD=${GO_CMD:-go}
GOOS=${GOOS:-linux}
GOARCH=${GOARCH:-amd64}
CGO_ENABLED=${CGO_ENABLED:-0}
GOCACHE=${GOCACHE:-"$ROOT_DIR/.gocache"}
GOMODCACHE=${GOMODCACHE:-"$ROOT_DIR/.gomodcache"}
GOTMPDIR=${GOTMPDIR:-"$ROOT_DIR/.gotmp"}
GO_BUILD_MOD=${GO_BUILD_MOD:-}

mkdir -p "$BIN_DIR" "$GOCACHE" "$GOMODCACHE" "$GOTMPDIR"

if [ -z "$GO_BUILD_MOD" ]; then
	if [ -d "$ROOT_DIR/vendor" ]; then
		GO_BUILD_MOD=vendor
	else
		GO_BUILD_MOD=mod
		echo "warning: vendor/ not found, falling back to module download mode" >&2
		echo "hint: run 'go mod vendor' in a networked environment first for offline builds" >&2
	fi
fi

find "$ROOT_DIR/cmd" -mindepth 1 -maxdepth 1 -type d | sort | while IFS= read -r cmd_dir; do
	if [ ! -f "$cmd_dir/main.go" ]; then
		continue
	fi

	app_name=$(basename "$cmd_dir")
	output_path="$BIN_DIR/$app_name"

	echo "building $app_name -> $output_path"

	env \
		CGO_ENABLED="$CGO_ENABLED" \
		GOOS="$GOOS" \
		GOARCH="$GOARCH" \
		GOCACHE="$GOCACHE" \
		GOMODCACHE="$GOMODCACHE" \
		GOTMPDIR="$GOTMPDIR" \
		"$GO_CMD" build -mod="$GO_BUILD_MOD" -trimpath -ldflags="-s -w" -o "$output_path" "./cmd/$app_name"
done

echo "build complete: $BIN_DIR"
