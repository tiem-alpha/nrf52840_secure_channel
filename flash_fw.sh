#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_dir="${BUILD_DIR:-$repo_dir/build/lock}"
dev_id=""

usage() {
  echo "Usage: BUILD_DIR=/path/to/build $0 [--dev-id JLINK_SERIAL]"
  echo "Flash the existing sysbuild image to an nRF52840 DK over its J-Link USB port."
}

while (( $# )); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --dev-id)
      if (( $# < 2 )) || [[ -z $2 ]]; then
        echo "--dev-id requires a J-Link serial number" >&2
        exit 2
      fi
      dev_id="$2"
      shift 2
      ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

source "$repo_dir/ncs_env.sh"
if [[ ! -f "$build_dir/CMakeCache.txt" ]]; then
  echo "No build found at $build_dir. Run ./build_fw.sh first." >&2
  exit 1
fi

args=(-d "$build_dir" --no-rebuild)
if [[ -n $dev_id ]]; then
  args+=(--dev-id "$dev_id")
fi
west flash "${args[@]}"
