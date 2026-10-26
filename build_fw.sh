#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_dir="${BUILD_DIR:-$repo_dir/build/lock}"

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  echo "Usage: BUILD_DIR=/path/to/build $0"
  echo "Build nRF52840 DK firmware with MCUboot using NCS/west."
  exit 0
fi
if (( $# != 0 )); then
  echo "Unexpected argument: $1" >&2
  exit 2
fi
source "$repo_dir/ncs_env.sh"

west build -b nrf52840dk/nrf52840 -s "$repo_dir/nrf52840" \
  -d "$build_dir" --sysbuild -- -DSB_CONFIG_BOOTLOADER_MCUBOOT=y
