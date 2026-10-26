#!/usr/bin/env bash
# Source this file from the build/flash scripts.
if command -v west >/dev/null 2>&1; then
  return 0
fi

ncs_home="${NCS_HOME:-$HOME/ncs}"
ncs_version="${NCS_VERSION:-v3.4.0}"
if [[ -z ${TOOLCHAIN_DIR:-} ]]; then
  toolchains=("$ncs_home"/toolchains/*/environment.json)
  if (( ${#toolchains[@]} != 1 )) || [[ ! -f ${toolchains[0]} ]]; then
    echo "Cannot select NCS toolchain. Set TOOLCHAIN_DIR to its directory." >&2
    return 1
  fi
  TOOLCHAIN_DIR="${toolchains[0]%/environment.json}"
fi
if [[ ! -f "$TOOLCHAIN_DIR/environment.json" || ! -d "$ncs_home/$ncs_version/zephyr" ]]; then
  echo "NCS toolchain/workspace not found. Set NCS_HOME, NCS_VERSION and TOOLCHAIN_DIR." >&2
  return 1
fi

# Apply the environment supplied by Nordic's installed toolchain.
eval "$(/usr/bin/python3 - "$TOOLCHAIN_DIR" <<'PY'
import json
import os
import shlex
import sys

root = sys.argv[1]
with open(os.path.join(root, 'environment.json'), encoding='utf-8') as f:
    entries = json.load(f)['env_vars']
for entry in entries:
    key = entry['key']
    if entry['type'] == 'string':
        value = entry['value']
    else:
        paths = [os.path.join(root, path) for path in entry['values']]
        value = os.pathsep.join(paths)
        if entry.get('existing_value_treatment') == 'prepend_to':
            value += os.pathsep + os.environ.get(key, '')
    print(f'export {key}={shlex.quote(value)}')
PY
)"
export ZEPHYR_BASE="$ncs_home/$ncs_version/zephyr"

if ! command -v west >/dev/null 2>&1; then
  echo "west is unavailable in the selected NCS toolchain." >&2
  return 1
fi
