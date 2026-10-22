#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
output="$(mktemp)"
trap 'rm -f "$output"' EXIT
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -Iinclude src/lkp1/framing.c tests/framing_test.c -o "$output"
"$output"
