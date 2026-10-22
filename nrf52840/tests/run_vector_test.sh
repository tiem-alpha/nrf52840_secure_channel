#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
test_dir="$(mktemp -d)"
trap 'rm -r "$test_dir"' EXIT
python3 nrf52840/tests/generate_vector_header.py python/tests/vectors.json "$test_dir/vectors.h"
cc -std=c11 -Wall -Wextra -Wno-deprecated-declarations \
  -I nrf52840/include -I "$test_dir" \
  nrf52840/src/lkp1/server.c nrf52840/src/lkp1/keys.c \
  nrf52840/src/lkp1/crypto.c nrf52840/src/lkp1/certificate.c \
  nrf52840/tests/server_vector_test.c -lcrypto -o "$test_dir/test"
"$test_dir/test"
