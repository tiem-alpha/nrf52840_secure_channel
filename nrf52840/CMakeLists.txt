# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(target)


# set(dfu_common_dir ${ZEPHYR_NRF_MODULE_DIR}/samples/bluetooth/mesh/dfu/common/src)

# include_directories(${dfu_common_dir})

target_include_directories(app PRIVATE include)
target_sources(app PRIVATE src/main.c src/lkp1/framing.c
  src/lkp1/certificate.c src/lkp1/crypto.c src/lkp1/keys.c
  src/lkp1/crypto_psa.c src/lkp1/server.c)
target_sources(app PRIVATE src/lkp1/acl.c)
