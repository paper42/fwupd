#!/bin/sh
set -e
set -x

#install dependencies
xbps-install -Suy python3
./contrib/ci/generate_dependencies.py | xargs xbps-install -y

#clone test firmware if necessary
. ./contrib/ci/get_test_firmware.sh

#build
rm -rf build
meson build \
 -Dman=false \
 -Ddocs=none \
 -Dgusb:tests=false \
 -Dgcab:docs=false \
 -Dconsolekit=false \
 -Dsystemd=false \
 -Db_lto=false \
 -Delogind=true
ninja -C build test -v
