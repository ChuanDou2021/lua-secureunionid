#!/bin/bash
set -eo pipefail

PLATFORM="`uname -s`"
[ "$1" ] && VERSION="$1" || VERSION="2.1devel"

do_tests() {
    echo
    cd tests
    luajit -e 'print("Testing Lua libsecureunionid version " .. require("secureunionid")._VERSION)'
    luajit test.lua
    cd ..
}

echo "===== Setting LuaRocks PATH ====="
eval "`luarocks path`"

echo "===== Cleaning old build data ====="
rm -f tests/libsecureunionid.*

echo "===== Verifying libsecureunionid.so is not installed ====="

cd tests
if lua -e 'require "libsecureunionid"' 2>/dev/null
then
    cat <<EOT
Please ensure you do not have the libsecureunionid module installed before
running these tests.
EOT
    exit 1
fi
cd ..

echo "===== Testing LuaRocks build ====="
luarocks make --local --no-install

echo "===== Testing Makefile build ====="
cp -r lib/secureunionid.lua build.luarocks/libsecureunionid.* tests
do_tests
rm tests/secureunionid.lua tests/libsecureunionid.*
