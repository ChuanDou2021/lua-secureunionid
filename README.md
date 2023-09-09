# lua-secureunionid

Lua wrapper [SecureUnionID](https://github.com/volcengine/SecureUnionID)

# DEV

## Make debug lib

```sh
mkdir b1
cd b1
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

## Note of gdb

```txt
gdb /usr/local/openresty/nginx/sbin/nginx  qemu_openresty_20230907-082853_132.core

## in GDB

file deps/lib/lua/5.1/libsecureunionid.so
bt
frame 1
info locals
```