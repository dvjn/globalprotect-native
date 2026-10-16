#!/bin/sh
# rpm passes 0 when the package is erased, dpkg passes "remove"; upgrades pass something else.
case "$1" in
0 | remove | purge)
	systemctl disable --now globalprotect-native.service >/dev/null 2>&1 || true
	;;
esac
