#!/bin/sh
# pacman runs this on removal only, not on an upgrade.
systemctl disable --now globalprotect-native.service >/dev/null 2>&1 || true
