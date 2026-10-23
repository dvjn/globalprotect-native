#!/bin/sh
# pacman runs this on a first install only. Its hooks create the gpn group and reload systemd
# after the transaction, too late for the service to start here.
systemd-sysusers globalprotect-native.conf >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable --now globalprotect-native.service >/dev/null 2>&1 || true
