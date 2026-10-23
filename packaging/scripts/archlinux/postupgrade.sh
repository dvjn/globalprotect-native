#!/bin/sh
# pacman runs this on an upgrade instead of the post-install script.
systemd-sysusers globalprotect-native.conf >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl try-restart globalprotect-native.service >/dev/null 2>&1 || true
for user in $(loginctl list-users --no-legend 2>/dev/null | awk '{print $2}'); do
	systemctl --user --machine="$user@" try-restart gpn-agent.service >/dev/null 2>&1 || true
done
