#!/bin/sh
systemd-sysusers globalprotect-native.conf >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true
update-desktop-database -q /usr/share/applications >/dev/null 2>&1 || true

# rpm passes 1 on a first install and 2 on an upgrade; dpkg passes "configure" and, on an
# upgrade, the old version as well.
if [ "$1" = 1 ] || { [ "$1" = configure ] && [ -z "$2" ]; }; then
	systemctl enable --now globalprotect-native.service >/dev/null 2>&1 || true
else
	systemctl try-restart globalprotect-native.service >/dev/null 2>&1 || true
	for user in $(loginctl list-users --no-legend 2>/dev/null | awk '{print $2}'); do
		systemctl --user --machine="$user@" try-restart gpn-agent.service >/dev/null 2>&1 || true
	done
fi
