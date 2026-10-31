module github.com/dvjn/globalprotect-native

go 1.27.2

require (
	fyne.io/systray v1.12.2
	github.com/godbus/dbus/v5 v5.2.4
	github.com/vishvananda/netlink v1.3.1
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
)

require (
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/mobile v0.0.0-20261011034528-197770444867 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
)

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
