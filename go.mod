module github.com/dvjn/globalprotect-native

go 1.27.2

require (
	fyne.io/systray v1.12.2
	github.com/godbus/dbus/v5 v5.2.4
	github.com/vishvananda/netlink v1.3.1
	go.yaml.in/yaml/v4 v4.0.0
	golang.org/x/net v0.63.0
	golang.org/x/sys v0.50.0
)

require (
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/mobile v0.0.0-20261117202452-47699113848a // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/tools v0.53.0 // indirect
)

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
