package desktop

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"math"
	"sync/atomic"

	"fyne.io/systray"

	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/relay"
)

var (
	outlineColor = color.NRGBA{R: 0xe6, G: 0xe6, B: 0xe6, A: 0xff}
	greenDot     = color.NRGBA{R: 0x3c, G: 0xc8, B: 0x6e, A: 0xff}
	yellowDot    = color.NRGBA{R: 0xf2, G: 0xc0, B: 0x2c, A: 0xff}
	redDot       = color.NRGBA{R: 0xe0, G: 0x48, B: 0x48, A: 0xff}

	// stateDots has no entry for states that show no dot.
	stateDots = map[string]color.NRGBA{
		control.StateConnected:    greenDot,
		control.StateConnecting:   yellowDot,
		control.StateReconnecting: yellowDot,
		control.StateNeedsLogin:   yellowDot,
		control.StateFailed:       redDot,
	}
)

// tray shows the daemon's state as a status icon with a menu, in desktop bars that host
// StatusNotifierItems.
type tray struct {
	state      atomic.Value
	summary    *systray.MenuItem
	connect    *systray.MenuItem
	reconnect  *systray.MenuItem
	disconnect *systray.MenuItem
	update     *systray.MenuItem
	end        func()
}

func startTray(ctx context.Context) *tray {
	start, end := systray.RunWithExternalLoop(nil, nil)
	start()
	systray.SetTitle("GlobalProtect")

	t := &tray{
		summary:    systray.AddMenuItem("", ""),
		connect:    systray.AddMenuItem("Connect", ""),
		reconnect:  systray.AddMenuItem("Reconnect", ""),
		disconnect: systray.AddMenuItem("Disconnect", ""),
		update:     systray.AddMenuItem("", ""),
		end:        end,
	}
	t.summary.Disable()
	t.update.Hide()
	go t.connectOnClick(ctx)
	go sendOnClick(t.reconnect, control.CommandReconnect)
	go sendOnClick(t.disconnect, control.CommandDisconnect)
	go func() {
		for range t.update.ClickedCh {
			requestUpdate()
		}
	}()

	t.showUnavailable()
	return t
}

func (t *tray) show(status control.Status) {
	t.state.Store(status.State)
	line := status.String()
	systray.SetIcon(trayIcon(stateDots[status.State]))
	systray.SetTooltip("GlobalProtect: " + line)
	t.summary.SetTitle(line)
	setEnabled(t.connect, status.State == control.StateDisconnected || status.State == control.StateFailed || status.State == control.StateNeedsLogin)
	setEnabled(t.reconnect, status.State == control.StateConnected)
	setEnabled(t.disconnect, status.State != control.StateDisconnected)
	switch {
	case status.Update.Installing:
		t.update.SetTitle("Updating to " + status.Update.Available + "…")
		t.update.Disable()
		t.update.Show()
	case status.Update.Available != "":
		t.update.SetTitle("Update to " + status.Update.Available)
		t.update.Enable()
		t.update.Show()
	default:
		t.update.Hide()
	}
}

func (t *tray) showUnavailable() {
	t.state.Store("")
	line := "gpn daemon not reachable"
	systray.SetIcon(trayIcon(color.NRGBA{}))
	systray.SetTooltip("GlobalProtect: " + line)
	t.summary.SetTitle(line)
	for _, item := range []*systray.MenuItem{t.connect, t.reconnect, t.disconnect} {
		item.Disable()
	}
	t.update.Hide()
}

// connectOnClick connects, or opens the browser login when the daemon is waiting for one.
func (t *tray) connectOnClick(ctx context.Context) {
	for range t.connect.ClickedCh {
		var err error
		if t.state.Load() == control.StateNeedsLogin {
			err = BrowserLogin(ctx, "")
		} else {
			_, err = control.Call(control.Request{Command: control.CommandConnect})
		}
		if err != nil && !errors.Is(err, relay.ErrLoginPending) {
			notify("GlobalProtect", err.Error())
		}
	}
}

func sendOnClick(item *systray.MenuItem, command string) {
	for range item.ClickedCh {
		if _, err := control.Call(control.Request{Command: command}); err != nil {
			notify("GlobalProtect", err.Error())
		}
	}
}

func setEnabled(item *systray.MenuItem, enabled bool) {
	if enabled {
		item.Enable()
	} else {
		item.Disable()
	}
}

const (
	iconSize        = 64
	iconSamples     = 4
	dotCenter       = 47.0
	dotRadius       = 12.0
	dotGapRadius    = 17.0
	outlineInset    = 0.75
	shieldTop       = 0.08
	shieldMiddle    = 0.5
	shieldBottom    = 0.94
	shieldHalfWidth = 0.78
)

// trayIcon draws a shield outline with a dot of the given colour in its lower right corner, as a
// PNG. A transparent dot leaves the outline whole. Each pixel averages a 4×4 grid of samples so
// the edges are smooth.
func trayIcon(dot color.NRGBA) []byte {
	icon := image.NewNRGBA(image.Rect(0, 0, iconSize, iconSize))
	for y := range iconSize {
		for x := range iconSize {
			var red, green, blue, alpha int
			for sy := range iconSamples {
				for sx := range iconSamples {
					sample := iconSample(float64(x)+(float64(sx)+0.5)/iconSamples, float64(y)+(float64(sy)+0.5)/iconSamples, dot)
					red += int(sample.R) * int(sample.A)
					green += int(sample.G) * int(sample.A)
					blue += int(sample.B) * int(sample.A)
					alpha += int(sample.A)
				}
			}
			if alpha > 0 {
				icon.SetNRGBA(x, y, color.NRGBA{
					R: uint8(red / alpha),
					G: uint8(green / alpha),
					B: uint8(blue / alpha),
					A: uint8(alpha / (iconSamples * iconSamples)),
				})
			}
		}
	}
	var encoded bytes.Buffer
	png.Encode(&encoded, icon)
	return encoded.Bytes()
}

// iconSample is the colour at pixel coordinates x, y: the dot, a clear ring around it that
// separates it from the outline, then the outline.
func iconSample(x, y float64, dot color.NRGBA) color.NRGBA {
	if dot.A != 0 {
		distance := math.Hypot(x-dotCenter, y-dotCenter)
		if distance <= dotRadius {
			return dot
		}
		if distance <= dotGapRadius {
			return color.NRGBA{}
		}
	}
	u, v := x/iconSize*2-1, y/iconSize
	innerU, innerV := u/outlineInset, shieldMiddle+(v-shieldMiddle)/outlineInset
	if insideShield(u, v) && !insideShield(innerU, innerV) {
		return outlineColor
	}
	return color.NRGBA{}
}

// insideShield reports whether a point lies in the shield, with u across from -1 to 1 and v down
// from 0 to 1: straight sides over the top half that narrow to a point at the bottom.
func insideShield(u, v float64) bool {
	switch {
	case v < shieldTop || v > shieldBottom:
		return false
	case v < shieldMiddle:
		return math.Abs(u) <= shieldHalfWidth
	default:
		return math.Abs(u) <= shieldHalfWidth*(shieldBottom-v)/(shieldBottom-shieldMiddle)
	}
}
