// Package login obtains a vault token for a person, either through their
// desktop browser or the device authorization grant.
package login

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/tvbeat/tvbeat-ssh/internal/site"
	"github.com/tvbeat/tvbeat-ssh/internal/vault"
)

// Method is how to sign in.
type Method string

const (
	Auto    Method = ""
	Browser Method = "browser"
	Device  Method = "device"
)

// Login carries what the flows need.
type Login struct {
	Site       *site.Site
	Vault      *vault.Client
	BrowserApp string
	// Out receives every human-facing message (stderr - stdout may be an
	// ssh transport).
	Out io.Writer
	QR  bool
}

func (l *Login) say(format string, a ...any) {
	fmt.Fprintf(l.Out, format+"\n", a...)
}

// Choose resolves Auto to a concrete method for this machine.
func (l *Login) Choose(m Method) Method {
	if m == Auto {
		if v := os.Getenv("TVBEAT_SSH_LOGIN"); v == string(Browser) || v == string(Device) {
			m = Method(v)
		}
	}
	if m != Auto {
		if m == Device && !l.Site.DeviceConfigured() {
			l.say("Device sign-in is not set up for this site yet; using the browser instead.")
			return Browser
		}
		return m
	}
	if !l.Site.DeviceConfigured() {
		return Browser
	}
	if Headless() {
		return Device
	}
	return Browser
}

// Headless guesses whether there is a browser on this machine for the user.
func Headless() bool {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return true
	}
	switch runtime.GOOS {
	case "windows", "darwin":
		return false
	}
	return os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == ""
}

// Run signs in with the chosen method.
func (l *Login) Run(ctx context.Context, m Method) (*vault.Auth, error) {
	switch l.Choose(m) {
	case Device:
		return l.Device(ctx)
	default:
		return l.Browser(ctx)
	}
}
