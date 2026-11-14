// Package browser opens URLs in the user's web browser.
package browser

import (
	"os"
	"os/exec"
	"strings"
)

// Open opens url in app, or the default browser when app is empty. The
// environment variable TVBEAT_SSH_BROWSER, when set, is a command that
// receives the URL as its last argument and takes precedence.
//
// The browser never gets our stdin/stdout: when we run as an ssh
// ProxyCommand those carry the ssh connection itself.
func Open(url, app string) error {
	if cmd := os.Getenv("TVBEAT_SSH_BROWSER"); cmd != "" {
		f := strings.Fields(cmd)
		return start(f[0], append(f[1:], url)...)
	}
	return openBrowser(url, app)
}

func start(prog string, args ...string) error {
	cmd := exec.Command(prog, args...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	// reap in the background; some browsers stay in the foreground
	go cmd.Wait()
	return nil
}
