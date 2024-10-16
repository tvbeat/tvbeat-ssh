package browser

import (
	"io"
	"os"
	"os/exec"
)

// OpenURL opens a new default browser
// (or app) window pointing to url.
func OpenURL(url, app string) error {
	return openBrowser(url, app)
}

var Stdout io.Writer = os.Stdout
var Stderr io.Writer = os.Stderr

func runCmd(prog string, args ...string) error {
	cmd := exec.Command(prog, args...)
	cmd.Stdout = Stdout
	cmd.Stderr = Stderr
	return cmd.Run()
}