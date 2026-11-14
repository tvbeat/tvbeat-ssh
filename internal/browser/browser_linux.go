//go:build !windows && !darwin

package browser

import (
	"os/exec"
	"strings"
)

func openBrowser(url, app string) error {
	if app != "" {
		path, err := exec.LookPath(app)
		if err != nil {
			return err
		}
		return start(path, url)
	}
	providers := []string{"xdg-open", "x-www-browser", "www-browser"}
	for _, p := range providers {
		if _, err := exec.LookPath(p); err == nil {
			return start(p, url)
		}
	}
	return &exec.Error{Name: strings.Join(providers, ","), Err: exec.ErrNotFound}
}
