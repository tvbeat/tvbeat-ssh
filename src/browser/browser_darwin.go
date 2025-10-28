package browser

import (
	"fmt"
)

func openBrowser(url, app string) error {
	if app != "" {
		return runCmd("open", "-a", fmt.Sprintf("/Applications/%s.app", app), url)
	}

	return runCmd("open", url)
}