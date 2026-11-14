package browser

import (
	"os/exec"

	"golang.org/x/sys/windows"
)

func openBrowser(url, app string) error {
	if app != "" {
		// app may be a full path or something on PATH such as "firefox"
		if p, err := exec.LookPath(app); err == nil {
			app = p
		}
		return windows.ShellExecute(0, nil, windows.StringToUTF16Ptr(app), windows.StringToUTF16Ptr(`"`+url+`"`), nil, windows.SW_SHOWNORMAL)
	}
	return windows.ShellExecute(0, nil, windows.StringToUTF16Ptr(url), nil, nil, windows.SW_SHOWNORMAL)
}
