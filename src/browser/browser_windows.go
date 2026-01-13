package browser

import (
	"errors"

	"golang.org/x/sys/windows"
)

func openBrowser(url, app string) error {
	if app != "" {
		return errors.New("not implemented: cannot override browser on Windows")
	}

	return windows.ShellExecute(0, nil, windows.StringToUTF16Ptr(url), nil, nil, windows.SW_SHOWNORMAL)
}