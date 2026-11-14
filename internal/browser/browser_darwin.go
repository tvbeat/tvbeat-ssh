package browser

func openBrowser(url, app string) error {
	if app != "" {
		// `open -a` takes an application name ("Firefox") or a path
		return start("open", "-a", app, url)
	}
	return start("open", url)
}
