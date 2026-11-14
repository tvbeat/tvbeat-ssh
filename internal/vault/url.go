package vault

import "net/url"

func urlq(s string) string { return url.QueryEscape(s) }
