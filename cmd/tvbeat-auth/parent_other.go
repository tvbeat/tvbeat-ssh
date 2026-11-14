//go:build !linux

package main

// parentIsVaultLogin is only worked out on Linux (the token helper is meant
// for servers); elsewhere a `vault login` may be preceded by a sign-in.
func parentIsVaultLogin() bool { return false }
