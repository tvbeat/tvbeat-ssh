package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/tvbeat/tvbeat-auth/internal/creds"
	"github.com/tvbeat/tvbeat-auth/internal/login"
	"github.com/tvbeat/tvbeat-auth/internal/site"
)

// cmdLegacySign is `tvbeat-ssh sign --role R [--browser B]`, which ssh
// configs written by tvbeat-ssh 1.x run from `Match ... exec`. Those configs
// point ssh at key files under <user cache dir>/tvbeat/.ssh, so this keeps a
// valid key and certificate there. It never writes the 1.x copy of the vault
// token that those configs scp to servers; `setup` replaces the whole
// arrangement.
func cmdLegacySign(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	role := fs.String("role", "all", "vault ssh role")
	browserApp := fs.String("browser", "", "browser to open for sign-in")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	s, err := site.Resolve("")
	if err != nil {
		return fail(err)
	}
	s.Role = *role
	if *browserApp != "" {
		s.Browser = *browserApp
	}
	paths, err := creds.LegacyPaths()
	if err != nil {
		return fail(err)
	}
	m := manager(s, login.Auto)
	m.NoAgent = true // the old config names a key file
	m.KeyPaths = &paths
	c, err := m.Ensure(ctx)
	if err != nil {
		return fail(err)
	}
	c.Close()
	if os.Getenv("TVBEAT_AUTH_QUIET") == "" && stderrIsTerminal() {
		if _, err := os.Stat(paths.Cert); err == nil && justSigned(c) {
			fmt.Fprintln(os.Stderr, "tvbeat-ssh is now tvbeat-auth: run `tvbeat-auth setup` once to switch to the new configuration.")
		}
	}
	return exitOK
}

// justSigned reports whether c was issued in the last minute, so the
// upgrade hint shows once per certificate rather than on every connection.
func justSigned(c *creds.Creds) bool {
	return c != nil && c.Cert != nil && int64(c.Cert.ValidAfter) > nowUnix()-120
}
