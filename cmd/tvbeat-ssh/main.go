// Command tvbeat-ssh gives people ssh access to tvbeat systems using short
// lived certificates signed by vault.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/tvbeat/tvbeat-ssh/internal/agentconn"
	"github.com/tvbeat/tvbeat-ssh/internal/creds"
	"github.com/tvbeat/tvbeat-ssh/internal/fsutil"
	"github.com/tvbeat/tvbeat-ssh/internal/hosts"
	"github.com/tvbeat/tvbeat-ssh/internal/login"
	"github.com/tvbeat/tvbeat-ssh/internal/proxy"
	"github.com/tvbeat/tvbeat-ssh/internal/site"
	"github.com/tvbeat/tvbeat-ssh/internal/sshconfig"
	"github.com/tvbeat/tvbeat-ssh/internal/vault"
)

// version is set at build time with -ldflags "-X main.version=..."
var version = ""

// exit codes
const (
	exitOK      = 0
	exitError   = 1
	exitUsage   = 2
	exitNotOurs = 1
	exitAction  = 3 // the user has to do something by hand
	exitSigInt  = 130
)

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) int
	hidden  bool
}

var commands []command

func init() {
	commands = []command{
		{"config", "set up ssh to use tvbeat-ssh (run once, and again after upgrading)", cmdConfig, false},
		{"login", "sign in now and fetch a certificate, instead of on the next ssh", cmdLogin, false},
		{"status", "show who you are signed in as and how long your certificate lasts", cmdStatus, false},
		{"logout", "revoke your vault token and remove your certificate", cmdLogout, false},
		{"vault-login", "sign in to vault and write ~/.vault-token (works on headless servers)", cmdVaultLogin, false},
		{"check-host", "exit 0 if a host name is handled by tvbeat-ssh", cmdCheckHost, false},
		{"proxycommand", "used by ssh as its ProxyCommand", cmdProxy, true},
		{"prepare", "used by ssh (Match exec) to have a certificate ready", cmdPrepare, true},
		{"version", "print the version", cmdVersion, false},
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "tvbeat-ssh - ssh access to tvbeat systems with short-lived certificates\n\nusage: tvbeat-ssh <command> [flags]\n\ncommands:\n")
	for _, c := range commands {
		if !c.hidden {
			fmt.Fprintf(w, "  %-13s %s\n", c.name, c.summary)
		}
	}
	fmt.Fprintf(w, "\nOnce configured you just use ssh:  ssh scoria.dev0-hetz\nRun `tvbeat-ssh <command> -h` for a command's flags.\n")
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(exitUsage)
	}
	name := os.Args[1]
	if name == "-h" || name == "--help" || name == "help" {
		usage(os.Stdout)
		return
	}
	if name == "--version" || name == "-v" {
		name = "version"
	}
	for _, c := range commands {
		if c.name == name {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			code := c.run(ctx, os.Args[2:])
			if ctx.Err() != nil && code != exitOK {
				code = exitSigInt
			}
			stop()
			os.Exit(code)
		}
	}
	fmt.Fprintf(os.Stderr, "tvbeat-ssh: unknown command %q\n\n", name)
	usage(os.Stderr)
	os.Exit(exitUsage)
}

func fail(err error) int {
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "tvbeat-ssh: interrupted")
		return exitSigInt
	}
	fmt.Fprintf(os.Stderr, "tvbeat-ssh: %v\n", err)
	return exitError
}

func versionString() string {
	v := version
	if v == "" {
		v = "dev"
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
		}
	}
	return v
}

func cmdVersion(_ context.Context, _ []string) int {
	fmt.Printf("tvbeat-ssh %s (%s/%s)\n", versionString(), runtime.GOOS, runtime.GOARCH)
	return exitOK
}

func stderrIsTerminal() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

func manager(s *site.Settings, method login.Method) *creds.Manager {
	return &creds.Manager{
		Settings:    s,
		Out:         os.Stderr,
		Method:      method,
		Interactive: stderrIsTerminal() || os.Getenv("TVBEAT_SSH_INTERACTIVE") == "1",
		NoAgent:     os.Getenv("TVBEAT_SSH_NO_AGENT") == "1",
	}
}

func methodFlag(fs *flag.FlagSet) (*bool, *bool) {
	return fs.Bool("browser", false, "sign in with your web browser"),
		fs.Bool("device", false, "sign in with a code on another device (for headless machines)")
}

func pickMethod(b, d bool) login.Method {
	switch {
	case d:
		return login.Device
	case b:
		return login.Browser
	}
	return login.Auto
}

// ---- config ----------------------------------------------------------------

func cmdConfig(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	username := fs.String("username", "", "your username on tvbeat linux systems (required the first time)")
	role := fs.String("role", "", "vault ssh role to request certificates from (default \"all\")")
	browserApp := fs.String("browser-app", "", "browser to open for sign-in, e.g. firefox (default: system default)")
	loginMethod := fs.String("login", "", "sign-in method: auto, browser or device (default auto)")
	siteRef := fs.String("site", "", "site description to use instead of the built-in one (file path or https URL)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	s, err := site.Load()
	if errors.Is(err, site.ErrNotConfigured) {
		s = &site.Settings{Role: "all", Site: site.Default}
	} else if err != nil {
		// a corrupt settings file is replaced, not fatal
		fmt.Fprintf(os.Stderr, "tvbeat-ssh: %v - starting afresh\n", err)
		s = &site.Settings{Role: "all", Site: site.Default}
	}

	if *username != "" {
		s.Username = *username
	}
	if s.Username == "" {
		fmt.Fprintln(os.Stderr, "tvbeat-ssh: --username is required, e.g. `tvbeat-ssh config --username jsmith`")
		return exitUsage
	}
	if *role != "" {
		s.Role = *role
	}
	if *browserApp != "" {
		s.Browser = *browserApp
	}
	switch *loginMethod {
	case "":
	case "auto":
		s.Login = ""
	case "browser", "device":
		s.Login = *loginMethod
	default:
		fmt.Fprintln(os.Stderr, "tvbeat-ssh: --login must be auto, browser or device")
		return exitUsage
	}

	ref := *siteRef
	if ref == "" && os.Getenv("TVBEAT_SSH_SITE") != "" {
		ref = os.Getenv("TVBEAT_SSH_SITE")
	}
	switch {
	case strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://"):
		ns, err := site.Fetch(ref)
		if err != nil {
			return fail(err)
		}
		s.Site, s.SiteFetched = *ns, time.Now()
	case ref != "":
		ns, err := site.LoadFile(ref)
		if err != nil {
			return fail(err)
		}
		s.Site = *ns
	case s.Site.URL != "":
		if ns, err := site.Fetch(s.Site.URL); err == nil {
			s.Site, s.SiteFetched = *ns, time.Now()
		} else {
			fmt.Fprintf(os.Stderr, "tvbeat-ssh: could not refresh site description (%v), keeping the previous one\n", err)
		}
	case len(s.Site.Clusters) == 0:
		s.Site = site.Default
	}

	if err := s.Save(); err != nil {
		return fail(err)
	}

	// the host CA public key is served unauthenticated by vault
	v := vault.New(s.Site.VaultAddr)
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	caKey, caErr := v.PublicKey(cctx, s.Site.HostMount)
	cancel()
	if caErr == nil {
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caKey)); err != nil {
			caErr = fmt.Errorf("unreadable host CA key: %w", err)
			caKey = ""
		}
	} else {
		caKey = ""
	}

	paths, err := sshconfig.Write(&s.Site, s.Username, caKey)
	if err != nil {
		return fail(err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fail(err)
	}
	sshDir := filepath.Join(home, ".ssh")
	if backup, err := sshconfig.RetireLegacy(sshDir); err != nil {
		fmt.Fprintf(os.Stderr, "tvbeat-ssh: could not retire the old ~/.ssh/tvbeat.conf: %v\n", err)
	} else if backup != "" {
		fmt.Printf("Retired the configuration from tvbeat-ssh 1.x (kept as %s).\n", backup)
	}
	res, target, err := sshconfig.EnsureInclude(sshDir)
	if err != nil {
		return fail(err)
	}

	fmt.Printf("Wrote %s\n", paths.Config)
	if caKey != "" {
		fmt.Printf("Wrote %s - tvbeat servers are verified by certificate, no fingerprint prompts.\n", paths.KnownHosts)
	} else {
		fmt.Printf("Note: vault has no host CA at %s/%s yet (%v); server fingerprints are checked the usual way for now.\n", s.Site.VaultAddr, s.Site.HostMount, caErr)
	}
	switch res {
	case sshconfig.IncludeAdded:
		fmt.Printf("Added `%s` to the top of %s\n", sshconfig.IncludeLine, target)
	case sshconfig.IncludeManual:
		fmt.Printf("\n%s is managed by something else, so it was left untouched.\nAdd this line at the very top of it yourself:\n\n  %s\n\n(home-manager: programs.ssh.includes = [ \"~/.ssh/tvbeat/config\" ];)\n", target, sshconfig.IncludeLine)
	}
	if _, err := agentconn.Connect(); err != nil {
		if runtime.GOOS == "windows" {
			fmt.Println("\nTip: the Windows ssh-agent service is not running, so your key will be kept in a file.\nTo keep it in memory instead, run this once in an administrator PowerShell:\n\n  Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent")
		} else {
			fmt.Println("\nNote: no ssh-agent found, so your short-lived key will be kept in ~/.ssh/tvbeat instead of in memory.")
		}
	}
	example := "scoria." + s.Site.Clusters[0].Name
	fmt.Printf("\nAll set, %s. Try: ssh %s\n", s.Username, example)
	if res == sshconfig.IncludeManual {
		return exitAction
	}
	return exitOK
}

// ---- login / logout / status -------------------------------------------------

func loadSettings() (*site.Settings, int) {
	s, err := site.Load()
	if err != nil {
		return nil, fail(err)
	}
	return s, exitOK
}

func cmdLogin(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	b, d := methodFlag(fs)
	force := fs.Bool("force", false, "sign in again even if you are already signed in")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	s, code := loadSettings()
	if s == nil {
		return code
	}
	m := manager(s, pickMethod(*b, *d))
	m.Interactive = true
	if *force {
		m.ForgetCert()
		if _, err := m.ForceLogin(ctx); err != nil {
			return fail(err)
		}
	}
	c, err := m.Ensure(ctx)
	if err != nil {
		return fail(err)
	}
	printCert(os.Stdout, c)
	return exitOK
}

func printCert(w io.Writer, c *creds.Creds) {
	exp := time.Unix(int64(c.Cert.ValidBefore), 0)
	where := "ssh-agent"
	if !c.InAgent {
		where = "~/.ssh/tvbeat"
	}
	fmt.Fprintf(w, "Certificate valid for %s (until %s), principals: %s, kept in %s.\n",
		time.Until(exp).Round(time.Minute), exp.Local().Format("Mon 15:04"), strings.Join(c.Cert.ValidPrincipals, ", "), where)
}

func cmdStatus(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	s, code := loadSettings()
	if s == nil {
		return code
	}
	m := manager(s, login.Auto)
	fmt.Printf("user:     %s (role %s)\n", s.Username, s.Role)
	fmt.Printf("vault:    %s\n", s.Site.VaultAddr)

	healthy := true
	if tok := creds.StoredToken(); tok != "" {
		v := vault.New(s.Site.VaultAddr)
		v.Token = tok
		if ti, err := v.LookupSelf(ctx); err == nil {
			who := ti.Meta["email"]
			if who == "" {
				who = ti.DisplayName
			}
			fmt.Printf("sign-in:  %s, valid for %s\n", who, ti.TTL.Round(time.Minute))
		} else {
			fmt.Printf("sign-in:  expired (you will be asked to sign in on your next ssh)\n")
			healthy = false
		}
	} else {
		fmt.Printf("sign-in:  not signed in (you will be asked on your next ssh)\n")
		healthy = false
	}
	if c, err := m.Current(); err == nil && c != nil {
		fmt.Print("cert:     ")
		printCert(os.Stdout, c)
	} else {
		fmt.Println("cert:     none (one is fetched on your next ssh)")
		healthy = false
	}
	paths, _ := creds.SSHPaths()
	if keys, err := sshconfig.HostCAKeys(paths.KnownHosts); err == nil && len(keys) > 0 {
		fmt.Printf("hosts:    verified by the tvbeat host CA (%s)\n", ssh.FingerprintSHA256(keys[0]))
	} else {
		fmt.Println("hosts:    no host CA configured - fingerprints are checked the usual way")
	}
	home, _ := os.UserHomeDir()
	if !sshconfig.HasInclude(filepath.Join(home, ".ssh")) {
		fmt.Printf("ssh:      ~/.ssh/config does not include %s - run `tvbeat-ssh config`\n", paths.Config)
		healthy = false
	}
	if !healthy {
		return exitError
	}
	return exitOK
}

func cmdLogout(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	s, code := loadSettings()
	if s == nil {
		return code
	}
	errs := manager(s, login.Auto).Logout(ctx)
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "tvbeat-ssh: %v\n", e)
	}
	fmt.Println("Signed out: vault token revoked (including tokens pushed to servers) and certificate removed.")
	if len(errs) > 0 {
		return exitError
	}
	return exitOK
}

// ---- vault-login -------------------------------------------------------------

func cmdVaultLogin(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("vault-login", flag.ContinueOnError)
	b, d := methodFlag(fs)
	siteRef := fs.String("site", "", "site description file (defaults to your config, else built-in)")
	out := fs.String("o", "", "where to write the token (default ~/.vault-token)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	// works without `tvbeat-ssh config`, e.g. on a server
	s, err := site.Load()
	if err != nil {
		s = &site.Settings{Role: "all", Site: site.Default}
	}
	if ref := firstNonEmpty(*siteRef, os.Getenv("TVBEAT_SSH_SITE")); ref != "" {
		ns, err := site.LoadFile(ref)
		if err != nil {
			return fail(err)
		}
		s.Site = *ns
	}
	if addr := os.Getenv("VAULT_ADDR"); addr != "" && strings.TrimRight(addr, "/") != s.Site.VaultAddr {
		fmt.Fprintf(os.Stderr, "Note: VAULT_ADDR is %s but tvbeat-ssh signs in to %s\n", addr, s.Site.VaultAddr)
	}

	v := vault.New(s.Site.VaultAddr)
	l := &login.Login{Site: &s.Site, Vault: v, BrowserApp: s.Browser, Out: os.Stderr, QR: true}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	method := pickMethod(*b, *d)
	if method == login.Auto {
		method = login.Method(s.Login)
	}
	auth, err := l.Run(lctx, method)
	if err != nil {
		return fail(err)
	}
	path := *out
	if path == "" {
		if path, err = creds.VaultCLITokenPath(); err != nil {
			return fail(err)
		}
	}
	if err := fsutil.WriteFileAtomic(path, []byte(auth.ClientToken), 0o600); err != nil {
		return fail(err)
	}
	who := auth.Metadata["email"]
	if who == "" {
		who = "you"
	}
	fmt.Fprintf(os.Stderr, "Signed in to vault as %s; token valid for %s, written to %s\n", who, (time.Duration(auth.LeaseDuration) * time.Second).Round(time.Minute), path)
	return exitOK
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---- check-host / proxycommand ----------------------------------------------

func cmdCheckHost(_ context.Context, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: tvbeat-ssh check-host <host>")
		return exitUsage
	}
	s, err := site.Load()
	if err != nil {
		return exitNotOurs
	}
	if _, ok := hosts.Parse(&s.Site, args[0]); ok {
		return exitOK
	}
	return exitNotOurs
}

// cmdPrepare runs from ssh's `Match exec`, before ssh loads key files, and
// makes sure a valid certificate is in place. Its exit status only decides
// whether an empty Match block applies, so failure is reported on stderr and
// remembered for the ProxyCommand that runs next.
func cmdPrepare(ctx context.Context, args []string) int {
	if len(args) != 1 {
		return exitUsage
	}
	s, err := site.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tvbeat-ssh: %v\n", err)
		creds.MarkPrepare(err)
		return exitError
	}
	if _, ok := hosts.Parse(&s.Site, args[0]); !ok {
		return exitNotOurs
	}
	c, err := manager(s, login.Auto).Ensure(ctx)
	creds.MarkPrepare(err)
	if err != nil {
		return fail(err)
	}
	c.Close()
	return exitOK
}

func cmdProxy(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("proxycommand", flag.ContinueOnError)
	debugFlag := fs.Bool("debug", os.Getenv("TVBEAT_SSH_DEBUG") == "1", "print diagnostics")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 3 {
		fmt.Fprintln(os.Stderr, "usage: tvbeat-ssh proxycommand <user> <host> <port>")
		return exitUsage
	}
	s, code := loadSettings()
	if s == nil {
		return code
	}
	err := proxy.Run(ctx, &proxy.Options{
		Manager: manager(s, login.Auto),
		User:    fs.Arg(0),
		Host:    fs.Arg(1),
		Port:    fs.Arg(2),
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Log:     os.Stderr,
		Debug:   *debugFlag,
	})
	if err != nil {
		return fail(err)
	}
	return exitOK
}
