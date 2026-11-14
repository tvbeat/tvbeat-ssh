// Command tvbeat-auth signs people in to tvbeat systems: short-lived ssh
// certificates signed by vault, and vault tokens on laptops and servers.
//
// It also answers to the 1.x name `tvbeat-ssh` and its `sign` command, so
// ssh configs written by tvbeat-ssh 1.x keep working until `setup` replaces
// them.
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
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/tvbeat/tvbeat-auth/internal/agentconn"
	"github.com/tvbeat/tvbeat-auth/internal/creds"
	"github.com/tvbeat/tvbeat-auth/internal/fsutil"
	"github.com/tvbeat/tvbeat-auth/internal/hosts"
	"github.com/tvbeat/tvbeat-auth/internal/login"
	"github.com/tvbeat/tvbeat-auth/internal/nodetoken"
	"github.com/tvbeat/tvbeat-auth/internal/proxy"
	"github.com/tvbeat/tvbeat-auth/internal/site"
	"github.com/tvbeat/tvbeat-auth/internal/sshconfig"
	"github.com/tvbeat/tvbeat-auth/internal/vault"
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
		{"setup", "set up ssh and sign in (run once, and again after upgrading)", cmdSetup, false},
		{"login", "sign in now and fetch a certificate, instead of on the next ssh", cmdLogin, false},
		{"status", "show who you are signed in as and how long your certificate lasts", cmdStatus, false},
		{"logout", "revoke your vault token and remove your certificate", cmdLogout, false},
		{"vault-login", "sign in to vault and write ~/.vault-token (works on headless servers)", cmdVaultLogin, false},
		{"version", "print the version", cmdVersion, false},
		// plumbing: run by ssh and vault, not by people
		{"check-host", "exit 0 if a host name is handled by tvbeat-auth", cmdCheckHost, true},
		{"prepare", "used by ssh (Match exec) to have a certificate ready", cmdPrepare, true},
		{"ssh-proxy", "used by ssh as its ProxyCommand", cmdProxy, true},
		{"token-helper", "vault CLI token helper (get|store|erase)", cmdTokenHelper, true},
		// earlier names
		{"config", "", cmdSetup, true},       // 2.0 development name; also `tvbeat-ssh config --username U` from 1.x
		{"proxycommand", "", cmdProxy, true}, // 2.0 development name
		{"sign", "", cmdLegacySign, true},    // tvbeat-ssh 1.x ssh configs
	}
}

// progName is what the user called us: tvbeat-auth, or tvbeat-ssh through
// the compatibility link.
func progName() string {
	base := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	if base == "tvbeat-ssh" {
		return base
	}
	return "tvbeat-auth"
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "tvbeat-auth - sign in to tvbeat systems: ssh with short-lived certificates, vault tokens\n\nusage: tvbeat-auth <command> [flags]\n\ncommands:\n")
	for _, c := range commands {
		if !c.hidden {
			fmt.Fprintf(w, "  %-13s %s\n", c.name, c.summary)
		}
	}
	fmt.Fprintf(w, "\nOnce set up you just use ssh:  ssh scoria.dev0-hetz\nRun `tvbeat-auth <command> -h` for a command's flags.\n")
	if progName() == "tvbeat-ssh" {
		fmt.Fprintf(w, "\n(tvbeat-ssh is now called tvbeat-auth; this name keeps old ssh configs working until you run `tvbeat-auth setup`.)\n")
	}
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
	fmt.Fprintf(os.Stderr, "tvbeat-auth: unknown command %q\n\n", name)
	usage(os.Stderr)
	os.Exit(exitUsage)
}

func fail(err error) int {
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "tvbeat-auth: interrupted")
		return exitSigInt
	}
	fmt.Fprintf(os.Stderr, "tvbeat-auth: %v\n", err)
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
	fmt.Printf("tvbeat-auth %s (%s/%s)\n", versionString(), runtime.GOOS, runtime.GOARCH)
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
		Interactive: stderrIsTerminal() || os.Getenv("TVBEAT_AUTH_INTERACTIVE") == "1",
		NoAgent:     os.Getenv("TVBEAT_AUTH_NO_AGENT") == "1",
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

// ---- setup -----------------------------------------------------------------

func cmdSetup(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	username := fs.String("username", "", "your username on tvbeat linux systems (normally looked up from your account)")
	role := fs.String("role", "", "vault ssh role to request certificates from (default \"all\")")
	browserApp := fs.String("browser-app", "", "browser to open for sign-in, e.g. firefox (default: system default)")
	fs.StringVar(browserApp, "browser", "", "same as --browser-app")
	loginMethod := fs.String("login", "", "sign-in method: auto, browser or device (default auto)")
	siteRef := fs.String("site", "", "site description to use instead of the built-in one (file path or https URL)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *username != "" {
		if err := validUsername(*username); err != nil {
			fmt.Fprintf(os.Stderr, "tvbeat-auth: --username: %v\n", err)
			return exitUsage
		}
	}

	s, err := site.Load()
	if errors.Is(err, site.ErrNotConfigured) {
		s = &site.Settings{Role: "all", Site: site.Default}
	} else if err != nil {
		// a corrupt settings file is replaced, not fatal
		fmt.Fprintf(os.Stderr, "tvbeat-auth: %v - starting afresh\n", err)
		s = &site.Settings{Role: "all", Site: site.Default}
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
		fmt.Fprintln(os.Stderr, "tvbeat-auth: --login must be auto, browser or device")
		return exitUsage
	}

	ref := *siteRef
	if ref == "" && os.Getenv("TVBEAT_AUTH_SITE") != "" {
		ref = os.Getenv("TVBEAT_AUTH_SITE")
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
			fmt.Fprintf(os.Stderr, "tvbeat-auth: could not refresh site description (%v), keeping the previous one\n", err)
		}
	case len(s.Site.Clusters) == 0:
		s.Site = site.Default
	}

	switch {
	case *username != "":
		s.Username = *username
	case s.Username == "":
		// the username lives in the person's account (Google Workspace,
		// through vault); signing in now also means the first ssh is instant
		u, err := discoverUsername(ctx, s)
		if err != nil {
			return fail(err)
		}
		s.Username = u
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
		fmt.Fprintf(os.Stderr, "tvbeat-auth: could not retire the old ~/.ssh/tvbeat.conf: %v\n", err)
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
		fmt.Printf("ssh:      ~/.ssh/config does not include %s - run `tvbeat-auth setup`\n", paths.Config)
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
		fmt.Fprintf(os.Stderr, "tvbeat-auth: %v\n", e)
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
	siteRef := fs.String("site", "", "site description file (default: your settings, then "+site.SystemFile+", then built-in)")
	out := fs.String("o", "", "where to write the token (default ~/.vault-token)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	// works without `tvbeat-auth setup`, e.g. on a server
	s, err := site.Resolve(*siteRef)
	if err != nil {
		return fail(err)
	}
	if addr := os.Getenv("VAULT_ADDR"); addr != "" && strings.TrimRight(addr, "/") != s.Site.VaultAddr {
		fmt.Fprintf(os.Stderr, "Note: VAULT_ADDR is %s but tvbeat-auth signs in to %s\n", addr, s.Site.VaultAddr)
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
		// ~/.vault-token, marked as ours so a token pushed later on connect
		// only replaces it once it is the better one
		if path, err = nodetoken.Path(); err != nil {
			return fail(err)
		}
		expires := time.Now().Add(time.Duration(auth.LeaseDuration) * time.Second)
		if err := nodetoken.WriteManaged(auth.ClientToken, expires); err != nil {
			return fail(err)
		}
	} else if err := fsutil.WriteFileAtomic(path, []byte(auth.ClientToken), 0o600); err != nil {
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

// ---- check-host / prepare / ssh-proxy -------------------------------------

func cmdCheckHost(_ context.Context, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: tvbeat-auth check-host <host>")
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
		fmt.Fprintf(os.Stderr, "tvbeat-auth: %v\n", err)
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
	// ssh sends its ProxyCommand SIGHUP when the session ends. Outlive it
	// briefly so an in-flight vault token push completes rather than being
	// cut off before authenticating: sshd counts such connections against
	// the source address (PerSourcePenalties), and for nodes that is the
	// jump host everybody shares. proxy.Run waits at most 10s for the push.
	signal.Ignore(syscall.SIGHUP)
	fs := flag.NewFlagSet("ssh-proxy", flag.ContinueOnError)
	debugFlag := fs.Bool("debug", os.Getenv("TVBEAT_AUTH_DEBUG") == "1", "print diagnostics")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 3 {
		fmt.Fprintln(os.Stderr, "usage: tvbeat-auth ssh-proxy <user> <host> <port>")
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
