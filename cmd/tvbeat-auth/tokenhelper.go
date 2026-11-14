package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"

	"github.com/tvbeat/tvbeat-auth/internal/login"
	"github.com/tvbeat/tvbeat-auth/internal/nodetoken"
	"github.com/tvbeat/tvbeat-auth/internal/site"
	"github.com/tvbeat/tvbeat-auth/internal/vault"
)

func nowUnix() int64 { return time.Now().Unix() }

// openTTY opens the controlling terminal; vault keeps the helper's stdout
// and stderr to itself, so this is the only way to talk to the person.
var openTTY = func() (io.ReadWriteCloser, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }

// tokenMinTTL: a token closer than this to expiry is replaced up front, so
// the vault command that asked for it does not fail half way through.
const tokenMinTTL = 30 * time.Second

// cmdTokenHelper implements vault's token helper protocol
// (https://developer.hashicorp.com/vault/docs/commands/token-helper): the
// vault CLI runs `<helper> get|store|erase` instead of reading and writing
// ~/.vault-token itself. On servers the NixOS module points `token_helper`
// at this.
//
// get prints a valid token. When the token has expired - typical in a tmux
// session that outlives it - and there is a terminal, it signs the person in
// right there with a device code, then hands the new token to the waiting
// vault command, which carries on as if nothing happened.
func cmdTokenHelper(ctx context.Context, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: tvbeat-auth token-helper get|store|erase")
		return exitUsage
	}
	switch args[0] {
	case "get":
		return helperGet(ctx, os.Stdout)
	case "store":
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
		if err != nil {
			return fail(err)
		}
		// `vault login` by hand: from now on it is the user's own token
		if err := nodetoken.WriteUser(string(b)); err != nil {
			return fail(err)
		}
	case "erase":
		if err := nodetoken.Erase(); err != nil {
			return fail(err)
		}
	default:
		// the protocol says to ignore operations we do not know
	}
	return exitOK
}

// tokenState says what a token is good for.
type tokenState int

const (
	tokenMissing tokenState = iota
	tokenValid
	tokenExpired
	tokenUnknown // vault unreachable; let the vault command find out
)

func checkToken(ctx context.Context, addr, tok string) tokenState {
	if tok == "" {
		return tokenMissing
	}
	v := vault.New(addr)
	v.Token = tok
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ti, err := v.LookupSelf(cctx)
	var ve *vault.Error
	switch {
	case err == nil && (ti.TTL == 0 || ti.TTL > tokenMinTTL):
		return tokenValid
	case err == nil, errors.As(err, &ve):
		return tokenExpired
	default:
		return tokenUnknown
	}
}

func sameVault(a, b string) bool {
	return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
}

func helperGet(ctx context.Context, out io.Writer) int {
	tok := nodetoken.Read()
	s, err := site.Resolve("")
	if err != nil {
		fmt.Fprint(out, tok)
		return exitOK
	}
	addr := firstNonEmpty(os.Getenv("VAULT_ADDR"), s.Site.VaultAddr)
	if !sameVault(addr, s.Site.VaultAddr) {
		// some other vault: just be a plain token file
		fmt.Fprint(out, tok)
		return exitOK
	}
	state := checkToken(ctx, addr, tok)
	if state == tokenValid || state == tokenUnknown {
		fmt.Fprint(out, tok)
		return exitOK
	}
	if parentIsVaultLogin() {
		// `vault login` asks for the current token before replacing it;
		// signing in here first would only be in the way
		return exitOK
	}

	tty, err := openTTY()
	if err != nil {
		what := "expired"
		if state == tokenMissing {
			what = "missing"
		}
		fmt.Fprintf(os.Stderr, "tvbeat-auth: your vault token is %s - run `tvbeat-auth vault-login` in a terminal\n", what)
		return exitOK
	}
	defer tty.Close()
	if !s.Site.DeviceConfigured() {
		fmt.Fprintln(tty, "Your vault token has expired. Sign in again with `vault login -method=oidc` (with a port forward), or from your laptop by reconnecting.")
		return exitOK
	}

	// one sign-in at a time, however many vault commands are waiting
	unlock, err := helperLock(ctx, tty)
	if err != nil {
		fmt.Fprintf(tty, "tvbeat-auth: %v\n", err)
		return exitOK
	}
	defer unlock()
	if again := nodetoken.Read(); again != tok && checkToken(ctx, addr, again) == tokenValid {
		fmt.Fprint(out, again)
		return exitOK
	}

	if state == tokenMissing {
		fmt.Fprintln(tty, "You are not signed in to vault.")
	} else {
		fmt.Fprintln(tty, "Your vault token has expired.")
	}
	v := vault.New(s.Site.VaultAddr)
	l := &login.Login{Site: &s.Site, Vault: v, Out: tty, QR: true}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	auth, err := l.Device(lctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(tty, "Sign-in cancelled.")
		} else {
			fmt.Fprintf(tty, "Sign-in failed: %v\n", err)
		}
		return exitOK
	}
	expires := time.Now().Add(time.Duration(auth.LeaseDuration) * time.Second)
	if err := nodetoken.WriteManaged(auth.ClientToken, expires); err != nil {
		fmt.Fprintf(tty, "tvbeat-auth: could not save the vault token: %v\n", err)
	}
	who := firstNonEmpty(auth.Metadata["email"], "you")
	fmt.Fprintf(tty, "Signed in to vault as %s (valid for %s).\n\n", who, (time.Duration(auth.LeaseDuration) * time.Second).Round(time.Minute))
	fmt.Fprint(out, auth.ClientToken)
	return exitOK
}

func helperLock(ctx context.Context, tty io.Writer) (func(), error) {
	d, err := nodetoken.Dir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, err
	}
	fl := flock.New(filepath.Join(d, "helper.lock"))
	ok, err := fl.TryLock()
	if err != nil {
		return nil, err
	}
	if !ok {
		fmt.Fprintln(tty, "Waiting for a vault sign-in in another terminal to finish...")
		lctx, cancel := context.WithTimeout(ctx, 11*time.Minute)
		defer cancel()
		if ok, err = fl.TryLockContext(lctx, 250*time.Millisecond); err != nil || !ok {
			return nil, fmt.Errorf("gave up waiting for the other sign-in: %v", err)
		}
	}
	return func() { fl.Unlock() }, nil
}

// vaultSubcommand returns the first argument that is not a flag.
func vaultSubcommand(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}
