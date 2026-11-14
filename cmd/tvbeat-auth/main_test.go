package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tvbeat/tvbeat-auth/internal/nodetoken"
)

func TestValidUsername(t *testing.T) {
	for _, ok := range []string{"aka", "antonija", "robertf", "_svc", "a.b-c_d"} {
		if err := validUsername(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Alan", "1abc", "a b", "a\nHost *", "x@y", strings.Repeat("a", 33)} {
		if validUsername(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAskUsername(t *testing.T) {
	var out bytes.Buffer
	// enter accepts the suggestion from the email
	u, err := askUsername(strings.NewReader("\n"), &out, "alan@tvbeat.com", true)
	if err != nil || u != "alan" || !strings.Contains(out.String(), "[alan]") {
		t.Fatalf("suggestion: %q %v %q", u, err, out.String())
	}
	// a typed name wins; an invalid one is asked again
	out.Reset()
	u, err = askUsername(strings.NewReader("Not Valid\naka\n"), &out, "alan@tvbeat.com", true)
	if err != nil || u != "aka" || !strings.Contains(out.String(), "not a valid") {
		t.Fatalf("typed: %q %v %q", u, err, out.String())
	}
	// no terminal: never guess
	if _, err := askUsername(strings.NewReader("aka\n"), io.Discard, "alan@tvbeat.com", false); err == nil || !strings.Contains(err.Error(), "--username") {
		t.Fatalf("no tty: %v", err)
	}
	// nothing usable at all
	if _, err := askUsername(strings.NewReader(""), io.Discard, "", true); err == nil {
		t.Fatal("empty input accepted")
	}
}

func TestVaultSubcommand(t *testing.T) {
	cases := map[string][]string{
		"login": {"-address=x", "login", "-method=oidc"},
		"token": {"token", "lookup"},
		"":      {"-h"},
	}
	for want, args := range cases {
		if got := vaultSubcommand(args); got != want {
			t.Errorf("%v: %q, want %q", args, got, want)
		}
	}
}

// fakeVault answers lookup-self: tokens in valid are fine, anything else is
// refused the way vault refuses an expired or revoked token.
func fakeVault(t *testing.T, valid map[string]time.Duration) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" {
			http.NotFound(w, r)
			return
		}
		ttl, ok := valid[r.Header.Get("X-Vault-Token")]
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"errors":["permission denied"]}`)
			return
		}
		fmt.Fprintf(w, `{"data":{"ttl":%d,"meta":{"email":"alice@tvbeat.com"}}}`, int(ttl.Seconds()))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func helperEnv(t *testing.T, vaultAddr string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir) // os.UserHomeDir on windows
	t.Setenv("TVBEAT_AUTH_HOME", filepath.Join(dir, "cfg"))
	sitePath := filepath.Join(dir, "site.json")
	os.WriteFile(sitePath, []byte(`{"vault_addr":"`+vaultAddr+`","clusters":[{"name":"dev0-hetz","jump":"jump:443"}]}`), 0o600)
	t.Setenv("TVBEAT_AUTH_SITE", sitePath)
	t.Setenv("VAULT_ADDR", vaultAddr)
}

func TestTokenHelper(t *testing.T) {
	srv := fakeVault(t, map[string]time.Duration{"hvs.good": time.Hour, "hvs.dying": 5 * time.Second})
	helperEnv(t, srv.URL)

	ttyOpened := 0
	openTTY = func() (io.ReadWriteCloser, error) {
		ttyOpened++
		return nil, errors.New("no tty in tests")
	}
	t.Cleanup(func() { openTTY = func() (io.ReadWriteCloser, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) } })

	get := func() string {
		var out bytes.Buffer
		if rc := helperGet(context.Background(), &out); rc != exitOK {
			t.Fatalf("get: rc %d", rc)
		}
		return out.String()
	}

	// nothing stored, no terminal: nothing to hand out, and no hang
	if got := get(); got != "" || ttyOpened != 1 {
		t.Fatalf("missing: %q (tty opened %d)", got, ttyOpened)
	}
	// a valid token is handed out as is (vault rereads it every command)
	nodetoken.WriteManaged("hvs.good", time.Now().Add(time.Hour))
	if got := get(); got != "hvs.good" {
		t.Fatalf("valid: %q", got)
	}
	// expired or about to expire: a sign-in would be needed, but there is
	// no terminal here, so nothing is printed rather than a dead token
	for _, tok := range []string{"hvs.revoked", "hvs.dying"} {
		nodetoken.WriteManaged(tok, time.Now().Add(time.Hour))
		ttyOpened = 0
		if got := get(); got != "" || ttyOpened != 1 {
			t.Fatalf("%s: %q (tty opened %d)", tok, got, ttyOpened)
		}
	}
	// a different vault: just a token file, no checks, no sign-in
	nodetoken.WriteUser("hvs.other-vault")
	t.Setenv("VAULT_ADDR", "https://vault.example.com")
	ttyOpened = 0
	if got := get(); got != "hvs.other-vault" || ttyOpened != 0 {
		t.Fatalf("other vault: %q (tty opened %d)", got, ttyOpened)
	}
	// vault unreachable: hand out what we have and let vault report
	t.Setenv("VAULT_ADDR", srv.URL)
	srv.Close()
	if got := get(); got != "hvs.other-vault" {
		t.Fatalf("unreachable: %q", got)
	}
}

func TestTokenHelperStoreErase(t *testing.T) {
	helperEnv(t, "http://127.0.0.1:1")
	nodetoken.WriteManaged("hvs.pushed", time.Now().Add(time.Hour))

	stdin := os.Stdin
	t.Cleanup(func() { os.Stdin = stdin })
	r, w, _ := os.Pipe()
	io.WriteString(w, "hvs.mine\n")
	w.Close()
	os.Stdin = r

	if rc := cmdTokenHelper(context.Background(), []string{"store"}); rc != exitOK {
		t.Fatalf("store rc %d", rc)
	}
	if got := nodetoken.Read(); got != "hvs.mine" {
		t.Fatalf("stored %q", got)
	}
	if _, managed := nodetoken.Managed("hvs.mine"); managed {
		t.Fatal("a token from `vault login` must count as the user's own")
	}
	if rc := cmdTokenHelper(context.Background(), []string{"erase"}); rc != exitOK || nodetoken.Read() != "" {
		t.Fatalf("erase rc %d, left %q", rc, nodetoken.Read())
	}
	if rc := cmdTokenHelper(context.Background(), []string{"frobnicate"}); rc != exitOK {
		t.Fatalf("unknown op must be ignored, rc %d", rc)
	}
}

func TestProgName(t *testing.T) {
	args := os.Args
	t.Cleanup(func() { os.Args = args })
	for argv0, want := range map[string]string{
		"/usr/local/bin/tvbeat-ssh":  "tvbeat-ssh",
		`C:\bin\tvbeat-ssh.exe`:      "tvbeat-ssh",
		"/usr/local/bin/tvbeat-auth": "tvbeat-auth",
		"./anything":                 "tvbeat-auth",
	} {
		os.Args = []string{filepath.FromSlash(argv0)}
		if got := progName(); got != want && !(strings.Contains(argv0, `\`) && got == "tvbeat-auth") {
			t.Errorf("%s: %s, want %s", argv0, got, want)
		}
	}
}
