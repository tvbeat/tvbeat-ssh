package creds

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/tvbeat/tvbeat-ssh/internal/site"
)

// fakeVault validates one token and signs user certificates with an
// in-memory CA, like vault's ssh secrets engine.
type fakeVault struct {
	*httptest.Server
	signs atomic.Int32
	ttl   time.Duration
}

func newFakeVault(t *testing.T) *fakeVault {
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPriv)
	fv := &fakeVault{ttl: time.Hour}
	fv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "good" {
			w.WriteHeader(403)
			io.WriteString(w, `{"errors":["permission denied"]}`)
			return
		}
		switch {
		case r.URL.Path == "/v1/auth/token/lookup-self":
			io.WriteString(w, `{"data":{"ttl":3600,"entity_id":"e1","path":"auth/oidc/oidc/callback"}}`)
		case r.URL.Path == "/v1/ssh/sign/all":
			fv.signs.Add(1)
			var body struct {
				PublicKey string `json:"public_key"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(body.PublicKey))
			if err != nil {
				w.WriteHeader(400)
				return
			}
			now := time.Now()
			cert := &ssh.Certificate{
				Key: pub, CertType: ssh.UserCert, KeyId: "vault-test",
				ValidPrincipals: []string{"jump", "a@b"},
				ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
				ValidBefore:     uint64(now.Add(fv.ttl).Unix()),
			}
			cert.SignCert(rand.Reader, ca)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"signed_key": string(ssh.MarshalAuthorizedKey(cert))}})
		case r.URL.Path == "/v1/ssh/sign/devops":
			w.WriteHeader(403)
			io.WriteString(w, `{"errors":["permission denied"]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fv.Close)
	return fv
}

func setup(t *testing.T, withAgent bool) (*Manager, *fakeVault, agent.Agent) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("TVBEAT_SSH_HOME", filepath.Join(home, "state"))
	os.MkdirAll(filepath.Join(home, "state"), 0o700)
	os.WriteFile(filepath.Join(home, "state", "vault-token"), []byte("good\n"), 0o600)

	var kr agent.Agent
	if withAgent {
		kr = agent.NewKeyring()
		sock := filepath.Join(home, "agent.sock")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go agent.ServeAgent(kr, c)
			}
		}()
		t.Setenv("SSH_AUTH_SOCK", sock)
	} else {
		t.Setenv("SSH_AUTH_SOCK", "")
	}

	fv := newFakeVault(t)
	s := &site.Settings{Username: "a", Role: "all", Site: site.Site{VaultAddr: fv.URL, UserMount: "ssh", AuthMount: "oidc"}}
	return &Manager{Settings: s, Out: io.Discard, Interactive: false}, fv, kr
}

func TestEnsureAgent(t *testing.T) {
	m, fv, kr := setup(t, true)
	ctx := context.Background()

	c, err := m.Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !c.InAgent {
		t.Fatal("expected the key in the agent")
	}
	keys, _ := kr.List()
	if len(keys) != 1 || keys[0].Comment != "tvbeat-ssh role=all" || !strings.Contains(keys[0].Format, "cert") {
		t.Fatalf("agent keys: %v", keys)
	}
	paths, _ := SSHPaths()
	if _, err := os.Stat(paths.Key); !os.IsNotExist(err) {
		t.Fatal("private key must not be written to disk in agent mode")
	}
	b, err := os.ReadFile(paths.AgentCert)
	if err != nil || !strings.HasPrefix(string(b), "ssh-ed25519-cert-v01@openssh.com ") {
		t.Fatalf("agent-cert.pub: %q %v", b, err)
	}

	// a valid certificate is reused without asking vault again
	c2, err := m.Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
	if n := fv.signs.Load(); n != 1 {
		t.Fatalf("signed %d times, want 1", n)
	}
	// and its signer works
	if _, err := c2.Signer.Sign(rand.Reader, []byte("x")); err == nil {
		t.Fatal("expected closed agent connection to fail after Close")
	}
}

func TestEnsureParallelSignsOnce(t *testing.T) {
	m, fv, _ := setup(t, true)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mm := *m
			if c, err := mm.Ensure(context.Background()); err != nil {
				errs <- err
			} else {
				c.Close()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := fv.signs.Load(); n != 1 {
		t.Fatalf("signed %d times, want 1", n)
	}
}

func TestEnsureExpiringIsRenewed(t *testing.T) {
	m, fv, _ := setup(t, true)
	fv.ttl = 30 * time.Second // renew margin is a fifth: 6s, so still fine
	if _, err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	fv.ttl = 3 * time.Second // already inside its margin once issued
	m.Settings.Role = "all"
	m.ForgetCert()
	if _, err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond)
	if _, err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := fv.signs.Load(); n != 3 {
		t.Fatalf("signed %d times, want 3", n)
	}
}

func TestEnsureFiles(t *testing.T) {
	m, fv, _ := setup(t, false)
	c, err := m.Ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.InAgent {
		t.Fatal("no agent, yet InAgent")
	}
	paths, _ := SSHPaths()
	st, err := os.Stat(paths.Key)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	if _, err := m.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := fv.signs.Load(); n != 1 {
		t.Fatalf("signed %d times, want 1", n)
	}
}

func TestEnsureForbiddenRole(t *testing.T) {
	m, _, _ := setup(t, true)
	m.Settings.Role = "devops"
	_, err := m.Ensure(context.Background())
	if err == nil || !strings.Contains(err.Error(), `not allowed to use the "devops" ssh role`) {
		t.Fatalf("err = %v", err)
	}
}

func TestNoTokenNonInteractiveDevice(t *testing.T) {
	m, _, _ := setup(t, true)
	os.Remove(filepath.Join(os.Getenv("TVBEAT_SSH_HOME"), "vault-token"))
	m.Settings.Site.SSO = site.SSO{Issuer: "http://127.0.0.1:1", Device: site.Client{ID: "d"}, Browser: site.Client{ID: "b"}}
	m.Settings.Login = "device"
	_, err := m.Ensure(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nobody can see the sign-in code") {
		t.Fatalf("err = %v", err)
	}
}

func TestUsable(t *testing.T) {
	now := time.Now()
	c := &ssh.Certificate{CertType: ssh.UserCert, ValidAfter: uint64(now.Add(-time.Hour).Unix()), ValidBefore: uint64(now.Add(23 * time.Hour).Unix())}
	if !usable(c, now) {
		t.Error("fresh 24h cert not usable")
	}
	if usable(c, now.Add(23*time.Hour-5*time.Minute)) {
		t.Error("cert 5 minutes from expiry should be renewed (margin 10m)")
	}
	c.CertType = ssh.HostCert
	if usable(c, now) {
		t.Error("host cert accepted as user cert")
	}
}

func TestTokenFromOtherMountIgnored(t *testing.T) {
	m, fv, _ := setup(t, true)
	// the site now signs in through the google jwt mount; our stored token
	// came from the oidc mount, so it must not be used for signing
	m.Settings.Site.SSO = site.SSO{Issuer: "http://127.0.0.1:1", VaultMount: "google", Browser: site.Client{ID: "b"}}
	m.Settings.Login = "browser"
	_, err := m.Ensure(context.Background())
	if err == nil {
		t.Fatal("expected a sign-in attempt (which fails here), not reuse of the oidc token")
	}
	if fv.signs.Load() != 0 {
		t.Fatal("signed with a token from the wrong mount")
	}
}
