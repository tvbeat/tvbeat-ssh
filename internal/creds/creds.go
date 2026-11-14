// Package creds makes sure the user holds a valid vault token and a valid
// ssh certificate, signing in only when there is no other way.
package creds

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/tvbeat/tvbeat-ssh/internal/agentconn"
	"github.com/tvbeat/tvbeat-ssh/internal/fsutil"
	"github.com/tvbeat/tvbeat-ssh/internal/login"
	"github.com/tvbeat/tvbeat-ssh/internal/site"
	"github.com/tvbeat/tvbeat-ssh/internal/vault"
)

// AgentComment marks keys tvbeat-ssh put in the agent.
const AgentComment = "tvbeat-ssh"

// minTokenTTL is how long a vault token must still be valid to be used.
const minTokenTTL = 5 * time.Minute

// Manager holds everything needed to produce credentials.
type Manager struct {
	Settings *site.Settings
	Out      io.Writer
	// Method forces a login method; login.Auto picks one.
	Method login.Method
	// Interactive is false when nobody can see our messages; a login is
	// then refused instead of waiting for a person who is not there.
	Interactive bool
	// NoAgent forces key files even when an agent is available.
	NoAgent bool

	vault *vault.Client
}

// Creds is a usable certificate.
type Creds struct {
	Cert   *ssh.Certificate
	Signer ssh.Signer
	// InAgent is true when the key lives only in ssh-agent.
	InAgent bool
	// closer is the agent connection backing Signer, if any
	closer io.Closer
}

// Close releases the agent connection behind Signer.
func (c *Creds) Close() error {
	if c.closer != nil {
		return c.closer.Close()
	}
	return nil
}

// Paths of the files under ~/.ssh/tvbeat.
type Paths struct {
	Dir, Key, Pub, Cert, AgentCert, Config, KnownHosts string
}

// SSHPaths returns the paths tvbeat-ssh uses under ~/.ssh.
func SSHPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	d := filepath.Join(home, ".ssh", "tvbeat")
	return Paths{
		Dir:        d,
		Key:        filepath.Join(d, "id_ed25519"),
		Pub:        filepath.Join(d, "id_ed25519.pub"),
		Cert:       filepath.Join(d, "id_ed25519-cert.pub"),
		AgentCert:  filepath.Join(d, "agent-cert.pub"),
		Config:     filepath.Join(d, "config"),
		KnownHosts: filepath.Join(d, "known_hosts"),
	}, nil
}

func (m *Manager) say(format string, a ...any) {
	fmt.Fprintf(m.Out, format+"\n", a...)
}

// Vault returns a client for the configured vault (without a token).
func (m *Manager) Vault() *vault.Client {
	if m.vault == nil {
		m.vault = vault.New(m.Settings.Site.VaultAddr)
	}
	return m.vault
}

func tokenPath() (string, error) {
	d, err := site.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "vault-token"), nil
}

// VaultCLITokenPath is where the vault CLI keeps its token.
func VaultCLITokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".vault-token"), nil
}

// StoredToken returns our saved token, if any.
func StoredToken() string {
	p, err := tokenPath()
	if err != nil {
		return ""
	}
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}

// lock serialises sign-ins and signing across concurrent ssh invocations.
func (m *Manager) lock(ctx context.Context) (func(), error) {
	d, err := site.Dir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, err
	}
	fl := flock.New(filepath.Join(d, "lock"))
	ok, err := fl.TryLock()
	if err != nil {
		return nil, err
	}
	if !ok {
		m.say("Waiting for a sign-in in progress elsewhere to finish...")
		lctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		defer cancel()
		ok, err = fl.TryLockContext(lctx, 250*time.Millisecond)
		if err != nil || !ok {
			return nil, fmt.Errorf("gave up waiting for another tvbeat-ssh to finish signing in: %v", err)
		}
	}
	return func() { fl.Unlock() }, nil
}

// Token returns a vault client holding a valid token, signing in if needed.
// The caller must hold the lock.
func (m *Manager) token(ctx context.Context) (*vault.Client, error) {
	v := m.Vault()

	candidates := []string{StoredToken()}
	if p, err := VaultCLITokenPath(); err == nil {
		if b, err := os.ReadFile(p); err == nil {
			candidates = append(candidates, strings.TrimSpace(string(b)))
		}
	}
	for _, t := range candidates {
		if t == "" {
			continue
		}
		v.Token = t
		ti, err := v.LookupSelf(ctx)
		// only a token from the mount we sign in on will do: the ssh roles
		// fill in the email principal from that mount's identity alias, and
		// root/approle tokens have no identity at all
		if err == nil && ti.EntityID != "" && m.fromOurMount(ti) && (ti.TTL == 0 || ti.TTL > minTokenTTL) {
			return v, nil
		}
	}
	v.Token = ""
	return m.loginOnly(ctx)
}

// EnsureToken returns a vault client with a valid token, taking the lock.
func (m *Manager) EnsureToken(ctx context.Context) (*vault.Client, error) {
	unlock, err := m.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return m.token(ctx)
}

// ForceLogin signs in even if a token is already present.
func (m *Manager) ForceLogin(ctx context.Context) (*vault.Client, error) {
	unlock, err := m.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if p, err := tokenPath(); err == nil {
		os.Remove(p)
	}
	m.Vault().Token = ""
	// deliberately no fallback to ~/.vault-token here
	return m.loginOnly(ctx)
}

func (m *Manager) loginOnly(ctx context.Context) (*vault.Client, error) {
	v := m.Vault()
	l := &login.Login{Site: &m.Settings.Site, Vault: v, BrowserApp: m.Settings.Browser, Out: m.Out, QR: true}
	method := m.Method
	if method == login.Auto {
		method = login.Method(m.Settings.Login)
	}
	method = l.Choose(method)
	// a browser sign-in works even when our messages are hidden (ansible,
	// IDEs capture stderr); a device code that nobody can read does not
	if method == login.Device && !m.Interactive {
		return nil, errors.New("you need to sign in, but nobody can see the sign-in code here - run `tvbeat-ssh login` in a terminal first")
	}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	auth, err := l.Run(lctx, method)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, errors.New("timed out waiting for sign-in")
	}
	if err != nil {
		return nil, err
	}
	v.Token = auth.ClientToken
	if err := m.saveToken(auth.ClientToken); err != nil {
		return nil, err
	}
	if who := auth.Metadata["email"]; who != "" {
		m.say("Signed in as %s.", who)
	} else {
		m.say("Signed in.")
	}
	return v, nil
}

// saveToken stores token for tvbeat-ssh, and for the vault CLI when that has
// no usable token of its own (we never clobber a working ~/.vault-token).
func (m *Manager) saveToken(token string) error {
	p, err := tokenPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(p, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	cli, err := VaultCLITokenPath()
	if err != nil {
		return nil
	}
	if b, err := os.ReadFile(cli); err == nil {
		existing := strings.TrimSpace(string(b))
		if existing != "" {
			probe := vault.New(m.Settings.Site.VaultAddr)
			probe.Token = existing
			if _, err := probe.LookupSelf(context.Background()); err == nil {
				return nil
			}
		}
	}
	return fsutil.WriteFileAtomic(cli, []byte(token), 0o600)
}

// renewMargin is how close to expiry a certificate is replaced.
func renewMargin(c *ssh.Certificate) time.Duration {
	total := time.Duration(c.ValidBefore-c.ValidAfter) * time.Second
	m := total / 5
	if m > 10*time.Minute {
		m = 10 * time.Minute
	}
	return m
}

func usable(c *ssh.Certificate, now time.Time) bool {
	if c == nil || c.CertType != ssh.UserCert {
		return false
	}
	if c.ValidBefore == ssh.CertTimeInfinity {
		return true
	}
	exp := time.Unix(int64(c.ValidBefore), 0)
	return now.After(time.Unix(int64(c.ValidAfter), 0).Add(-time.Minute)) && exp.Sub(now) > renewMargin(c)
}

func agentComment(role string) string { return AgentComment + " role=" + role }

// Ensure returns a usable certificate, signing (and signing in) if needed.
func (m *Manager) Ensure(ctx context.Context) (*Creds, error) {
	paths, err := SSHPaths()
	if err != nil {
		return nil, err
	}
	if c, err := m.current(paths); err == nil && c != nil {
		return c, nil
	}

	unlock, err := m.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// someone else may have done the work while we waited
	if c, err := m.current(paths); err == nil && c != nil {
		return c, nil
	}
	return m.sign(ctx, paths)
}

// Current returns the usable certificate if there is one, without signing.
func (m *Manager) Current() (*Creds, error) {
	paths, err := SSHPaths()
	if err != nil {
		return nil, err
	}
	return m.current(paths)
}

func (m *Manager) current(paths Paths) (*Creds, error) {
	now := time.Now()
	role := m.Settings.Role

	if !m.NoAgent {
		if a, err := agentconn.Connect(); err == nil {
			keep := false
			defer func() {
				if !keep {
					a.Close()
				}
			}()
			keys, err := a.List()
			if err != nil {
				return nil, err
			}
			for _, k := range keys {
				if k.Comment != agentComment(role) {
					continue
				}
				pk, err := ssh.ParsePublicKey(k.Blob)
				if err != nil {
					continue
				}
				cert, ok := pk.(*ssh.Certificate)
				if !ok || !usable(cert, now) {
					continue
				}
				signers, err := a.Signers()
				if err != nil {
					return nil, err
				}
				for _, s := range signers {
					if string(s.PublicKey().Marshal()) == string(cert.Marshal()) {
						// keep the files ssh reads in step with the agent
						if err := writeAgentCert(paths, cert, role); err != nil {
							return nil, err
						}
						keep = true
						return &Creds{Cert: cert, Signer: s, InAgent: true, closer: a}, nil
					}
				}
			}
			return nil, nil
		}
	}

	// key files
	certBytes, err := os.ReadFile(paths.Cert)
	if err != nil {
		return nil, nil
	}
	keyBytes, err := os.ReadFile(paths.Key)
	if err != nil {
		return nil, nil
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, nil
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok || !usable(cert, now) || !strings.Contains(string(certBytes), agentComment(role)) {
		return nil, nil
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, nil
	}
	cs, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, nil
	}
	return &Creds{Cert: cert, Signer: cs}, nil
}

// writeAgentCert writes the certificate that lives in the agent to
// agent-cert.pub, which the ssh config names as an IdentityFile: ssh then
// asks the agent to sign with exactly this certificate (with IdentitiesOnly
// it ignores agent keys it was not told about). Leftover key files from the
// no-agent mode are removed so ssh does not offer stale ones.
func writeAgentCert(paths Paths, cert *ssh.Certificate, role string) error {
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		return err
	}
	for _, p := range []string{paths.Key, paths.Pub, paths.Cert, paths.AgentCert} {
		os.Remove(p)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	if b, err := os.ReadFile(paths.AgentCert); err == nil && strings.HasPrefix(string(b), line+" ") {
		return nil
	}
	return fsutil.WriteFileAtomic(paths.AgentCert, []byte(line+" "+agentComment(role)+"\n"), 0o644)
}

// writeKeyFiles is the no-agent mode: private key, public key and
// certificate as files, named so ssh pairs them by itself.
func writeKeyFiles(paths Paths, keyPEM []byte, cert *ssh.Certificate, role string) error {
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		return err
	}
	os.Remove(paths.AgentCert)
	if err := fsutil.WriteFileAtomic(paths.Key, keyPEM, 0o600); err != nil {
		return err
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert.Key)))
	if err := fsutil.WriteFileAtomic(paths.Pub, []byte(pub+" "+AgentComment+"\n"), 0o644); err != nil {
		return err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	return fsutil.WriteFileAtomic(paths.Cert, []byte(line+" "+agentComment(role)+"\n"), 0o644)
}

func (m *Manager) sign(ctx context.Context, paths Paths) (*Creds, error) {
	v, err := m.token(ctx)
	if err != nil {
		return nil, err
	}
	s := &m.Settings.Site
	role := m.Settings.Role

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	signed, err := v.SignUserKey(ctx, s.UserMount, s.SSHRole(role), string(ssh.MarshalAuthorizedKey(sshPub)))
	if vault.IsPermissionDenied(err) {
		return nil, fmt.Errorf("your account is not allowed to use the %q ssh role (%v)", s.SSHRole(role), err)
	}
	if err != nil {
		return nil, fmt.Errorf("signing your ssh key: %w", err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signed))
	if err != nil {
		return nil, fmt.Errorf("vault returned an unreadable certificate: %w", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("vault returned a key that is not a certificate")
	}
	for _, p := range cert.ValidPrincipals {
		if strings.Contains(p, "{{") {
			return nil, fmt.Errorf("vault issued a certificate with an unresolved principal %q - the vault token in use has no identity; run `tvbeat-ssh login --force`", p)
		}
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	cs, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		return nil, err
	}

	lifetime := time.Until(time.Unix(int64(cert.ValidBefore), 0))
	if cert.ValidBefore == ssh.CertTimeInfinity || lifetime > 30*24*time.Hour {
		lifetime = 24 * time.Hour
	}

	if !m.NoAgent {
		if a, err := agentconn.Connect(); err == nil {
			defer a.Close()
			removeOurs(a)
			err := a.Add(agent.AddedKey{
				PrivateKey:   priv,
				Certificate:  cert,
				Comment:      agentComment(role),
				LifetimeSecs: uint32(lifetime / time.Second),
			})
			if err == nil {
				if err := writeAgentCert(paths, cert, role); err != nil {
					return nil, err
				}
				return &Creds{Cert: cert, Signer: cs, InAgent: true}, nil
			}
			m.say("(could not add the certificate to ssh-agent: %v; using key files instead)", err)
		}
	}

	block, err := ssh.MarshalPrivateKey(priv, AgentComment)
	if err != nil {
		return nil, err
	}
	if err := writeKeyFiles(paths, pem.EncodeToMemory(block), cert, role); err != nil {
		return nil, err
	}
	return &Creds{Cert: cert, Signer: cs}, nil
}

func removeOurs(a agent.Agent) {
	keys, err := a.List()
	if err != nil {
		return
	}
	for _, k := range keys {
		if strings.HasPrefix(k.Comment, AgentComment) {
			a.Remove(k)
		}
	}
}

// Logout removes our certificates from the agent and our files from disk,
// and revokes our vault token (which revokes every child token we pushed).
func (m *Manager) Logout(ctx context.Context) []error {
	var errs []error
	if a, err := agentconn.Connect(); err == nil {
		removeOurs(a)
		a.Close()
	}
	if paths, err := SSHPaths(); err == nil {
		for _, p := range []string{paths.Key, paths.Pub, paths.Cert, paths.AgentCert} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	tok := StoredToken()
	if tok != "" {
		v := m.Vault()
		v.Token = tok
		if err := v.RevokeSelf(ctx); err != nil {
			var ve *vault.Error
			// an already expired/revoked token is not worth reporting
			if !errors.As(err, &ve) || ve.Status != 403 {
				errs = append(errs, fmt.Errorf("revoking vault token: %w", err))
			}
		}
		if cli, err := VaultCLITokenPath(); err == nil {
			if b, err := os.ReadFile(cli); err == nil && strings.TrimSpace(string(b)) == tok {
				os.Remove(cli)
			}
		}
	}
	if p, err := tokenPath(); err == nil {
		os.Remove(p)
	}
	if d, err := site.Dir(); err == nil {
		os.Remove(filepath.Join(d, "pushed.json"))
	}
	return errs
}

// ForgetCert removes our certificate from the agent and disk without
// touching the vault token.
func (m *Manager) ForgetCert() {
	if a, err := agentconn.Connect(); err == nil {
		removeOurs(a)
		a.Close()
	}
	if paths, err := SSHPaths(); err == nil {
		for _, p := range []string{paths.Key, paths.Pub, paths.Cert, paths.AgentCert} {
			os.Remove(p)
		}
	}
}

func prepareMarker() string {
	d, err := site.Dir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "prepare-failed")
}

// MarkPrepare records whether `prepare` (run by ssh's Match exec) failed, so
// the ProxyCommand that follows does not ask the user to sign in twice.
func MarkPrepare(err error) {
	p := prepareMarker()
	if p == "" {
		return
	}
	if err == nil {
		os.Remove(p)
		return
	}
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, []byte(err.Error()), 0o600)
}

// RecentPrepareFailure returns the error `prepare` hit moments ago, if any.
func RecentPrepareFailure() error {
	p := prepareMarker()
	st, err := os.Stat(p)
	if err != nil || time.Since(st.ModTime()) > 30*time.Second {
		return nil
	}
	b, _ := os.ReadFile(p)
	return errors.New(strings.TrimSpace(string(b)))
}

// fromOurMount reports whether a token was created by a login on the auth
// mount this site signs in with (child tokens carry their parent's entity
// but not its path, so they are not reused either).
func (m *Manager) fromOurMount(ti *vault.TokenInfo) bool {
	s := &m.Settings.Site
	mount := s.AuthMount
	if s.SSOConfigured() || s.DeviceConfigured() {
		mount = s.SSO.VaultMount
	}
	return strings.HasPrefix(ti.Path, "auth/"+mount+"/")
}
