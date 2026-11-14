// Package proxy implements `tvbeat-ssh proxycommand`: it makes sure the user
// holds a valid certificate, connects to the cluster's jump host and hands
// ssh a byte stream to the target node.
//
// The jump hop is done in-process with golang.org/x/crypto/ssh rather than by
// running `ssh -W`. That avoids re-entering the user's ssh config (and this
// very ProxyCommand), lets us verify the jump host's certificate against the
// host CA ourselves, behaves the same on Windows, and gives us a connection
// we can reuse to push a vault token to the node.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/tvbeat/tvbeat-ssh/internal/creds"
	"github.com/tvbeat/tvbeat-ssh/internal/hosts"
	"github.com/tvbeat/tvbeat-ssh/internal/sshconfig"
)

// Options for one proxied connection.
type Options struct {
	Manager *creds.Manager
	User    string
	Host    string
	Port    string
	Stdin   io.Reader
	Stdout  io.Writer
	Log     io.Writer
	// Debug enables extra diagnostics on Log.
	Debug bool
}

func (o *Options) debugf(format string, a ...any) {
	if o.Debug {
		fmt.Fprintf(o.Log, "tvbeat-ssh: "+format+"\n", a...)
	}
}

// Run proxies one connection; it returns when either side closes.
func Run(ctx context.Context, o *Options) error {
	s := &o.Manager.Settings.Site
	t, ok := hosts.Parse(s, o.Host)
	if !ok {
		return fmt.Errorf("%q is not a tvbeat host name - expected <node>.<cluster>, e.g. scoria.%s", o.Host, s.Clusters[0].Name)
	}

	c, err := o.Manager.Current()
	if err != nil || c == nil {
		if perr := creds.RecentPrepareFailure(); perr != nil {
			// `prepare` already told the user why; do not prompt again
			return errors.New("not connecting: no valid certificate (see above)")
		}
		// normally `prepare` has done this already; this covers ssh configs
		// without the Match block
		if c, err = o.Manager.Ensure(ctx); err != nil {
			return err
		}
	}
	defer c.Close()
	o.debugf("certificate %s valid until %s (agent=%v)", c.Cert.KeyId, time.Unix(int64(c.Cert.ValidBefore), 0).Format(time.RFC3339), c.InAgent)

	if t.IsJump() {
		// ssh is talking to the jump host itself and verifies it on its own
		conn, err := net.DialTimeout("tcp", t.Cluster.Jump, 15*time.Second)
		if err != nil {
			return fmt.Errorf("cannot reach %s: %w", t.Cluster.Jump, err)
		}
		return pipe(conn, o.Stdin, o.Stdout)
	}

	paths, err := creds.SSHPaths()
	if err != nil {
		return err
	}
	hkc, err := hostKeyCallback(paths.KnownHosts, hosts.Principals(t.Cluster, "")[0])
	if err != nil {
		return err
	}

	jumpUser := o.Manager.Settings.Username
	cfg := &ssh.ClientConfig{
		User:              jumpUser,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(c.Signer)},
		HostKeyCallback:   hkc.callback,
		HostKeyAlgorithms: hkc.algorithms,
		Timeout:           15 * time.Second,
	}
	o.debugf("connecting to jump host %s as %s", t.Cluster.Jump, jumpUser)
	jump, err := ssh.Dial("tcp", t.Cluster.Jump, cfg)
	if err != nil {
		return explainDialError(t.Cluster.Jump, err)
	}
	defer jump.Close()
	go keepalive(jump)

	addr := t.DialAddr(o.Port)
	o.debugf("opening %s through the jump host", addr)
	conn, err := jump.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("the jump host could not reach %s: %w", addr, err)
	}

	var wg sync.WaitGroup
	if t.Cluster.PushVaultToken {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := pushToken(ctx, o, jump, t, c); err != nil {
				o.debugf("vault token not pushed: %v", err)
			}
		}()
	}

	err = pipe(conn, o.Stdin, o.Stdout)

	// give an in-flight token push a moment to finish
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return err
}

func keepalive(c *ssh.Client) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	fails := 0
	for range t.C {
		if _, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			fails++
			if fails >= 3 {
				c.Close()
				return
			}
			continue
		}
		fails = 0
	}
}

func explainDialError(addr string, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unable to authenticate"):
		return fmt.Errorf("the jump host %s did not accept your certificate - your account may not be allowed on this cluster (%v)", addr, err)
	case errors.Is(err, errHostKey) || strings.Contains(msg, errHostKey.Error()):
		return fmt.Errorf("refusing to connect to %s: %v", addr, err)
	}
	return fmt.Errorf("cannot connect to jump host %s: %w", addr, err)
}

var errHostKey = errors.New("host key verification failed")

type hostKeyChecker struct {
	callback   ssh.HostKeyCallback
	algorithms []string
}

var certAlgos = []string{
	ssh.CertAlgoED25519v01,
	ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01,
	ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01,
}

// hostKeyCallback verifies the jump host. With a host CA it must present a
// certificate for principal; without one (before host certificates are
// rolled out) we fall back to ~/.ssh/known_hosts, trusting a new host on first
// use exactly like `StrictHostKeyChecking accept-new` and refusing changes.
func hostKeyCallback(knownHostsPath, principal string) (*hostKeyChecker, error) {
	cas, err := sshconfig.HostCAKeys(knownHostsPath)
	if err == nil && len(cas) > 0 {
		cc := &ssh.CertChecker{
			IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
				for _, ca := range cas {
					if string(ca.Marshal()) == string(auth.Marshal()) {
						return true
					}
				}
				return false
			},
		}
		return &hostKeyChecker{
			algorithms: certAlgos,
			callback: func(addr string, remote net.Addr, key ssh.PublicKey) error {
				cert, ok := key.(*ssh.Certificate)
				if !ok {
					return fmt.Errorf("%w: %s presented a plain host key, not a certificate from the tvbeat host CA", errHostKey, addr)
				}
				if err := cc.CheckHostKey(principal+":0", remote, cert); err != nil {
					return fmt.Errorf("%w: %v", errHostKey, err)
				}
				return nil
			},
		}, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	khPath := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(khPath); errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(filepath.Dir(khPath), 0o700)
		os.WriteFile(khPath, nil, 0o600)
	}
	kh, err := knownhosts.New(khPath)
	if err != nil {
		return nil, err
	}
	return &hostKeyChecker{
		callback: func(addr string, remote net.Addr, key ssh.PublicKey) error {
			err := kh(addr, remote, key)
			var ke *knownhosts.KeyError
			if errors.As(err, &ke) && len(ke.Want) == 0 {
				line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, key)
				f, ferr := os.OpenFile(khPath, os.O_APPEND|os.O_WRONLY, 0o600)
				if ferr == nil {
					fmt.Fprintln(f, line)
					f.Close()
				}
				return nil
			}
			if errors.As(err, &ke) {
				return fmt.Errorf("%w: the host key of %s has CHANGED - this could be an attack; ask devops before removing it from %s", errHostKey, addr, khPath)
			}
			return err
		},
	}, nil
}
