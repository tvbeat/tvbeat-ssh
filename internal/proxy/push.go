package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/tvbeat/tvbeat-ssh/internal/creds"
	"github.com/tvbeat/tvbeat-ssh/internal/fsutil"
	"github.com/tvbeat/tvbeat-ssh/internal/hosts"
	"github.com/tvbeat/tvbeat-ssh/internal/site"
)

// pushScript installs the token from stdin as ~/.vault-token, unless the
// user put a token of their own there (one we did not push).
const pushScript = `umask 077
set -e
t=$(cat)
d="$HOME/.cache/tvbeat-ssh"
f="$HOME/.vault-token"
m="$d/pushed-token.sha256"
mkdir -p "$d"
if [ -s "$f" ]; then
  if ! [ -f "$m" ] || [ "$(sha256sum < "$f" | cut -d' ' -f1)" != "$(cat "$m")" ]; then
    exit 3
  fi
fi
printf '%s' "$t" > "$f.tmp"
mv "$f.tmp" "$f"
printf '%s' "$t" | sha256sum | cut -d' ' -f1 > "$m"
`

// a push is repeated when the token we pushed has less than this left
const pushRefresh = time.Hour

type pushRecord struct {
	Parent  string    `json:"parent"`
	Expires time.Time `json:"expires"`
	Kept    bool      `json:"kept,omitempty"`
}

func pushStatePath() (string, error) {
	d, err := site.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "pushed.json"), nil
}

func loadPushState() map[string]pushRecord {
	m := map[string]pushRecord{}
	p, err := pushStatePath()
	if err != nil {
		return m
	}
	if b, err := os.ReadFile(p); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

func savePushState(m map[string]pushRecord) {
	p, err := pushStatePath()
	if err != nil {
		return
	}
	now := time.Now()
	for k, v := range m {
		if now.After(v.Expires) {
			delete(m, k)
		}
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	fsutil.WriteFileAtomic(p, b, 0o600)
}

// pushToken copies a short-lived child of the user's vault token to the
// node, so `vault` works there without another sign-in. The child dies with
// the parent, so `tvbeat-ssh logout` revokes every pushed token at once.
func pushToken(ctx context.Context, o *Options, jump *ssh.Client, t hosts.Target, c *creds.Creds) error {
	key := o.User + "@" + t.Node + "." + t.Cluster.Name

	parent := o.Manager.Vault().Token
	if parent == "" {
		parent = creds.StoredToken()
	}
	if parent == "" {
		return errors.New("no vault token of our own to derive from")
	}
	parentID := shortHash(parent)

	state := loadPushState()
	if r, ok := state[key]; ok && r.Parent == parentID && time.Until(r.Expires) > pushRefresh {
		return nil
	}

	v := o.Manager.Vault()
	if v.Token == "" {
		v.Token = parent
	}
	child, err := v.CreateChild(ctx, o.Manager.Settings.Site.PushTokenTTL, "tvbeat-ssh-"+t.Node+"."+t.Cluster.Name)
	if err != nil {
		return err
	}
	expires := time.Now().Add(time.Duration(child.LeaseDuration) * time.Second)

	paths, err := creds.SSHPaths()
	if err != nil {
		return err
	}
	principals := hosts.Principals(t.Cluster, t.Node)
	hkc, err := hostKeyCallback(paths.KnownHosts, principals[0])
	if err != nil {
		return err
	}
	conn, err := jump.Dial("tcp", t.DialAddr(o.Port))
	if err != nil {
		return err
	}
	cc, chans, reqs, err := ssh.NewClientConn(conn, principals[0]+":"+o.Port, &ssh.ClientConfig{
		User:              o.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(c.Signer)},
		HostKeyCallback:   hkc.callback,
		HostKeyAlgorithms: hkc.algorithms,
		Timeout:           15 * time.Second,
	})
	if err != nil {
		conn.Close()
		return err
	}
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(child.ClientToken)
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	err = sess.Run("sh -c '" + strings.ReplaceAll(pushScript, "'", `'\''`) + "'")

	rec := pushRecord{Parent: parentID, Expires: expires}
	var ee *ssh.ExitError
	switch {
	case errors.As(err, &ee) && ee.ExitStatus() == 3:
		// the user has their own ~/.vault-token there; leave it alone and
		// do not ask again for a while
		rec.Kept = true
		rec.Expires = time.Now().Add(2 * pushRefresh)
		revokeQuietly(ctx, o, child.ClientToken)
	case err != nil:
		revokeQuietly(ctx, o, child.ClientToken)
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	state[key] = rec
	savePushState(state)
	o.debugf("pushed a vault token valid until %s to %s", expires.Format(time.RFC3339), key)
	return nil
}

func revokeQuietly(ctx context.Context, o *Options, token string) {
	v := *o.Manager.Vault()
	v.Token = token
	v.RevokeSelf(ctx)
}
