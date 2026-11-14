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

	"github.com/gofrs/flock"
	"golang.org/x/crypto/ssh"

	"github.com/tvbeat/tvbeat-auth/internal/creds"
	"github.com/tvbeat/tvbeat-auth/internal/fsutil"
	"github.com/tvbeat/tvbeat-auth/internal/hosts"
	"github.com/tvbeat/tvbeat-auth/internal/nodetoken"
	"github.com/tvbeat/tvbeat-auth/internal/site"
)

// pushScript installs the token from stdin as ~/.vault-token, valid until
// the unix time in $1. It writes the meta file internal/nodetoken reads, in
// the same format. It leaves the file alone, and exits non-zero, when:
//   - 3: the token there is the user's own (no matching meta), or
//   - 4: it is one of ours that lasts longer than the new one (e.g. from a
//     sign-in on the server), so replacing it would be a downgrade.
const pushScript = `umask 077
set -e
t=$(cat)
exp=$1
d="$HOME/` + nodetoken.MetaDir + `"
f="$HOME/.vault-token"
m="$d/` + nodetoken.MetaName + `"
mkdir -p "$d"
if [ -s "$f" ]; then
  [ -f "$m" ] || exit 3
  read -r sum oldexp < "$m" || exit 3
  [ "$(tr -d '\n\r\t ' < "$f" | sha256sum | cut -d' ' -f1)" = "$sum" ] || exit 3
  [ "${oldexp:-0}" -gt "$exp" ] && exit 4
fi
printf '%s %s\n' "$(printf '%s' "$t" | sha256sum | cut -d' ' -f1)" "$exp" > "$m.tmp"
mv "$m.tmp" "$m"
printf '%s' "$t" > "$f.tmp"
mv "$f.tmp" "$f"
`

// pushCommand is what runs on the node; the token goes in on stdin.
func pushCommand(expires time.Time) string {
	return "sh -c '" + strings.ReplaceAll(pushScript, "'", `'\''`) + "' tvbeat-auth-push " + fmt.Sprint(expires.Unix())
}

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
// the parent, so `tvbeat-auth logout` revokes every pushed token at once.
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

	// One push per node at a time: parallel ssh would otherwise open a
	// burst of extra connections to the node from the jump host's address.
	// Losing the race just means someone else is pushing.
	if d, err := site.Dir(); err == nil {
		fl := flock.New(filepath.Join(d, "push-"+shortHash(key)+".lock"))
		if ok, err := fl.TryLock(); err != nil || !ok {
			return nil
		}
		defer fl.Unlock()
	}

	state := loadPushState()
	if r, ok := state[key]; ok && r.Parent == parentID && time.Until(r.Expires) > pushRefresh {
		return nil
	}

	v := o.Manager.Vault()
	if v.Token == "" {
		v.Token = parent
	}
	child, err := v.CreateChild(ctx, o.Manager.Settings.Site.PushTokenTTL, "tvbeat-auth-"+t.Node+"."+t.Cluster.Name)
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
	err = sess.Run(pushCommand(expires))

	rec := pushRecord{Parent: parentID, Expires: expires}
	var ee *ssh.ExitError
	switch {
	case errors.As(err, &ee) && (ee.ExitStatus() == 3 || ee.ExitStatus() == 4):
		// 3: the user has their own ~/.vault-token there; 4: a longer-lived
		// one of ours (a sign-in on the server). Leave it alone and do not
		// ask again for a while.
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
