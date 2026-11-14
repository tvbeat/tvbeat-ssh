// Package nodetoken manages ~/.vault-token on a server: the file the vault
// CLI (through `tvbeat-auth token-helper`) and other tools read.
//
// A token tvbeat-auth put there - pushed from a laptop on connect, or from a
// sign-in on the server - is "managed": a small meta file next to it records
// the token's hash and expiry. A token without matching meta is the user's
// own (e.g. from `vault login`) and is never replaced while it still works.
//
// The push script in internal/proxy writes the same meta format from sh, so
// keep the two in step: "<sha256 hex of the token> <expiry unix seconds>\n".
package nodetoken

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tvbeat/tvbeat-auth/internal/fsutil"
)

// MetaDir is relative to $HOME, not os.UserCacheDir: the push script runs
// as plain sh on the server and has to find the same place.
const MetaDir = ".cache/tvbeat-auth"

// MetaName is the meta file's name inside MetaDir.
const MetaName = "vault-token.meta"

func home() (string, error) { return os.UserHomeDir() }

// Path is the vault CLI's token file.
func Path() (string, error) {
	h, err := home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".vault-token"), nil
}

// Dir holds the meta file and the helper's lock.
func Dir() (string, error) {
	h, err := home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, MetaDir), nil
}

func metaPath() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, MetaName), nil
}

// Hash is how the meta file identifies a token.
func Hash(token string) string {
	s := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(s[:])
}

// Read returns the token in ~/.vault-token ("" if none).
func Read() string {
	p, err := Path()
	if err != nil {
		return ""
	}
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}

// Managed reports whether token is one tvbeat-auth put in place, and until
// when it was issued.
func Managed(token string) (time.Time, bool) {
	p, err := metaPath()
	if err != nil || token == "" {
		return time.Time{}, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return time.Time{}, false
	}
	f := strings.Fields(string(b))
	if len(f) != 2 || f[0] != Hash(token) {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

// WriteManaged installs a token tvbeat-auth obtained, valid until expires.
func WriteManaged(token string, expires time.Time) error {
	p, err := Path()
	if err != nil {
		return err
	}
	mp, err := metaPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(mp), 0o700); err != nil {
		return err
	}
	token = strings.TrimSpace(token)
	// meta first: a reader that sees the new token also sees it as ours
	if err := fsutil.WriteFileAtomic(mp, []byte(fmt.Sprintf("%s %d\n", Hash(token), expires.Unix())), 0o600); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(p, []byte(token), 0o600)
}

// WriteUser installs a token the user chose (`vault login` through the token
// helper). It is theirs from now on: pushes will not replace it.
func WriteUser(token string) error {
	p, err := Path()
	if err != nil {
		return err
	}
	if mp, err := metaPath(); err == nil {
		os.Remove(mp)
	}
	return fsutil.WriteFileAtomic(p, []byte(strings.TrimSpace(token)), 0o600)
}

// Erase removes the token (`vault logout`-style erase from the CLI).
func Erase() error {
	p, err := Path()
	if err != nil {
		return err
	}
	if mp, err := metaPath(); err == nil {
		os.Remove(mp)
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
