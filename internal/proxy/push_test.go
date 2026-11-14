package proxy

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tvbeat/tvbeat-auth/internal/nodetoken"
)

// runPush runs the push script the way a node would, with HOME pointing at
// a scratch directory, and returns its exit status.
func runPush(t *testing.T, home, token string, expires time.Time) int {
	t.Helper()
	cmd := exec.Command("sh", "-c", pushCommand(expires))
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdin = strings.NewReader(token)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		t.Fatalf("push: %v: %s", err, out)
	}
	return 0
}

// The push script (sh, on the node) and package nodetoken (Go, the token
// helper on the node) must agree on what is "ours".
func TestPushScriptAndNodeTokenAgree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh and sha256sum")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("needs sha256sum")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	now := time.Now().Truncate(time.Second)

	// empty node: the push lands and is recognised as ours
	if rc := runPush(t, home, "hvs.child1", now.Add(2*time.Hour)); rc != 0 {
		t.Fatalf("first push: rc %d", rc)
	}
	if got := nodetoken.Read(); got != "hvs.child1" {
		t.Fatalf("token file = %q", got)
	}
	exp, ok := nodetoken.Managed("hvs.child1")
	if !ok || !exp.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("Managed = %v %v", exp, ok)
	}
	if st, _ := os.Stat(filepath.Join(home, ".vault-token")); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}

	// a later push replaces an earlier one of ours
	if rc := runPush(t, home, "hvs.child2", now.Add(3*time.Hour)); rc != 0 || nodetoken.Read() != "hvs.child2" {
		t.Fatalf("second push: rc %d, token %q", rc, nodetoken.Read())
	}

	// a sign-in on the server (longer-lived, written by Go) is not downgraded
	if err := nodetoken.WriteManaged("hvs.server", now.Add(144*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rc := runPush(t, home, "hvs.child3", now.Add(2*time.Hour)); rc != 4 || nodetoken.Read() != "hvs.server" {
		t.Fatalf("downgrade: rc %d, token %q", rc, nodetoken.Read())
	}

	// the user's own token (vault login via the helper's store) is never touched
	if err := nodetoken.WriteUser("hvs.mine"); err != nil {
		t.Fatal(err)
	}
	if _, ok := nodetoken.Managed("hvs.mine"); ok {
		t.Fatal("user token reported as managed")
	}
	if rc := runPush(t, home, "hvs.child4", now.Add(200*time.Hour)); rc != 3 || nodetoken.Read() != "hvs.mine" {
		t.Fatalf("user token: rc %d, token %q", rc, nodetoken.Read())
	}

	// ... nor is a token some other tool wrote, even with a stale meta file
	if err := nodetoken.WriteManaged("hvs.old", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(home, ".vault-token"), []byte("hvs.other\n"), 0o600)
	if rc := runPush(t, home, "hvs.child5", now.Add(200*time.Hour)); rc != 3 {
		t.Fatalf("foreign token: rc %d", rc)
	}

	// erase leaves nothing behind
	if err := nodetoken.Erase(); err != nil || nodetoken.Read() != "" {
		t.Fatalf("erase: %v %q", err, nodetoken.Read())
	}
	if rc := runPush(t, home, "hvs.child6", now.Add(time.Hour)); rc != 0 {
		t.Fatalf("after erase: rc %d", rc)
	}
}
