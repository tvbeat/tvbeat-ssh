package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/tvbeat/tvbeat-ssh/internal/creds"
	"github.com/tvbeat/tvbeat-ssh/internal/site"
)

const caKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGinXEo9HjjFC4RD2xBxe4s3WUoEioOw6OUWr3pCfaaa"

func TestKnownHostsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(p, KnownHosts(&site.Default, caKey), 0o644); err != nil {
		t.Fatal(err)
	}
	keys, err := HostCAKeys(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d CA keys, want 1 (deduplicated)", len(keys))
	}
	want, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(caKey))
	if string(keys[0].Marshal()) != string(want.Marshal()) {
		t.Fatal("CA key mismatch")
	}
	b, _ := os.ReadFile(p)
	for _, pat := range []string{"*.dev0-hetz", "[*.dev0-hetz]:*", "dev0-hetz+*", "jump.dev0-hetz.tvbeat.com"} {
		if !strings.Contains(string(b), pat) {
			t.Errorf("known_hosts lacks pattern %s", pat)
		}
	}
}

func TestRender(t *testing.T) {
	paths := creds.Paths{
		AgentCert:  "/home/x/.ssh/tvbeat/agent-cert.pub",
		Key:        "/home/x/.ssh/tvbeat/id_ed25519",
		Cert:       "/home/x/.ssh/tvbeat/id_ed25519-cert.pub",
		KnownHosts: "/home/x/.ssh/tvbeat/known_hosts",
	}
	b, err := Render(&site.Default, "jdoe", "/usr/local/bin/tvbeat-ssh", true, paths)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"Host *.dev0-hetz dev0-hetz+* dev0-hetz jump.dev0-hetz.tvbeat.com",
		"ProxyCommand /usr/local/bin/tvbeat-ssh proxycommand %r %h %p",
		"User jdoe",
		"IdentityFile /home/x/.ssh/tvbeat/agent-cert.pub",
		"IdentitiesOnly yes",
		"StrictHostKeyChecking yes",
		"Match host *.dev0-hetz,dev0-hetz+*,dev0-hetz,jump.dev0-hetz.tvbeat.com,",
		`exec "/usr/local/bin/tvbeat-ssh prepare %h"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("config lacks %q:\n%s", want, s)
		}
	}

	b, _ = Render(&site.Default, "jdoe", "/Users/John Smith/bin/tvbeat-ssh", false, paths)
	s = string(b)
	if !strings.Contains(s, `ProxyCommand "/Users/John Smith/bin/tvbeat-ssh" proxycommand`) ||
		!strings.Contains(s, `exec "'/Users/John Smith/bin/tvbeat-ssh' prepare %h"`) {
		t.Errorf("paths with spaces not quoted:\n%s", s)
	}
	if strings.Contains(s, "StrictHostKeyChecking") {
		t.Error("without a host CA, host key checking must be left alone")
	}
}

func TestEnsureIncludeNewFile(t *testing.T) {
	dir := t.TempDir()
	res, _, err := EnsureInclude(dir)
	if err != nil || res != IncludeAdded {
		t.Fatalf("res=%v err=%v", res, err)
	}
	res, _, err = EnsureInclude(dir)
	if err != nil || res != IncludeAlreadyPresent {
		t.Fatalf("second run: res=%v err=%v", res, err)
	}
}

func TestEnsureIncludePrependsAndMigrates(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	old := "# tvbeat configuration added by `tvbeat-ssh config` command\nInclude tvbeat.conf\n\nHost github.com\n  User git\n"
	os.WriteFile(cfg, []byte(old), 0o640)
	if res, _, err := EnsureInclude(dir); err != nil || res != IncludeAdded {
		t.Fatalf("res=%v err=%v", res, err)
	}
	b, _ := os.ReadFile(cfg)
	s := string(b)
	if strings.Contains(s, "Include tvbeat.conf") {
		t.Error("legacy include not removed")
	}
	if !strings.HasPrefix(s, "# added by `tvbeat-ssh config`") || !strings.Contains(s, IncludeLine+"\n\nHost github.com") {
		t.Errorf("unexpected config:\n%s", s)
	}
	if st, _ := os.Stat(cfg); st.Mode().Perm() != 0o640 {
		t.Errorf("mode changed to %v", st.Mode().Perm())
	}
}

func TestEnsureIncludeKeepsSymlink(t *testing.T) {
	dir := t.TempDir()
	dotfiles := filepath.Join(dir, "dotfiles")
	os.Mkdir(dotfiles, 0o755)
	real := filepath.Join(dotfiles, "ssh_config")
	os.WriteFile(real, []byte("Host *\n  ServerAliveInterval 30\n"), 0o644)
	sshDir := filepath.Join(dir, ".ssh")
	os.Mkdir(sshDir, 0o700)
	os.Symlink(real, filepath.Join(sshDir, "config"))

	res, target, err := EnsureInclude(sshDir)
	if err != nil || res != IncludeAdded || target != real {
		t.Fatalf("res=%v target=%s err=%v", res, target, err)
	}
	if fi, _ := os.Lstat(filepath.Join(sshDir, "config")); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}
	b, _ := os.ReadFile(real)
	if !strings.Contains(string(b), IncludeLine) {
		t.Fatal("include not written through the symlink")
	}
}

func TestEnsureIncludeReadOnlyIsManual(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write anywhere")
	}
	dir := t.TempDir()
	ro := filepath.Join(dir, "store")
	os.Mkdir(ro, 0o755)
	real := filepath.Join(ro, "ssh_config")
	os.WriteFile(real, []byte("Host *\n"), 0o444)
	os.Chmod(ro, 0o555)
	defer os.Chmod(ro, 0o755)
	sshDir := filepath.Join(dir, ".ssh")
	os.Mkdir(sshDir, 0o700)
	os.Symlink(real, filepath.Join(sshDir, "config"))

	res, _, err := EnsureInclude(sshDir)
	if err != nil || res != IncludeManual {
		t.Fatalf("res=%v err=%v", res, err)
	}
	b, _ := os.ReadFile(real)
	if string(b) != "Host *\n" {
		t.Fatal("read-only config was modified")
	}
}
