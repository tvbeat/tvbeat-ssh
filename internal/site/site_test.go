package site

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSSHRole(t *testing.T) {
	s := Default
	// today: vault's OIDC flow on the `oidc` mount, the existing roles
	if got := s.SSHRole("all"); got != "all" {
		t.Fatalf("no SSO: %q", got)
	}
	// once the Google clients are filled in, the sso-* roles follow
	s.SSO.Issuer = "https://accounts.google.com"
	s.SSO.Browser.ID = "x.apps.googleusercontent.com"
	if got := s.SSHRole("all"); got != "sso-all" {
		t.Fatalf("SSO: %q", got)
	}
	if got := s.SSHRole("devops"); got != "sso-devops" {
		t.Fatalf("SSO devops: %q", got)
	}
	if got := s.SSHRole("custom"); got != "custom" {
		t.Fatalf("unmapped: %q", got)
	}
}

func TestResolve(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TVBEAT_AUTH_HOME", filepath.Join(dir, "cfg"))
	t.Setenv("TVBEAT_AUTH_SITE", "")

	// nothing anywhere: the built-in site (SystemFile does not exist in tests)
	if _, err := os.Stat(SystemFile); err == nil {
		t.Skip(SystemFile + " exists on this machine")
	}
	s, err := Resolve("")
	if err != nil || s.Site.VaultAddr != Default.VaultAddr || s.Role != "all" {
		t.Fatalf("default: %+v %v", s, err)
	}

	// an explicit file wins over everything
	f := filepath.Join(dir, "site.json")
	os.WriteFile(f, []byte(`{"vault_addr":"http://v:8200/","clusters":[{"name":"c","jump":"j:443"}]}`), 0o600)
	s, err = Resolve(f)
	if err != nil || s.Site.VaultAddr != "http://v:8200" {
		t.Fatalf("file: %+v %v", s, err)
	}
	// ... and so does the environment
	t.Setenv("TVBEAT_AUTH_SITE", f)
	if s, err = Resolve(""); err != nil || s.Site.VaultAddr != "http://v:8200" {
		t.Fatalf("env: %+v %v", s, err)
	}
	t.Setenv("TVBEAT_AUTH_SITE", "")

	// the user's settings come next
	saved := &Settings{Username: "aka", Role: "devops", Site: Site{VaultAddr: "http://mine", Clusters: []Cluster{{Name: "x", Jump: "j:1"}}}}
	if err := saved.Save(); err != nil {
		t.Fatal(err)
	}
	s, err = Resolve("")
	if err != nil || s.Site.VaultAddr != "http://mine" || s.Username != "aka" || s.Role != "devops" {
		t.Fatalf("settings: %+v %v", s, err)
	}

	// a broken explicit file is an error, not a silent fallback
	if _, err := Resolve(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing file accepted")
	}
}
