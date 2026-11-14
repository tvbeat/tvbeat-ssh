// Package site holds everything tvbeat-ssh knows about the infrastructure it
// talks to (vault, identity provider, clusters) plus the per-user settings
// written by `tvbeat-ssh config`.
package site

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tvbeat/tvbeat-ssh/internal/fsutil"
)

// Cluster describes one environment reachable through a jump host.
type Cluster struct {
	// Name is the short cluster name users type, e.g. "dev0-hetz".
	Name string `json:"name"`
	// Jump is host:port of the cluster's jump host.
	Jump string `json:"jump"`
	// NodeSuffix is appended to a node name to form the address the jump
	// host dials, e.g. ".node" turns "scoria" into "scoria.node".
	NodeSuffix string `json:"node_suffix"`
	// PushVaultToken copies a short-lived child vault token to nodes in this
	// cluster on connect, so vault works there without a separate login.
	PushVaultToken bool `json:"push_vault_token,omitempty"`
}

// Client is an OAuth client registered with the identity provider. For the
// kinds used here (Google "Desktop app" and "TVs and Limited Input devices")
// the secret is not confidential and ships in the binary, as Google expects.
type Client struct {
	ID     string `json:"id"`
	Secret string `json:"secret,omitempty"`
}

// SSO describes signing in directly with the identity provider and handing
// the resulting ID token to vault (a role_type=jwt login).
//
// Vault refuses JWT logins on a mount that is set up for its own OIDC
// redirect flow (it needs oidc_client_id/secret for that), so this uses a
// separate jwt mount configured only with oidc_discovery_url.
type SSO struct {
	Issuer string `json:"issuer"`
	// Scopes defaults to "openid email profile" (all Google allows for the
	// device flow).
	Scopes     string `json:"scopes,omitempty"`
	VaultMount string `json:"vault_mount"`
	VaultRole  string `json:"vault_role"`
	// Browser is a loopback/PKCE "desktop" client, Device a device-flow one.
	Browser Client `json:"browser"`
	Device  Client `json:"device"`
}

// Site is the organisation-wide configuration.
type Site struct {
	VaultAddr string `json:"vault_addr"`

	// SSO, when its issuer is set, is used for every sign-in.
	SSO SSO `json:"sso"`

	// Otherwise the browser sign-in goes through vault's own OIDC redirect
	// flow (what tvbeat-ssh 1.x and `vault login -method=oidc` use) on this
	// mount and role. It needs a fixed localhost callback port, and there is
	// no device sign-in.
	AuthMount    string `json:"auth_mount"`
	BrowserRole  string `json:"browser_role"`
	CallbackPort int    `json:"callback_port"`

	// UserMount signs user certificates, HostMount signs host certificates.
	UserMount string `json:"user_mount"`
	HostMount string `json:"host_mount"`
	// SSHRoles maps the role names people pass to --role onto vault ssh
	// role names; missing entries map to themselves.
	SSHRoles map[string]string `json:"ssh_roles,omitempty"`
	// PushTokenTTL is the TTL of child tokens pushed to nodes.
	PushTokenTTL string    `json:"push_token_ttl"`
	Clusters     []Cluster `json:"clusters"`
	// URL, when set, is fetched by `config` to refresh this description.
	URL string `json:"url,omitempty"`
}

// SSOConfigured reports whether direct identity provider sign-in is set up.
func (s *Site) SSOConfigured() bool { return s.SSO.Issuer != "" && s.SSO.Browser.ID != "" }

// DeviceConfigured reports whether the device flow can be used.
func (s *Site) DeviceConfigured() bool { return s.SSO.Issuer != "" && s.SSO.Device.ID != "" }

// SSHRole maps a role name to the vault ssh role.
func (s *Site) SSHRole(name string) string {
	if r, ok := s.SSHRoles[name]; ok && r != "" {
		return r
	}
	return name
}

// Default is compiled into the binary; it is what a plain
// `tvbeat-ssh config --username x` uses.
var Default = Site{
	VaultAddr: "https://vault.tvbeat.com",
	SSO: SSO{
		// TODO(aanderse): fill in once the Google OAuth clients and the
		// `google` jwt mount exist (see deployments draft). Until then the
		// browser sign-in uses vault's OIDC flow and there is no device flow.
		Issuer:     "",
		VaultMount: "google",
		VaultRole:  "tvbeat-ssh",
	},
	AuthMount:    "oidc",
	BrowserRole:  "default",
	CallbackPort: 8250,
	UserMount:    "ssh",
	HostMount:    "ssh-host",
	PushTokenTTL: "8h",
	Clusters: []Cluster{
		{Name: "dev0-hetz", Jump: "jump.dev0-hetz.tvbeat.com:443", NodeSuffix: ".node", PushVaultToken: true},
		{Name: "alpha0-hetz", Jump: "jump.alpha0-hetz.tvbeat.com:443", NodeSuffix: ".node"},
		{Name: "stage0-hetz", Jump: "jump.stage0-hetz.tvbeat.com:443", NodeSuffix: ".node"},
		{Name: "prod0-hetz", Jump: "jump.prod0-hetz.tvbeat.com:443", NodeSuffix: ".node"},
	},
}

// Settings are per-user choices plus the site they apply to.
type Settings struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	// Browser is an optional browser to open for the browser flow.
	Browser string `json:"browser,omitempty"`
	// Login forces "browser" or "device"; empty means pick automatically.
	Login string `json:"login,omitempty"`
	Site  Site   `json:"site"`
	// SiteFetched records when Site was last refreshed from Site.URL.
	SiteFetched time.Time `json:"site_fetched,omitempty"`
}

// ErrNotConfigured is returned when `tvbeat-ssh config` has not been run.
var ErrNotConfigured = errors.New("tvbeat-ssh is not configured yet - run `tvbeat-ssh config --username <you>`")

// Dir is where settings, the vault token and lock files live.
func Dir() (string, error) {
	if d := os.Getenv("TVBEAT_SSH_HOME"); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "tvbeat-ssh"), nil
}

func settingsPath() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "settings.json"), nil
}

// Load reads the user's settings.
func Load() (*Settings, error) {
	p, err := settingsPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotConfigured
	}
	if err != nil {
		return nil, err
	}
	var s Settings
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s is corrupt (%v) - re-run `tvbeat-ssh config`", p, err)
	}
	s.Site.fillDefaults()
	return &s, nil
}

// Save writes the user's settings atomically.
func (s *Settings) Save() error {
	p, err := settingsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(p, append(b, '\n'), 0o600)
}

func (s *Site) fillDefaults() {
	d := Default
	if s.VaultAddr == "" {
		s.VaultAddr = d.VaultAddr
	}
	s.VaultAddr = strings.TrimRight(s.VaultAddr, "/")
	if s.AuthMount == "" {
		s.AuthMount = d.AuthMount
	}
	if s.BrowserRole == "" {
		s.BrowserRole = d.BrowserRole
	}
	if s.UserMount == "" {
		s.UserMount = d.UserMount
	}
	if s.HostMount == "" {
		s.HostMount = d.HostMount
	}
	if s.PushTokenTTL == "" {
		s.PushTokenTTL = d.PushTokenTTL
	}
	if s.SSO.VaultMount == "" {
		s.SSO.VaultMount = d.SSO.VaultMount
	}
	if s.SSO.VaultRole == "" {
		s.SSO.VaultRole = d.SSO.VaultRole
	}
	s.SSO.Issuer = strings.TrimRight(s.SSO.Issuer, "/")
}

// LoadFile reads a site description from a local file.
func LoadFile(path string) (*Site, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(b)
}

func parse(b []byte) (*Site, error) {
	var s Site
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("invalid site description: %w", err)
	}
	if len(s.Clusters) == 0 {
		return nil, errors.New("invalid site description: no clusters")
	}
	s.fillDefaults()
	return &s, nil
}

// Fetch downloads a site description from url.
func Fetch(url string) (*Site, error) {
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	s, err := parse(b)
	if err != nil {
		return nil, err
	}
	if s.URL == "" {
		s.URL = url
	}
	return s, nil
}

// Cluster returns the cluster with the given name.
func (s *Site) Cluster(name string) (*Cluster, bool) {
	for i := range s.Clusters {
		if s.Clusters[i].Name == name {
			return &s.Clusters[i], true
		}
	}
	return nil, false
}

// JumpHost returns the jump host name without port.
func (c *Cluster) JumpHost() string {
	h := c.Jump
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return h
}
