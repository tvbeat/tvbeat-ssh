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

// Device holds the OAuth "TVs and limited input devices" client used for the
// device authorization grant. The resulting ID token is exchanged with vault
// through a role_type=jwt role on the same mount as the browser flow.
type Device struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	VaultRole    string `json:"vault_role"`
	// Scopes defaults to "openid email profile" (all Google allows here).
	Scopes string `json:"scopes,omitempty"`
}

// Site is the organisation-wide configuration.
type Site struct {
	VaultAddr string `json:"vault_addr"`
	// AuthMount is the vault jwt/oidc auth mount path.
	AuthMount string `json:"auth_mount"`
	// BrowserRole is the role_type=oidc role used by the browser flow.
	BrowserRole string `json:"browser_role"`
	// CallbackPort is the localhost port for the browser flow redirect.
	// 0 picks a free port; this needs an IdP client that accepts any
	// loopback port (Google "Desktop app" clients do, "Web" clients do not).
	CallbackPort int    `json:"callback_port"`
	Device       Device `json:"device"`
	// UserMount signs user certificates, HostMount signs host certificates.
	UserMount string `json:"user_mount"`
	HostMount string `json:"host_mount"`
	// PushTokenTTL is the TTL of child tokens pushed to nodes.
	PushTokenTTL string    `json:"push_token_ttl"`
	Clusters     []Cluster `json:"clusters"`
	// URL, when set, is fetched by `config` and `login` to refresh this file.
	URL string `json:"url,omitempty"`
}

// Default is compiled into the binary; it is what a plain
// `tvbeat-ssh config --username x` uses.
var Default = Site{
	VaultAddr:    "https://vault.tvbeat.com",
	AuthMount:    "oidc",
	BrowserRole:  "default",
	CallbackPort: 8250,
	Device: Device{
		Issuer: "https://accounts.google.com",
		// TODO(aanderse): "TVs and Limited Input devices" OAuth client. Until it
		// exists the device flow is unavailable and the browser flow is used.
		ClientID:     "",
		ClientSecret: "",
		VaultRole:    "device",
	},
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
	if s.Device.VaultRole == "" {
		s.Device.VaultRole = d.Device.VaultRole
	}
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
