// Package vault is a deliberately tiny client for the handful of vault
// endpoints tvbeat-auth uses.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to one vault server.
type Client struct {
	Addr  string
	Token string
	HTTP  *http.Client
}

// New returns a client for addr.
func New(addr string) *Client {
	return &Client{
		Addr: strings.TrimRight(addr, "/"),
		HTTP: &http.Client{Timeout: 30 * time.Second},
	}
}

// Error is a vault API error.
type Error struct {
	Status int
	Errors []string
	Path   string
}

func (e *Error) Error() string {
	msg := strings.Join(e.Errors, "; ")
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("vault %s: %s", e.Path, msg)
}

// IsPermissionDenied reports whether err is a vault 403.
func IsPermissionDenied(err error) bool {
	var ve *Error
	return errors.As(err, &ve) && ve.Status == http.StatusForbidden
}

// Secret is the generic vault response envelope.
type Secret struct {
	Data     map[string]any `json:"data"`
	Auth     *Auth          `json:"auth"`
	Warnings []string       `json:"warnings"`
}

// Auth is the auth block of a login response.
type Auth struct {
	ClientToken   string            `json:"client_token"`
	Accessor      string            `json:"accessor"`
	Policies      []string          `json:"policies"`
	LeaseDuration int               `json:"lease_duration"`
	EntityID      string            `json:"entity_id"`
	Metadata      map[string]string `json:"metadata"`
}

// Do performs a request against /v1/path; body may be nil.
func (c *Client) Do(ctx context.Context, method, path string, body any) (*Secret, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Addr+"/v1/"+strings.TrimLeft(path, "/"), rd)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("X-Vault-Token", c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach vault at %s: %w", c.Addr, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		ve := &Error{Status: resp.StatusCode, Path: path}
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(raw, &e)
		ve.Errors = e.Errors
		return nil, ve
	}
	if resp.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(raw)) == 0 {
		return &Secret{}, nil
	}
	var s Secret
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("vault %s: unexpected response: %w", path, err)
	}
	return &s, nil
}

// Raw performs an unauthenticated GET and returns the body, for endpoints
// such as ssh/public_key that do not return JSON.
func (c *Client) Raw(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Addr+"/v1/"+strings.TrimLeft(path, "/"), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach vault at %s: %w", c.Addr, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &Error{Status: resp.StatusCode, Path: path}
	}
	return b, nil
}

// TokenInfo is the subset of auth/token/lookup-self we care about.
type TokenInfo struct {
	TTL         time.Duration
	DisplayName string
	Policies    []string
	EntityID    string
	Accessor    string
	Meta        map[string]string
	// Path is the login path that created the token, e.g. auth/google/login
	Path string
}

// LookupSelf validates the client's token.
func (c *Client) LookupSelf(ctx context.Context) (*TokenInfo, error) {
	s, err := c.Do(ctx, http.MethodGet, "auth/token/lookup-self", nil)
	if err != nil {
		return nil, err
	}
	ti := &TokenInfo{}
	if n, ok := s.Data["ttl"].(json.Number); ok {
		v, _ := n.Int64()
		ti.TTL = time.Duration(v) * time.Second
	}
	ti.DisplayName, _ = s.Data["display_name"].(string)
	ti.EntityID, _ = s.Data["entity_id"].(string)
	ti.Accessor, _ = s.Data["accessor"].(string)
	ti.Path, _ = s.Data["path"].(string)
	if ps, ok := s.Data["policies"].([]any); ok {
		for _, p := range ps {
			if ps, ok := p.(string); ok {
				ti.Policies = append(ti.Policies, ps)
			}
		}
	}
	if m, ok := s.Data["meta"].(map[string]any); ok {
		ti.Meta = map[string]string{}
		for k, v := range m {
			if vs, ok := v.(string); ok {
				ti.Meta[k] = vs
			}
		}
	}
	return ti, nil
}

// RevokeSelf revokes the client's token and all its children.
func (c *Client) RevokeSelf(ctx context.Context) error {
	_, err := c.Do(ctx, http.MethodPost, "auth/token/revoke-self", nil)
	return err
}

// CreateChild creates a child token of the client's token.
func (c *Client) CreateChild(ctx context.Context, ttl, displayName string) (*Auth, error) {
	s, err := c.Do(ctx, http.MethodPost, "auth/token/create", map[string]any{
		"ttl":               ttl,
		"explicit_max_ttl":  ttl,
		"display_name":      displayName,
		"renewable":         false,
		"no_default_policy": false,
	})
	if err != nil {
		return nil, err
	}
	if s.Auth == nil {
		return nil, errors.New("vault returned no token")
	}
	return s.Auth, nil
}

// SignUserKey asks mount/sign/role to sign an ssh public key.
func (c *Client) SignUserKey(ctx context.Context, mount, role, publicKey string) (string, error) {
	s, err := c.Do(ctx, http.MethodPost, mount+"/sign/"+role, map[string]any{
		"public_key": publicKey,
		"cert_type":  "user",
	})
	if err != nil {
		return "", err
	}
	signed, _ := s.Data["signed_key"].(string)
	if signed == "" {
		return "", errors.New("vault returned no signed key")
	}
	return signed, nil
}

// PublicKey returns the CA public key of an ssh secrets mount.
func (c *Client) PublicKey(ctx context.Context, mount string) (string, error) {
	b, err := c.Raw(ctx, mount+"/public_key")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// OIDCAuthURL starts the browser flow.
func (c *Client) OIDCAuthURL(ctx context.Context, mount, role, redirect, clientNonce string) (string, error) {
	s, err := c.Do(ctx, http.MethodPost, "auth/"+mount+"/oidc/auth_url", map[string]any{
		"role":         role,
		"redirect_uri": redirect,
		"client_nonce": clientNonce,
	})
	if err != nil {
		return "", err
	}
	u, _ := s.Data["auth_url"].(string)
	if u == "" {
		return "", errors.New("vault returned an empty auth_url - is the redirect URI allowed for this role?")
	}
	return u, nil
}

// OIDCCallback completes the browser flow.
func (c *Client) OIDCCallback(ctx context.Context, mount, state, code, clientNonce string) (*Auth, error) {
	q := "auth/" + mount + "/oidc/callback?state=" + urlq(state) + "&code=" + urlq(code) + "&client_nonce=" + urlq(clientNonce)
	s, err := c.Do(ctx, http.MethodGet, q, nil)
	if err != nil {
		return nil, err
	}
	if s.Auth == nil {
		return nil, errors.New("vault returned no token")
	}
	return s.Auth, nil
}

// JWTLogin exchanges an ID token for a vault token.
func (c *Client) JWTLogin(ctx context.Context, mount, role, jwt string) (*Auth, error) {
	s, err := c.Do(ctx, http.MethodPost, "auth/"+mount+"/login", map[string]any{
		"role": role,
		"jwt":  jwt,
	})
	if err != nil {
		return nil, err
	}
	if s.Auth == nil {
		return nil, errors.New("vault returned no token")
	}
	return s.Auth, nil
}
