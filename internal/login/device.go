package login

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"

	"github.com/tvbeat/tvbeat-auth/internal/site"
	"github.com/tvbeat/tvbeat-auth/internal/vault"
)

type discovery struct {
	AuthEndpoint   string `json:"authorization_endpoint"`
	DeviceEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint  string `json:"token_endpoint"`
}

type deviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	// Google calls it verification_url
	VerificationURL         string `json:"verification_url"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenResponse struct {
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func scopes(s site.SSO) string {
	if s.Scopes != "" {
		return s.Scopes
	}
	return "openid email profile"
}

// Device runs the OAuth 2.0 device authorization grant (RFC 8628) against the
// identity provider and exchanges the resulting ID token for a vault token.
func (l *Login) Device(ctx context.Context) (*vault.Auth, error) {
	sso := l.Site.SSO
	hc := &http.Client{Timeout: 30 * time.Second}

	disc, err := discover(ctx, hc, sso.Issuer)
	if err != nil {
		return nil, err
	}
	if disc.DeviceEndpoint == "" {
		return nil, fmt.Errorf("%s does not support device sign-in", sso.Issuer)
	}

	form := url.Values{"client_id": {sso.Device.ID}, "scope": {scopes(sso)}}
	if sso.Device.Secret != "" {
		form.Set("client_secret", sso.Device.Secret)
	}
	var dc deviceCode
	if err := postForm(ctx, hc, disc.DeviceEndpoint, form, &dc); err != nil {
		return nil, fmt.Errorf("starting device sign-in: %w", err)
	}
	verify := firstNonEmpty(dc.VerificationURI, dc.VerificationURL)
	if dc.DeviceCode == "" || dc.UserCode == "" || verify == "" {
		return nil, errors.New("identity provider returned an incomplete device code response")
	}

	l.say("To sign in to tvbeat, open this page on any device:\n\n  %s\n\nand enter the code:\n\n  %s\n", verify, dc.UserCode)
	if l.QR {
		l.say("Or scan this with your phone:")
		qrterminal.GenerateWithConfig(firstNonEmpty(dc.VerificationURIComplete, verify), qrterminal.Config{
			Level:          qrterminal.L,
			Writer:         l.Out,
			HalfBlocks:     true,
			BlackChar:      qrterminal.BLACK_BLACK,
			WhiteBlackChar: qrterminal.WHITE_BLACK,
			WhiteChar:      qrterminal.WHITE_WHITE,
			BlackWhiteChar: qrterminal.BLACK_WHITE,
			QuietZone:      1,
		})
	}
	l.say("Waiting for you to approve the sign-in...")

	interval := time.Duration(dc.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	expires := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	if dc.ExpiresIn <= 0 {
		expires = time.Now().Add(10 * time.Minute)
	}

	poll := url.Values{
		"client_id":   {sso.Device.ID},
		"device_code": {dc.DeviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}
	if sso.Device.Secret != "" {
		poll.Set("client_secret", sso.Device.Secret)
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		if time.Now().After(expires) {
			return nil, errors.New("the sign-in code expired before it was approved - please try again")
		}
		var tr tokenResponse
		err := postForm(ctx, hc, disc.TokenEndpoint, poll, &tr)
		switch {
		case tr.Error == "authorization_pending":
			continue
		case tr.Error == "slow_down":
			interval += 5 * time.Second
			continue
		case tr.Error == "access_denied":
			return nil, errors.New("the sign-in was declined")
		case tr.Error == "expired_token":
			return nil, errors.New("the sign-in code expired before it was approved - please try again")
		case tr.Error != "":
			msg := tr.Error
			if tr.ErrorDescription != "" {
				msg += ": " + tr.ErrorDescription
			}
			return nil, fmt.Errorf("device sign-in failed: %s", msg)
		case err != nil:
			return nil, fmt.Errorf("device sign-in failed: %w", err)
		}
		if tr.IDToken == "" {
			return nil, errors.New("identity provider returned no id_token (is the openid scope allowed?)")
		}
		auth, err := l.Vault.JWTLogin(ctx, sso.VaultMount, sso.VaultRole, tr.IDToken)
		if err != nil {
			return nil, fmt.Errorf("vault rejected the sign-in: %w", err)
		}
		return auth, nil
	}
}

func discover(ctx context.Context, hc *http.Client, issuer string) (*discovery, error) {
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the identity provider: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("identity provider discovery %s: %s", u, resp.Status)
	}
	var d discovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return nil, fmt.Errorf("identity provider discovery: %w", err)
	}
	return &d, nil
}

// postForm posts form and decodes the JSON body into out. OAuth errors
// arrive as 4xx with a JSON body; those decode into tokenResponse.Error and
// are left for the caller.
func postForm(ctx context.Context, hc *http.Client, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if jerr := json.Unmarshal(b, out); jerr != nil {
		if resp.StatusCode >= 300 {
			return fmt.Errorf("%s: %s", endpoint, resp.Status)
		}
		return jerr
	}
	if resp.StatusCode >= 300 {
		if te, ok := out.(*tokenResponse); ok && te.Error != "" {
			return nil
		}
		return fmt.Errorf("%s: %s", endpoint, resp.Status)
	}
	return nil
}
