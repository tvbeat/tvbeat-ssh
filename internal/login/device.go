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

	"github.com/tvbeat/tvbeat-ssh/internal/vault"
)

// DeviceConfigured reports whether the device flow can be used.
func (l *Login) DeviceConfigured() bool {
	return l.Site.Device.Issuer != "" && l.Site.Device.ClientID != ""
}

type discovery struct {
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

// Device runs the OAuth 2.0 device authorization grant (RFC 8628) against the
// identity provider and exchanges the resulting ID token for a vault token.
func (l *Login) Device(ctx context.Context) (*vault.Auth, error) {
	d := l.Site.Device
	hc := &http.Client{Timeout: 30 * time.Second}

	disc, err := discover(ctx, hc, d.Issuer)
	if err != nil {
		return nil, err
	}
	if disc.DeviceEndpoint == "" {
		return nil, fmt.Errorf("%s does not support device sign-in", d.Issuer)
	}

	scopes := d.Scopes
	if scopes == "" {
		scopes = "openid email profile"
	}
	form := url.Values{"client_id": {d.ClientID}, "scope": {scopes}}
	if d.ClientSecret != "" {
		form.Set("client_secret", d.ClientSecret)
	}
	var dc deviceCode
	if err := postForm(ctx, hc, disc.DeviceEndpoint, form, &dc); err != nil {
		return nil, fmt.Errorf("starting device sign-in: %w", err)
	}
	verify := dc.VerificationURI
	if verify == "" {
		verify = dc.VerificationURL
	}
	if dc.DeviceCode == "" || dc.UserCode == "" || verify == "" {
		return nil, errors.New("identity provider returned an incomplete device code response")
	}

	l.say("To sign in to tvbeat, open this page on any device:\n\n  %s\n\nand enter the code:\n\n  %s\n", verify, dc.UserCode)
	if l.QR {
		qrTarget := dc.VerificationURIComplete
		if qrTarget == "" {
			qrTarget = verify
		}
		l.say("Or scan this with your phone:")
		qrterminal.GenerateWithConfig(qrTarget, qrterminal.Config{
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
		"client_id":   {d.ClientID},
		"device_code": {dc.DeviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}
	if d.ClientSecret != "" {
		poll.Set("client_secret", d.ClientSecret)
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
		auth, err := l.Vault.JWTLogin(ctx, l.Site.AuthMount, d.VaultRole, tr.IDToken)
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
		return nil, fmt.Errorf("cannot reach identity provider: %w", err)
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

// postForm posts form and decodes the JSON body into out. A non-2xx status
// is only an error if the body did not decode (OAuth errors arrive as 400s
// with a JSON body).
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
		// decoded fine; let the caller look at the OAuth error fields
		if te, ok := out.(*tokenResponse); ok && te.Error != "" {
			return nil
		}
		return fmt.Errorf("%s: %s", endpoint, resp.Status)
	}
	return nil
}
