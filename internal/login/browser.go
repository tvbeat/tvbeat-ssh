package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tvbeat/tvbeat-auth/internal/browser"
	"github.com/tvbeat/tvbeat-auth/internal/vault"
)

// Browser signs in through the user's web browser: directly with the
// identity provider when SSO is configured, else through vault's OIDC flow.
func (l *Login) Browser(ctx context.Context) (*vault.Auth, error) {
	if l.Site.SSOConfigured() {
		return l.ssoBrowser(ctx)
	}
	return l.vaultBrowser(ctx)
}

// openBrowser is swapped out in tests.
var openBrowser = browser.Open

// callback is a short-lived localhost listener for an OAuth redirect.
type callback struct {
	ln   net.Listener
	srv  *http.Server
	got  chan url.Values
	path string
}

func listenCallback(port int, path string) (*callback, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("cannot receive the sign-in callback on localhost:%d (%v) - another sign-in (vault login?) is probably in progress; finish or close it and try again", port, err)
	}
	cb := &callback{ln: ln, got: make(chan url.Values, 1), path: path}
	return cb, nil
}

func (cb *callback) port() int { return cb.ln.Addr().(*net.TCPAddr).Port }

// serve hands each request on cb.path to handle, which renders the page.
func (cb *callback) serve(handle func(q url.Values) (ok bool, msg string, done bool)) {
	mux := http.NewServeMux()
	mux.HandleFunc(cb.path, func(w http.ResponseWriter, r *http.Request) {
		ok, msg, done := handle(r.URL.Query())
		status := http.StatusOK
		if !ok {
			status = http.StatusBadRequest
		}
		page(w, status, ok, msg)
		if done {
			select {
			case cb.got <- r.URL.Query():
			default:
			}
		}
	})
	mux.HandleFunc("/", http.NotFound)
	cb.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go cb.srv.Serve(cb.ln)
}

func (cb *callback) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cb.srv.Shutdown(ctx)
}

func (l *Login) open(u string) {
	l.say("Opening your browser to sign in to tvbeat...")
	l.say("If it does not open, visit:\n\n  %s\n", u)
	if err := openBrowser(u, l.BrowserApp); err != nil {
		l.say("(could not open a browser: %v)", err)
	}
}

// ssoBrowser is the OAuth authorization code flow with PKCE against the
// identity provider (RFC 8252 native app: loopback redirect on a random
// port), followed by a vault JWT login with the ID token.
func (l *Login) ssoBrowser(ctx context.Context) (*vault.Auth, error) {
	sso := l.Site.SSO
	hc := &http.Client{Timeout: 30 * time.Second}
	disc, err := discover(ctx, hc, sso.Issuer)
	if err != nil {
		return nil, err
	}
	cb, err := listenCallback(0, "/callback")
	if err != nil {
		return nil, err
	}
	redirect := "http://127.0.0.1:" + strconv.Itoa(cb.port()) + "/callback"

	state, nonce, verifier := randomString(), randomString(), randomString()+randomString()
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {sso.Browser.ID},
		"redirect_uri":          {redirect},
		"scope":                 {scopes(sso)},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	authURL := disc.AuthEndpoint + "?" + q.Encode()

	type result struct {
		auth *vault.Auth
		err  error
	}
	res := make(chan result, 1)
	finish := func(r result) {
		select {
		case res <- r:
		default:
		}
	}
	cb.serve(func(q url.Values) (bool, string, bool) {
		if e := q.Get("error"); e != "" {
			msg := firstNonEmpty(q.Get("error_description"), e)
			finish(result{err: fmt.Errorf("sign-in was not completed: %s", msg)})
			return false, "Sign-in was not completed: " + msg, true
		}
		if q.Get("state") != state {
			return false, "This sign-in link has expired. Please run your ssh command again.", false
		}
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {q.Get("code")},
			"redirect_uri":  {redirect},
			"client_id":     {sso.Browser.ID},
			"code_verifier": {verifier},
		}
		if sso.Browser.Secret != "" {
			form.Set("client_secret", sso.Browser.Secret)
		}
		var tr tokenResponse
		if err := postForm(ctx, hc, disc.TokenEndpoint, form, &tr); err != nil || tr.Error != "" {
			msg := firstNonEmpty(tr.ErrorDescription, tr.Error)
			if err != nil {
				msg = err.Error()
			}
			finish(result{err: fmt.Errorf("sign-in failed: %s", msg)})
			return false, "Sign-in failed: " + msg, true
		}
		if err := checkNonce(tr.IDToken, nonce); err != nil {
			finish(result{err: err})
			return false, err.Error(), true
		}
		auth, err := l.Vault.JWTLogin(ctx, sso.VaultMount, sso.VaultRole, tr.IDToken)
		if err != nil {
			finish(result{err: fmt.Errorf("vault rejected the sign-in: %w", err)})
			return false, "Vault rejected the sign-in: " + err.Error(), true
		}
		finish(result{auth: auth})
		return true, "", true
	})
	defer cb.close()

	l.open(authURL)
	select {
	case r := <-res:
		return r.auth, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// vaultBrowser is vault's own OIDC flow (auth_url + callback), as used by
// `vault login -method=oidc`.
func (l *Login) vaultBrowser(ctx context.Context) (*vault.Auth, error) {
	s := l.Site
	cb, err := listenCallback(s.CallbackPort, "/oidc/callback")
	if err != nil {
		return nil, err
	}
	redirect := "http://localhost:" + strconv.Itoa(cb.port()) + "/oidc/callback"
	clientNonce := randomString()

	authURL, err := l.Vault.OIDCAuthURL(ctx, s.AuthMount, s.BrowserRole, redirect, clientNonce)
	if err != nil {
		cb.ln.Close()
		return nil, fmt.Errorf("starting sign-in: %w", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		cb.ln.Close()
		return nil, fmt.Errorf("vault returned an invalid auth_url: %w", err)
	}
	wantState := u.Query().Get("state")

	type result struct {
		auth *vault.Auth
		err  error
	}
	res := make(chan result, 1)
	finish := func(r result) {
		select {
		case res <- r:
		default:
		}
	}
	cb.serve(func(q url.Values) (bool, string, bool) {
		if e := q.Get("error"); e != "" {
			msg := firstNonEmpty(q.Get("error_description"), e)
			finish(result{err: fmt.Errorf("sign-in was not completed: %s", msg)})
			return false, "Sign-in was not completed: " + msg, true
		}
		if q.Get("state") != wantState {
			return false, "This sign-in link has expired. Please run your ssh command again.", false
		}
		auth, err := l.Vault.OIDCCallback(ctx, s.AuthMount, q.Get("state"), q.Get("code"), clientNonce)
		if err != nil {
			finish(result{err: fmt.Errorf("vault rejected the sign-in: %w", err)})
			return false, "Vault rejected the sign-in: " + err.Error(), true
		}
		finish(result{auth: auth})
		return true, "", true
	})
	defer cb.close()

	l.open(authURL)
	select {
	case r := <-res:
		return r.auth, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// checkNonce makes sure the ID token was minted for this sign-in. Vault
// verifies the signature; this only binds the token to our request.
func checkNonce(idToken, nonce string) error {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return errors.New("identity provider returned a malformed id_token")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("identity provider returned a malformed id_token")
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(b, &claims); err != nil {
		return errors.New("identity provider returned a malformed id_token")
	}
	if claims.Nonce != nonce {
		return errors.New("the id_token does not belong to this sign-in (nonce mismatch)")
	}
	return nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func randomString() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

var pageTmpl = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .OK}}Signed in{{else}}Sign-in failed{{end}} - tvbeat</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
         font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
         background: Canvas; color: CanvasText; }
  .card { max-width: 28rem; padding: 2rem 2.5rem; border-radius: 12px; text-align: center;
          border: 1px solid color-mix(in srgb, CanvasText 15%, transparent); }
  .mark { font-size: 2.5rem; line-height: 1; }
  .ok   { color: #1a7f37; }
  .bad  { color: #cf222e; }
  h1 { font-size: 1.25rem; margin: .75rem 0 .25rem; }
  p  { margin: .25rem 0; opacity: .8; }
</style>
</head>
<body>
<div class="card">
{{if .OK}}
  <div class="mark ok">&#10003;</div>
  <h1>You're signed in to tvbeat</h1>
  <p>Your ssh session is continuing in the terminal.</p>
  <p id="close">You can close this tab.</p>
{{else}}
  <div class="mark bad">&#10007;</div>
  <h1>Sign-in failed</h1>
  <p>{{.Msg}}</p>
{{end}}
</div>
{{if .OK}}<script>setTimeout(function () { window.close(); }, 1500);</script>{{end}}
</body>
</html>
`))

func page(w http.ResponseWriter, status int, ok bool, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	pageTmpl.Execute(w, struct {
		OK  bool
		Msg string
	}{ok, msg})
}
