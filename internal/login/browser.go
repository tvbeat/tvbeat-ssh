package login

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/tvbeat/tvbeat-ssh/internal/browser"
	"github.com/tvbeat/tvbeat-ssh/internal/vault"
)

// Browser runs the vault OIDC authorization code flow through the user's
// browser and a short-lived listener on localhost.
func (l *Login) Browser(ctx context.Context) (*vault.Auth, error) {
	s := l.Site

	ln, port, err := listen(s.CallbackPort)
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	redirect := "http://localhost:" + strconv.Itoa(port) + "/oidc/callback"
	nonce := randomString()

	authURL, err := l.Vault.OIDCAuthURL(ctx, s.AuthMount, s.BrowserRole, redirect, nonce)
	if err != nil {
		return nil, fmt.Errorf("starting sign-in: %w", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		return nil, fmt.Errorf("vault returned an invalid auth_url: %w", err)
	}
	wantState := u.Query().Get("state")

	type result struct {
		auth *vault.Auth
		err  error
	}
	done := make(chan result, 1)
	finish := func(r result) {
		select {
		case done <- r:
		default:
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			msg := e
			if d := q.Get("error_description"); d != "" {
				msg = d
			}
			page(w, http.StatusUnauthorized, false, "Sign-in was not completed: "+msg)
			finish(result{err: fmt.Errorf("sign-in was not completed: %s", msg)})
			return
		}
		if q.Get("state") != wantState {
			// not ours (a stale tab, or someone else poking the port)
			page(w, http.StatusBadRequest, false, "This sign-in link has expired. Please run your ssh command again.")
			return
		}
		auth, err := l.Vault.OIDCCallback(r.Context(), s.AuthMount, q.Get("state"), q.Get("code"), nonce)
		if err != nil {
			page(w, http.StatusUnauthorized, false, "Vault rejected the sign-in: "+err.Error())
			finish(result{err: fmt.Errorf("vault rejected the sign-in: %w", err)})
			return
		}
		page(w, http.StatusOK, true, "")
		finish(result{auth: auth})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()

	l.say("Opening your browser to sign in to tvbeat...")
	l.say("If it does not open, visit:\n\n  %s\n", authURL)
	if err := browser.Open(authURL, l.BrowserApp); err != nil {
		l.say("(could not open a browser: %v)", err)
	}

	select {
	case r := <-done:
		return r.auth, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func listen(port int) (net.Listener, int, error) {
	// listen on the IPv4 loopback; browsers fall back to it for "localhost"
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, 0, fmt.Errorf("cannot receive the sign-in callback on localhost:%d (%v) - another sign-in (vault login?) is probably in progress; finish or close it and try again", port, err)
	}
	return ln, ln.Addr().(*net.TCPAddr).Port, nil
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
