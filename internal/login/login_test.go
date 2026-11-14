package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tvbeat/tvbeat-ssh/internal/site"
	"github.com/tvbeat/tvbeat-ssh/internal/vault"
)

func fakeJWT(claims map[string]any) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	b, _ := json.Marshal(claims)
	return h + "." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

// idp is a minimal OAuth server: authorization code + PKCE, and device flow.
type idp struct {
	*httptest.Server
	nonce     string
	challenge string
	polls     atomic.Int32
}

func newIDP(t *testing.T) *idp {
	i := &idp{}
	mux := http.NewServeMux()
	i.Server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint":        i.URL + "/auth",
			"token_endpoint":                i.URL + "/token",
			"device_authorization_endpoint": i.URL + "/device/code",
		})
	})
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("client_id") != "dev" || r.Form.Get("client_secret") != "devsecret" {
			http.Error(w, "bad client", 401)
			return
		}
		// google style field name
		json.NewEncoder(w).Encode(map[string]any{
			"device_code": "DC", "user_code": "ABCD-EFGH", "verification_url": "https://example/device",
			"expires_in": 60, "interval": 1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch r.Form.Get("grant_type") {
		case "urn:ietf:params:oauth:grant-type:device_code":
			if i.polls.Add(1) == 1 {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"authorization_pending"}`)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"id_token": fakeJWT(map[string]any{"aud": "dev"})})
		case "authorization_code":
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != i.challenge || r.Form.Get("code") != "CODE" {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"id_token": fakeJWT(map[string]any{"nonce": i.nonce})})
		}
	})
	t.Cleanup(i.Close)
	return i
}

func newVault(t *testing.T, mount string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/"+mount+"/login" {
			http.NotFound(w, r)
			return
		}
		var body struct{ Role, JWT string }
		json.NewDecoder(r.Body).Decode(&body)
		if body.Role != "tvbeat-ssh" || strings.Count(body.JWT, ".") != 2 {
			w.WriteHeader(400)
			io.WriteString(w, `{"errors":["bad login"]}`)
			return
		}
		io.WriteString(w, `{"auth":{"client_token":"hvs.test","lease_duration":3600,"metadata":{"email":"a@b"}}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testSite(i *idp, v *httptest.Server) *site.Site {
	return &site.Site{
		VaultAddr: v.URL,
		SSO: site.SSO{
			Issuer: i.URL, VaultMount: "google", VaultRole: "tvbeat-ssh",
			Browser: site.Client{ID: "desk"},
			Device:  site.Client{ID: "dev", Secret: "devsecret"},
		},
	}
}

func TestDeviceFlow(t *testing.T) {
	i := newIDP(t)
	v := newVault(t, "google")
	var out strings.Builder
	l := &Login{Site: testSite(i, v), Vault: vault.New(v.URL), Out: &out, QR: true}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	auth, err := l.Device(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if auth.ClientToken != "hvs.test" {
		t.Fatalf("token %q", auth.ClientToken)
	}
	if !strings.Contains(out.String(), "ABCD-EFGH") || !strings.Contains(out.String(), "https://example/device") {
		t.Fatalf("code not shown:\n%s", out.String())
	}
	if i.polls.Load() < 2 {
		t.Fatal("did not keep polling while authorization was pending")
	}
}

func TestSSOBrowserFlow(t *testing.T) {
	i := newIDP(t)
	v := newVault(t, "google")
	openBrowser = func(u, _ string) error {
		pu, err := url.Parse(u)
		if err != nil {
			return err
		}
		q := pu.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "desk" {
			t.Errorf("bad auth request %s", u)
		}
		i.nonce, i.challenge = q.Get("nonce"), q.Get("code_challenge")
		go func() {
			// a stale/foreign request must be ignored...
			http.Get(q.Get("redirect_uri") + "?code=X&state=wrong")
			// ...and the real one accepted
			resp, err := http.Get(q.Get("redirect_uri") + "?code=CODE&state=" + url.QueryEscape(q.Get("state")))
			if err == nil {
				b, _ := io.ReadAll(resp.Body)
				if !strings.Contains(string(b), "signed in to tvbeat") {
					t.Errorf("success page: %s", b)
				}
			}
		}()
		return nil
	}
	defer func() { openBrowser = nil }()

	var out strings.Builder
	l := &Login{Site: testSite(i, v), Vault: vault.New(v.URL), Out: &out}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	auth, err := l.Browser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if auth.ClientToken != "hvs.test" {
		t.Fatalf("token %q", auth.ClientToken)
	}
}

func TestCheckNonce(t *testing.T) {
	if err := checkNonce(fakeJWT(map[string]any{"nonce": "n1"}), "n1"); err != nil {
		t.Fatal(err)
	}
	if err := checkNonce(fakeJWT(map[string]any{"nonce": "n1"}), "n2"); err == nil {
		t.Fatal("nonce mismatch accepted")
	}
	if err := checkNonce("garbage", "n"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestChoose(t *testing.T) {
	t.Setenv("TVBEAT_SSH_LOGIN", "")
	t.Setenv("SSH_CONNECTION", "1.2.3.4 1 5.6.7.8 22")
	var out strings.Builder
	s := &site.Site{}
	l := &Login{Site: s, Out: &out}
	if l.Choose(Auto) != Browser {
		t.Error("without a device client the browser must be used")
	}
	if l.Choose(Device) != Browser || !strings.Contains(out.String(), "not set up") {
		t.Error("forcing device without a device client should fall back with a message")
	}
	s.SSO = site.SSO{Issuer: "x", Device: site.Client{ID: "d"}}
	if l.Choose(Auto) != Device {
		t.Error("over ssh the device flow should be chosen")
	}
	t.Setenv("TVBEAT_SSH_LOGIN", "browser")
	if l.Choose(Auto) != Browser {
		t.Error("TVBEAT_SSH_LOGIN not honoured")
	}
}
