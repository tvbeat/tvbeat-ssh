package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/pkg/browser"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

const successHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vault Authentication Succeeded</title>
    <style>
      body {
        font-size: 14px;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI",
          "Roboto", "Oxygen", "Ubuntu", "Cantarell", "Fira Sans", "Droid Sans",
          "Helvetica Neue", sans-serif;
      }
      hr {
        border-color: #fdfdfe;
        margin: 24px 0;
      }
      .container {
        display: flex;
        justify-content: center;
        align-items: center;
        height: 70vh;
      }
      #logo {
        display: block;
        fill: #6f7682;
        margin-bottom: 16px;
      }
      .message {
        display: flex;
        min-width: 40vw;
        background: #fafdfa;
        border: 1px solid #c6e9c9;
        margin-bottom: 12px;
        padding: 12px 16px 16px 12px;
        position: relative;
        border-radius: 2px;
        font-size: 14px;
      }
      .message-content {
        margin-left: 4px;
      }
      .message #checkbox {
        fill: #2eb039;
      }
      .message .message-title {
        color: #1e7125;
        font-size: 16px;
        font-weight: 700;
        line-height: 1.25;
      }
      .message .message-body {
        border: 0;
        margin-top: 4px;
      }
      .message p {
        font-size: 12px;
        margin: 0;
        padding: 0;
        color: #17421b;
      }
      a {
        display: block;
        margin: 8px 0;
        color: #1563ff;
        text-decoration: none;
        font-weight: 600;
      }
      a:hover {
        color: black;
      }
      a svg {
        fill: currentcolor;
      }
      .icon {
        align-items: center;
        display: inline-flex;
        justify-content: center;
        height: 21px;
        width: 21px;
        vertical-align: middle;
      }
      h1 {
        font-size: 17.5px;
        font-weight: 700;
        margin-bottom: 0;
      }
      h1 + p {
        margin: 8px 0 16px 0;
      }
    </style>
  </head>
  <body translate="no" >
    <div class="container">
      <div>
        <svg id="logo" width="146" height="51" viewBox="0 0 146 51" xmlns="http://www.w3.org/2000/svg">
          <g id="vault-logo-v" fill-rule="nonzero">
            <path d="M0,0 L25.4070312,51 L51,0 L0,0 Z M28.5,10.5 L31.5,10.5 L31.5,13.5 L28.5,13.5 L28.5,10.5 Z M22.5,22.5 L19.5,22.5 L19.5,19.5 L22.5,19.5 L22.5,22.5 Z M22.5,18 L19.5,18 L19.5,15 L22.5,15 L22.5,18 Z M22.5,13.5 L19.5,13.5 L19.5,10.5 L22.5,10.5 L22.5,13.5 Z M26.991018,27 L24,27 L24,24 L27,24 L26.991018,27 Z M26.991018,22.5 L24,22.5 L24,19.5 L27,19.5 L26.991018,22.5 Z M26.991018,18 L24,18 L24,15 L27,15 L26.991018,18 Z M26.991018,13.5 L24,13.5 L24,10.5 L27,10.5 L26.991018,13.5 Z M28.5,15 L31.5,15 L31.5,18 L28.5089552,18 L28.5,15 Z M28.5,22.5 L28.5,19.5 L31.5,19.5 L31.5,22.4601182 L28.5,22.5 Z"></path>
          </g>
          <path id="vault-logo-name" d="M69.7218638,30.2482468 L63.2587814,8.45301543 L58,8.45301543 L65.9885305,34.6072931 L73.4551971,34.6072931 L81.4437276,8.45301543 L76.1849462,8.45301543 L69.7218638,30.2482468 Z M97.6329749,22.0014025 C97.6329749,17.2103787 95.8265233,15.0897616 89.6845878,15.0897616 C87.5168459,15.0897616 84.8272401,15.4431978 82.9806452,15.9929874 L83.5827957,19.6451613 C85.3089606,19.2917251 87.2358423,19.056101 89.0021505,19.056101 C92.1333333,19.056101 92.7354839,19.802244 92.7354839,21.9228612 L92.7354839,23.9256662 L88.0387097,23.9256662 C84.0645161,23.9256662 82.3383513,25.4179523 82.3383513,29.3057504 C82.3383513,32.6044881 83.8637993,35 87.4365591,35 C89.4035842,35 91.4910394,34.4502104 93.2573477,33.3113604 L93.618638,34.6072931 L97.6329749,34.6072931 L97.6329749,22.0014025 Z M92.7354839,30.2089762 C91.8121864,30.7194951 90.4874552,31.1907433 89.0422939,31.1907433 C87.5168459,31.1907433 87.0752688,30.601683 87.0752688,29.2664797 C87.0752688,27.8134642 87.5168459,27.3814867 89.1225806,27.3814867 L92.7354839,27.3814867 L92.7354839,30.2089762 Z M102.421505,15.4824684 L102.421505,29.345021 C102.421505,32.7615708 103.585663,35 106.837276,35 C109.125448,35 112.216487,34.1753156 114.665233,32.997195 L115.146953,34.6072931 L118.880287,34.6072931 L118.880287,15.4824684 L113.982796,15.4824684 L113.982796,28.7559607 C112.216487,29.6591865 110.088889,30.3660589 108.884588,30.3660589 C107.760573,30.3660589 107.318996,29.85554 107.318996,28.8345021 L107.318996,15.4824684 L102.421505,15.4824684 Z M129.168459,34.6072931 L129.168459,7 L124.270968,7.66760168 L124.270968,34.6072931 L129.168459,34.6072931 Z M144.394265,30.601683 C143.551254,30.8373072 142.6681,30.9943899 141.94552,30.9943899 C140.660932,30.9943899 140.179211,30.3267882 140.179211,29.3057504 L140.179211,19.2917251 L144.875986,19.2917251 L145.197133,15.4824684 L140.179211,15.4824684 L140.179211,10.0631136 L135.28172,10.7307153 L135.28172,15.4824684 L132.351254,15.4824684 L132.351254,19.2917251 L135.28172,19.2917251 L135.28172,29.9340813 C135.28172,33.3506311 137.088172,35 140.660932,35 C141.905376,35 143.912545,34.6858345 144.956272,34.2538569 L144.394265,30.601683 Z"></path>
        </svg>
        <div class="message is-success">
          <svg id="checkbox" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 512 512">
            <path d="M256 32C132.3 32 32 132.3 32 256s100.3 224 224 224 224-100.3 224-224S379.7 32 256 32zm114.9 149.1L231.8 359.6c-1.1 1.1-2.9 3.5-5.1 3.5-2.3 0-3.8-1.6-5.1-2.9-1.3-1.3-78.9-75.9-78.9-75.9l-1.5-1.5c-.6-.9-1.1-2-1.1-3.2 0-1.2.5-2.3 1.1-3.2.4-.4.7-.7 1.1-1.2 7.7-8.1 23.3-24.5 24.3-25.5 1.3-1.3 2.4-3 4.8-3 2.5 0 4.1 2.1 5.3 3.3 1.2 1.2 45 43.3 45 43.3l111.3-143c1-.8 2.2-1.4 3.5-1.4 1.3 0 2.5.5 3.5 1.3l30.6 24.1c.8 1 1.3 2.2 1.3 3.5.1 1.3-.4 2.4-1 3.3z"></path>
        </svg>
          <div class="message-content">
            <div class="message-title">
              Signed in via your OIDC provider (google)
            </div>
            <p class="message-body">
              You can now close this window and start using Vault.
            </p>
          </div>
        </div>
        <hr />
        <h1>Not sure how to get started?</h1>
        <p class="learn">
          Check out beginner and advanced guides on HashiCorp Vault at the HashiCorp Learn site or read more in the official documentation.
        </p>
        <a href="https://learn.hashicorp.com/vault" rel="noreferrer noopener">
         <span class="icon">
            <svg width="16" height="16" viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
              <path d="M8.338 2.255a.79.79 0 0 0-.645 0L.657 5.378c-.363.162-.534.538-.534.875 0 .337.171.713.534.875l1.436.637c-.332.495-.638 1.18-.744 2.106a.887.887 0 0 0-.26 1.559c.02.081.03.215.013.392-.02.205-.074.43-.162.636-.186.431-.45.64-.741.64v.98c.651 0 1.108-.365 1.403-.797l.06.073c.32.372.826.763 1.455.763v-.98c-.215 0-.474-.145-.71-.42-.111-.13-.2-.27-.259-.393a1.014 1.014 0 0 1-.06-.155c-.01-.036-.013-.055-.013-.058h-.022a2.544 2.544 0 0 0 .031-.641.886.886 0 0 0-.006-1.51c.1-.868.398-1.477.699-1.891l.332.147-.023.746v2.228c0 .115.04.22.105.304.124.276.343.5.587.677.297.217.675.396 1.097.54.846.288 1.943.456 3.127.456 1.185 0 2.281-.168 3.128-.456.422-.144.8-.323 1.097-.54.244-.177.462-.401.586-.677a.488.488 0 0 0 .106-.304V8.218l2.455-1.09c.363-.162.534-.538.534-.875 0-.337-.17-.713-.534-.875L8.338 2.255zm-.34 2.955L3.64 7.38l4.375 1.942 6.912-3.069-6.912-3.07-6.912 3.07 1.665.74 4.901-2.44.328.657zM14.307 1H12.5a.5.5 0 1 1 0-1h3a.499.499 0 0 1 .5.65V3.5a.5.5 0 1 1-1 0V1.72l-1.793 1.774a.5.5 0 0 1-.713-.701L14.307 1zm-2.368 7.653v2.383a.436.436 0 0 0-.007.021c-.017.063-.084.178-.282.322-.193.14-.473.28-.836.404-.724.247-1.71.404-2.812.404-1.1 0-2.087-.157-2.811-.404a3.188 3.188 0 0 1-.836-.404c-.198-.144-.265-.26-.282-.322a.437.437 0 0 0-.007-.02V8.983l.01-.338 3.617 1.605a.791.791 0 0 0 .645 0l3.6-1.598z" fill-rule="evenodd"></path>
            </svg>
          </span>
          Get started with Vault
        </a>
        <a href="https://vaultproject.io/docs" rel="noreferrer noopener">
         <span class="icon">
          <svg width="16" height="16" viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
    <path d="M13.307 1H11.5a.5.5 0 1 1 0-1h3a.499.499 0 0 1 .5.65V3.5a.5.5 0 1 1-1 0V1.72l-1.793 1.774a.5.5 0 0 1-.713-.701L13.307 1zM12 14V8a.5.5 0 1 1 1 0v6.5a.5.5 0 0 1-.5.5H.563a.5.5 0 0 1-.5-.5v-13a.5.5 0 0 1 .5-.5H8a.5.5 0 0 1 0 1H1v12h11zM4 6a.5.5 0 0 1 0-1h3a.5.5 0 0 1 0 1H4zm0 2.5a.5.5 0 0 1 0-1h5a.5.5 0 0 1 0 1H4zM4 11a.5.5 0 1 1 0-1h5a.5.5 0 1 1 0 1H4z"/>
  </svg> 
          </span>
          View the official Vault documentation
        </a>
      </div>
    </div>
  </body>
</html>
`

const (
	vaultAddr = "https://vault.tvbeat.com"
)

var (
	//go:embed resources
	res embed.FS
)

// the following resources were invaluable in figuring out how to do this
// https://hvac.readthedocs.io/en/stable/usage/auth_methods/jwt-oidc.html
// https://github.com/hashicorp/vault-plugin-auth-jwt/blob/main/cli.go

func main() {
	app := &cli.App{
		Name:  "tvbeat-ssh",
		Usage: "a small tool to grant you ssh access to tvbeat systems",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "verbose", Value: false, Usage: "print messages useful for debugging"},
		},
		Commands: []*cli.Command{
			{
				Name:  "config",
				Usage: "generate and apply the ssh client configuration required to access tvbeat systems",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "username", Required: true, Usage: "your tvbeat username on google"},
					&cli.StringFlag{Name: "role", Value: "all", Usage: "which vault role to use when logging in"},
				},
				Action: configAction,
			},
			{
				Name:  "sign",
				Usage: "generate and sign a ssh key which can be used to access tvbeat systems via ssh",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "role", Value: "all", Usage: "which vault role to use when logging in"},
				},
				Action: signAction,
			},
		},
	}

	app.Before = func(cCtx *cli.Context) error {
		if !cCtx.Bool("verbose") {
			log.SetOutput(io.Discard)
		}

		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func configAction(cCtx *cli.Context) error {
	// initial setup, ensure all directories required exist
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		panic(err)
	}

	cacheDir := filepath.Join(userCacheDir, "tvbeat")
	if err := os.Mkdir(cacheDir, 0700); err != nil && !os.IsExist(err) {
		panic(err)
	}

	sshDir := filepath.Join(userHomeDir, ".ssh")
	if err := os.Mkdir(sshDir, 0700); err != nil && !os.IsExist(err) {
		panic(err)
	}

	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}

	// generate ssh configuration required to access tvbeat servers over ssh via vault
	data := struct {
		Token        string
		IdentityFile string
		Username     string
		Role         string
		PowerShell   bool
		Suffix       string
	}{
		Token:        filepath.Join(cacheDir, ".vault-token"),
		IdentityFile: filepath.Join(cacheDir, ".ssh", "id_ed25519"),
		Username:     cCtx.String("username"),
		Role:         cCtx.String("role"),
		PowerShell:   runtime.GOOS == "windows",
		Suffix:       suffix,
	}

	// use ~/variable expansion inside ~/.ssh configuration files if possible
	if strings.HasPrefix(cacheDir, userHomeDir) {
		if runtime.GOOS == "windows" {
			data.Token = strings.Replace(data.Token, userHomeDir, "$env:USERPROFILE", 1)
		} else {
			data.Token = strings.Replace(data.Token, userHomeDir, "~", 1)
		}

		data.IdentityFile = strings.Replace(data.IdentityFile, userHomeDir, "~", 1)
	}

	tmpl, err := template.New("tvbeat.conf.tmpl").ParseFS(res, "resources/tvbeat.conf.tmpl")
	if err != nil {
		panic(err)
	}

	tvbeatConfigFile, err := os.Create(filepath.Join(sshDir, "tvbeat.conf"))
	if err != nil {
		panic(err)
	}

	err = tmpl.Execute(tvbeatConfigFile, data)
	if err != nil {
		panic(err)
	}

	err = tvbeatConfigFile.Close()
	if err != nil {
		panic(err)
	}

	// `Include` tvbeat configuration into users ~/.ssh/config file as unobtrusively as possible, if not already there
	sshConfigFile := filepath.Join(sshDir, "config")

	contents, err := os.ReadFile(sshConfigFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		panic(err)
	}

	if !strings.Contains(string(contents), "\nInclude tvbeat.conf\n") {
		file, err := os.CreateTemp(sshDir, "config")
		if err != nil {
			panic(err)
		}

		defer func() {
			if err := os.Remove(file.Name()); err != nil && !os.IsNotExist(err) {
				panic(err)
			}
		}()

		if _, err := file.WriteString(fmt.Sprintf("# tvbeat configuration added by `tvbeat-ssh config` command\nInclude tvbeat.conf\n\n%s", contents)); err != nil {
			panic(err)
		}

		if err := file.Close(); err != nil {
			panic(err)
		}

		if err := os.Rename(file.Name(), filepath.Join(sshConfigFile)); err != nil {
			panic(err)
		}
	}

	fmt.Printf("%s has been successfully generated.", filepath.Join(sshDir, "tvbeat.conf"))

	return nil
}

func signAction(cCtx *cli.Context) error {
	// initial setup, ensure all directories required exist
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		panic(err)
	}

	cacheDir := filepath.Join(userCacheDir, "tvbeat")
	if err := os.Mkdir(cacheDir, 0700); err != nil && !os.IsExist(err) {
		panic(err)
	}

	sshDir := filepath.Join(cacheDir, ".ssh")
	if err := os.Mkdir(sshDir, 0700); err != nil && !os.IsExist(err) {
		panic(err)
	}

	// generate a ssh key to sign and use - source: https://stackoverflow.com/a/77536858
	privateKey := filepath.Join(sshDir, "id_ed25519")

	if _, err := os.Stat(privateKey); err != nil && os.IsNotExist(err) {
		privateKeyFile, err := os.Create(privateKey)
		if err != nil {
			panic(err)
		}

		err = privateKeyFile.Chmod(0600)
		if err != nil {
			panic(err)
		}

		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}

		block, err := ssh.MarshalPrivateKey(crypto.PrivateKey(priv), "generated by tvbeat-ssh utility")
		if err != nil {
			panic(err)
		}

		err = pem.Encode(privateKeyFile, block)
		if err != nil {
			panic(err)
		}

		err = privateKeyFile.Close()
		if err != nil {
			panic(err)
		}

		publicKey, err := ssh.NewPublicKey(pub)
		err = os.WriteFile(privateKey+".pub", []byte("ssh-ed25519 "+base64.StdEncoding.EncodeToString(publicKey.Marshal())), 0600)
		if err != nil {
			panic(err)
		}
	}

	// check ttl of ssh certificate, if it exists... anything that expires in the next hour should be signed again
	signedCert := filepath.Join(sshDir, "id_ed25519-cert.pub")

	if _, err := os.Stat(signedCert); err != nil && !os.IsNotExist(err) {
		contents, err := os.ReadFile(signedCert)
		if err != nil {
			panic(err)
		}

		publicKey, _, _, _, err := ssh.ParseAuthorizedKey(contents)
		if asCertificate, ok := publicKey.(*ssh.Certificate); ok {
			details, err := InspectCertificate(asCertificate)
			if err != nil {
				// maybe something went bad with the certificate? just (soft) delete it and the user can try again
				os.Rename(signedCert, signedCert+time.Now().Format("20060102150405"))

				panic(err)
			}

			cutoff := time.Now().Add(1 * time.Hour)
			if cutoff.After(details.ValidAfter) && cutoff.Before(details.ValidBefore) {
				// the certificate is valid for more than the next hour, no further action is required
				return nil
			}
		}
	}

	// initial vault client setup
	ctx := context.Background()

	client, err := vault.New(
		vault.WithAddress(vaultAddr),
		vault.WithRequestTimeout(90*time.Second),
	)
	if err != nil {
		panic(err)
	}

	// check the ttl on our vault token, if it exists
	var ttl int64 = 0

	vaultToken := filepath.Join(userHomeDir, ".vault-token")

	contents, err := os.ReadFile(vaultToken)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		panic(err)
	}

	client.SetToken(strings.TrimSpace(string(contents)))

	response, err := client.Auth.TokenLookUpSelf(
		ctx,
	)
	if err == nil {
		if number, ok := response.Data["ttl"].(json.Number); ok {
			ttl, _ = number.Int64()
		}
	}

	// if our token expires in the next hour force a login
	if ttl < 3600 {
		type loginResp struct {
			secret string
			err    error
		}

		sigintCh := make(chan os.Signal, 1)
		signal.Notify(sigintCh, os.Interrupt, os.Kill)
		defer signal.Stop(sigintCh)

		response, err := client.Auth.JwtOidcRequestAuthorizationUrl(
			ctx,
			schema.JwtOidcRequestAuthorizationUrlRequest{
				RedirectUri: "http://localhost:8250/oidc/callback",
				Role:        "default",
			},
			vault.WithMountPath("oidc"),
		)
		if err != nil {
			panic(err)
		}

		authUrl := response.Data["auth_url"].(string)

		params, err := url.ParseQuery(authUrl)
		if err != nil {
			panic(err)
		}

		nonce := params.Get("nonce")
		state := params.Get("state")

		doneCh := make(chan error)

		http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			var data string
			var err error

			defer func() {
				w.Write([]byte(data))
				doneCh <- err
			}()

			params, err := url.ParseQuery(req.URL.RawQuery)
			if err != nil {
				panic(err)
			}

			code := params.Get("code")

			response, err := client.Auth.JwtOidcCallback(
				ctx,
				nonce,
				code,
				state,
				vault.WithMountPath("oidc"),
			)
			if err != nil {
				panic(err)
			}

			err = os.WriteFile(vaultToken, []byte(response.Auth.ClientToken), 0600)
			if err != nil {
				log.Printf("could not write vault token to %s: %s", vaultToken, err)
			}

			client.SetToken(response.Auth.ClientToken)

			data = successHTML
			err = nil
		})

		listener, err := net.Listen("tcp", "localhost:8250")
		if err != nil {
			panic(err)
		}
		defer listener.Close()

		go func() {
			err := http.Serve(listener, nil)
			if err != nil && err != http.ErrServerClosed {
				doneCh <- err
			}
		}()

		log.Printf("Complete the login via your OIDC provider. Launching browser to:\n\n%s\n\nWaiting for OIDC authentication to complete...", authUrl)
		browser.OpenURL(authUrl)

		select {
		case err := <-doneCh:
			if err != nil {
				panic(err)
			}
		case <-sigintCh:
			log.Println("interrupted")
			return nil
		case <-time.After(120 * time.Second):
			log.Println("timed out waiting for response")
			return nil
		}

		// place a copy of ~/.vault-token into our application cache directory
		// openssh configuration will make use of this token - copying it into
		// onto the destination server we are logging into if it is in the
		// dev0-hetz cluster
		source, err := os.Open(filepath.Join(userHomeDir, ".vault-token"))
		if err != nil {
			panic(err)
		}
		defer source.Close()

		dest, err := os.Create(filepath.Join(cacheDir, ".vault-token"))
		if err != nil {
			panic(err)
		}
		defer dest.Close()

		_, err = io.Copy(dest, source)
		if err != nil {
			panic(err)
		}
	}

	contents, err = os.ReadFile(privateKey + ".pub")
	if err != nil {
		panic(err)
	}

	response, err = client.Secrets.SshSignCertificate(
		ctx,
		cCtx.String("role"),
		schema.SshSignCertificateRequest{
			PublicKey: string(contents),
		},
		vault.WithMountPath("ssh"),
	)

	if err != nil {
		panic(err)
	}

	signedKey := response.Data["signed_key"].(string)

	err = os.WriteFile(signedCert, []byte(signedKey), 0600)
	if err != nil {
		panic(err)
	}

	return nil
}
