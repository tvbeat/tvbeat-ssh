# tvbeat-ssh

`ssh` into tvbeat servers with short-lived certificates from vault. You set it
up once, then keep using plain `ssh`, `scp`, `rsync`, `git` and your editor's
remote features as usual:

```console
$ ssh scoria.dev0-hetz
Opening your browser to sign in to tvbeat...
Signed in as you@tvbeat.com.
[you@scoria:~]$
```

When you need to sign in, a browser tab opens. On a machine without a
browser, you get a code to approve on your phone instead. Your certificate
lasts a day. Your sign-in lasts six days, and you are only asked again when
it runs out. tvbeat servers are recognised by certificate, so you never see
an "authenticity of host can't be established" prompt.

## Install

Download the archive for your platform from
[releases](https://github.com/tvbeat/tvbeat-ssh/releases), put `tvbeat-ssh`
on your `PATH`, then run once:

```console
$ tvbeat-ssh config --username <your linux username>
```

That is all. Run it again after upgrading.

<details><summary>macOS</summary>

```console
% curl -LO https://github.com/tvbeat/tvbeat-ssh/releases/latest/download/tvbeat-ssh-darwin-arm64.tar.gz   # Intel: darwin-amd64
% tar xf tvbeat-ssh-darwin-arm64.tar.gz
% sudo mkdir -p /usr/local/bin && sudo mv tvbeat-ssh /usr/local/bin/
% xattr -d com.apple.quarantine /usr/local/bin/tvbeat-ssh   # avoids the "cannot be opened" dialog
% tvbeat-ssh config --username jsmith
```
</details>

<details><summary>Linux</summary>

```console
$ curl -LO https://github.com/tvbeat/tvbeat-ssh/releases/latest/download/tvbeat-ssh-linux-amd64.tar.gz
$ tar xf tvbeat-ssh-linux-amd64.tar.gz && sudo mv tvbeat-ssh /usr/local/bin/
$ tvbeat-ssh config --username jsmith
```

Nix users: `nix profile install github:tvbeat/tvbeat-ssh`. With home-manager,
add `programs.ssh.includes = [ "~/.ssh/tvbeat/config" ];` because
`tvbeat-ssh config` cannot edit a read-only `~/.ssh/config` and will tell you
so.
</details>

<details><summary>Windows (PowerShell)</summary>

```powershell
PS> Invoke-WebRequest https://github.com/tvbeat/tvbeat-ssh/releases/latest/download/tvbeat-ssh-windows-amd64.zip -OutFile tvbeat-ssh.zip
PS> New-Item -ItemType Directory -Force "$env:USERPROFILE\bin" | Out-Null
PS> Expand-Archive tvbeat-ssh.zip "$env:USERPROFILE\bin" -Force
PS> [Environment]::SetEnvironmentVariable("PATH", [Environment]::GetEnvironmentVariable("PATH", "User") + ";$env:USERPROFILE\bin", "User")
PS> # open a new PowerShell window, then:
PS> tvbeat-ssh config --username jsmith
```

For the key to be kept in memory rather than in a file, start the OpenSSH
agent once from an administrator PowerShell:
`Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent`.
</details>

## Host names

| you type | goes to |
|---|---|
| `ssh scoria.dev0-hetz` | node `scoria` via the dev0-hetz jump host |
| `ssh dev0-hetz+scoria.node` | the same (the 1.x spelling still works) |
| `ssh root@scoria.dev0-hetz` | as root, if you configured `--role devops` and are in devops |
| `ssh dev0-hetz` | the jump host itself |

## Commands

| command | does |
|---|---|
| `tvbeat-ssh config --username x [--role all\|devops] [--login auto\|browser\|device] [--browser-app firefox]` | set up `ssh`; safe to re-run |
| `tvbeat-ssh login [--browser\|--device] [--force]` | sign in now, e.g. before running ansible |
| `tvbeat-ssh status` | who you are, how long your sign-in and certificate last |
| `tvbeat-ssh logout` | revoke your vault token (including any pushed to servers) and drop the certificate |
| `tvbeat-ssh vault-login` | sign in to vault and write `~/.vault-token`; works on headless servers |
| `tvbeat-ssh check-host <name>` | exit 0 if `<name>` is a tvbeat host |
| `tvbeat-ssh version` | print the version |

## Vault on servers

On `dev0-hetz` nodes, your first connection leaves a vault token in
`~/.vault-token` on the server, so `vault` works there straight away. That
token is a child of your own sign-in. It lasts at most 8 hours, and
`tvbeat-ssh logout` revokes it. If you put a token of your own in that file,
it is left alone. To sign in on a server yourself, run
`tvbeat-ssh vault-login`. It shows a code to approve on your phone, so no
browser or port forwarding is needed.

## How it works

- `tvbeat-ssh config` writes `~/.ssh/tvbeat/config` and includes it from the
  top of `~/.ssh/config`. It also writes `~/.ssh/tvbeat/known_hosts`, which
  trusts the host CA public key that vault serves at `ssh-host/public_key`.
- For tvbeat host names only, ssh runs `tvbeat-ssh prepare`. This is a quick
  local check that you hold a valid certificate. When you don't, it signs you
  in, creates a fresh ed25519 key, and has vault sign it. The key and
  certificate go into your ssh-agent with an expiry that matches the
  certificate, and the private key is never written to disk. Without an
  agent, they are written to `~/.ssh/tvbeat` as files instead.
- `tvbeat-ssh proxycommand` then connects to the cluster's jump host on port
  443. It checks that the jump host has a certificate from the host CA, then
  opens a tunnel to the node. ssh checks the node's certificate itself.
- If several ssh commands start at once, a lock makes sure only one sign-in
  happens.

Sign-in happens directly with Google: in the browser with PKCE on a random
localhost port, or with a device code. The resulting ID token is exchanged at
vault's `google` jwt mount. Until that is configured, the browser sign-in
falls back to vault's own OIDC flow on the `oidc` mount, which is what 1.x
used.

## Development

```console
$ nix develop
$ go test ./...
$ nix flake check -L     # includes a NixOS VM test with vault, dex, a jump host and a node
```

The VM test (`nix/tests/vm.nix`) configures a vault dev server the way
`deployments/infra/vault/tf` configures the real one. It uses Dex in place of
Google, and drives both the browser and the device sign-in from scripts.
