# tvbeat-auth

Sign in to tvbeat systems. `ssh` into tvbeat servers with short-lived
certificates from vault, and have `vault` just work, on your laptop and on
the servers. You set it up once, then keep using plain `ssh`, `scp`,
`rsync`, `git` and your editor's remote features as usual:

```console
$ ssh scoria.dev0-hetz
[you@scoria:~]$ vault kv get kv/something   # works, no separate login
```

- **Signing in.** A browser tab opens when you need to sign in. On a machine
  without a browser you get a code to approve on your phone instead.
- **How long things last.** Your certificate lasts a day, and your sign-in
  lasts six days. You are only asked again when it runs out.
- **No fingerprint prompts.** tvbeat servers are recognised by certificate,
  so you never see an "authenticity of host can't be established" prompt.

tvbeat-auth was called tvbeat-ssh up to 1.x. See
[Upgrading from tvbeat-ssh 1.x](#upgrading-from-tvbeat-ssh-1x).

## Install

Download the archive for your platform from
[releases](https://github.com/tvbeat/tvbeat-auth/releases), put `tvbeat-auth`
on your `PATH`, then run once:

```console
$ tvbeat-auth setup
```

It signs you in and looks up your linux username from your account. Run it
again after upgrading.

<details><summary>macOS</summary>

```console
% curl -LO https://github.com/tvbeat/tvbeat-auth/releases/latest/download/tvbeat-auth-darwin-arm64.tar.gz   # Intel: darwin-amd64
% tar xf tvbeat-auth-darwin-arm64.tar.gz
% sudo mkdir -p /usr/local/bin && sudo mv tvbeat-auth /usr/local/bin/
% xattr -d com.apple.quarantine /usr/local/bin/tvbeat-auth   # avoids the "cannot be opened" dialog
% tvbeat-auth setup
```
</details>

<details><summary>Linux</summary>

```console
$ curl -LO https://github.com/tvbeat/tvbeat-auth/releases/latest/download/tvbeat-auth-linux-amd64.tar.gz
$ tar xf tvbeat-auth-linux-amd64.tar.gz && sudo mv tvbeat-auth /usr/local/bin/
$ tvbeat-auth setup
```

- **Nix users:** `nix profile install github:tvbeat/tvbeat-auth`.
- **home-manager:** add `programs.ssh.includes = [ "~/.ssh/tvbeat/config" ];`.
  `tvbeat-auth setup` cannot edit a read-only `~/.ssh/config`, and will tell
  you so.
</details>

<details><summary>Windows (PowerShell)</summary>

```powershell
PS> Invoke-WebRequest https://github.com/tvbeat/tvbeat-auth/releases/latest/download/tvbeat-auth-windows-amd64.zip -OutFile tvbeat-auth.zip
PS> New-Item -ItemType Directory -Force "$env:USERPROFILE\bin" | Out-Null
PS> Expand-Archive tvbeat-auth.zip "$env:USERPROFILE\bin" -Force
PS> [Environment]::SetEnvironmentVariable("PATH", [Environment]::GetEnvironmentVariable("PATH", "User") + ";$env:USERPROFILE\bin", "User")
PS> # open a new PowerShell window, then:
PS> tvbeat-auth setup
```

To keep the key in memory rather than in a file, start the OpenSSH agent
once from an administrator PowerShell:
`Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent`.
</details>

### Your linux username

`setup` reads your linux username from your Google Workspace account (the
custom attribute `external.username`, which vault passes along at sign-in).
If it is not filled in yet, `setup` asks once and suggests the part of your
email before the `@`. `tvbeat-auth setup --username <name>` overrides it.

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
| `tvbeat-auth setup [--role all\|devops] [--login auto\|browser\|device] [--browser firefox] [--username x]` | set up `ssh` and sign in; safe to re-run |
| `tvbeat-auth login [--browser\|--device] [--force]` | sign in now, e.g. before running ansible |
| `tvbeat-auth status` | who you are, how long your sign-in and certificate last |
| `tvbeat-auth logout` | revoke your vault token (including any pushed to servers) and drop the certificate |
| `tvbeat-auth vault-login` | sign in to vault and write `~/.vault-token`; works on headless servers |
| `tvbeat-auth version` | print the version |

ssh and vault run the plumbing commands `prepare`, `ssh-proxy`,
`check-host` and `token-helper` themselves.

## Vault on servers

- **On connect.** Connecting to a `dev0-hetz` node puts a vault token in
  `~/.vault-token` there, so `vault` works straight away. The token is a
  child of your own sign-in: it lasts at most 8 hours, and
  `tvbeat-auth logout` revokes it.
- **Long-lived sessions.** Servers set up with the NixOS module (below) run
  every `vault` command through tvbeat-auth as its
  [token helper](https://developer.hashicorp.com/vault/docs/commands/token-helper).
  When the token has run out, say in a tmux session open since Monday, the
  next `vault` command shows a code to approve on your phone, then carries
  on:

  ```console
  [you@scoria:~]$ vault kv get kv/something
  Your vault token has expired.
  To sign in to tvbeat, open this page on any device:

    https://www.google.com/device

  and enter the code:

    WXYZ-ABCD

  Signed in to vault as you@tvbeat.com (valid for 144h0m).

  ====== Data ======
  ...
  ```
- **Your own tokens are left alone.** A token you put in place yourself
  (`vault login ...`) is never replaced by one pushed on connect. A token
  from signing in on the server is not replaced by a shorter-lived pushed
  one either.
- **Signing in by hand.** `tvbeat-auth vault-login` does the same sign-in
  explicitly.

### NixOS module

```nix
{
  inputs.tvbeat-auth.url = "github:tvbeat/tvbeat-auth";

  # in the server's configuration:
  imports = [ inputs.tvbeat-auth.nixosModules.default ];
  programs.tvbeat-auth.enable = true;
  # optional: programs.tvbeat-auth.site = ./site.json;   (default: built in)
}
```

The module installs `tvbeat-auth` and sets `VAULT_CONFIG_PATH` to a file
with `token_helper` pointing at it. Turn that part off with
`programs.tvbeat-auth.vaultTokenHelper = false`.

## Upgrading from tvbeat-ssh 1.x

Install `tvbeat-auth` and run `tvbeat-auth setup`. That retires
`~/.ssh/tvbeat.conf` (kept as `tvbeat.conf.old`) and its `Include` line.
You can then delete the old `tvbeat-ssh` binary.

Until you run `setup`, your 1.x ssh config keeps calling `tvbeat-ssh sign`.
tvbeat-auth answers to that name as well. The Nix package ships a
`tvbeat-ssh` link. With the release archives, either keep your 1.x binary
until you have run `setup`, or link `tvbeat-ssh` to `tvbeat-auth` yourself.

## How it works

- **Setup.** `tvbeat-auth setup` writes `~/.ssh/tvbeat/config` and includes
  it from the top of `~/.ssh/config`. It also writes
  `~/.ssh/tvbeat/known_hosts`, which trusts the host CA public key that vault
  serves at `ssh-host/public_key`.
- **Before each connection.** For tvbeat host names only, ssh runs
  `tvbeat-auth prepare`, a quick local check that you hold a valid
  certificate. When you don't, it signs you in (if needed), creates a fresh
  ed25519 key, and has vault sign it.
  - The key and certificate go into your ssh-agent with an expiry matching
    the certificate. The private key is never written to disk.
  - Without an agent, they are written to `~/.ssh/tvbeat` as files instead.
- **The connection.** `tvbeat-auth ssh-proxy` connects to the cluster's jump
  host on port 443 and checks that it has a certificate from the host CA.
  It then opens a tunnel to the node, and ssh checks the node's certificate
  itself.
- **Parallel connections.** When several ssh commands start at once, a lock
  makes sure only one sign-in happens.

Sign-in happens directly with Google, either in the browser (PKCE, random
localhost port) or with a device code. The ID token is exchanged at vault's
`google` jwt mount. Until that mount is configured, the browser sign-in falls
back to vault's own OIDC flow on the `oidc` mount, which is what 1.x used.

## Development

```console
$ nix develop
$ go test ./...
$ nix flake check -L     # includes a NixOS VM test with vault, dex, a jump host and a node
```

The VM test (`nix/tests/vm.nix`):

- configures a vault dev server the way `deployments/infra/vault/tf`
  configures the real one
- uses Dex in place of Google
- drives the browser and device sign-ins from scripts, including the token
  helper's sign-in inside a tmux session on the node
- runs a 1.x user's old ssh config.
