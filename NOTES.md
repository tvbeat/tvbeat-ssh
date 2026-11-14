# tvbeat-ssh 2 - status notes

Branch `rewrite`, built from scratch. Nothing has been pushed anywhere.

## Design decisions (and one correction)

- **The device flow cannot use the existing `oidc` mount.** What I told
  Aaron earlier was wrong. Vault's jwt plugin refuses JWT logins on any mount
  that has `oidc_client_id`/`oidc_client_secret`, because that config makes
  it an "OIDC flow" mount. Vault then answers `error configuring token
  validator: unsupported config type` (`backend.go`, `authType()`). I
  confirmed this against a real vault 2.2.1.
  - **Fix:** a new `google` jwt mount, configured with
    `oidc_discovery_url` only.
  - **Browser sign-in moves too.** tvbeat-ssh now does both browser sign-in
    (PKCE, random loopback port, so the port 8250 clash is gone) and device
    sign-in directly with Google. Both log in to that mount with the ID
    token.
  - **Fallback.** Vault's own OIDC flow on `oidc` remains the fallback, so
    the binary works against today's vault unchanged.
- **A second mount means a second identity.** An external group can have
  only one alias, so the new mount needs its own `google:*` groups (same
  policies). The ssh roles template the email principal from one mount's
  identity alias. When that alias is missing, vault fails the request with
  `alias not found`; it does not skip it. So there are new
  `sso-all`/`sso-devops` roles templated on the new mount. tvbeat-ssh maps
  `--role all` to `sso-all` through the site config (`ssh_roles`).
  `all`/`devops` keep working for 1.x.
- **Jump hop is in-process** (x/crypto/ssh), not `ssh -W`:
  - it does not re-enter the user's ssh config or our own ProxyCommand
  - we verify the jump host's certificate ourselves
  - Windows needs no shell quoting
  - the same connection pushes the vault token.

  The cost: user ssh_config settings for the jump hop are not applied.
- **When credentials are prepared.** ssh loads identity files before it
  runs the ProxyCommand (`ssh.c`: `load_public_identity_files` comes before
  `ssh_connect`). So a fresh certificate has to exist before that, and a
  cheap `Match host <ours> exec "tvbeat-ssh prepare %h"` makes sure it does.
  - It runs only for our host names (the `host` criterion short-circuits
    `exec`).
  - It costs one local ssh-agent query when the certificate is valid (an
    ssh round trip takes about 80ms locally).
  - Ordinary hosts are matched by plain `Host` patterns, with no exec at
    all.
  - `check-host` still exists for scripts.
- **Picking the agent certificate.** With `IdentitiesOnly`, ssh only uses
  agent keys that match an IdentityFile. A `CertificateFile` paired with a
  missing private key does *not* match the certificate held in the agent;
  I verified this with `ssh -vv`. So agent mode writes the certificate to
  `agent-cert.pub` and names that as the IdentityFile. File mode uses
  `id_ed25519` + `id_ed25519-cert.pub`.
- **Host certificate principals cover every spelling**, since ssh checks the
  principal against the name as typed:
  - nodes: `<node>.<cluster>` and `<cluster>+<node>.node`
  - jump hosts: `jump.<cluster>.tvbeat.com` and `<cluster>`

  A dev0 certificate is therefore useless for prod names.
- **Token push.**
  - What is pushed: a child of the user's token (TTL 8h, explicit max TTL,
    not renewable). It inherits the entity, so it gets the identity
    policies too, and it dies when the parent is revoked or `logout` runs.
  - When: at most once per node per 7h.
  - It never overwrites a `~/.vault-token` the user put there themselves.
    A sha256 marker in `~/.cache/tvbeat-ssh` records what we pushed.
- **Reusing existing tokens.** A token from `~/.vault-token` is reused only
  if it has an entity *and* came from the mount we sign in on. Root or
  approle tokens produce `{{...}}` principals, and tokens from the other
  mount produce `alias not found`.

## Verified

- **Unit tests** (`go test ./...`, also `-race` in CI): host name parsing,
  config rendering and quoting, idempotent `Include` that keeps symlinks
  intact and leaves read-only configs alone, legacy 1.x config migration,
  agent and file modes, a single signing under 8 parallel callers, renewal
  near expiry, forbidden role message, refusal to use a device code
  non-interactively, PKCE browser flow and device flow against a mock IdP,
  nonce check, host key verification (CA, wrong principal, wrong CA, plain
  key, TOFU fallback refusing changed keys), pipe half-close.
- **Cross-compile and vet**: linux, darwin and windows, each on amd64 and
  arm64.
- **NixOS VM test** (`nix flake check`; `nix/tests/vm.nix`): vault dev
  configured like `infra/vault/tf` plus the new mounts, Dex standing in for
  Google, a jump host on 443 and a node. Each holds a host certificate from
  the host CA and trusts the user CA. Users get an empty `known_hosts`, and
  every ssh runs with `BatchMode=yes`. RESULT: see bottom.
- **Local runs** against vault/dex/sshd processes: browser flow (both SSO and
  vault OIDC), device flow, 8 parallel cold-start ssh producing one sign-in,
  legacy names, the jump host directly.

## Not verified

- **macOS and Windows clients were never run.** Only cross-compiled, plus
  unit tests in the CI workflow, which has not run yet. The Windows risks,
  in order:
  - whether Win32-OpenSSH runs `ProxyCommand tvbeat-ssh.exe ...` /
    `Match exec` the way we expect (1.x relied on both, so probably)
  - the named-pipe agent
  - ACL warnings on the fallback key file.
- **Real Google is untested.** Not tested: the Desktop/TV clients, Google's
  `verification_url` field name (handled, unit tested only), the `hd` claim
  binding, and gsuite group fetch on a jwt-type mount (the code path exists
  in `path_login.go`, untested).
- The deployments draft has only been through `tofu validate`. It was never
  planned or applied. `bin/sign-host-keys` was never run: I assumed
  `teraflops ssh` passes stdin through.
- Behaviour behind ansible, VS Code Remote and similar tools: a browser
  sign-in works with hidden stderr, while a device code refuses and says to
  run `tvbeat-ssh login`.

## What Aaron needs to provide or apply

1. Two Google OAuth clients in the vault's Google Cloud project:
   - "Desktop app" for browser sign-in
   - "TVs and Limited Input devices" for device sign-in

   Their ids and (non-confidential) secrets go into `site.Default.SSO` in
   `internal/site/site.go`. The ids also go into `google.tf` locals.
2. Review and apply the `deployments-draft` branch `tvbeat-ssh-2` (local
   commits only). It adds the `ssh-host` mount/CA/role, the `google` jwt
   mount and role, the `google:*` groups, the `sso-*` ssh roles, and policy
   additions.
3. Run `bin/sign-host-keys <cluster> --jump <jumpnode> <nodes...>` per
   cluster, then deploy `ssh-host-cert.nix` (wired into the dev0-hetz jump
   host only so far). Users only get `StrictHostKeyChecking yes` once
   `ssh-host/public_key` exists when they run `tvbeat-ssh config`. Before
   that, the config leaves host key checking alone.
4. Install `tvbeat-ssh` on dev0-hetz nodes so `tvbeat-ssh vault-login`
   works there.

## Open questions

- Role names: `sso-all`/`sso-devops` exist alongside `all`/`devops` until
  1.x is retired. Then either repoint the old roles at the google mount or
  rename. Which?
- Host certificates last 1 year and are re-signed by hand. Is that fine, or
  do you want a reminder or a check (e.g. an alert 30 days before expiry)?
- Should the jump hosts' own users keep `nologin` shells? `ssh dev0-hetz`
  to the jump host works only for accounts with a shell, which matches
  today.
- Site description hosting: `Site.URL` lets `config` refresh clusters from
  a URL, so new clusters don't need a release. Where should it live, if
  anywhere?
- `ssh -G <tvbeat host>` triggers `prepare`, so it can prompt a sign-in.
  Acceptable?
- Side effect during local testing: a `push_vault_token` run against a
  local sshd created an empty `~/.cache/tvbeat-ssh` in the bot's real home
  directory. I removed it. It did not touch the existing
  `~/.vault-token`: the "not ours, keep it" path worked as designed. Local
  push testing was disabled after that, and push is only exercised in the
  VMs.
