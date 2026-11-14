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

### Why not a jwt role on the existing `oidc` mount (the agreed plan)

I built the agreed plan first. Against a real vault, it fails:

- **Vault refuses the login.** `vault write auth/oidc/role/device
  role_type=jwt ...` is accepted, but every login on it is refused with
  `error configuring token validator: unsupported config type`. The source
  shows why: `path_config.go` `authType()` returns `OIDCFlow` whenever
  `oidc_discovery_url`, `oidc_client_id` and `oidc_client_secret` are all
  set. `backend.go` `jwtValidator()` has no case for `OIDCFlow`, so no
  role_type=jwt login can work on a mount set up for the browser redirect
  flow. Removing the client id/secret from `oidc` would break the vault UI,
  `vault login -method=oidc` and every 1.x client. So the only way to get a
  device flow without breaking those is a second mount configured with
  `oidc_discovery_url` only.
- **The coordinator's concern holds for the existing roles.** A login on
  `google` creates or uses an entity with an alias on `google`, not on
  `auth_oidc_9d47994e`. So `{{identity.entity.aliases.auth_oidc_9d47994e.metadata.email}}`
  does not resolve for it. I tested the shortcut of listing both templates
  in one role: vault returns HTTP 500 `template ... could not be rendered
  -> alias not found`; it does not drop the unresolved principal. Adding
  the google mount as a second alias of the existing external groups does
  not work either: a group holds exactly one alias, and writing a second
  one *moved* the alias off the `oidc` mount (I verified this, then reset).

How principals and policies stay correct, concretely (deployments draft
`infra/vault/tf`, mirrored in `nix/tests/vault-setup.sh`):

| | 1.x / vault UI (`oidc` mount) | 2.x (`google` mount) |
|---|---|---|
| ssh role | `all`, `devops` (unchanged) | `sso-all`, `sso-devops` (new, identical except the template) |
| email principal template | `{{identity.entity.aliases.auth_oidc_9d47994e.metadata.email}}` | `{{identity.entity.aliases.<google accessor>.metadata.email}}` |
| static principal | `jump` / `devops` | `jump` / `devops` |
| `metadata.email` filled by | role `claim_mappings email=email` | same mapping on role `tvbeat-ssh` |
| group membership | external groups `all@…` etc., alias on `oidc` | external groups `google:all@…` etc., alias on `google`, same policy each (`for_each` in identity.tf) |
| who may sign `sso-all` | n/a | policy `all` gains `ssh/sign/sso-all` |
| who may sign `sso-devops` | n/a | policy `devops` already has `ssh/sign/*` |
| login restricted to | `bound_claims groups=all@tvbeat.com` | the same, plus `hd=tvbeat.com` |

The certificates are identical either way: principals `jump`/`devops` plus
the person's email, the same extensions, the same user CA. No server-side
`authorized_principals` change is needed.

The VM test checks this end to end. An SSO sign-in gets a certificate with
principals `alice@tvbeat.com, jump`. alice is refused `sso-devops`
(`permission denied` → "not allowed to use the \"sso-devops\" ssh role").
bob, in devops@, signs `sso-devops` through the device flow and logs in as
root. mallory, outside all@, is turned away at login. The legacy `oidc`
flow with the old `all` role still signs and logs in.

Cost: each person has two vault entities (one per mount). Nothing here keys
on entity identity apart from these templates. Once 1.x is retired, the old
roles and groups can be removed, or entities merged if anything else ever
needs one identity.
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

## VM test result

**PASSED**: all 16 subtests in `nix build .#checks.x86_64-linux.vm`. The
test script took 344s under TCG emulation, with no KVM on this host.

1. vault and dex come up; vault is configured like production plus the
   new mounts
2. hosts get certificates from the host CA (deploy-time signing)
3. `config` writes the ssh config and a CA-only known_hosts; it is
   idempotent, and `check-host` works
4. the first ssh signs in through the browser, with no host key prompt;
   the certificate is held only in the agent
5. later connections need no sign-in; the new name, the legacy
   `cluster+node.node` name and the jump host itself all work
6. a child vault token is pushed to the node: non-orphan, identity policy
   `all`, TTL 2h in this test
7. parallel ssh from a cold start (6 at once) signs in exactly once; the
   preceding `logout` revoked the pushed child token
8. an expired certificate (120s TTL here) is dropped by the agent and
   replaced without a sign-in
9. an expired or revoked sign-in asks again
10. roles stay separate: an `all` certificate cannot log in as root, and
    alice is refused `sso-devops`
11. device sign-in: bob (devops) gets `sso-devops` and logs in as root
12. mallory, outside all@, is turned away by vault
13. `vault-login` on a headless node uses the device flow and writes a
    working `~/.vault-token`
14. without an ssh-agent the key lives in 0600 files
15. vault's OIDC flow on the existing `oidc` mount with the old `all` role
    still works
16. nothing was ever trusted on first use: users' `~/.ssh/known_hosts`
    stayed empty

One test-harness fix: the vault-login subtest is now started with
`systemd-run` instead of a backgrounded `su - alice -c '... &'`. With the
`su` version, the process never reached Dex on that VM, and I did not pin
down why. The same pattern works for bob on the client.
