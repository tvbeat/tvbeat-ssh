# tvbeat-auth - status notes

tvbeat-auth is the from-scratch rewrite of tvbeat-ssh, renamed in round 2.
This branch has local commits only; nothing is pushed.

## Round 2: rename, username from the account, vault token helper

- **Rename to `tvbeat-auth`.** The binary, Go module
  (`github.com/tvbeat/tvbeat-auth`), flake package, env vars
  (`TVBEAT_AUTH_*`), config dir (`~/.config/tvbeat-auth`) and agent comment
  all changed.
  - `~/.ssh/tvbeat/` keeps its neutral name.
  - The 2.0 dev names (`config`, `proxycommand`, `~/.config/tvbeat-ssh`)
    never shipped, so there is no migration for them. `config` and
    `proxycommand` remain hidden aliases.
- **Commands.**
  - For people: `setup`, `login`, `status`, `logout`, `vault-login`,
    `version`.
  - Plumbing (hidden from `--help`): `prepare`, `ssh-proxy`, `check-host`,
    `token-helper`.
- **1.x compatibility.**
  - `sign --role R [--browser B]` is accepted under either name. It keeps a
    valid key and certificate at the paths 1.x configs name
    (`<user cache dir>/tvbeat/.ssh/id_ed25519{,-cert.pub}`), in file mode.
  - It never writes the 1.x vault-token copy that 1.x configs scp to
    servers, so that `LocalCommand` becomes a no-op.
  - `tvbeat-ssh config --username U [--role R] [--browser B]` (the
    documented 1.x command) still works: `config` is `setup`, and
    `--browser` takes a value there.
  - The Nix package ships `bin/tvbeat-ssh -> tvbeat-auth`, and the overlay
    keeps `pkgs.tvbeat-ssh` as an alias. That matters because
    `deployments/infra/teams` uses `tvbeat-ssh.overlays.default` and
    `pkgs.tvbeat-ssh`.
  - Release archives contain only `tvbeat-auth`. The README tells 1.x users
    to keep the old binary, or link the name, until they have run `setup`.
  - `setup` retires `~/.ssh/tvbeat.conf` as before.
- **Username without typing.**
  - `setup` takes no required arguments. When the username is not known
    yet, it signs in (reusing a valid token if there is one) and reads
    `meta.username` from `lookup-self`.
  - Vault fills that in through `claim_mappings "/external/username" =
    "username"` (deployments draft `3033d247e`, on both the `oidc` and
    `google` roles).
  - If the attribute is empty it asks once on a terminal, suggesting the
    email's local part. Without a terminal it refuses with a pointer to
    `--username`, rather than guess.
  - Names are validated (`^[a-z_][a-z0-9_.-]{0,31}$`) because they go into
    the ssh config.
  - Re-running `setup` keeps the stored name and does not sign in again.
    `--username` overrides it.
- **Vault token helper.** `token-helper get|store|erase` implements vault's
  token helper protocol over `~/.vault-token`, so tools that read the file
  directly stay in step.
  - **get** prints the token if `lookup-self` says it has more than 30s
    left. If vault is unreachable, it prints the token anyway and lets the
    vault command report the problem. If `VAULT_ADDR` points at a
    different vault, it behaves as a plain token file.
  - **When the token has expired or is missing** and `/dev/tty` opens, it
    runs the device flow on the tty (code plus QR), saves the new token and
    prints it, so the waiting vault command just continues. vault keeps the
    helper's stdout and stderr to itself, so the tty is the only way to
    reach the person.
  - **With no terminal** it prints nothing (plus a one-line stderr hint)
    and exits 0, never a failure. Every vault command, `vault login`
    included, calls `get` first, so a failing helper would lock people out.
  - **`vault login`.** On Linux it skips the prompt when the parent process
    is `vault login` (walks `/proc` up to 3 levels).
  - **Locking.** One sign-in at a time per user (flock); other waiting
    commands pick up the result.
  - **store** (a hand-made `vault login`) writes the token as the user's own
    and removes the meta file. **erase** removes both.
- **One notion of "ours" on the node: `~/.cache/tvbeat-auth/vault-token.meta`**
  holds `<sha256> <expiry>`. It is written in Go by `internal/nodetoken`
  (token helper, `vault-login`) and in sh by the push script, and a unit
  test runs the real script against the Go reader. The push script:
  - writes when the file is empty, or holds one of ours that expires sooner
    than the new token
  - exits 3 for the user's own token (no matching meta)
  - exits 4 for a longer-lived one of ours, such as a token from signing in
    on the server, which is not downgraded to an 8h child.
- **NixOS module** (`nixosModules.default`, `programs.tvbeat-auth`):
  - installs the package
  - optionally writes `site` to `/etc/tvbeat-auth/site.json`
  - by default sets `VAULT_CONFIG_PATH=/etc/vault/tvbeat-auth.hcl` with
    `token_helper` pointing at a store-path wrapper script (vault wants an
    absolute path to a file, with no arguments).
  - Setting `VAULT_CONFIG_PATH` means a user's own `~/.vault` config is not
    read on those servers. It is documented, and
    `vaultTokenHelper = false` turns it off.
- **Site resolution for commands that work without `setup`** (vault-login,
  token helper, the 1.x shim), in order: `--site` /
  `$TVBEAT_AUTH_SITE`, the user's settings,
  `/etc/tvbeat-auth/site.json`, the built-in default.
- **Latent trap fixed.** `Site.SSO.SSHRoles` (default `all -> sso-all`,
  `devops -> sso-devops`) applies automatically once the Google client ids
  are filled in. Before, filling them in without also adding a role
  mapping would have requested the `oidc`-templated `all` role with a
  `google` token, which fails with `alias not found`.
- **Deployments draft.** The google jwt role is renamed `tvbeat-ssh` ->
  `tvbeat-auth` to match the client default (`654a51ad8`, local only).

## Design decisions (and one correction)

- **The device flow cannot use the existing `oidc` mount.** What I told
  Aaron earlier was wrong. Vault's jwt plugin refuses JWT logins on any mount
  that has `oidc_client_id`/`oidc_client_secret`, because that config makes
  it an "OIDC flow" mount. Vault then answers `error configuring token
  validator: unsupported config type` (`backend.go`, `authType()`). I
  confirmed this against a real vault 2.2.1.
  - **Fix:** a new `google` jwt mount, configured with
    `oidc_discovery_url` only.
  - **Browser sign-in moves too.** tvbeat-auth now does both browser sign-in
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
  `sso-all`/`sso-devops` roles templated on the new mount. tvbeat-auth maps
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
| `metadata.email` filled by | role `claim_mappings email=email` | same mapping on role `tvbeat-auth` |
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
  cheap `Match host <ours> exec "tvbeat-auth prepare %h"` makes sure it does.
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
    `~/.cache/tvbeat-auth/vault-token.meta` on the node (token hash and
    expiry) records what tvbeat-auth put there; see "Round 2" below for how
    pushes, the token helper and `vault-login` share it.
- **Reusing existing tokens.** A token from `~/.vault-token` is reused only
  if it has an entity *and* came from the mount we sign in on. Root or
  approle tokens produce `{{...}}` principals, and tokens from the other
  mount produce `alias not found`.


## Verified

- **Unit tests** (`go test -race ./...`):
  - **From round 1:** host name parsing; config rendering and quoting; an
    idempotent `Include` that keeps symlinks intact and leaves read-only
    configs alone; legacy 1.x config migration; agent and file modes; a
    single signing under 8 parallel callers; renewal near expiry; the
    forbidden-role message; refusing a device code non-interactively; PKCE
    browser and device flows against a mock IdP; the nonce check; host key
    verification; pipe half-close.
  - **New in round 2:**
    - the real push script (sh) against `internal/nodetoken` (Go):
      first push, replace, no downgrade, the user's own token, a foreign
      token with stale meta, erase
    - token helper `get` against a fake vault: valid, expired, about to
      expire, missing, foreign `VAULT_ADDR`, vault unreachable, no tty
    - `store`/`erase`, unknown ops ignored
    - username validation and the prompt (suggestion, retry, no-tty
      refusal)
    - site resolution order; SSO role mapping
    - `progName`; `vaultSubcommand`.
- **Cross-compile and vet**: linux, darwin and windows, each on amd64 and
  arm64, with `CGO_ENABLED=0`. CI now sets that for vet as well.
- **NixOS VM test**: see the result at the bottom.

## Not verified

- **macOS and Windows clients were never run**, only cross-compiled. The
  token helper and module are meant for Linux servers.
- **Real Google is untested.** That includes the `external.username`
  custom attribute reaching vault as a claim. The plugin code path is
  `fillCustomSchemas` → `claim_mappings` with a JSON pointer. The VM test
  maps Dex's `name` claim instead, because Dex has no custom attributes.
- **The deployments draft** was never planned or applied, and
  `bin/sign-host-keys` was never run.
- **Release archives contain only `tvbeat-auth`**, no `tvbeat-ssh` copy.
  The README documents the upgrade path.
- **Nix consumers build with their own nixpkgs.** `infra/teams` sets
  `tvbeat-ssh.inputs.nixpkgs.follows`, so it builds this flake with its own
  nixpkgs, and `go.mod` requires Go 1.26. I have not checked that
  `infra/teams`' nixpkgs has it.

## What Aaron needs to provide or apply

1. **Two Google OAuth clients** ("Desktop app" and "TVs and Limited Input
   devices"). Their ids and secrets go in `site.Default.SSO`
   (`internal/site/site.go`), and their ids in the `google.tf` locals.
2. **Fill in `external.username`** in Google Workspace for everyone (CSV
   bulk update from `tvbeat/idm`).
3. **Review and apply the deployments draft**, branch `tvbeat-ssh-2`
   (local commits; the latest is `654a51ad8`).
4. **Sign host keys** with `bin/sign-host-keys` for each cluster, then
   deploy `ssh-host-cert.nix`.
5. **Servers.** In `infra/teams`, which already has the flake input, add
   `tvbeat-ssh.nixosModules.default` and `programs.tvbeat-auth.enable =
   true`. The input name can stay until the repo is renamed. This is not
   drafted yet.
6. **Rename the GitHub repo** to `tvbeat/tvbeat-auth` when convenient.
   GitHub redirects the old URL, so existing flake inputs keep working.
7. **Recommended, and already relevant with 1.x:** exempt the jump hosts
   from sshd's `PerSourcePenalties` on nodes
   (`PerSourcePenaltyExemptList`). Every connection to a node comes from
   its cluster's jump host, so a few failed logins by one person penalise
   that address for everyone (OpenSSH ≥ 9.8 defaults). The VM test shows
   it: the roles subtest's deliberate root-login refusal earns the jump
   host a "failed authentication" penalty on the node.

## Open questions

- Role names: `sso-all`/`sso-devops` exist alongside `all`/`devops` until
  1.x is retired. Then either repoint the old roles or rename them.
- Host certificates last a year and are re-signed by hand. Is that fine, or
  should something alert before they expire?
- `ssh -G <tvbeat host>` runs `prepare`, so it can prompt a sign-in. Is
  that acceptable?
- `VAULT_CONFIG_PATH` on servers overrides users' own `~/.vault`. Does
  anyone rely on one?
- `Site.URL` lets `setup` refresh clusters from a URL. Should it be hosted
  anywhere?

## VM test result

**PASSED**: all 19 subtests of `nix build .#checks.x86_64-linux.vm` on
the final tree, which is also `nix flake check` on the PR branch (the same
derivation). The test script took 408s under TCG emulation (no KVM on this
host).

1. vault and dex come up; vault is configured like production, plus the
   new mounts and the username claim mapping
2. hosts get certificates from the host CA (deploy-time signing)
3. `setup` with no username signs in once and finds `alice` from the
   account; it writes the ssh config and a CA-only known_hosts. Re-running
   it is idempotent and does not sign in again. `check-host` works.
4. carol.jones@ gets `User cjones` from her account (not a guess from her
   email) and lands as `cjones`
5. the first ssh after `setup` needs no further sign-in and shows no host
   key prompt; the certificate is held only in the agent
6. later connections: the new name, the 1.x `cluster+node.node` name and
   the jump host itself all work
7. a child vault token is pushed to the node: non-orphan, identity policy
   `all`, marked as ours in the meta file
8. parallel ssh from a cold start (6 at once) signs in exactly once;
   `logout` revoked the pushed child token. The node logs no sshd penalty
   against the jump host's address.
9. **token helper in a tmux session:**
   - `vault` uses the pushed token
   - the token is revoked; without a terminal, `vault` fails at once
     rather than hanging
   - in the same tmux session, the next `vault token lookup` shows "Your
     vault token has expired." and a device code; the code is approved
     through Dex and the command completes with a token from
     `auth/google/login`
   - the session was never restarted
   - the new token is in `~/.vault-token`, marked as ours, and the next
     connect does not replace it with a shorter-lived pushed token
10. an expired certificate (120s TTL here) is dropped by the agent and
    replaced without a sign-in
11. an expired or revoked sign-in asks again
12. roles stay separate: an `all` certificate cannot log in as root, and
    alice is refused `sso-devops`
13. device sign-in: bob (devops) gets `sso-devops` and logs in as root
14. mallory, outside all@, is turned away by vault
15. `vault-login` on a headless node uses the device flow and finds the
    site in `/etc/tvbeat-auth/site.json` (module)
16. without an ssh-agent the key lives in 0600 files
17. vault's OIDC flow on the existing `oidc` mount with the old `all` role
    still works
18. **1.x upgrade (dave):**
    - dave's verbatim 1.x `~/.ssh/tvbeat.conf` + `~/.ssh/config` connect
      through `tvbeat-ssh sign` (the shim) with one sign-in, and never
      write the 1.x token copy
    - `tvbeat-auth setup` then finds `dave` from the account, retires
      `tvbeat.conf` and its `Include`, and reuses the sign-in
    - the new name works with no second prompt
19. nothing was ever trusted on first use: alice's, bob's and carol's
    `~/.ssh/known_hosts` stayed empty

Harness notes:

- The first run of this round failed in subtest 18 only. The fixture was
  copied from `/etc` with `cp`, so dave's `~/.ssh/config` was read-only,
  and `setup` correctly refused to edit it (exit 3, "add this line
  yourself"). The fixture now uses `install -m 600`.
- As in round 1, the `vault-login` subtest starts through `systemd-run`.

Real bugs the VM test found this round (fixed in "fix races under parallel
ssh"):

- **One parallel session out of six failed to authenticate**, on one run in
  three. Every `prepare` deleted and rewrote `agent-cert.pub`, the
  IdentityFile ssh reads, and a parallel ssh reading it in the gap had no
  key. The file is now only replaced atomically, and new agent keys are
  added before old ones are removed. This was a round-1 bug.
- **Token pushes were cut off before authenticating.** ssh sends its
  ProxyCommand SIGHUP when the session ends, which killed in-flight pushes
  half way through the handshake. The node's sshd then logged
  PerSourcePenalties against the jump host's address. `ssh-proxy` now
  ignores SIGHUP and waits for the push (bounded at 10s). Only one process
  pushes to a node at a time.
