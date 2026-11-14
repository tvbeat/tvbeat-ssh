#!/usr/bin/env bash
# Configure a (dev) vault the way deployments/infra/vault/tf configures the
# real one, plus the additions this rewrite needs (ssh-host CA, device role).
#
# env: VAULT_ADDR VAULT_TOKEN ISSUER BROWSER_CLIENT_ID BROWSER_CLIENT_SECRET
#      DESKTOP_CLIENT_ID DEVICE_CLIENT_ID [CERT_TTL] [TOKEN_TTL] [EMAIL_DOMAIN]
set -euo pipefail

CERT_TTL=${CERT_TTL:-86400}
TOKEN_TTL=${TOKEN_TTL:-518400}
EMAIL_DOMAIN=${EMAIL_DOMAIN:-tvbeat.com}
REDIRECT=${REDIRECT:-http://localhost:8250/oidc/callback}

v() { vault "$@"; }

# --- auth: oidc mount (browser flow, as today) ------------------------------
v auth enable -path=oidc oidc
v write auth/oidc/config \
  oidc_discovery_url="$ISSUER" \
  oidc_client_id="$BROWSER_CLIENT_ID" \
  oidc_client_secret="$BROWSER_CLIENT_SECRET" \
  default_role=default
ACCESSOR=$(v auth list -format=json | jq -r '."oidc/".accessor')

v write auth/oidc/role/default - <<JSON
{
  "role_type": "oidc",
  "bound_audiences": ["$BROWSER_CLIENT_ID"],
  "user_claim": "sub",
  "groups_claim": "groups",
  "oidc_scopes": ["profile", "email", "openid", "groups"],
  "allowed_redirect_uris": ["$REDIRECT"],
  "token_policies": ["default"],
  "token_ttl": $TOKEN_TTL,
  "token_max_ttl": $TOKEN_TTL,
  "bound_claims": {"groups": "all@$EMAIL_DOMAIN"},
  "claim_mappings": {"email": "email"}
}
JSON

# --- auth: google jwt mount (new) ---------------------------------------------
# vault refuses JWT logins on a mount configured for its OIDC redirect flow,
# so tvbeat-ssh 2 signs in with the IdP itself and logs in here with the ID
# token. Configured with oidc_discovery_url only (no client id/secret).
v auth enable -path=google jwt
v write auth/google/config oidc_discovery_url="$ISSUER"
GACCESSOR=$(v auth list -format=json | jq -r '."google/".accessor')
v write auth/google/role/tvbeat-ssh - <<JSON
{
  "role_type": "jwt",
  "bound_audiences": ["$DESKTOP_CLIENT_ID", "$DEVICE_CLIENT_ID"],
  "user_claim": "sub",
  "groups_claim": "groups",
  "token_policies": ["default"],
  "token_ttl": $TOKEN_TTL,
  "token_max_ttl": $TOKEN_TTL,
  "bound_claims": {"groups": "all@$EMAIL_DOMAIN"},
  "claim_mappings": {"email": "email"}
}
JSON

# --- policies & identity groups (identity.tf / policies.tf) ------------------
v policy write all - <<'HCL'
path "cubbyhole/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "ssh/sign/all" { capabilities = ["create", "update"] }
path "ssh/sign/sso-all" { capabilities = ["create", "update"] }
path "auth/token/create" { capabilities = ["update"] }
HCL
v policy write devops - <<'HCL'
path "ssh/sign/*" { capabilities = ["create", "update"] }
HCL

# an external group has exactly one alias, so each mount gets its own set of
# groups carrying the same policies
for g in all devops; do
  gid=$(v write -format=json identity/group name="$g@$EMAIL_DOMAIN" type=external policies="$g" | jq -r .data.id)
  v write identity/group-alias name="$g@$EMAIL_DOMAIN" mount_accessor="$ACCESSOR" canonical_id="$gid" >/dev/null
  gid=$(v write -format=json identity/group name="google:$g@$EMAIL_DOMAIN" type=external policies="$g" | jq -r .data.id)
  v write identity/group-alias name="$g@$EMAIL_DOMAIN" mount_accessor="$GACCESSOR" canonical_id="$gid" >/dev/null
done

# --- ssh user CA (ssh.tf) ----------------------------------------------------
# all/devops: as today, principal from the oidc mount identity (1.x clients)
# sso-all/sso-devops: same, from the google mount identity (2.x clients)
v secrets enable -path=ssh ssh
v write ssh/config/ca generate_signing_key=true >/dev/null
for role in all devops sso-all sso-devops; do
  principal=jump acc=$ACCESSOR
  case $role in *devops) principal=devops ;; esac
  case $role in sso-*) acc=$GACCESSOR ;; esac
  v write ssh/roles/$role - <<JSON
{
  "key_type": "ca",
  "allow_user_certificates": true,
  "allowed_extensions": "permit-agent-forwarding,permit-port-forwarding,permit-pty",
  "default_extensions": {"permit-agent-forwarding": "", "permit-port-forwarding": "", "permit-pty": ""},
  "allowed_users": "$principal,{{identity.entity.aliases.$acc.metadata.email}}",
  "allowed_users_template": true,
  "default_user": "$principal,{{identity.entity.aliases.$acc.metadata.email}}",
  "default_user_template": true,
  "ttl": $CERT_TTL
}
JSON
done

# --- ssh host CA (new) -------------------------------------------------------
v secrets enable -path=ssh-host ssh
v write ssh-host/config/ca generate_signing_key=true >/dev/null
v write ssh-host/roles/hosts - <<'JSON'
{
  "key_type": "ca",
  "allow_host_certificates": true,
  "allow_user_certificates": false,
  "allowed_domains": "*",
  "allow_bare_domains": true,
  "allow_subdomains": true,
  "ttl": "8760h",
  "max_ttl": "8760h"
}
JSON

echo "vault configured (oidc accessor $ACCESSOR, google accessor $GACCESSOR)"
