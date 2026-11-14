#!/usr/bin/env bash
# Stands in for a person at a browser: follows the sign-in URL through Dex's
# password form and lets the final redirect hit tvbeat-ssh's localhost
# callback. env: FAKE_LOGIN FAKE_PASSWORD [FAKE_BROWSER_LOG]
set -euo pipefail
url=$1
log=${FAKE_BROWSER_LOG:-/dev/null}
echo "$(date +%s) $url" >> "$log"
jar=$(mktemp)
trap 'rm -f "$jar"' EXIT
# auth url -> dex login form
form=$(curl -fsS -L -c "$jar" -b "$jar" -o /dev/null -w '%{url_effective}' "$url")
# submit credentials; dex redirects to the localhost callback
curl -fsS -L -c "$jar" -b "$jar" -o "${FAKE_BROWSER_PAGE:-/dev/null}" \
  --data-urlencode "login=$FAKE_LOGIN" --data-urlencode "password=$FAKE_PASSWORD" "$form"
echo "$(date +%s) done" >> "$log"
