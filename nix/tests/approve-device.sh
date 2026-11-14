#!/usr/bin/env bash
# Approves a device sign-in in Dex, as a person on their phone would.
# usage: approve-device.sh <dex issuer> <user code>   env: FAKE_LOGIN FAKE_PASSWORD
set -euo pipefail
issuer=$1 code=$2
jar=$(mktemp)
trap 'rm -f "$jar"' EXIT
curl -fsS -c "$jar" -b "$jar" -o /dev/null "$issuer/device?user_code=$code"
form=$(curl -fsS -L -c "$jar" -b "$jar" -o /dev/null -w '%{url_effective}' \
  --data-urlencode "user_code=$code" "$issuer/device/auth/verify_code")
curl -fsS -L -c "$jar" -b "$jar" -o /dev/null \
  --data-urlencode "login=$FAKE_LOGIN" --data-urlencode "password=$FAKE_PASSWORD" "$form"
