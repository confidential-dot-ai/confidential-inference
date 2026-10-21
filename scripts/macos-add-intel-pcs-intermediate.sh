#!/bin/sh
# Add Sectigo's R46 cross-certificate to the macOS login keychain.
# Intel PCS chains to Sectigo Public Server Authentication Root R46, which
# some macOS versions lack. The cross-certificate is R46 signed by
# "AAA Certificate Services", which macOS trusts. It is added as an
# intermediate certificate; no trust setting changes.
set -eu
FINGERPRINT=CE:75:58:0B:C6:79:6D:3B:3E:A2:C3:E7:42:59:D0:D4:03:07:24:08:E9:60:C7:71:39:C2:FB:5A:3D:94:19:E4
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl --fail --silent --show-error --location -o "$work/r46.p7c" \
  http://crt.sectigo.com/SectigoPublicServerAuthenticationRootR46.p7c
openssl pkcs7 -inform DER -print_certs -in "$work/r46.p7c" |
  awk '/^issuer=.*AAA Certificate Services/ {take=1} take && /BEGIN/ {keep=1} keep {print} keep && /END/ {exit}' \
  > "$work/cross.pem"
if ! openssl x509 -in "$work/cross.pem" -noout -fingerprint -sha256 | grep -q "$FINGERPRINT"; then
  echo "unexpected certificate; nothing added" >&2
  exit 1
fi
if security find-certificate -a -Z ~/Library/Keychains/login.keychain-db |
  grep -q B84733486BA4F61D833FCD3F2C81804989373118; then
  echo "already in the login keychain"
else
  security add-certificates -k ~/Library/Keychains/login.keychain-db "$work/cross.pem"
  echo "added Sectigo R46 (signed by AAA Certificate Services) to the login keychain"
fi
