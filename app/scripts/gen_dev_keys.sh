#!/usr/bin/env sh
# Generate the local signing/JWT key pairs the app needs to start (dev and tests).
# Private keys are git-ignored; never commit them.
set -e
cd "$(dirname "$0")/.."
mkdir -p keys
[ -f keys/signing_key.pem ] || {
  openssl genpkey -algorithm ed25519 -out keys/signing_key.pem
  openssl pkey -in keys/signing_key.pem -pubout -out keys/signing_pub.pem
}
[ -f keys/jwt_ec_key.pem ] || {
  openssl ecparam -name prime256v1 -genkey -noout -out keys/jwt_ec_key.pem
  openssl ec -in keys/jwt_ec_key.pem -pubout -out keys/jwt_ec_pub.pem
}
echo "Dev keys ready in keys/"
