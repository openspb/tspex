#!/usr/bin/env bash
# Rebuilds test/fixtures/openssl: requests, responses and tokens made by the
# `openssl ts` tool (3.x) against a throwaway CA and two throwaway TSA
# certificates (RSA and EC). Only the outputs are kept: every key is created
# in a temporary directory and deleted at the end, so nothing secret is in
# the repository. Run: OPENSSL=/path/to/openssl bash test/support/gen_fixtures.sh
set -euo pipefail
O=${OPENSSL:-openssl}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/../fixtures/openssl
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
mkdir -p "$OUT"
cd "$W"
printf 'hello\n' > hello.txt

# --- a CA and the TSA certificates (extendedKeyUsage critical, timeStamping)
$O genrsa -out ca.key 2048 2>/dev/null
$O req -x509 -new -key ca.key -sha256 -days 7300 -subj "/C=BR/O=tspex tests/CN=tspex test CA" \
  -addext "basicConstraints=critical,CA:true" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out ca.pem

cat > tsa.ext <<CNF
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF

$O genrsa -out tsa_rsa.key 2048 2>/dev/null
$O ecparam -name prime256v1 -genkey -noout -out tsa_ec.key
for kind in rsa ec; do
  $O req -new -key tsa_$kind.key -subj "/C=BR/O=tspex tests/CN=tspex test TSA $kind" -out tsa_$kind.csr
  $O x509 -req -in tsa_$kind.csr -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 \
    -extfile tsa.ext -days 7300 -out tsa_$kind.pem 2>/dev/null
  cat > ts_$kind.cnf <<CNF
[ tsa ]
default_tsa = t
[ t ]
serial = $W/serial_$kind
crypto_device = builtin
signer_cert = $W/tsa_$kind.pem
certs = $W/tsa_$kind.pem
signer_key = $W/tsa_$kind.key
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.5.6, 1.2.3.4.5.7
digests = sha1, sha224, sha256, sha384, sha512
accuracy = secs:1, millisecs:500, microsecs:100
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
CNF
  echo 01 > serial_$kind
done

# --- certificates and the data, in DER
$O x509 -in ca.pem -outform DER -out "$OUT/ca.der"
$O x509 -in tsa_rsa.pem -outform DER -out "$OUT/tsa_rsa.der"
$O x509 -in tsa_ec.pem -outform DER -out "$OUT/tsa_ec.der"
cp hello.txt "$OUT/hello.txt"

# --- requests: name, options
rm -f "$OUT"/*.tsq "$OUT"/*.tsr "$OUT"/*.tst
query() { # name, options...
  local name=$1; shift
  $O ts -query -data hello.txt "$@" -out "$OUT/$name.tsq"
}
query q_sha256 -sha256 -cert
query q_no_nonce -sha256 -no_nonce -cert
query q_policy -sha256 -no_nonce -cert -tspolicy 1.2.3.4.5.6
query q_no_cert -sha256 -no_nonce
query q_sha224 -sha224 -cert
query q_sha384 -sha384 -cert
query q_sha512 -sha512 -cert
query q_sha1 -sha1 -cert
query q_policy_unknown -sha256 -cert -tspolicy 1.9.9
# an MD5 request: the TSA refuses the algorithm
$O ts -query -data hello.txt -md5 -cert -out "$OUT/q_md5.tsq" 2>/dev/null || true

# --- responses and tokens
reply() { # name, kind, query
  $O ts -reply -config ts_$2.cnf -queryfile "$OUT/$3.tsq" -out "$OUT/$1.tsr"
}
token() {
  $O ts -reply -config ts_$2.cnf -queryfile "$OUT/$3.tsq" -out "$OUT/$1.tst" -token_out
}
reply r_rsa rsa q_sha256
token r_rsa rsa q_sha256
reply r_ec ec q_sha256
token r_ec ec q_sha256
reply r_rsa_no_nonce rsa q_no_nonce
reply r_rsa_policy rsa q_policy
reply r_rsa_no_cert rsa q_no_cert
reply r_rsa_sha224 rsa q_sha224
reply r_rsa_sha384 rsa q_sha384
reply r_rsa_sha512 rsa q_sha512
reply r_rsa_sha1 rsa q_sha1
reply r_policy_reject rsa q_policy_unknown
[ -s "$OUT/q_md5.tsq" ] && reply r_alg_reject rsa q_md5

# --- what the tool says about its own output (for the readme of the tests)
$O ts -verify -queryfile "$OUT/q_sha256.tsq" -in "$OUT/r_rsa.tsr" -CAfile ca.pem >/dev/null
$O ts -verify -queryfile "$OUT/q_sha256.tsq" -in "$OUT/r_ec.tsr" -CAfile ca.pem >/dev/null
echo "fixtures written to $OUT"
