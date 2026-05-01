#!/usr/bin/env bash
set -euo pipefail

# Fetch the k3s service-account public key from a node over SSH and update
# openid/v1/jwks with a single RS256 JWK.
#
# Usage:
#   ./scripts/update-jwks-from-node.sh --ssh-target node101@node101
#   ./scripts/update-jwks-from-node.sh --ssh-target ubuntu@10.0.0.5 \
#     --key-path /var/lib/rancher/k3s/server/tls/service.key.pub
#
# Notes:
# - If the public key path is absent, the script falls back to the k3s
#   private service-account keys and derives the public key from them.
# - kid is read from a live Kubernetes service-account token so Azure can
#   match the token header to the JWKS entry. If that fails, the script falls
#   back to an RFC7638 JWK thumbprint for {"e","kty","n"}.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_FILE="$REPO_ROOT/openid/v1/jwks"

SSH_TARGET=""
KEY_PATH="/var/lib/rancher/k3s/server/tls/service.key.pub"

usage() {
  cat <<EOF
Usage: $0 --ssh-target <user@host> [--key-path <remote-path>] [--out <jwks-file>]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-target)
      SSH_TARGET="${2:-}"
      shift 2
      ;;
    --key-path)
      KEY_PATH="${2:-}"
      shift 2
      ;;
    --out)
      OUT_FILE="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$SSH_TARGET" ]]; then
  echo "ERROR: --ssh-target is required" >&2
  usage
  exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
  echo "ERROR: ssh not found" >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl not found" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
pub_pem="$tmp_dir/service.pub"

ssh -o BatchMode=yes "$SSH_TARGET" "set -euo pipefail
if sudo test -f '$KEY_PATH'; then
  sudo cat '$KEY_PATH'
elif sudo test -f /var/lib/rancher/k3s/server/tls/service.current.key; then
  sudo openssl rsa -in /var/lib/rancher/k3s/server/tls/service.current.key -pubout 2>/dev/null
elif sudo test -f /var/lib/rancher/k3s/server/tls/service.key; then
  sudo openssl rsa -in /var/lib/rancher/k3s/server/tls/service.key -pubout 2>/dev/null
else
  echo 'ERROR: no k3s service-account signing key found' >&2
  exit 1
fi" > "$pub_pem"

token_kid="$(
ssh -o BatchMode=yes "$SSH_TARGET" "set -euo pipefail
if command -v kubectl >/dev/null 2>&1; then
  token=\$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml \
    -n default create token default \
    --audience api://AzureADTokenExchange \
    --duration 10m 2>/dev/null || true)
  if [ -n \"\$token\" ]; then
    python3 - \"\$token\" <<'PY' 2>/dev/null || true
import base64
import json
import sys

header = sys.argv[1].split('.', 1)[0]
header += '=' * (-len(header) % 4)
print(json.loads(base64.urlsafe_b64decode(header.encode('ascii')))['kid'])
PY
  fi
fi" | tail -n 1
)"

mod_hex="$(openssl rsa -pubin -in "$pub_pem" -noout -modulus | sed 's/^Modulus=//')"
exp_dec="$(openssl rsa -pubin -in "$pub_pem" -text -noout | awk '/Exponent: /{print $2; exit}')"

if [[ -z "$mod_hex" || -z "$exp_dec" ]]; then
  echo "ERROR: failed to extract modulus/exponent from remote public key" >&2
  exit 1
fi

jwks_json="$(
python3 - "$mod_hex" "$exp_dec" "$token_kid" <<'PY'
import base64
import hashlib
import json
import sys

mod_hex = sys.argv[1].strip()
exp_dec = int(sys.argv[2].strip())
token_kid = sys.argv[3].strip()

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

n_bytes = bytes.fromhex(mod_hex)
e_bytes = exp_dec.to_bytes((exp_dec.bit_length() + 7) // 8, "big")

n = b64url(n_bytes)
e = b64url(e_bytes)

thumbprint_obj = {"e": e, "kty": "RSA", "n": n}
thumbprint_json = json.dumps(thumbprint_obj, separators=(",", ":"), sort_keys=True)
kid = token_kid or b64url(hashlib.sha256(thumbprint_json.encode("utf-8")).digest())

jwk = {
    "use": "sig",
    "kty": "RSA",
    "kid": kid,
    "alg": "RS256",
    "n": n,
    "e": e,
}
print(json.dumps({"keys": [jwk]}, separators=(",", ":")))
PY
)"

mkdir -p "$(dirname "$OUT_FILE")"
printf '%s\n' "$jwks_json" > "$OUT_FILE"

echo "Updated JWKS: $OUT_FILE"
echo "kid: $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["keys"][0]["kid"])' "$OUT_FILE")"