#!/usr/bin/env bash
# Create a private RustFS bucket and a user that can only use that bucket.
#
# Requires the RustFS CLI `rc` (https://github.com/rustfs/cli, binaries on its
# GitHub Releases page; or `cargo install rustfs-cli`). Safe to re-run.
#
#   RUSTFS_ENDPOINT=http://localhost:9000 \
#   RUSTFS_ADMIN_ACCESS_KEY=rustfsadmin \
#   RUSTFS_ADMIN_SECRET_KEY=rustfsadmin \
#   BUCKET=auth-bucket \
#   ./scripts/create-rustfs-bucket.sh
#
# Optional: BUCKET_USER (default "<bucket>-app"), BUCKET_PASSWORD (default: random,
# printed once). If the user already exists and BUCKET_PASSWORD is not given, the
# password is left unchanged.
set -euo pipefail

: "${RUSTFS_ENDPOINT:?set RUSTFS_ENDPOINT, e.g. http://localhost:9000}"
: "${RUSTFS_ADMIN_ACCESS_KEY:?set RUSTFS_ADMIN_ACCESS_KEY}"
: "${RUSTFS_ADMIN_SECRET_KEY:?set RUSTFS_ADMIN_SECRET_KEY}"
BUCKET="${BUCKET:-auth-bucket}"
BUCKET_USER="${BUCKET_USER:-${BUCKET}-app}"
POLICY_NAME="${POLICY_NAME:-${BUCKET}-rw}"
ALIAS="${RC_ALIAS:-rustfs-setup}"

command -v rc >/dev/null 2>&1 || {
  echo "rc (RustFS CLI) not found. Get it from https://github.com/rustfs/cli/releases" >&2
  echo "or: cargo install rustfs-cli" >&2
  exit 1
}

WORK="$(mktemp -d)"
cleanup() {
  # Do not leave the admin credentials in rc's alias store.
  rc alias remove "$ALIAS" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

rc alias set "$ALIAS" "$RUSTFS_ENDPOINT" "$RUSTFS_ADMIN_ACCESS_KEY" "$RUSTFS_ADMIN_SECRET_KEY" >/dev/null

echo "==> bucket: $BUCKET"
if rc bucket list "$ALIAS/$BUCKET" >/dev/null 2>&1; then
  echo "    already exists"
else
  rc bucket create "$ALIAS/$BUCKET"
fi

echo "==> policy: $POLICY_NAME"
cat >"$WORK/policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
      "Resource": ["arn:aws:s3:::${BUCKET}"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
      "Resource": ["arn:aws:s3:::${BUCKET}/*"]
    }
  ]
}
EOF
# "create" overwrites a policy of the same name, so re-runs apply changes.
rc admin policy create "$ALIAS" "$POLICY_NAME" "$WORK/policy.json"

echo "==> user: $BUCKET_USER"
GENERATED=0
if [ -z "${BUCKET_PASSWORD:-}" ]; then
  if rc admin user info "$ALIAS" "$BUCKET_USER" >/dev/null 2>&1; then
    echo "    user exists and BUCKET_PASSWORD not given: password unchanged"
  else
    BUCKET_PASSWORD="$(openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-40)"
    GENERATED=1
  fi
fi
if [ -n "${BUCKET_PASSWORD:-}" ]; then
  rc admin user add "$ALIAS" "$BUCKET_USER" "$BUCKET_PASSWORD"
fi

rc admin policy attach "$ALIAS" "$POLICY_NAME" --user "$BUCKET_USER"

echo
echo "Done. Put this in the service's environment:"
echo
echo "S3_ENDPOINT=$RUSTFS_ENDPOINT"
echo "S3_ACCESS_KEY=$BUCKET_USER"
if [ -n "${BUCKET_PASSWORD:-}" ]; then
  echo "S3_SECRET_KEY=$BUCKET_PASSWORD"
  [ "$GENERATED" = 1 ] && echo "# (password was generated; it is not stored anywhere else)"
else
  echo "S3_SECRET_KEY=<unchanged>"
fi
echo "S3_BUCKET=$BUCKET"
