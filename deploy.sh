#!/usr/bin/env bash
# Deploys Bannaa to your AWS account. Run from AWS CloudShell (or any shell with AWS CLI v2 + python3 + openssl).
#   bash deploy.sh                 deploy or update everything (asks only for what it doesn't know yet)
#   bash deploy.sh --import        also imports the data exported from the claude.ai version (seed/)
#   bash deploy.sh --web-only      re-upload the web files only
set -euo pipefail
cd "$(dirname "$0")"
STACK="${STACK:-bannaa}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-central-1}}"
export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
ART="bannaa-artifacts-${ACCOUNT}-${REGION}"
out(){ aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
prev(){ aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Parameters[?ParameterKey=='$1'].ParameterValue" --output text 2>/dev/null | sed 's/^None$//' || true; }
secret_get(){ aws secretsmanager get-secret-value --secret-id "$1" --query SecretString --output text 2>/dev/null || true; }
pw_ok(){ [[ ${#1} -ge 8 && "$1" =~ [0-9] && "$1" =~ [a-z] ]]; }

echo "== Bannaa → AWS account $ACCOUNT, region $REGION, stack $STACK"

if [[ "${1:-}" != "--web-only" ]]; then
  OWNER_EMAIL="${OWNER_EMAIL:-$(prev OwnerEmail)}";   [[ -n "$OWNER_EMAIL" ]] || read -rp "Owner email (full access): " OWNER_EMAIL
  SENDER_EMAIL="${SENDER_EMAIL:-$(prev SenderEmail)}"; [[ -n "$SENDER_EMAIL" ]] || read -rp "Sender email for system mails (SES): " SENDER_EMAIL
  if [[ -z "${DOMAIN+x}" ]]; then DOMAIN="$(prev DomainName)"
    if ! aws cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1; then read -rp "Custom domain, e.g. bannaa.alrasiyat.com (Enter = none): " DOMAIN; fi; fi
  ZONE=""
  if [[ -n "$DOMAIN" ]]; then
    z="$DOMAIN"
    while [[ "$z" == *.* ]]; do
      id="$(aws route53 list-hosted-zones-by-name --dns-name "$z" --max-items 1 --query "HostedZones[?Name=='${z}.'].Id | [0]" --output text 2>/dev/null || true)"
      if [[ -n "$id" && "$id" != "None" ]]; then ZONE="${id##*/}"; break; fi; z="${z#*.}"
    done
    [[ -n "$ZONE" ]] || { echo "!! No Route 53 hosted zone found for $DOMAIN in this account. Create it (or set DOMAIN= to skip) and run again."; exit 1; }
    echo "   domain $DOMAIN → hosted zone $ZONE"
  fi

  # --- secrets ---
  if [[ -z "$(secret_get bannaa/anthropic)" ]]; then
    read -rsp "Anthropic API key (sk-ant-...; Enter to skip AI): " KEY; echo
    aws secretsmanager create-secret --name bannaa/anthropic --secret-string "${KEY:-none}" >/dev/null; fi
  ORIGIN_SECRET="$(secret_get bannaa/origin-secret)"
  if [[ -z "$ORIGIN_SECRET" ]]; then ORIGIN_SECRET="$(openssl rand -hex 24)"; aws secretsmanager create-secret --name bannaa/origin-secret --secret-string "$ORIGIN_SECRET" >/dev/null; fi
  # key pair that signs the photo cookies: private key stays in Secrets Manager, public key goes to CloudFront
  KEYIDS="$(secret_get bannaa/cf-key-ids)"
  if [[ -z "$KEYIDS" ]]; then
    echo "== creating the CloudFront key that protects site photos"
    T="$(mktemp -d)"; openssl genrsa -out "$T/k.pem" 2048 2>/dev/null; openssl rsa -in "$T/k.pem" -pubout -out "$T/p.pem" 2>/dev/null
    aws secretsmanager create-secret --name bannaa/cf-private-key --secret-string "file://$T/k.pem" >/dev/null 2>&1 || aws secretsmanager put-secret-value --secret-id bannaa/cf-private-key --secret-string "file://$T/k.pem" >/dev/null
    python3 - "$T/p.pem" "$T/cfg.json" <<'PY'
import json, sys, time
json.dump({"CallerReference": str(time.time()), "Name": "bannaa-blob-%d" % time.time(), "EncodedKey": open(sys.argv[1]).read(), "Comment": "Bannaa photo cookies"}, open(sys.argv[2], "w"))
PY
    PUB="$(aws cloudfront create-public-key --public-key-config "file://$T/cfg.json" --query PublicKey.Id --output text)"
    KG="$(aws cloudfront create-key-group --key-group-config "Name=bannaa-blob-keys-$(date +%s),Items=$PUB" --query KeyGroup.Id --output text)"
    KEYIDS="{\"publicKeyId\":\"$PUB\",\"keyGroupId\":\"$KG\"}"
    aws secretsmanager create-secret --name bannaa/cf-key-ids --secret-string "$KEYIDS" >/dev/null; rm -rf "$T"
  fi
  PUB="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["publicKeyId"])' "$KEYIDS")"
  KG="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["keyGroupId"])' "$KEYIDS")"

  # --- edge stack in us-east-1: firewall (WAF) + HTTPS certificate for the custom domain ---
  echo "== firewall${DOMAIN:+ and certificate for $DOMAIN} (us-east-1)"
  aws cloudformation deploy --region us-east-1 --stack-name "${STACK}-edge" --template-file template-edge.yaml \
    --parameter-overrides DomainName="$DOMAIN" HostedZoneId="$ZONE" --no-fail-on-empty-changeset
  eout(){ aws cloudformation describe-stacks --region us-east-1 --stack-name "${STACK}-edge" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
  WAF="$(eout WebAclArn)"; CERT="$(eout CertificateArn)"; [[ "$CERT" == "None" ]] && CERT=""

  aws s3api head-bucket --bucket "$ART" 2>/dev/null || {
    if [[ "$REGION" == "us-east-1" ]]; then aws s3api create-bucket --bucket "$ART" >/dev/null
    else aws s3api create-bucket --bucket "$ART" --create-bucket-configuration LocationConstraint="$REGION" >/dev/null; fi
    aws s3api put-public-access-block --bucket "$ART" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true; }

  echo "== deploying the platform (CloudFront takes ~5–10 minutes the first time)"
  aws cloudformation package --template-file template.yaml --s3-bucket "$ART" --output-template-file .packaged.yaml >/dev/null
  aws cloudformation deploy --template-file .packaged.yaml --stack-name "$STACK" --capabilities CAPABILITY_IAM --no-fail-on-empty-changeset \
    --parameter-overrides OwnerEmail="$OWNER_EMAIL" SenderEmail="$SENDER_EMAIL" AnthropicSecretName=bannaa/anthropic \
      DomainName="$DOMAIN" HostedZoneId="$ZONE" CertificateArn="$CERT" WebAclArn="$WAF" OriginSecret="$ORIGIN_SECRET" \
      CfKeyGroupId="$KG" CfPublicKeyId="$PUB" CfKeySecretName=bannaa/cf-private-key

  aws sesv2 get-email-identity --email-identity "$SENDER_EMAIL" >/dev/null 2>&1 || {
    aws sesv2 create-email-identity --email-identity "$SENDER_EMAIL" >/dev/null
    echo "   SES: a verification email was sent to $SENDER_EMAIL — open it and click the link."; }
fi

URL="$(out Url)"; BUCKET="$(out SiteBucket)"; DIST="$(out DistributionId)"; TABLE="$(out Table)"; POOL="$(out UserPoolId)"
if [[ -n "${OWNER_EMAIL:-}" ]] && ! aws cognito-idp admin-get-user --user-pool-id "$POOL" --username "$OWNER_EMAIL" >/dev/null 2>&1; then
  aws cognito-idp admin-create-user --user-pool-id "$POOL" --username "$OWNER_EMAIL" --message-action SUPPRESS \
    --user-attributes Name=email,Value="$OWNER_EMAIL" Name=email_verified,Value=true Name=name,Value="Owner" >/dev/null
  while :; do read -rsp "Temporary password for $OWNER_EMAIL (8+ chars, lowercase letters and numbers): " OWNER_PW; echo; pw_ok "$OWNER_PW" && break; echo "   too weak, try again"; done
  aws cognito-idp admin-set-user-password --user-pool-id "$POOL" --username "$OWNER_EMAIL" --no-permanent --password "$OWNER_PW" >/dev/null
  echo "   platform admin account created for $OWNER_EMAIL (you will choose your own password at first sign-in)"
fi
cat > web/config.js <<CFG
window.BANNAA_CONFIG={clientId:'$(out ClientId)',region:'$REGION',wsUrl:'$(out WsUrl)'};
CFG
echo "== uploading web files"
aws s3 sync web "s3://$BUCKET" --delete --cache-control "no-cache" >/dev/null
aws cloudfront create-invalidation --distribution-id "$DIST" --paths "/*" >/dev/null

if [[ "${1:-}" == "--import" ]]; then
  echo "== importing data from the claude.ai version into $TABLE"
  sed "s/__TABLE__/$TABLE/" seed/seed-ddb.json > .seed.json
  aws dynamodb batch-write-item --request-items file://.seed.json >/dev/null && rm .seed.json && echo "   done (projects are converted to the versioned format on first open)"
fi

echo
echo "✅ Bannaa is live: $URL"
echo "   Sign in with ${OWNER_EMAIL:-the owner email} and the temporary password, then choose your own password."
