#!/usr/bin/env bash
# Deploys Bannaa to your AWS account. Run from AWS CloudShell (or any shell with AWS CLI v2 configured).
#   bash deploy.sh                 first deploy (asks for owner email, sender email, Anthropic key)
#   bash deploy.sh --import        also imports the data exported from the claude.ai version (seed/)
#   bash deploy.sh --web-only      re-upload the web files only
set -euo pipefail
cd "$(dirname "$0")"
STACK="${STACK:-bannaa}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-central-1}}"
export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
ART="bannaa-artifacts-${ACCOUNT}-${REGION}"
SECRET="bannaa/anthropic"
out(){ aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }

echo "== Bannaa → AWS account $ACCOUNT, region $REGION, stack $STACK"

if [[ "${1:-}" != "--web-only" ]]; then
  if [[ -z "${OWNER_EMAIL:-}" ]]; then read -rp "Owner email (full access): " OWNER_EMAIL; fi
  if [[ -z "${SENDER_EMAIL:-}" ]]; then read -rp "Sender email for invitations (SES): " SENDER_EMAIL; fi

  if ! aws secretsmanager describe-secret --secret-id "$SECRET" >/dev/null 2>&1; then
    read -rsp "Anthropic API key (sk-ant-...; leave empty to skip AI): " KEY; echo
    aws secretsmanager create-secret --name "$SECRET" --secret-string "${KEY:-none}" >/dev/null
    echo "   secret $SECRET created"
  else echo "   secret $SECRET already exists (update: aws secretsmanager put-secret-value --secret-id $SECRET --secret-string sk-ant-...)"; fi

  aws s3api head-bucket --bucket "$ART" 2>/dev/null || {
    if [[ "$REGION" == "us-east-1" ]]; then aws s3api create-bucket --bucket "$ART" >/dev/null
    else aws s3api create-bucket --bucket "$ART" --create-bucket-configuration LocationConstraint="$REGION" >/dev/null; fi
    aws s3api put-public-access-block --bucket "$ART" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true; }

  echo "== packaging and deploying (CloudFront takes ~5–10 minutes the first time)"
  aws cloudformation package --template-file template.yaml --s3-bucket "$ART" --output-template-file .packaged.yaml >/dev/null
  aws cloudformation deploy --template-file .packaged.yaml --stack-name "$STACK" --capabilities CAPABILITY_IAM \
    --parameter-overrides OwnerEmail="$OWNER_EMAIL" SenderEmail="$SENDER_EMAIL" AnthropicSecretName="$SECRET" --no-fail-on-empty-changeset

  aws sesv2 get-email-identity --email-identity "$SENDER_EMAIL" >/dev/null 2>&1 || {
    aws sesv2 create-email-identity --email-identity "$SENDER_EMAIL" >/dev/null
    echo "   SES: a verification email was sent to $SENDER_EMAIL — open it and click the link."; }
fi

URL="$(out Url)"; BUCKET="$(out SiteBucket)"; DIST="$(out DistributionId)"; TABLE="$(out Table)"
POOL="$(out UserPoolId)"
if [[ -n "${OWNER_EMAIL:-}" ]] && ! aws cognito-idp admin-get-user --user-pool-id "$POOL" --username "$OWNER_EMAIL" >/dev/null 2>&1; then
  aws cognito-idp admin-create-user --user-pool-id "$POOL" --username "$OWNER_EMAIL" --message-action SUPPRESS \
    --user-attributes Name=email,Value="$OWNER_EMAIL" Name=email_verified,Value=true Name=name,Value="Owner" >/dev/null
  aws cognito-idp admin-set-user-password --user-pool-id "$POOL" --username "$OWNER_EMAIL" --permanent --password "Bn$(openssl rand -hex 16)a9" >/dev/null
  echo "   owner account created for $OWNER_EMAIL"
fi
cat > web/config.js <<CFG
window.BANNAA_CONFIG={cognitoDomain:'$(out CognitoDomain)',clientId:'$(out ClientId)',region:'$REGION'};
CFG
echo "== uploading web files"
aws s3 sync web "s3://$BUCKET" --delete --cache-control "no-cache" >/dev/null
aws cloudfront create-invalidation --distribution-id "$DIST" --paths "/*" >/dev/null

if [[ "${1:-}" == "--import" ]]; then
  echo "== importing data from the claude.ai version into $TABLE"
  sed "s/__TABLE__/$TABLE/" seed/seed-ddb.json > .seed.json
  aws dynamodb batch-write-item --request-items file://.seed.json >/dev/null && rm .seed.json && echo "   done"
fi

echo
echo "✅ Bannaa is live: $URL"
echo "   First sign-in: open the link → 'Forgot your password?' → enter ${OWNER_EMAIL:-the owner email} → set your password from the emailed code."
