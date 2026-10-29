#!/usr/bin/env bash
# ==============================================================================
# Zero Infrastructure, Zero Phishing — Production GCP Setup & Deploy Script
#
# Provisions, idempotently:
#   1. Required APIs and the Firestore (Datastore mode) database
#   2. Least-privilege service accounts (one per stage, plus Eventarc trigger and
#      Cloud Scheduler identities) with topic-level Pub/Sub grants
#   3. Pub/Sub topics, a dead-letter topic and a dead-letter inspection subscription
#   4. Cloud Run functions (2nd gen) with --retry, wired to the dead-letter topic
#      with bounded exponential backoff
#   5. A daily Cloud Scheduler job that renews the Gmail users.watch subscription
#   6. Cloud Monitoring alerts, emailed to ALERT_EMAIL: an email in the dead-letter
#      queue, a Gmail sign-in that needs renewing, an email that could not be scanned
#
# Re-run safely after any change: every step checks before it creates.
# ==============================================================================
set -euo pipefail

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

: "${GOOGLE_CLOUD_PROJECT:?Set GOOGLE_CLOUD_PROJECT in .env or environment}"
PROJECT="${GOOGLE_CLOUD_PROJECT}"
GCP_REGION="${GCP_REGION:-us-central1}"
FIRESTORE_LOCATION="${FIRESTORE_LOCATION:-${GCP_REGION}}"
GOOGLE_CLOUD_LOCATION="${GOOGLE_CLOUD_LOCATION:-global}"
PYTHON_RUNTIME="${PYTHON_RUNTIME:-python312}"
GEMINI_MODEL="${GEMINI_MODEL:-gemini-3.8-flash}"
GEMINI_THINKING_LEVEL="${GEMINI_THINKING_LEVEL:-LOW}"
# Optional second opinion for borderline emails; empty disables escalation.
GEMINI_ESCALATION_MODEL="${GEMINI_ESCALATION_MODEL:-}"
GEMINI_ESCALATION_THINKING_LEVEL="${GEMINI_ESCALATION_THINKING_LEVEL:-LOW}"
# Per-request Gemini timeout; two calls (first pass + escalation) must fit in FUNCTION_TIMEOUT.
GEMINI_TIMEOUT_SECONDS="${GEMINI_TIMEOUT_SECONDS:-55}"
TOPIC_EMAIL_WATCH="${TOPIC_EMAIL_WATCH:-email-watch}"
TOPIC_EMAIL_ANALYZE="${TOPIC_EMAIL_ANALYZE:-email-analyze}"
TOPIC_EMAIL_OUTCOME="${TOPIC_EMAIL_OUTCOME:-email-outcome}"
TOPIC_EMAIL_DLQ="${TOPIC_EMAIL_DLQ:-email-dlq}"
DLQ_SUBSCRIPTION="${DLQ_SUBSCRIPTION:-${TOPIC_EMAIL_DLQ}-inspect}"
PEF_MAX_DELIVERY_ATTEMPTS="${PEF_MAX_DELIVERY_ATTEMPTS:-10}"
# Event function timeout. Must stay below PEF_CLAIM_LEASE_SECONDS (default 300s) so a
# crashed invocation's lease expires before the work could still be running.
FUNCTION_TIMEOUT="${FUNCTION_TIMEOUT:-120s}"
PEF_CLAIM_LEASE_SECONDS="${PEF_CLAIM_LEASE_SECONDS:-300}"
PEF_MAX_MESSAGE_ATTEMPTS="${PEF_MAX_MESSAGE_ATTEMPTS:-5}"
PEF_MIN_RETRY_DELAY="${PEF_MIN_RETRY_DELAY:-10s}"
PEF_MAX_RETRY_DELAY="${PEF_MAX_RETRY_DELAY:-600s}"
PEF_CONFIDENCE_CUTOFF="${PEF_CONFIDENCE_CUTOFF:-0.85}"
PEF_COMPONENT_CUTOFF="${PEF_COMPONENT_CUTOFF:-0.90}"
ALLOW_SIMULATED_PAYLOADS="${ALLOW_SIMULATED_PAYLOADS:-false}"
SAFE_BROWSING_FAIL_CLOSED="${SAFE_BROWSING_FAIL_CLOSED:-true}"
LOG_FULL_REASONING="${LOG_FULL_REASONING:-false}"
USE_SECRET_MANAGER="${USE_SECRET_MANAGER:-false}"
WATCH_RENEWAL_SCHEDULE="${WATCH_RENEWAL_SCHEDULE:-17 6 * * *}"
WATCH_RENEWAL_TIME_ZONE="${WATCH_RENEWAL_TIME_ZONE:-Etc/UTC}"
# Resource labels applied to all label-capable resources (Cloud Run functions, Pub/Sub
# topics & subscriptions) for Cloud Billing attribution and label-filtered teardown.
RESOURCE_LABELS="${RESOURCE_LABELS:-app=pef-gemini,managed-by=deploy-sh}"
# Optional: a service account for Cloud Build. Needed in projects where the default
# compute service account has no roles (org policy disabling automatic IAM grants).
BUILD_SERVICE_ACCOUNT="${BUILD_SERVICE_ACCOUNT:-}"
# Where the Cloud Monitoring alerts go (tools/alerts.py). Defaults to the first address in
# ALLOWED_EMAILS; ALERT_EMAIL=none skips the alerts.
ALERT_EMAIL="${ALERT_EMAIL:-${ALLOWED_EMAILS:-}}"
ALERT_EMAIL="${ALERT_EMAIL%%,*}"
ALERT_EMAIL="${ALERT_EMAIL// /}"
if [[ -x .venv/bin/python ]]; then PYTHON="${PYTHON:-.venv/bin/python}"; else PYTHON="${PYTHON:-python3}"; fi

if [[ -z "${GOOGLE_CALLBACK_URL:-}" || "${GOOGLE_CALLBACK_URL}" == *"your-gcp-project-id"* ]]; then
  GOOGLE_CALLBACK_URL="https://${GCP_REGION}-${PROJECT}.cloudfunctions.net/auth_callback"
fi

sa_email() { echo "$1@${PROJECT}.iam.gserviceaccount.com"; }
AUTH_SA="$(sa_email pef-auth-sa)"
INGEST_SA="$(sa_email pef-ingest-sa)"
ANALYZE_SA="$(sa_email pef-analyze-sa)"
OUTCOME_SA="$(sa_email pef-outcome-sa)"
TRIGGER_SA="$(sa_email pef-trigger-sa)"
SCHEDULER_SA="$(sa_email pef-scheduler-sa)"

# Retry helper: IAM changes and new service accounts take a few seconds to propagate.
retry() {
  local attempt
  for attempt in 1 2 3 4 5 6; do
    if "$@"; then return 0; fi
    echo "    (attempt ${attempt} failed; retrying in $((attempt * 5))s)" >&2
    sleep $((attempt * 5))
  done
  echo "ERROR: command failed after retries: $*" >&2
  return 1
}

TIMEOUT_SECONDS="${FUNCTION_TIMEOUT%s}"
if [[ ! "${TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || (( TIMEOUT_SECONDS >= PEF_CLAIM_LEASE_SECONDS )); then
  echo "ERROR: FUNCTION_TIMEOUT (${FUNCTION_TIMEOUT}) must be whole seconds (e.g. 120s) and below" >&2
  echo "       PEF_CLAIM_LEASE_SECONDS (${PEF_CLAIM_LEASE_SECONDS})." >&2
  exit 1
fi

# Pre-flight: the OAuth client and consent screen can only be created in the Cloud
# Console (there is no public API for them), so check they exist before deploying.
# See "Before You Deploy" in README.md.
PREFLIGHT_ERRORS=()
if [[ "${PROJECT}" == "your-gcp-project-id" ]]; then
  PREFLIGHT_ERRORS+=("GOOGLE_CLOUD_PROJECT is still the placeholder; set your project ID.")
fi
if [[ -z "${GOOGLE_CLIENT_ID:-}" || "${GOOGLE_CLIENT_ID}" == your-* || "${GOOGLE_CLIENT_ID}" != *.apps.googleusercontent.com ]]; then
  PREFLIGHT_ERRORS+=("GOOGLE_CLIENT_ID is missing or a placeholder; create a Web application OAuth client.")
fi
if [[ "${USE_SECRET_MANAGER}" != "true" && ( -z "${GOOGLE_CLIENT_SECRET:-}" || "${GOOGLE_CLIENT_SECRET}" == your-* ) ]]; then
  PREFLIGHT_ERRORS+=("GOOGLE_CLIENT_SECRET is missing or a placeholder; copy it from the same OAuth client.")
fi
if [[ "${ALLOW_ANY_ONBOARDING_EMAIL:-false}" != "true" && ( -z "${ALLOWED_EMAILS:-}" || "${ALLOWED_EMAILS}" == "your-email@example.com" ) ]]; then
  PREFLIGHT_ERRORS+=("ALLOWED_EMAILS is missing or a placeholder; set the mailbox address(es) to protect.")
fi
if (( ${#PREFLIGHT_ERRORS[@]} > 0 )); then
  echo "ERROR: .env is not ready to deploy:" >&2
  printf '  - %s\n' "${PREFLIGHT_ERRORS[@]}" >&2
  echo "" >&2
  echo "  Run ./setup.sh to fill these in step by step. Or create the OAuth client in the"
  echo "  Cloud Console yourself (Google Auth Platform > Clients)," >&2
  echo "  type Web application, with this authorised redirect URI:" >&2
  echo "    ${GOOGLE_CALLBACK_URL}" >&2
  echo "  Full steps: README.md, \"Before You Deploy\"." >&2
  exit 1
fi
# Optional values left as placeholders are treated as not set.
if [[ "${SAFE_BROWSING_API_KEY:-}" == your-* ]]; then
  echo "    Note: SAFE_BROWSING_API_KEY is a placeholder; deploying without the reputation check."
  SAFE_BROWSING_API_KEY=""
fi
if [[ "${GOOGLE_SHEET_ID:-}" == your-* ]]; then
  GOOGLE_SHEET_ID=""
fi

echo "==> Target project: ${PROJECT} | Region: ${GCP_REGION} | Model: ${GEMINI_MODEL}${GEMINI_ESCALATION_MODEL:+ (escalates to ${GEMINI_ESCALATION_MODEL})}"
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT}" --format='value(projectNumber)')"
PUBSUB_AGENT="service-${PROJECT_NUMBER}@gcp-sa-pubsub.iam.gserviceaccount.com"

# ------------------------------------------------------------------------------
echo "==> 1. Enabling APIs and creating the Firestore (Datastore mode) database..."
APIS=(
  cloudfunctions.googleapis.com run.googleapis.com cloudbuild.googleapis.com
  artifactregistry.googleapis.com eventarc.googleapis.com pubsub.googleapis.com
  firestore.googleapis.com datastore.googleapis.com aiplatform.googleapis.com
  gmail.googleapis.com sheets.googleapis.com safebrowsing.googleapis.com
  cloudscheduler.googleapis.com iam.googleapis.com monitoring.googleapis.com logging.googleapis.com
)
if [[ "${USE_SECRET_MANAGER}" == "true" ]]; then
  APIS+=(secretmanager.googleapis.com)
fi
gcloud services enable "${APIS[@]}" --project="${PROJECT}" --quiet

DB_TYPE="$(gcloud firestore databases describe --database="(default)" --project="${PROJECT}" \
  --format='value(type)' 2>/dev/null || true)"
if [[ -z "${DB_TYPE}" ]]; then
  gcloud firestore databases create --database="(default)" --location="${FIRESTORE_LOCATION}" \
    --type=datastore-mode --project="${PROJECT}" --quiet
elif [[ "${DB_TYPE}" != "DATASTORE_MODE" ]]; then
  echo "ERROR: the (default) database in ${PROJECT} is ${DB_TYPE}, but PEF needs Firestore in" >&2
  echo "       Datastore mode. Use a project whose default database is in Datastore mode." >&2
  exit 1
fi

# ------------------------------------------------------------------------------
echo "==> 2. Creating least-privilege service accounts..."
# pef-analyze-sa deliberately gets NO Datastore or Gmail access: the stage that reads
# hostile email with an LLM holds no mailbox credentials, so a successful prompt
# injection cannot read or change the mailbox.
for sa in pef-auth-sa pef-ingest-sa pef-analyze-sa pef-outcome-sa pef-trigger-sa pef-scheduler-sa; do
  gcloud iam service-accounts describe "$(sa_email "${sa}")" --project="${PROJECT}" >/dev/null 2>&1 || \
    gcloud iam service-accounts create "${sa}" --display-name="PEF v2 ${sa}" --project="${PROJECT}" --quiet
done

for sa in "${AUTH_SA}" "${INGEST_SA}" "${OUTCOME_SA}"; do
  retry gcloud projects add-iam-policy-binding "${PROJECT}" \
    --member="serviceAccount:${sa}" --role="roles/datastore.user" --condition=None --quiet >/dev/null
done
retry gcloud projects add-iam-policy-binding "${PROJECT}" \
  --member="serviceAccount:${ANALYZE_SA}" --role="roles/aiplatform.user" --condition=None --quiet >/dev/null

if [[ -n "${BUILD_SERVICE_ACCOUNT}" ]]; then
  BUILD_ARGS=(--build-service-account="projects/${PROJECT}/serviceAccounts/${BUILD_SERVICE_ACCOUNT}")
else
  BUILD_ARGS=()
fi

# ------------------------------------------------------------------------------
echo "==> 3. Creating Pub/Sub topics, dead-letter topic and topic-level grants..."
for topic in "${TOPIC_EMAIL_WATCH}" "${TOPIC_EMAIL_ANALYZE}" "${TOPIC_EMAIL_OUTCOME}" "${TOPIC_EMAIL_DLQ}"; do
  if gcloud pubsub topics describe "${topic}" --project="${PROJECT}" >/dev/null 2>&1; then
    gcloud pubsub topics update "${topic}" --update-labels="${RESOURCE_LABELS}" --project="${PROJECT}" --quiet >/dev/null
  else
    gcloud pubsub topics create "${topic}" --labels="${RESOURCE_LABELS}" --project="${PROJECT}" --quiet
  fi
done

# Dead-lettered messages are dropped if the DLQ topic has no subscription, so keep one
# for inspection and replay (7-day retention).
if gcloud pubsub subscriptions describe "${DLQ_SUBSCRIPTION}" --project="${PROJECT}" >/dev/null 2>&1; then
  gcloud pubsub subscriptions update "${DLQ_SUBSCRIPTION}" --update-labels="${RESOURCE_LABELS}" --project="${PROJECT}" --quiet >/dev/null
else
  gcloud pubsub subscriptions create "${DLQ_SUBSCRIPTION}" --topic="${TOPIC_EMAIL_DLQ}" \
    --message-retention-duration=7d --labels="${RESOURCE_LABELS}" --project="${PROJECT}" --quiet
fi

# Publish rights only on the topic each stage writes to.
retry gcloud pubsub topics add-iam-policy-binding "${TOPIC_EMAIL_WATCH}" --project="${PROJECT}" \
  --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" --role="roles/pubsub.publisher" --quiet >/dev/null
retry gcloud pubsub topics add-iam-policy-binding "${TOPIC_EMAIL_ANALYZE}" --project="${PROJECT}" \
  --member="serviceAccount:${INGEST_SA}" --role="roles/pubsub.publisher" --quiet >/dev/null
retry gcloud pubsub topics add-iam-policy-binding "${TOPIC_EMAIL_OUTCOME}" --project="${PROJECT}" \
  --member="serviceAccount:${ANALYZE_SA}" --role="roles/pubsub.publisher" --quiet >/dev/null
# Projects created before 8 April 2021: the Pub/Sub service agent must be able to mint
# OIDC tokens for the trigger identity. Scoped to that one service account.
retry gcloud iam service-accounts add-iam-policy-binding "${TRIGGER_SA}" --project="${PROJECT}" \
  --member="serviceAccount:${PUBSUB_AGENT}" --role="roles/iam.serviceAccountTokenCreator" --quiet >/dev/null
# The Pub/Sub service agent forwards failed messages to the dead-letter topic.
retry gcloud pubsub topics add-iam-policy-binding "${TOPIC_EMAIL_DLQ}" --project="${PROJECT}" \
  --member="serviceAccount:${PUBSUB_AGENT}" --role="roles/pubsub.publisher" --quiet >/dev/null

# ------------------------------------------------------------------------------
# Env var lists use "##" as the separator (passed with gcloud's "^##^" delimiter syntax)
# so values may contain commas, e.g. ALLOWED_EMAILS=a@example.com,b@example.com.
COMMON_ENV_VARS="GOOGLE_CLOUD_PROJECT=${PROJECT}##GOOGLE_CLOUD_LOCATION=${GOOGLE_CLOUD_LOCATION}##GOOGLE_GENAI_USE_ENTERPRISE=true##TOPIC_EMAIL_WATCH=${TOPIC_EMAIL_WATCH}##TOPIC_EMAIL_ANALYZE=${TOPIC_EMAIL_ANALYZE}##TOPIC_EMAIL_OUTCOME=${TOPIC_EMAIL_OUTCOME}##ALLOW_SIMULATED_PAYLOADS=${ALLOW_SIMULATED_PAYLOADS}##PEF_CLAIM_LEASE_SECONDS=${PEF_CLAIM_LEASE_SECONDS}##PEF_MAX_MESSAGE_ATTEMPTS=${PEF_MAX_MESSAGE_ATTEMPTS}"
ANALYZE_ENV_VARS="${COMMON_ENV_VARS}##GEMINI_MODEL=${GEMINI_MODEL}##GEMINI_THINKING_LEVEL=${GEMINI_THINKING_LEVEL}##GEMINI_ESCALATION_MODEL=${GEMINI_ESCALATION_MODEL}##GEMINI_ESCALATION_THINKING_LEVEL=${GEMINI_ESCALATION_THINKING_LEVEL}##GEMINI_TIMEOUT_SECONDS=${GEMINI_TIMEOUT_SECONDS}##PEF_ANALYSIS_BUDGET_SECONDS=$((TIMEOUT_SECONDS - 10))##SAFE_BROWSING_FAIL_CLOSED=${SAFE_BROWSING_FAIL_CLOSED}"
OUTCOME_ENV_VARS="${COMMON_ENV_VARS}##GOOGLE_SHEET_ID=${GOOGLE_SHEET_ID:-}##PEF_CONFIDENCE_CUTOFF=${PEF_CONFIDENCE_CUTOFF}##PEF_COMPONENT_CUTOFF=${PEF_COMPONENT_CUTOFF}##LOG_FULL_REASONING=${LOG_FULL_REASONING}"
AUTH_ENV_VARS="${COMMON_ENV_VARS}##GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID:-}##GOOGLE_CALLBACK_URL=${GOOGLE_CALLBACK_URL:-}##ALLOWED_EMAILS=${ALLOWED_EMAILS:-}##ALLOW_ANY_ONBOARDING_EMAIL=${ALLOW_ANY_ONBOARDING_EMAIL:-false}"

AUTH_SECRET_ARGS=()
ANALYZE_SECRET_ARGS=()
if [[ "${USE_SECRET_MANAGER}" == "true" ]]; then
  echo "==>    Granting Secret Manager access (./setup.sh creates the secrets)..."
  if ! gcloud secrets describe GOOGLE_CLIENT_SECRET --project="${PROJECT}" >/dev/null 2>&1; then
    echo "ERROR: Secret 'GOOGLE_CLIENT_SECRET' not found. Run ./setup.sh, or create it:" >&2
    echo "  printf '%s' \"\$VALUE\" | gcloud secrets create GOOGLE_CLIENT_SECRET --data-file=- --project=${PROJECT}" >&2
    exit 1
  fi
  retry gcloud secrets add-iam-policy-binding GOOGLE_CLIENT_SECRET --project="${PROJECT}" \
    --member="serviceAccount:${AUTH_SA}" --role="roles/secretmanager.secretAccessor" --quiet >/dev/null
  AUTH_SECRET_ARGS=(--set-secrets="GOOGLE_CLIENT_SECRET=GOOGLE_CLIENT_SECRET:latest")
  # The Safe Browsing key is optional: without the secret, analysis runs without the check.
  if gcloud secrets describe SAFE_BROWSING_API_KEY --project="${PROJECT}" >/dev/null 2>&1; then
    retry gcloud secrets add-iam-policy-binding SAFE_BROWSING_API_KEY --project="${PROJECT}" \
      --member="serviceAccount:${ANALYZE_SA}" --role="roles/secretmanager.secretAccessor" --quiet >/dev/null
    ANALYZE_SECRET_ARGS=(--set-secrets="SAFE_BROWSING_API_KEY=SAFE_BROWSING_API_KEY:latest")
  else
    echo "    Note: no SAFE_BROWSING_API_KEY secret; deploying without the reputation check."
    ANALYZE_ENV_VARS="${ANALYZE_ENV_VARS}##SAFE_BROWSING_API_KEY="
  fi
else
  AUTH_ENV_VARS="${AUTH_ENV_VARS}##GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET:-}"
  ANALYZE_ENV_VARS="${ANALYZE_ENV_VARS}##SAFE_BROWSING_API_KEY=${SAFE_BROWSING_API_KEY:-}"
fi

deploy_http_fn() {
  # deploy_http_fn NAME ENTRY AUTH_FLAG
  gcloud functions deploy "$1" --gen2 --runtime="${PYTHON_RUNTIME}" --region="${GCP_REGION}" --project="${PROJECT}" \
    --service-account="${AUTH_SA}" --source=functions/auth_setup --entry-point="$2" \
    --trigger-http "$3" --update-labels="${RESOURCE_LABELS}" --set-env-vars="^##^${AUTH_ENV_VARS}" \
    ${AUTH_SECRET_ARGS[@]+"${AUTH_SECRET_ARGS[@]}"} ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} --quiet
}

deploy_event_fn() {
  # deploy_event_fn NAME SOURCE_DIR TOPIC RUNTIME_SA ENV_VARS [extra deploy args...]
  local name="$1" source_dir="$2" topic="$3" runtime_sa="$4" env_vars="$5"
  shift 5
  gcloud functions deploy "${name}" --gen2 --runtime="${PYTHON_RUNTIME}" --region="${GCP_REGION}" --project="${PROJECT}" \
    --service-account="${runtime_sa}" --trigger-service-account="${TRIGGER_SA}" \
    --source="${source_dir}" --entry-point="${name}" --trigger-topic="${topic}" --retry \
    --timeout="${FUNCTION_TIMEOUT}" --update-labels="${RESOURCE_LABELS}" --set-env-vars="^##^${env_vars}" "$@" ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} --quiet

  # Only the Eventarc trigger identity may invoke the function.
  retry gcloud functions add-invoker-policy-binding "${name}" --region="${GCP_REGION}" --project="${PROJECT}" \
    --member="serviceAccount:${TRIGGER_SA}" --quiet >/dev/null

  # Wire the Eventarc-managed subscription to the dead-letter topic with bounded,
  # exponential backoff. Re-applied on every deploy because redeploys can recreate it.
  local trigger subscription
  trigger="$(gcloud functions describe "${name}" --gen2 --region="${GCP_REGION}" --project="${PROJECT}" \
    --format='value(eventTrigger.trigger)')"
  subscription="$(gcloud eventarc triggers describe "${trigger}" --location="${GCP_REGION}" --project="${PROJECT}" \
    --format='value(transport.pubsub.subscription)')"
  if [[ -z "${subscription}" ]]; then
    echo "ERROR: could not find the Pub/Sub subscription behind ${name}'s trigger." >&2
    exit 1
  fi
  retry gcloud pubsub subscriptions update "${subscription}" --project="${PROJECT}" \
    --update-labels="${RESOURCE_LABELS}" \
    --dead-letter-topic="projects/${PROJECT}/topics/${TOPIC_EMAIL_DLQ}" \
    --max-delivery-attempts="${PEF_MAX_DELIVERY_ATTEMPTS}" \
    --min-retry-delay="${PEF_MIN_RETRY_DELAY}" --max-retry-delay="${PEF_MAX_RETRY_DELAY}" --quiet >/dev/null
  retry gcloud pubsub subscriptions add-iam-policy-binding "${subscription}" --project="${PROJECT}" \
    --member="serviceAccount:${PUBSUB_AGENT}" --role="roles/pubsub.subscriber" --quiet >/dev/null
  echo "    ${name}: retries -> ${subscription} -> dead letter after ${PEF_MAX_DELIVERY_ATTEMPTS} attempts"
}

# ------------------------------------------------------------------------------
echo "==> 4. Deploying Stage 0: auth_init, auth_callback & auth_renew_watch..."
deploy_http_fn auth_init auth_init --allow-unauthenticated
deploy_http_fn auth_callback auth_callback --allow-unauthenticated
deploy_http_fn auth_renew_watch auth_renew_watch --no-allow-unauthenticated
retry gcloud functions add-invoker-policy-binding auth_renew_watch --region="${GCP_REGION}" --project="${PROJECT}" \
  --member="serviceAccount:${SCHEDULER_SA}" --quiet >/dev/null

echo "==> 5. Deploying Stage 1: email_ingest (Pub/Sub: ${TOPIC_EMAIL_WATCH})..."
deploy_event_fn email_ingest functions/email_ingest "${TOPIC_EMAIL_WATCH}" "${INGEST_SA}" "${COMMON_ENV_VARS}"

echo "==> 6. Deploying Stage 2: email_analyze (Pub/Sub: ${TOPIC_EMAIL_ANALYZE})..."
deploy_event_fn email_analyze functions/email_analyze "${TOPIC_EMAIL_ANALYZE}" "${ANALYZE_SA}" "${ANALYZE_ENV_VARS}" \
  ${ANALYZE_SECRET_ARGS[@]+"${ANALYZE_SECRET_ARGS[@]}"}

echo "==> 7. Deploying Stage 3: email_outcome (Pub/Sub: ${TOPIC_EMAIL_OUTCOME})..."
deploy_event_fn email_outcome functions/email_outcome "${TOPIC_EMAIL_OUTCOME}" "${OUTCOME_SA}" "${OUTCOME_ENV_VARS}"

# ------------------------------------------------------------------------------
echo "==> 8. Scheduling daily Gmail users.watch renewal..."
RENEW_URL="$(gcloud functions describe auth_renew_watch --gen2 --region="${GCP_REGION}" --project="${PROJECT}" \
  --format='value(serviceConfig.uri)')"
SCHEDULER_ARGS=(
  --location="${GCP_REGION}" --project="${PROJECT}"
  --schedule="${WATCH_RENEWAL_SCHEDULE}" --time-zone="${WATCH_RENEWAL_TIME_ZONE}"
  --uri="${RENEW_URL}" --http-method=POST
  --oidc-service-account-email="${SCHEDULER_SA}" --oidc-token-audience="${RENEW_URL}"
  --attempt-deadline=300s --quiet
)
if gcloud scheduler jobs describe pef-gmail-watch-renewal --location="${GCP_REGION}" --project="${PROJECT}" >/dev/null 2>&1; then
  gcloud scheduler jobs update http pef-gmail-watch-renewal "${SCHEDULER_ARGS[@]}"
else
  gcloud scheduler jobs create http pef-gmail-watch-renewal "${SCHEDULER_ARGS[@]}"
fi

AUTH_INIT_URL="$(gcloud functions describe auth_init --gen2 --region="${GCP_REGION}" --project="${PROJECT}" \
  --format='value(serviceConfig.uri)')"

# ------------------------------------------------------------------------------
echo "==> 9. Creating alerts..."
ALERTS_STATUS="not set up (set ALERT_EMAIL in .env)"
if [[ -z "${ALERT_EMAIL}" || "${ALERT_EMAIL}" == "none" ]]; then
  echo "    Skipped: ALERT_EMAIL is empty or 'none'."
elif ! command -v "${PYTHON}" >/dev/null 2>&1; then
  echo "    Skipped: no Python found (${PYTHON}); run: python3 tools/alerts.py --help"
  ALERTS_STATUS="not set up (no Python)"
elif "${PYTHON}" tools/alerts.py --project="${PROJECT}" --email="${ALERT_EMAIL}" \
    --onboarding-url="${AUTH_INIT_URL}" --dlq-subscription="${DLQ_SUBSCRIPTION}"; then
  ALERTS_STATUS="emailed to ${ALERT_EMAIL} (Cloud Monitoring > Alerting)"
else
  # The pipeline itself is deployed; don't fail the whole run over the alerts.
  echo "    WARNING: could not create the alerts (see above). Re-run ./deploy.sh to retry." >&2
  ALERTS_STATUS="FAILED to set up (see the warning above)"
fi

echo "==> Deployment complete (labels: ${RESOURCE_LABELS})."
echo "    OAuth Onboarding URL:   ${AUTH_INIT_URL}"
echo "    OAuth Redirect URI:     ${GOOGLE_CALLBACK_URL}"
echo "    Alerts:                 ${ALERTS_STATUS}"
echo "    Dead-lettered messages: gcloud pubsub subscriptions pull ${DLQ_SUBSCRIPTION} --project=${PROJECT} --limit=10 --auto-ack"
echo "    Teardown:               ./destroy.sh --dry-run   (then ./destroy.sh)"
