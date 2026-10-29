#!/usr/bin/env bash
# ==============================================================================
# Zero Infrastructure, Zero Phishing — GCP Teardown Script
#
# Removes what deploy.sh created, in reverse dependency order:
#   1. Stored Gmail access: stops each mailbox's push watch, revokes its refresh
#      token and deletes the pipeline's Datastore records (tools/teardown_datastore.py)
#   2. Cloud Scheduler job (pef-gmail-watch-renewal)
#   3. Cloud Run functions (2nd gen), which also removes their Eventarc triggers
#   4. Pub/Sub subscriptions and topics
#   5. IAM bindings and the six least-privilege service accounts
#
# It discovers everything first, prints the plan and asks before deleting anything.
# Resources are found by name AND by the label app=pef-gemini: anything else in the
# project carrying that label is deleted too, and is listed in the plan.
#
# Kept on purpose (see the summary printed at the end): the Firestore database itself,
# EmailAuditLog records (unless --purge-audit), Secret Manager secrets, enabled APIs,
# the OAuth client, and Cloud Build artefacts shared with other functions.
#
# Usage:
#   ./destroy.sh                 # show the plan, ask, then delete
#   ./destroy.sh --dry-run       # show the plan only
#   ./destroy.sh --yes           # no prompt
#   ./destroy.sh --purge-audit   # also delete EmailAuditLog (verdict history)
#   ./destroy.sh --keep-tokens   # skip step 1 (not recommended: tokens stay valid)
# ==============================================================================
set -euo pipefail

ASSUME_YES="false"
DRY_RUN="false"
PURGE_AUDIT="false"
KEEP_TOKENS="false"
for arg in "$@"; do
  case "${arg}" in
    -y|--yes) ASSUME_YES="true" ;;
    --dry-run) DRY_RUN="true" ;;
    --purge-audit) PURGE_AUDIT="true" ;;
    --keep-tokens) KEEP_TOKENS="true" ;;
    -h|--help)
      sed -n '/^# Usage:/,/^# =====/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'
      exit 0
      ;;
    *)
      echo "Unknown option: ${arg}. See ./destroy.sh --help" >&2
      exit 1
      ;;
  esac
done

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

: "${GOOGLE_CLOUD_PROJECT:?Set GOOGLE_CLOUD_PROJECT in .env or environment}"
PROJECT="${GOOGLE_CLOUD_PROJECT}"
GCP_REGION="${GCP_REGION:-us-central1}"
TOPIC_EMAIL_WATCH="${TOPIC_EMAIL_WATCH:-email-watch}"
TOPIC_EMAIL_ANALYZE="${TOPIC_EMAIL_ANALYZE:-email-analyze}"
TOPIC_EMAIL_OUTCOME="${TOPIC_EMAIL_OUTCOME:-email-outcome}"
TOPIC_EMAIL_DLQ="${TOPIC_EMAIL_DLQ:-email-dlq}"
DLQ_SUBSCRIPTION="${DLQ_SUBSCRIPTION:-${TOPIC_EMAIL_DLQ}-inspect}"
APP_LABEL="${APP_LABEL:-pef-gemini}"
SCHEDULER_JOB="pef-gmail-watch-renewal"
SERVICE_ACCOUNTS=(pef-auth-sa pef-ingest-sa pef-analyze-sa pef-outcome-sa pef-trigger-sa pef-scheduler-sa)
if [[ -x .venv/bin/python ]]; then PYTHON="${PYTHON:-.venv/bin/python}"; else PYTHON="${PYTHON:-python3}"; fi
TEARDOWN_ARGS=(--project="${PROJECT}")
if [[ "${PURGE_AUDIT}" == "true" ]]; then TEARDOWN_ARGS+=(--purge-audit); fi

sa_email() { echo "$1@${PROJECT}.iam.gserviceaccount.com"; }
contains() { local item="$1"; shift; local x; for x in "$@"; do [[ "${x}" == "${item}" ]] && return 0; done; return 1; }

# ------------------------------------------------------------------------------
echo "==> Discovering PEF resources in ${PROJECT} (${GCP_REGION}, label app=${APP_LABEL})..."

HAS_JOB="false"
if gcloud scheduler jobs describe "${SCHEDULER_JOB}" --location="${GCP_REGION}" --project="${PROJECT}" >/dev/null 2>&1; then
  HAS_JOB="true"
fi

FUNCTIONS=()
for fn in email_outcome email_analyze email_ingest auth_renew_watch auth_callback auth_init; do
  if gcloud functions describe "${fn}" --gen2 --region="${GCP_REGION}" --project="${PROJECT}" >/dev/null 2>&1; then
    FUNCTIONS+=("${fn}")
  fi
done
while IFS= read -r name; do
  [[ -z "${name}" ]] && continue
  short="${name##*/}"
  contains "${short}" ${FUNCTIONS[@]+"${FUNCTIONS[@]}"} || FUNCTIONS+=("${short}")
done < <(gcloud functions list --regions="${GCP_REGION}" --project="${PROJECT}" \
  --filter="labels.app=${APP_LABEL}" --format="value(name)" 2>/dev/null || true)

SUBSCRIPTIONS=()
if gcloud pubsub subscriptions describe "${DLQ_SUBSCRIPTION}" --project="${PROJECT}" >/dev/null 2>&1; then
  SUBSCRIPTIONS+=("${DLQ_SUBSCRIPTION}")
fi
while IFS= read -r name; do
  [[ -z "${name}" ]] && continue
  short="${name##*/}"
  contains "${short}" ${SUBSCRIPTIONS[@]+"${SUBSCRIPTIONS[@]}"} || SUBSCRIPTIONS+=("${short}")
done < <(gcloud pubsub subscriptions list --project="${PROJECT}" \
  --filter="labels.app=${APP_LABEL}" --format="value(name)" 2>/dev/null || true)

TOPICS=()
for topic in "${TOPIC_EMAIL_WATCH}" "${TOPIC_EMAIL_ANALYZE}" "${TOPIC_EMAIL_OUTCOME}" "${TOPIC_EMAIL_DLQ}"; do
  if gcloud pubsub topics describe "${topic}" --project="${PROJECT}" >/dev/null 2>&1; then
    TOPICS+=("${topic}")
  fi
done
while IFS= read -r name; do
  [[ -z "${name}" ]] && continue
  short="${name##*/}"
  contains "${short}" ${TOPICS[@]+"${TOPICS[@]}"} || TOPICS+=("${short}")
done < <(gcloud pubsub topics list --project="${PROJECT}" \
  --filter="labels.app=${APP_LABEL}" --format="value(name)" 2>/dev/null || true)

ACCOUNTS=()
for sa in "${SERVICE_ACCOUNTS[@]}"; do
  if gcloud iam service-accounts describe "$(sa_email "${sa}")" --project="${PROJECT}" >/dev/null 2>&1; then
    ACCOUNTS+=("$(sa_email "${sa}")")
  fi
done

list() { if [[ $# -eq 0 ]]; then echo "      (none)"; else printf '      %s\n' "$@"; fi; }
echo
echo "    Plan:"
if [[ "${KEEP_TOKENS}" == "true" ]]; then
  echo "    1. Stored Gmail access: SKIPPED (--keep-tokens). Refresh tokens stay valid in Datastore."
else
  echo "    1. Stored Gmail access and pipeline records in Datastore:"
  "${PYTHON}" tools/teardown_datastore.py "${TEARDOWN_ARGS[@]}" --dry-run | sed 's/^/  /' || {
      echo "ERROR: could not read Datastore with ${PYTHON}. Install the requirements" >&2
      echo "       (pip install -r requirements.txt) and run 'gcloud auth application-default login'," >&2
      echo "       or pass --keep-tokens to skip revoking stored Gmail access." >&2
      exit 1
    }
fi
echo "    2. Cloud Scheduler job:"; if [[ "${HAS_JOB}" == "true" ]]; then list "${SCHEDULER_JOB}"; else list; fi
echo "    3. Cloud Run functions:"; list ${FUNCTIONS[@]+"${FUNCTIONS[@]}"}
echo "    4. Pub/Sub subscriptions:"; list ${SUBSCRIPTIONS[@]+"${SUBSCRIPTIONS[@]}"}
echo "       Pub/Sub topics:"; list ${TOPICS[@]+"${TOPICS[@]}"}
echo "    5. Service accounts (and their project role bindings):"; list ${ACCOUNTS[@]+"${ACCOUNTS[@]}"}
echo

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "==> Dry run: nothing was changed."
  exit 0
fi
if [[ "${ASSUME_YES}" != "true" ]]; then
  read -r -p "Delete everything listed above in '${PROJECT}'? [y/N] " confirm
  if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
  fi
fi

# ------------------------------------------------------------------------------
if [[ "${KEEP_TOKENS}" != "true" ]]; then
  echo "==> 1. Revoking stored Gmail access and deleting pipeline records..."
  "${PYTHON}" tools/teardown_datastore.py "${TEARDOWN_ARGS[@]}"
fi

echo "==> 2. Deleting the Cloud Scheduler job..."
if [[ "${HAS_JOB}" == "true" ]]; then
  gcloud scheduler jobs delete "${SCHEDULER_JOB}" --location="${GCP_REGION}" --project="${PROJECT}" --quiet
fi

echo "==> 3. Deleting Cloud Run functions and their Eventarc triggers..."
for fn in ${FUNCTIONS[@]+"${FUNCTIONS[@]}"}; do
  gcloud functions delete "${fn}" --gen2 --region="${GCP_REGION}" --project="${PROJECT}" --quiet
done

echo "==> 4. Deleting Pub/Sub subscriptions and topics..."
for sub in ${SUBSCRIPTIONS[@]+"${SUBSCRIPTIONS[@]}"}; do
  # Eventarc removes its own subscriptions with the function, so some may be gone already.
  if gcloud pubsub subscriptions describe "${sub}" --project="${PROJECT}" >/dev/null 2>&1; then
    gcloud pubsub subscriptions delete "${sub}" --project="${PROJECT}" --quiet
  fi
done
for topic in ${TOPICS[@]+"${TOPICS[@]}"}; do
  gcloud pubsub topics delete "${topic}" --project="${PROJECT}" --quiet
done

echo "==> 5. Removing project role bindings and deleting service accounts..."
for sa in pef-auth-sa pef-ingest-sa pef-outcome-sa; do
  gcloud projects remove-iam-policy-binding "${PROJECT}" --member="serviceAccount:$(sa_email "${sa}")" \
    --role="roles/datastore.user" --condition=None --quiet >/dev/null 2>&1 || true
done
gcloud projects remove-iam-policy-binding "${PROJECT}" --member="serviceAccount:$(sa_email pef-analyze-sa)" \
  --role="roles/aiplatform.user" --condition=None --quiet >/dev/null 2>&1 || true
for secret in GOOGLE_CLIENT_SECRET:pef-auth-sa SAFE_BROWSING_API_KEY:pef-analyze-sa; do
  name="${secret%%:*}"
  if gcloud secrets describe "${name}" --project="${PROJECT}" >/dev/null 2>&1; then
    gcloud secrets remove-iam-policy-binding "${name}" --project="${PROJECT}" \
      --member="serviceAccount:$(sa_email "${secret##*:}")" --role="roles/secretmanager.secretAccessor" \
      --quiet >/dev/null 2>&1 || true
  fi
done
for account in ${ACCOUNTS[@]+"${ACCOUNTS[@]}"}; do
  gcloud iam service-accounts delete "${account}" --project="${PROJECT}" --quiet
done

echo "==> Teardown complete. Still in the project (delete by hand if you no longer need them):"
if [[ "${PURGE_AUDIT}" == "true" ]]; then
  echo "    - The Firestore (Datastore mode) database itself (now without PEF records)."
else
  echo "    - The Firestore (Datastore mode) database and its EmailAuditLog verdict history."
fi
echo "    - Secret Manager secrets GOOGLE_CLIENT_SECRET / SAFE_BROWSING_API_KEY, if you created them."
echo "    - Cloud Build artefacts shared with other functions: images in the Artifact Registry"
echo "      repository gcf-artifacts and source buckets named gcf-v2-sources-* / gcf-v2-uploads-*."
echo "    - Enabled APIs, and the OAuth client in Google Auth Platform."
echo "    - The Safe Browsing API key created by setup.sh, if any:"
echo "      gcloud services api-keys list --filter=displayName=pef-safe-browsing --project=${PROJECT}"
