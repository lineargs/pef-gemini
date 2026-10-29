#!/usr/bin/env bash
# ==============================================================================
# Zero Infrastructure, Zero Phishing — First-time setup
#
# Walks you through everything deploy.sh needs and writes it to .env:
#   1. Project, region and billing check
#   2. The mailbox(es) to protect (ALLOWED_EMAILS)
#   3. The OAuth client (Cloud Console only: the script prints the exact values,
#      then asks you to paste the client ID and secret)
#   4. Optional escalation of borderline emails to Gemini 4 Argon
#   5. Optional Safe Browsing reputation check (enables the API, creates a key
#      restricted to Safe Browsing, and tests it)
#   6. Optional audit Google Sheet
#
# Safe to re-run: current values are offered as defaults and existing resources are
# reused. Nothing is deployed; run ./deploy.sh afterwards.
# Works with the bash 3.2 that ships with macOS.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")"

ENV_FILE=".env"
SB_KEY_NAME="pef-safe-browsing"
SB_TEST_URL="http://testsafebrowsing.appspot.com/s/phishing.html"

die() { echo "ERROR: $*" >&2; exit 1; }
say() { printf '\n==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }

# Read a value from .env (last occurrence), or empty.
get_env() { grep -E "^$1=" "${ENV_FILE}" 2>/dev/null | tail -1 | cut -d= -f2- || true; }

# Write KEY=VALUE into .env, replacing an existing line or appending one.
# Values pass through the environment, so slashes, ampersands and backslashes are safe.
set_env() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  if grep -qE "^${key}=" "${ENV_FILE}"; then
    KEY="${key}" VALUE="${value}" awk 'BEGIN { k = ENVIRON["KEY"]; v = ENVIRON["VALUE"] }
      index($0, k "=") == 1 { print k "=" v; next } { print }' "${ENV_FILE}" > "${tmp}"
  else
    cat "${ENV_FILE}" > "${tmp}"
    printf '%s=%s\n' "${key}" "${value}" >> "${tmp}"
  fi
  cat "${tmp}" > "${ENV_FILE}"   # keeps the file's permissions
  rm -f "${tmp}"
}

is_unset() { [[ -z "$1" || "$1" == your-* ]]; }
mask() { if [[ ${#1} -gt 8 ]]; then printf '%s…' "${1:0:6}"; else printf '(set)'; fi; }

# ask "Prompt" "default" -> reply on stdout (prompt goes to stderr)
ask() {
  local prompt="$1" default="${2:-}" reply
  if [[ -n "${default}" ]]; then
    read -r -p "    ${prompt} [${default}]: " reply
  else
    read -r -p "    ${prompt}: " reply
  fi
  printf '%s' "${reply:-${default}}"
}

# ask_yn "Question" y|n -> exit status 0 for yes
ask_yn() {
  local prompt="$1" default="$2" hint reply
  if [[ "${default}" == "y" ]]; then hint="Y/n"; else hint="y/N"; fi
  read -r -p "    ${prompt} [${hint}]: " reply
  reply="${reply:-${default}}"
  [[ "${reply}" =~ ^[Yy] ]]
}

ask_secret() {
  local prompt="$1" reply
  read -r -s -p "    ${prompt}: " reply
  echo >&2
  printf '%s' "${reply}"
}

# Store a value as the latest version of a Secret Manager secret (created if missing).
store_secret() {
  local name="$1" value="$2"
  gcloud services enable secretmanager.googleapis.com --project="${PROJECT}" \
    --billing-project="${PROJECT}" --quiet >/dev/null
  if gcloud secrets describe "${name}" --project="${PROJECT}" >/dev/null 2>&1; then
    printf '%s' "${value}" | gcloud secrets versions add "${name}" --data-file=- \
      --project="${PROJECT}" --quiet >/dev/null
  else
    printf '%s' "${value}" | gcloud secrets create "${name}" --data-file=- \
      --project="${PROJECT}" --quiet >/dev/null
  fi
  note "Stored in Secret Manager as ${name} (not written to .env)."
}

# ------------------------------------------------------------------------------
command -v gcloud >/dev/null 2>&1 || die "gcloud is not installed: https://cloud.google.com/sdk/docs/install"
ACCOUNT="$(gcloud config get-value account 2>/dev/null || true)"
[[ -n "${ACCOUNT}" ]] || die "gcloud is not signed in. Run: gcloud auth login"

if [[ ! -f "${ENV_FILE}" ]]; then
  cp .env.example "${ENV_FILE}"
  echo "Created ${ENV_FILE} from .env.example."
fi
chmod 600 "${ENV_FILE}"
echo "Signed in to gcloud as ${ACCOUNT}. Press Enter to accept a [default]."

# ------------------------------------------------------------------------------
say "1/6 Project and region"
current_project="$(get_env GOOGLE_CLOUD_PROJECT)"
if is_unset "${current_project}"; then current_project="$(gcloud config get-value project 2>/dev/null || true)"; fi
PROJECT="$(ask "Google Cloud project ID" "${current_project}")"
[[ -n "${PROJECT}" ]] || die "A project ID is required."
gcloud projects describe "${PROJECT}" --format='value(projectNumber)' >/dev/null 2>&1 \
  || die "Can't access project '${PROJECT}' as ${ACCOUNT}. Check the ID, or create it first."
set_env GOOGLE_CLOUD_PROJECT "${PROJECT}"

BILLING="$(gcloud billing projects describe "${PROJECT}" --billing-project="${PROJECT}" \
  --format='value(billingEnabled)' 2>/dev/null || true)"
if [[ "${BILLING}" != "True" ]]; then
  note "WARNING: couldn't confirm billing is enabled on ${PROJECT}. Cloud Run functions need it:"
  note "https://console.cloud.google.com/billing/linkedaccount?project=${PROJECT}"
fi

current_region="$(get_env GCP_REGION)"
REGION="$(ask "Region for the functions" "${current_region:-us-central1}")"
set_env GCP_REGION "${REGION}"
current_fs="$(get_env FIRESTORE_LOCATION)"
if [[ -z "${current_fs}" || "${current_fs}" == "${current_region}" ]]; then
  set_env FIRESTORE_LOCATION "${REGION}"
fi
CALLBACK="https://${REGION}-${PROJECT}.cloudfunctions.net/auth_callback"
set_env GOOGLE_CALLBACK_URL "${CALLBACK}"

# ------------------------------------------------------------------------------
say "2/6 Mailbox to protect"
note "Only these Gmail addresses can complete onboarding (comma-separated)."
current_emails="$(get_env ALLOWED_EMAILS)"
if [[ "${current_emails}" == "your-email@example.com" ]]; then current_emails=""; fi
while :; do
  EMAILS="$(ask "Gmail address(es)" "${current_emails:-${ACCOUNT}}")"
  [[ "${EMAILS}" == *@* ]] && break
  note "That doesn't look like an email address."
done
set_env ALLOWED_EMAILS "${EMAILS}"

# ------------------------------------------------------------------------------
say "3/6 OAuth client (Cloud Console only; Google has no API for this)"
USE_SM="$(get_env USE_SECRET_MANAGER)"
current_id="$(get_env GOOGLE_CLIENT_ID)"
current_secret="$(get_env GOOGLE_CLIENT_SECRET)"
have_client="n"
if [[ "${current_id}" == *.apps.googleusercontent.com && "${current_id}" != your-* ]] \
  && { [[ "${USE_SM}" == "true" ]] || ! is_unset "${current_secret}"; }; then
  have_client="y"
fi
if [[ "${have_client}" == "y" ]] && ask_yn "Keep the existing OAuth client (${current_id%%-*}-…)?" y; then
  note "Keeping it. Its authorised redirect URI must be: ${CALLBACK}"
else
  note "Open https://console.cloud.google.com/auth/overview?project=${PROJECT} and:"
  note "  a. Branding: app name (e.g. PEF Gemini) and your support email."
  note "  b. Audience: External, Testing. Add test user(s): ${EMAILS}"
  note "  c. Data Access → Add or remove scopes → Manually add scopes, paste:"
  note "     https://www.googleapis.com/auth/gmail.modify, https://www.googleapis.com/auth/spreadsheets,"
  note "     openid, https://www.googleapis.com/auth/userinfo.email, https://www.googleapis.com/auth/userinfo.profile"
  note "  d. Clients → Create client → Web application, authorised redirect URI:"
  note "     ${CALLBACK}"
  note "  e. Copy the client ID and secret (the secret is only shown once)."
  while :; do
    CLIENT_ID="$(ask "Client ID" "")"
    [[ "${CLIENT_ID}" == *.apps.googleusercontent.com ]] && break
    note "A client ID ends in .apps.googleusercontent.com."
  done
  CLIENT_SECRET=""
  while [[ -z "${CLIENT_SECRET}" ]]; do
    CLIENT_SECRET="$(ask_secret "Client secret (hidden)")"
  done
  set_env GOOGLE_CLIENT_ID "${CLIENT_ID}"
  if [[ "${USE_SM}" == "true" ]]; then
    store_secret GOOGLE_CLIENT_SECRET "${CLIENT_SECRET}"
    set_env GOOGLE_CLIENT_SECRET ""
  else
    set_env GOOGLE_CLIENT_SECRET "${CLIENT_SECRET}"
  fi
fi

# ------------------------------------------------------------------------------
say "4/6 Escalation to Gemini 4 Argon"
note "Every email is analysed by Gemini 3.8 Flash. When Flash is unsure, the email can get a"
note "second opinion from Gemini 4 Argon (a bigger, pricier model; only borderline emails pay for it)."
current_esc="$(get_env GEMINI_ESCALATION_MODEL)"
esc_default="y"
if grep -qE '^GEMINI_ESCALATION_MODEL=$' "${ENV_FILE}"; then esc_default="n"; fi  # turned off before
if ask_yn "Escalate borderline emails to Gemini 4 Argon?" "${esc_default}"; then
  set_env GEMINI_ESCALATION_MODEL "${current_esc:-gemini-4-argon}"
else
  set_env GEMINI_ESCALATION_MODEL ""
fi

# ------------------------------------------------------------------------------
say "5/6 Safe Browsing reputation check (optional)"
note "Checks the sender domain and links against Google Safe Browsing before Gemini runs."
note "Free for non-commercial use; use Web Risk for commercial deployments."
current_key="$(get_env SAFE_BROWSING_API_KEY)"
if ask_yn "Turn on the Safe Browsing check?" y; then
  KEY=""
  if [[ "${USE_SM}" != "true" ]] && ! is_unset "${current_key}" && ask_yn "Keep the existing key ($(mask "${current_key}"))?" y; then
    KEY="${current_key}"
  else
    note "Enabling the Safe Browsing and API Keys APIs on ${PROJECT}..."
    gcloud services enable safebrowsing.googleapis.com apikeys.googleapis.com \
      --project="${PROJECT}" --billing-project="${PROJECT}" --quiet >/dev/null
    KEY_RESOURCE="$(gcloud services api-keys list --project="${PROJECT}" --billing-project="${PROJECT}" \
      --filter="displayName=${SB_KEY_NAME}" --format='value(name)' --limit=1)"
    if [[ -z "${KEY_RESOURCE}" ]]; then
      note "Creating API key '${SB_KEY_NAME}', restricted to the Safe Browsing API..."
      # gcloud prints the new key in its result; keep it off the screen unless creation fails.
      if ! create_out="$(gcloud services api-keys create --display-name="${SB_KEY_NAME}" \
        --api-target=service=safebrowsing.googleapis.com \
        --project="${PROJECT}" --billing-project="${PROJECT}" --quiet 2>&1)"; then
        echo "${create_out}" >&2
        die "Could not create the API key."
      fi
      KEY_RESOURCE="$(gcloud services api-keys list --project="${PROJECT}" --billing-project="${PROJECT}" \
        --filter="displayName=${SB_KEY_NAME}" --format='value(name)' --limit=1)"
      [[ -n "${KEY_RESOURCE}" ]] || die "The API key was created but can't be found; re-run ./setup.sh."
    else
      note "Reusing the existing API key '${SB_KEY_NAME}'."
    fi
    KEY="$(gcloud services api-keys get-key-string "${KEY_RESOURCE}" \
      --billing-project="${PROJECT}" --format='value(keyString)')"
  fi

  note "Testing the key against Google's test phishing page (a new key can take a minute)..."
  BODY='{"client":{"clientId":"pef-gemini","clientVersion":"2.0.0"},"threatInfo":{"threatTypes":["SOCIAL_ENGINEERING","MALWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":"'"${SB_TEST_URL}"'"}]}}'
  status=""
  for attempt in 1 2 3 4 5 6; do
    status="$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d "${BODY}" \
      "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${KEY}" || true)"
    if [[ "${status}" == "200" ]]; then break; fi
    if [[ "${attempt}" -lt 6 ]]; then sleep 10; fi
  done
  if [[ "${status}" == "200" ]]; then
    note "The key works."
  else
    note "WARNING: the test returned HTTP ${status:-no response}. Saving the key anyway; re-run"
    note "./setup.sh in a few minutes to test again."
  fi
  if [[ "${USE_SM}" == "true" ]]; then
    store_secret SAFE_BROWSING_API_KEY "${KEY}"
    set_env SAFE_BROWSING_API_KEY ""
    SB_STATE="on (key in Secret Manager)"
  else
    set_env SAFE_BROWSING_API_KEY "${KEY}"
    SB_STATE="on"
  fi
else
  set_env SAFE_BROWSING_API_KEY ""
  SB_STATE="off"
  note "Skipped: outcomes will record reputationStatus=disabled."
  if [[ "${USE_SM}" == "true" ]]; then
    note "If a SAFE_BROWSING_API_KEY secret exists from before, deploy.sh still uses it; delete it to turn the check off."
  fi
fi

# ------------------------------------------------------------------------------
say "6/6 Audit Google Sheet (optional)"
current_sheet="$(get_env GOOGLE_SHEET_ID)"
sheet_default="y"
if is_unset "${current_sheet}"; then sheet_default="n"; fi
if ask_yn "Log every verdict to a Google Sheet?" "${sheet_default}"; then
  if ! is_unset "${current_sheet}" && ask_yn "Keep the existing sheet (${current_sheet})?" y; then
    :
  else
    note "Create a sheet at https://sheets.new while signed in as the protected mailbox."
    note "Name its tab Sheet1 and paste this header row into A1 (it fills A1 to H1):"
    printf '\n%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n\n' "Message ID" "Category" "Score" "Verdict" \
      "Model" "Phishing probability" "Signals" "Reasoning"
    note "If you format it as a table, keep the table to the header row."
    while :; do
      SHEET="$(ask "Sheet URL or ID" "")"
      SHEET="$(printf '%s' "${SHEET}" | sed -E 's#.*/d/([^/?#]+).*#\1#')"
      [[ "${SHEET}" =~ ^[A-Za-z0-9_-]{20,}$ ]] && break
      note "Paste the sheet's URL (https://docs.google.com/spreadsheets/d/…) or its ID."
    done
    set_env GOOGLE_SHEET_ID "${SHEET}"
  fi
else
  set_env GOOGLE_SHEET_ID ""
fi

# ------------------------------------------------------------------------------
say "Done. ${ENV_FILE} is ready:"
note "Project:        ${PROJECT} (${REGION})"
note "Mailbox(es):    ${EMAILS}"
note "OAuth client:   $(get_env GOOGLE_CLIENT_ID | cut -c1-24)…"
note "Redirect URI:   ${CALLBACK}"
note "Escalation:     $(get_env GEMINI_ESCALATION_MODEL | sed 's/^$/off/')"
note "Safe Browsing:  ${SB_STATE}"
sheet="$(get_env GOOGLE_SHEET_ID)"; note "Audit sheet:    ${sheet:-none}"
echo
note "Next:"
note "  gcloud auth application-default login"
note "  gcloud auth application-default set-quota-project ${PROJECT}"
note "  ./deploy.sh"
note "Then open the onboarding URL that deploy.sh prints, signed in as the mailbox."
