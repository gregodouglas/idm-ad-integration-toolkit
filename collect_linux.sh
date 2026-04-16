#!/usr/bin/env bash
# Linux collector — assess fit against FAQ 003 target architecture:
#   AD for auth only, IdM for Linux policy, via cross-forest trust.
#   On a target host: id/auth/access/sudo_provider = ipa; host enrolled to IdM;
#   AD subdomain visible in SSSD (indicates working trust).
#
# Logging:
#   LOG_LEVEL  = debug | info | warn | error   (default: info)
#   LOG_COLOR  = auto | always | never         (default: auto; color only on TTY)
#   Messages >= LOG_LEVEL are mirrored to stderr. Everything goes to $REPORT.
#   WARN/ERROR counts are surfaced in summary.{env,json}.
set -u

OUTDIR="${1:-./collector-output/linux-$(hostname -s 2>/dev/null || hostname)-$(date +%Y%m%d-%H%M%S)}"
REPORT=""  # set after OUTDIR is writable
SUMMARY=""
JSON=""

# --- logging ---------------------------------------------------------------
LOG_LEVEL="${LOG_LEVEL:-info}"
case "$LOG_LEVEL" in
  debug) LOG_LEVEL_N=10 ;;
  info)  LOG_LEVEL_N=20 ;;
  warn)  LOG_LEVEL_N=30 ;;
  error) LOG_LEVEL_N=40 ;;
  *)     LOG_LEVEL_N=20; LOG_LEVEL=info ;;
esac

_log_color_enabled=0
case "${LOG_COLOR:-auto}" in
  always) _log_color_enabled=1 ;;
  never)  _log_color_enabled=0 ;;
  auto|*) [[ -t 2 ]] && _log_color_enabled=1 ;;
esac
if [[ "$_log_color_enabled" == 1 ]]; then
  C_DEBUG=$'\e[2m'; C_INFO=$'\e[36m'; C_WARN=$'\e[33m'; C_ERROR=$'\e[31m'; C_RESET=$'\e[0m'
else
  C_DEBUG=""; C_INFO=""; C_WARN=""; C_ERROR=""; C_RESET=""
fi

WARN_COUNT=0
ERROR_COUNT=0

_log() {
  local sev_name="$1" sev_n="$2" color="$3"; shift 3
  local msg="$*"
  local ts
  ts="$(date -Is 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"
  if [[ -n "$REPORT" ]]; then
    printf '%s [%-5s] %s\n' "$ts" "$sev_name" "$msg" >>"$REPORT"
  fi
  if (( sev_n >= LOG_LEVEL_N )); then
    printf '%s[%-5s]%s %s\n' "$color" "$sev_name" "$C_RESET" "$msg" >&2
  fi
}
log_debug() { _log DEBUG 10 "$C_DEBUG" "$@"; }
log_info()  { _log INFO  20 "$C_INFO"  "$@"; }
log_warn()  { WARN_COUNT=$((WARN_COUNT+1));   _log WARN  30 "$C_WARN"  "$@"; }
log_error() { ERROR_COUNT=$((ERROR_COUNT+1)); _log ERROR 40 "$C_ERROR" "$@"; }
# Raw report write (no level, no timestamp) — for section headers and command output
report() { [[ -n "$REPORT" ]] && printf '%s\n' "$*" >>"$REPORT"; }
die() { log_error "$*"; exit 2; }
# --- end logging -----------------------------------------------------------

run() {
  local title="$1"; shift
  report ""
  report "### $title"
  report "CMD: $*"
  if ! command -v "$1" >/dev/null 2>&1; then
    report "[skipped: '$1' not installed]"
    log_debug "skipped (not installed): $*"
    return 0
  fi
  if ! { "$@"; } >>"$REPORT" 2>&1; then
    log_warn "command failed: $*"
  fi
}
runsh() {
  local title="$1"; shift
  report ""
  report "### $title"
  report "SH: $*"
  if ! bash -lc "$*" >>"$REPORT" 2>&1; then
    log_warn "shell failed: $*"
  fi
}
file_dump() {
  local title="$1" file="$2"
  report ""
  report "### $title"
  report "FILE: $file"
  if [[ -f "$file" ]]; then
    if ! sed -n '1,250p' "$file" >>"$REPORT" 2>&1; then
      log_warn "file read failed: $file"
    fi
  else
    log_info "missing: $file"
  fi
}
exists() { command -v "$1" >/dev/null 2>&1; }
kv() { printf '%s=%q\n' "$1" "$2" >> "$SUMMARY"; }

mkdir -p "$OUTDIR" || { echo "ERROR: cannot create $OUTDIR" >&2; exit 2; }
REPORT="$OUTDIR/report.txt"
SUMMARY="$OUTDIR/summary.env"
JSON="$OUTDIR/summary.json"
: > "$REPORT" || die "cannot write to $REPORT"
: > "$SUMMARY" || die "cannot write to $SUMMARY"

HOST_FQDN="$(hostname -f 2>/dev/null || hostname)"
OS_PRETTY="$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"')"
SSSD_CONF="/etc/sssd/sssd.conf"
KRB5_CONF="/etc/krb5.conf"
IPA_CONF="/etc/ipa/default.conf"

# Tool presence
SSSD_PRESENT=no
SSSD_RUNNING=no
REALMD_PRESENT=no
IPA_CLIENT_PRESENT=no
ADCLI_PRESENT=no
exists sssctl && SSSD_PRESENT=yes
exists realm && REALMD_PRESENT=yes
exists ipa && IPA_CLIENT_PRESENT=yes
exists adcli && ADCLI_PRESENT=yes
systemctl is-active --quiet sssd 2>/dev/null && SSSD_RUNNING=yes

# Kerberos
KERBEROS_DEFAULT_REALM=""
if [[ -f "$KRB5_CONF" ]]; then
  KERBEROS_DEFAULT_REALM="$(awk -F= '/default_realm/ {gsub(/[[:space:]]/,""); split($0,a,"="); print a[2]; exit}' "$KRB5_CONF" 2>/dev/null || true)"
fi

# IdM client enrollment — single strongest indicator is /etc/ipa/default.conf
IPA_CLIENT_ENROLLED=no
IPA_REALM=""
IPA_DOMAIN=""
IPA_SERVER=""
if [[ -f "$IPA_CONF" ]]; then
  IPA_CLIENT_ENROLLED=yes
  IPA_REALM="$(awk -F= '/^realm[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$IPA_CONF" 2>/dev/null || true)"
  IPA_DOMAIN="$(awk -F= '/^domain[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$IPA_CONF" 2>/dev/null || true)"
  IPA_SERVER="$(awk -F= '/^server[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$IPA_CONF" 2>/dev/null || true)"
fi

# SSSD providers and domain
SSSD_DOMAIN_NAME=""
ID_PROVIDER=""
AUTH_PROVIDER=""
ACCESS_PROVIDER=""
SUDO_PROVIDER=""
CHPASS_PROVIDER=""
if [[ -f "$SSSD_CONF" ]]; then
  SSSD_DOMAIN_NAME="$(awk -F= '/^domains[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); split($2,a,","); print a[1]; exit}' "$SSSD_CONF" 2>/dev/null || true)"
  ID_PROVIDER="$(awk -F= '/^id_provider[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SSSD_CONF" 2>/dev/null || true)"
  AUTH_PROVIDER="$(awk -F= '/^auth_provider[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SSSD_CONF" 2>/dev/null || true)"
  ACCESS_PROVIDER="$(awk -F= '/^access_provider[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SSSD_CONF" 2>/dev/null || true)"
  SUDO_PROVIDER="$(awk -F= '/^sudo_provider[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SSSD_CONF" 2>/dev/null || true)"
  CHPASS_PROVIDER="$(awk -F= '/^chpass_provider[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SSSD_CONF" 2>/dev/null || true)"
fi

# Domain join evidence (realmd view)
REALM_LIST_OUT=""
DOMAIN_JOINED_AD=no
DOMAIN_JOINED_IPA=no
if exists realm; then
  REALM_LIST_OUT="$(realm list 2>/dev/null || true)"
  grep -qi 'active-directory' <<<"$REALM_LIST_OUT" && DOMAIN_JOINED_AD=yes
  grep -qi 'ipa' <<<"$REALM_LIST_OUT" && DOMAIN_JOINED_IPA=yes
fi
[[ "$IPA_CLIENT_ENROLLED" == "yes" ]] && DOMAIN_JOINED_IPA=yes

# AD-subdomain-via-trust visibility: the smoking gun of a working IdM↔AD trust
# sssctl domain-list typically prints `implicit_files`, the primary domain, and
# one line per trusted subdomain resolvable through SSSD.
AD_SUBDOMAIN_VISIBLE=no
SUBDOMAIN_LIST=""
if [[ "$SSSD_PRESENT" == yes && "$SSSD_RUNNING" == yes ]]; then
  ALL_DOMS="$(sssctl domain-list 2>/dev/null | grep -vE '^(implicit_files|[[:space:]]*)$' || true)"
  if [[ -n "$ALL_DOMS" && -n "$SSSD_DOMAIN_NAME" ]]; then
    SUBDOMAIN_LIST="$(printf '%s\n' "$ALL_DOMS" | grep -vxF "$SSSD_DOMAIN_NAME" | paste -sd, - || true)"
    [[ -n "$SUBDOMAIN_LIST" ]] && AD_SUBDOMAIN_VISIBLE=yes
  fi
fi

# Classification aligned to FAQ 003
is_ipa_providers() {
  [[ "$ID_PROVIDER" == "ipa" && "$AUTH_PROVIDER" == "ipa" \
     && ( "$ACCESS_PROVIDER" == "ipa" || -z "$ACCESS_PROVIDER" ) \
     && ( "$SUDO_PROVIDER"   == "ipa" || -z "$SUDO_PROVIDER"   ) ]]
}

CLASSIFICATION="unknown"
TARGET_GAP=""
if [[ "$IPA_CLIENT_ENROLLED" == "yes" ]] && is_ipa_providers; then
  if [[ "$AD_SUBDOMAIN_VISIBLE" == "yes" ]]; then
    CLASSIFICATION="target_idm_enrolled_with_trust"
    TARGET_GAP="At target pattern. Verify end-to-end AD-user login, HBAC enforcement, and sudo rule application."
  else
    CLASSIFICATION="target_idm_enrolled_trust_not_visible"
    TARGET_GAP="Host is IdM-enrolled, but no AD trusted subdomain is visible in SSSD. Check the trust on IdM ('ipa trust-find'), AD-side trust object, DNS forwarders, and restart SSSD to refresh subdomain list."
  fi
elif [[ "$ID_PROVIDER" == "ad" && "$AUTH_PROVIDER" == "ad" && "$IPA_CLIENT_ENROLLED" == "no" ]]; then
  CLASSIFICATION="direct_ad_no_idm"
  TARGET_GAP="Host is directly joined to AD without IdM. Anti-pattern for the target architecture. Unjoin AD, then enroll into IdM via 'ipa-client-install'; IdM will refer AD-user authentication over the trust."
elif [[ "$AUTH_PROVIDER" == "ad" && ( "$ACCESS_PROVIDER" == "ipa" || "$SUDO_PROVIDER" == "ipa" ) ]]; then
  CLASSIFICATION="split_provider_unusual"
  TARGET_GAP="Mixed providers (auth=ad, access/sudo=ipa). Unusual and not the FAQ 003 target. Re-enroll the host into IdM so all providers are 'ipa', then IdM routes AD auth via trust."
elif [[ -z "$ID_PROVIDER$AUTH_PROVIDER" && "$IPA_CLIENT_ENROLLED" == "no" && "$DOMAIN_JOINED_AD" == "no" ]]; then
  CLASSIFICATION="not_joined"
  TARGET_GAP="Host is not enrolled into any identity domain. Target: 'ipa-client-install' to join IdM (with trust already in place)."
else
  CLASSIFICATION="unknown"
  TARGET_GAP="State does not match a known pattern. Review SSSD config, IdM client state, realm membership, and krb5.conf."
fi

log_info "Collector started"
log_info "Host: $HOST_FQDN"
log_info "OS: ${OS_PRETTY:-unknown}"
log_info "Classification: $CLASSIFICATION"
[[ "$SSSD_PRESENT"  != yes ]] && log_info "sssctl not installed; SSSD-level probes will be skipped"
[[ "$IPA_CLIENT_PRESENT" != yes ]] && log_info "ipa client CLI not installed; ipa probes will be skipped"
[[ "$IPA_CLIENT_ENROLLED" == no && "$DOMAIN_JOINED_AD" == yes ]] && \
  log_warn "host is directly joined to AD and not enrolled in IdM (anti-pattern for FAQ 003 target)"

# Detail collection
run "Host identity" hostnamectl
run "OS release" cat /etc/os-release
run "Time status" timedatectl
exists chronyc && run "Chrony sources" chronyc sources -v
exists ntpq && run "NTP peers" ntpq -p
run "IP addresses" ip addr
run "Routes" ip route
file_dump "Resolver config" /etc/resolv.conf
file_dump "nsswitch" /etc/nsswitch.conf
file_dump "krb5.conf" "$KRB5_CONF"
runsh "krb5 realms/capaths section" "awk '/\\\[(capaths|realms|domain_realm)\\\]/,/^\\\[/' $KRB5_CONF 2>/dev/null | sed '200,\$d'"
file_dump "sssd.conf" "$SSSD_CONF"
file_dump "IPA default.conf" "$IPA_CONF"
runsh "Installed packages of interest" "rpm -qa | egrep '^(sssd|realmd|ipa-client|adcli|krb5-workstation|oddjob|samba-common-tools|authselect|chrony)-' | sort"
run "SSSD service" systemctl status sssd
exists realm && run "realm list" realm list
exists realm && run "realm discover (AD)" bash -c "realm discover 2>&1 | head -60"
exists adcli && run "adcli info" adcli info
exists ipa && run "ipa env" ipa env
exists ipa && runsh "ipa host-show self" "ipa host-show \"$HOST_FQDN\" 2>&1 | head -60"
exists authselect && run "authselect current" authselect current
run "PAM system-auth" sed -n '1,220p' /etc/pam.d/system-auth
run "PAM password-auth" sed -n '1,220p' /etc/pam.d/password-auth
exists sssctl && run "sssctl config-check" sssctl config-check
exists sssctl && run "sssctl domain-list" sssctl domain-list
if [[ -n "$SSSD_DOMAIN_NAME" ]]; then
  exists sssctl && runsh "sssctl domain-status primary" "sssctl domain-status '$SSSD_DOMAIN_NAME' 2>&1 | head -80"
fi
if [[ -n "$SUBDOMAIN_LIST" ]]; then
  IFS=',' read -ra SUBS <<<"$SUBDOMAIN_LIST"
  for sd in "${SUBS[@]}"; do
    exists sssctl && runsh "sssctl domain-status $sd" "sssctl domain-status '$sd' 2>&1 | head -80"
  done
fi
run "Keytab principals" klist -k
run "Ticket cache" klist
runsh "getent probe (users with uid>=1000)" "getent passwd | awk -F: '\$3 >= 1000 {print}' | head -25"
if [[ -n "$KERBEROS_DEFAULT_REALM" ]]; then
  runsh "id probe against default realm admin" "id \"admin@$KERBEROS_DEFAULT_REALM\" 2>&1 | head -5"
fi
runsh "sudoers and includes" "ls -la /etc/sudoers.d 2>/dev/null; echo; sed -n '1,220p' /etc/sudoers"

# Summary env
kv host_fqdn                   "$HOST_FQDN"
kv os_pretty                   "${OS_PRETTY:-unknown}"
kv sssd_present                "$SSSD_PRESENT"
kv sssd_running                "$SSSD_RUNNING"
kv realmd_present              "$REALMD_PRESENT"
kv ipa_client_present          "$IPA_CLIENT_PRESENT"
kv adcli_present               "$ADCLI_PRESENT"
kv ipa_client_enrolled         "$IPA_CLIENT_ENROLLED"
kv ipa_realm                   "$IPA_REALM"
kv ipa_domain                  "$IPA_DOMAIN"
kv ipa_server                  "$IPA_SERVER"
kv domain_joined_ad            "$DOMAIN_JOINED_AD"
kv domain_joined_ipa           "$DOMAIN_JOINED_IPA"
kv kerberos_default_realm      "$KERBEROS_DEFAULT_REALM"
kv sssd_domain_name            "$SSSD_DOMAIN_NAME"
kv id_provider                 "$ID_PROVIDER"
kv auth_provider               "$AUTH_PROVIDER"
kv access_provider             "$ACCESS_PROVIDER"
kv sudo_provider               "$SUDO_PROVIDER"
kv chpass_provider             "$CHPASS_PROVIDER"
kv ad_subdomain_visible        "$AD_SUBDOMAIN_VISIBLE"
kv subdomain_list              "$SUBDOMAIN_LIST"
kv classification              "$CLASSIFICATION"
kv target_gap                  "$TARGET_GAP"
kv warn_count                  "$WARN_COUNT"
kv error_count                 "$ERROR_COUNT"
kv log_level                   "$LOG_LEVEL"

# JSON summary
# Note: subdomain_list may contain commas; json-escape as a plain string
cat > "$JSON" <<EOFJSON
{
  "collector_type": "linux",
  "schema_version": 2,
  "host_fqdn": "${HOST_FQDN}",
  "os_pretty": "${OS_PRETTY:-unknown}",
  "tooling": {
    "sssd_present": "${SSSD_PRESENT}",
    "sssd_running": "${SSSD_RUNNING}",
    "realmd_present": "${REALMD_PRESENT}",
    "ipa_client_present": "${IPA_CLIENT_PRESENT}",
    "adcli_present": "${ADCLI_PRESENT}"
  },
  "enrollment": {
    "ipa_client_enrolled": "${IPA_CLIENT_ENROLLED}",
    "ipa_realm": "${IPA_REALM}",
    "ipa_domain": "${IPA_DOMAIN}",
    "ipa_server": "${IPA_SERVER}",
    "domain_joined_ad": "${DOMAIN_JOINED_AD}",
    "domain_joined_ipa": "${DOMAIN_JOINED_IPA}"
  },
  "kerberos": {
    "default_realm": "${KERBEROS_DEFAULT_REALM}"
  },
  "sssd": {
    "domain_name": "${SSSD_DOMAIN_NAME}",
    "id_provider": "${ID_PROVIDER}",
    "auth_provider": "${AUTH_PROVIDER}",
    "access_provider": "${ACCESS_PROVIDER}",
    "sudo_provider": "${SUDO_PROVIDER}",
    "chpass_provider": "${CHPASS_PROVIDER}",
    "ad_subdomain_visible": "${AD_SUBDOMAIN_VISIBLE}",
    "subdomain_list": "${SUBDOMAIN_LIST}"
  },
  "classification": "${CLASSIFICATION}",
  "target_gap": "${TARGET_GAP}",
  "logging": {
    "level": "${LOG_LEVEL}",
    "warn_count": ${WARN_COUNT},
    "error_count": ${ERROR_COUNT}
  }
}
EOFJSON

log_info "Collector finished: classification=$CLASSIFICATION warn=$WARN_COUNT error=$ERROR_COUNT"

cat > "$OUTDIR/checklist.txt" <<EOFCHK
Linux Collector Checklist (aligned with FAQ 003)
================================================
Host: $HOST_FQDN
OS:   ${OS_PRETTY:-unknown}

Target architecture (FAQ 003)
-----------------------------
- Host enrolled into IdM (not directly joined to AD)
- SSSD providers: id/auth/access/sudo_provider = ipa
- AD users are visible via a trusted subdomain under SSSD
- AD does auth (Kerberos referred through the trust); IdM does policy (HBAC/sudo)

Observed state
--------------
- IdM client enrolled:            $IPA_CLIENT_ENROLLED  (realm=${IPA_REALM:-n/a}, server=${IPA_SERVER:-n/a})
- Directly joined to AD (realmd): $DOMAIN_JOINED_AD
- SSSD running:                   $SSSD_RUNNING
- SSSD primary domain:            ${SSSD_DOMAIN_NAME:-unset}
- id_provider:                    ${ID_PROVIDER:-unset}
- auth_provider:                  ${AUTH_PROVIDER:-unset}
- access_provider:                ${ACCESS_PROVIDER:-unset}
- sudo_provider:                  ${SUDO_PROVIDER:-unset}
- Kerberos default realm:         ${KERBEROS_DEFAULT_REALM:-unset}
- AD trusted subdomain visible:   $AD_SUBDOMAIN_VISIBLE  (${SUBDOMAIN_LIST:-none})

Classification
--------------
- Current:  $CLASSIFICATION
- Gap:      $TARGET_GAP

What to review next
-------------------
- 'ipa-client-install' status if not enrolled
- 'ipa trust-find' on the IdM server (trust health drives subdomain visibility here)
- 'sssctl domain-status <ad_realm>' for per-subdomain detail
- krb5.conf realms/capaths/domain_realm alignment
- PAM/authselect profile
EOFCHK

printf 'Wrote Linux collector output to %s\n' "$OUTDIR"
