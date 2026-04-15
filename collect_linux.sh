#!/usr/bin/env bash
set -u

OUTDIR="${1:-./collector-output/linux-$(hostname -s 2>/dev/null || hostname)-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"
REPORT="$OUTDIR/report.txt"
SUMMARY="$OUTDIR/summary.env"
JSON="$OUTDIR/summary.json"

log() { printf '%s\n' "$*" | tee -a "$REPORT" >/dev/null; }
run() {
  local title="$1"; shift
  log ""
  log "### $title"
  log "CMD: $*"
  {
    "$@"
  } >> "$REPORT" 2>&1 || log "[WARN] command failed: $*"
}
file_dump() {
  local title="$1" file="$2"
  log ""
  log "### $title"
  log "FILE: $file"
  if [[ -f "$file" ]]; then
    sed -n '1,250p' "$file" >> "$REPORT" 2>&1 || true
  else
    log "[INFO] missing: $file"
  fi
}
exists() { command -v "$1" >/dev/null 2>&1; }
kv() { printf '%s=%q\n' "$1" "$2" >> "$SUMMARY"; }

: > "$REPORT"
: > "$SUMMARY"

HOST_FQDN="$(hostname -f 2>/dev/null || hostname)"
OS_PRETTY="$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"')"
REALM_LIST="$(realm list 2>/dev/null || true)"
SSSD_CONF="/etc/sssd/sssd.conf"
KRB5_CONF="/etc/krb5.conf"

SSSD_PRESENT=no
SSSD_RUNNING=no
REALMD_PRESENT=no
IPA_CLIENT_PRESENT=no
ADCLI_PRESENT=no
DOMAIN_JOINED_AD=no
DOMAIN_JOINED_IPA=no
KERBEROS_DEFAULT_REALM=""
SSSD_DOMAIN_NAME=""
ID_PROVIDER=""
AUTH_PROVIDER=""
ACCESS_PROVIDER=""
SUDO_PROVIDER=""
CHPASS_PROVIDER=""
AD_DISCOVERY=""
IPA_DISCOVERY=""
CLASSIFICATION="incomplete_or_unknown"
TARGET_GAP=""

log "Collector started on $(date -Is)"
log "Host: $HOST_FQDN"
log "OS: ${OS_PRETTY:-unknown}"

exists realm && REALMD_PRESENT=yes
exists ipa && IPA_CLIENT_PRESENT=yes
exists adcli && ADCLI_PRESENT=yes
exists sssctl && SSSD_PRESENT=yes

if systemctl is-active --quiet sssd 2>/dev/null; then
  SSSD_RUNNING=yes
fi

if [[ -f "$KRB5_CONF" ]]; then
  KERBEROS_DEFAULT_REALM="$(awk '/default_realm/ {gsub(/ /, "", $0); split($0,a,"="); print a[2]; exit}' "$KRB5_CONF" 2>/dev/null || true)"
fi

if [[ -f "$SSSD_CONF" ]]; then
  SSSD_DOMAIN_NAME="$(awk -F= '/^domains[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); split($2,a,","); print a[1]; exit}' "$SSSD_CONF" 2>/dev/null || true)"
  ID_PROVIDER="$(awk -F= '/^id_provider[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SSSD_CONF" 2>/dev/null || true)"
  AUTH_PROVIDER="$(awk -F= '/^auth_provider[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SSSD_CONF" 2>/dev/null || true)"
  ACCESS_PROVIDER="$(awk -F= '/^access_provider[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SSSD_CONF" 2>/dev/null || true)"
  SUDO_PROVIDER="$(awk -F= '/^sudo_provider[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SSSD_CONF" 2>/dev/null || true)"
  CHPASS_PROVIDER="$(awk -F= '/^chpass_provider[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SSSD_CONF" 2>/dev/null || true)"
fi

if grep -qi 'active-directory' <<<"$REALM_LIST" || grep -qi '^type: kerberos' <<<"$REALM_LIST"; then
  DOMAIN_JOINED_AD=yes
fi
if grep -qi 'ipa' <<<"$REALM_LIST" || [[ -f /etc/ipa/default.conf ]]; then
  DOMAIN_JOINED_IPA=yes
fi

if exists realm; then
  AD_DISCOVERY="$(realm discover 2>/dev/null | awk 'BEGIN{RS=""} /active-directory/ {print "yes"; exit} END{if (NR==0) print "no"}' || true)"
  IPA_DISCOVERY="$(realm discover 2>/dev/null | awk 'BEGIN{RS=""} /ipa/ {print "yes"; exit} END{if (NR==0) print "no"}' || true)"
fi

if [[ "$AUTH_PROVIDER" == "ad" && "$ACCESS_PROVIDER" != "ipa" && "$SUDO_PROVIDER" != "ipa" ]]; then
  CLASSIFICATION="direct_ad"
  TARGET_GAP="Missing IDM-backed Linux policy integration or not visible in SSSD"
elif [[ "$AUTH_PROVIDER" == "ipa" || "$ID_PROVIDER" == "ipa" ]]; then
  CLASSIFICATION="indirect_via_idm"
  TARGET_GAP="Authentication appears to terminate in IDM/IPA instead of AD"
elif [[ "$AUTH_PROVIDER" == "ad" && ( "$ACCESS_PROVIDER" == "ipa" || "$SUDO_PROVIDER" == "ipa" ) ]]; then
  CLASSIFICATION="hybrid_target_pattern"
  TARGET_GAP="Validate AD trust in IDM, HBAC/sudo content, and end-to-end logon"
else
  CLASSIFICATION="incomplete_or_unknown"
  TARGET_GAP="Review SSSD, realm join, Kerberos realm, and IDM policy linkage"
fi

kv host_fqdn "$HOST_FQDN"
kv os_pretty "${OS_PRETTY:-unknown}"
kv sssd_present "$SSSD_PRESENT"
kv sssd_running "$SSSD_RUNNING"
kv realmd_present "$REALMD_PRESENT"
kv ipa_client_present "$IPA_CLIENT_PRESENT"
kv adcli_present "$ADCLI_PRESENT"
kv domain_joined_ad "$DOMAIN_JOINED_AD"
kv domain_joined_ipa "$DOMAIN_JOINED_IPA"
kv kerberos_default_realm "$KERBEROS_DEFAULT_REALM"
kv sssd_domain_name "$SSSD_DOMAIN_NAME"
kv id_provider "$ID_PROVIDER"
kv auth_provider "$AUTH_PROVIDER"
kv access_provider "$ACCESS_PROVIDER"
kv sudo_provider "$SUDO_PROVIDER"
kv chpass_provider "$CHPASS_PROVIDER"
kv ad_discovery "$AD_DISCOVERY"
kv ipa_discovery "$IPA_DISCOVERY"
kv classification "$CLASSIFICATION"
kv target_gap "$TARGET_GAP"

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
file_dump "sssd.conf" "$SSSD_CONF"
file_dump "IPA default.conf" /etc/ipa/default.conf
run "Installed packages of interest" bash -lc "rpm -qa | egrep '^(sssd|realmd|ipa-client|adcli|krb5-workstation|oddjob|samba-common-tools|authselect|chrony)-' | sort"
run "SSSD service" systemctl status sssd
exists realm && run "realm list" realm list
exists realm && run "realm discover" realm discover
exists adcli && run "adcli info" adcli info
exists ipa && run "ipa env" ipa env
exists authselect && run "authselect current" authselect current
run "PAM system-auth" sed -n '1,220p' /etc/pam.d/system-auth
run "PAM password-auth" sed -n '1,220p' /etc/pam.d/password-auth
run "SSSD domain-status" bash -lc 'sssctl domain-list 2>/dev/null && echo && sssctl config-check 2>/dev/null'
run "Keytab principals" klist -k
run "Ticket cache" klist
run "getent passwd sample" bash -lc 'getent passwd | egrep -i "(admin|administrator|svc|test)" | head -25'
run "sudoers includes" bash -lc 'ls -la /etc/sudoers.d 2>/dev/null; echo; sed -n "1,220p" /etc/sudoers'

cat > "$JSON" <<EOFJSON
{
  "host_fqdn": "${HOST_FQDN}",
  "os_pretty": "${OS_PRETTY:-unknown}",
  "sssd_present": "${SSSD_PRESENT}",
  "sssd_running": "${SSSD_RUNNING}",
  "realmd_present": "${REALMD_PRESENT}",
  "ipa_client_present": "${IPA_CLIENT_PRESENT}",
  "adcli_present": "${ADCLI_PRESENT}",
  "domain_joined_ad": "${DOMAIN_JOINED_AD}",
  "domain_joined_ipa": "${DOMAIN_JOINED_IPA}",
  "kerberos_default_realm": "${KERBEROS_DEFAULT_REALM}",
  "sssd_domain_name": "${SSSD_DOMAIN_NAME}",
  "id_provider": "${ID_PROVIDER}",
  "auth_provider": "${AUTH_PROVIDER}",
  "access_provider": "${ACCESS_PROVIDER}",
  "sudo_provider": "${SUDO_PROVIDER}",
  "chpass_provider": "${CHPASS_PROVIDER}",
  "ad_discovery": "${AD_DISCOVERY}",
  "ipa_discovery": "${IPA_DISCOVERY}",
  "classification": "${CLASSIFICATION}",
  "target_gap": "${TARGET_GAP}"
}
EOFJSON

cat > "$OUTDIR/checklist.txt" <<EOFCHK
Linux Collector Checklist
=========================
Host: $HOST_FQDN
OS: ${OS_PRETTY:-unknown}

Observed State
--------------
- SSSD present: $SSSD_PRESENT
- SSSD running: $SSSD_RUNNING
- realmd present: $REALMD_PRESENT
- IPA client present: $IPA_CLIENT_PRESENT
- adcli present: $ADCLI_PRESENT
- Joined to AD: $DOMAIN_JOINED_AD
- Joined to IDM/IPA: $DOMAIN_JOINED_IPA
- Kerberos default realm: ${KERBEROS_DEFAULT_REALM:-unknown}
- SSSD domain: ${SSSD_DOMAIN_NAME:-unset}
- id_provider: ${ID_PROVIDER:-unset}
- auth_provider: ${AUTH_PROVIDER:-unset}
- access_provider: ${ACCESS_PROVIDER:-unset}
- sudo_provider: ${SUDO_PROVIDER:-unset}
- chpass_provider: ${CHPASS_PROVIDER:-unset}

Classification
--------------
- Current model: $CLASSIFICATION
- Gap to target: $TARGET_GAP

Target Pattern to Compare Against
---------------------------------
- AD for auth/identity
- IDM/IPA for Linux policy and host management
- Typical target signals:
  * id_provider = ad
  * auth_provider = ad
  * access_provider = ipa
  * sudo_provider = ipa

What To Review Next
-------------------
- realm list / realm discover output
- SSSD config-check results
- Keytab principals and Kerberos realm alignment
- PAM/authselect state
- Whether HBAC and sudo rules are expected from IDM
EOFCHK

printf 'Wrote Linux collector output to %s\n' "$OUTDIR"
