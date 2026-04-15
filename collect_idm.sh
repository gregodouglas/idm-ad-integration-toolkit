#!/usr/bin/env bash
set -u

OUTDIR="${1:-./collector-output/idm-$(hostname -s 2>/dev/null || hostname)-$(date +%Y%m%d-%H%M%S)}"
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
    sed -n '1,300p' "$file" >> "$REPORT" 2>&1 || true
  else
    log "[INFO] missing: $file"
  fi
}
exists() { command -v "$1" >/dev/null 2>&1; }
kv() { printf '%s=%q\n' "$1" "$2" >> "$SUMMARY"; }
count_ipa() {
  local cmd="$1"
  bash -lc "$cmd 2>/dev/null | awk 'BEGIN{c=0} /^[[:space:]]*[A-Za-z].*:/ {c++} END{print c}'" 2>/dev/null || echo 0
}

: > "$REPORT"
: > "$SUMMARY"

HOST_FQDN="$(hostname -f 2>/dev/null || hostname)"
OS_PRETTY="$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"')"
IPA_PRESENT=no
TRUST_COUNT=0
HBAC_RULE_COUNT=0
SUDO_RULE_COUNT=0
HOST_COUNT=0
HOSTGROUP_COUNT=0
AD_USERS_VISIBLE=unknown
CLASSIFICATION="idm_present_unknown_state"
TARGET_GAP=""

exists ipa && IPA_PRESENT=yes

if [[ "$IPA_PRESENT" == yes ]]; then
  TRUST_COUNT="$(count_ipa 'ipa trust-find')"
  HBAC_RULE_COUNT="$(count_ipa 'ipa hbacrule-find')"
  SUDO_RULE_COUNT="$(count_ipa 'ipa sudorule-find')"
  HOST_COUNT="$(count_ipa 'ipa host-find')"
  HOSTGROUP_COUNT="$(count_ipa 'ipa hostgroup-find')"
  if ipa user-find --all 2>/dev/null | grep -qi 'ipauniqueid'; then
    AD_USERS_VISIBLE=yes
  fi
fi

if [[ "$TRUST_COUNT" -gt 0 && "$HBAC_RULE_COUNT" -gt 0 ]]; then
  CLASSIFICATION="idm_policy_plane_with_ad_trust"
  TARGET_GAP="Validate clients consume IDM policy while authenticating to AD"
elif [[ "$TRUST_COUNT" -gt 0 && "$HBAC_RULE_COUNT" -eq 0 && "$SUDO_RULE_COUNT" -eq 0 ]]; then
  CLASSIFICATION="idm_trust_stub_only"
  TARGET_GAP="Trust exists but Linux policy content appears thin or absent"
elif [[ "$TRUST_COUNT" -eq 0 ]]; then
  CLASSIFICATION="idm_without_ad_trust"
  TARGET_GAP="AD trust not detected; hybrid target likely incomplete"
fi

kv host_fqdn "$HOST_FQDN"
kv os_pretty "$OS_PRETTY"
kv ipa_present "$IPA_PRESENT"
kv trust_count "$TRUST_COUNT"
kv hbac_rule_count "$HBAC_RULE_COUNT"
kv sudo_rule_count "$SUDO_RULE_COUNT"
kv host_count "$HOST_COUNT"
kv hostgroup_count "$HOSTGROUP_COUNT"
kv ad_users_visible "$AD_USERS_VISIBLE"
kv classification "$CLASSIFICATION"
kv target_gap "$TARGET_GAP"

log "Collector started on $(date -Is)"
log "Host: $HOST_FQDN"
log "OS: ${OS_PRETTY:-unknown}"

run "Host identity" hostnamectl
run "OS release" cat /etc/os-release
run "Time status" timedatectl
exists chronyc && run "Chrony sources" chronyc sources -v
file_dump "krb5.conf" /etc/krb5.conf
file_dump "sssd.conf" /etc/sssd/sssd.conf
file_dump "IPA default.conf" /etc/ipa/default.conf
run "Installed packages of interest" bash -lc "rpm -qa | egrep '^(ipa-server|ipa-client|sssd|krb5-server|bind|named|chrony)-' | sort"
exists ipa && run "ipa env" ipa env
exists ipa && run "ipa config-show" ipa config-show
exists ipa && run "ipa server-role-find" ipa server-role-find
exists ipa && run "ipa trust-find" ipa trust-find
exists ipa && run "ipa hbacrule-find" ipa hbacrule-find
exists ipa && run "ipa sudorule-find" ipa sudorule-find
exists ipa && run "ipa host-find" ipa host-find
exists ipa && run "ipa hostgroup-find" ipa hostgroup-find
exists ipa && run "ipa group-find" ipa group-find
exists ipa && run "ipa topologysegment-find domain" ipa topologysegment-find domain
exists ipa && run "ipa dnsconfig-show" ipa dnsconfig-show
run "Keytab principals" klist -k
run "Ticket cache" klist
run "SSSD service" systemctl status sssd
run "Dirsrv services" bash -lc 'systemctl status dirsrv@* 2>/dev/null || true'
run "HTTPD service" systemctl status httpd
run "named service" bash -lc 'systemctl status named-pkcs11 2>/dev/null || systemctl status named 2>/dev/null || true'

cat > "$JSON" <<EOFJSON
{
  "host_fqdn": "${HOST_FQDN}",
  "os_pretty": "${OS_PRETTY}",
  "ipa_present": "${IPA_PRESENT}",
  "trust_count": "${TRUST_COUNT}",
  "hbac_rule_count": "${HBAC_RULE_COUNT}",
  "sudo_rule_count": "${SUDO_RULE_COUNT}",
  "host_count": "${HOST_COUNT}",
  "hostgroup_count": "${HOSTGROUP_COUNT}",
  "ad_users_visible": "${AD_USERS_VISIBLE}",
  "classification": "${CLASSIFICATION}",
  "target_gap": "${TARGET_GAP}"
}
EOFJSON

cat > "$OUTDIR/checklist.txt" <<EOFCHK
IDM Collector Checklist
=======================
Host: $HOST_FQDN
OS: ${OS_PRETTY:-unknown}

Observed State
--------------
- IPA/IDM CLI present: $IPA_PRESENT
- AD trust count: $TRUST_COUNT
- HBAC rules: $HBAC_RULE_COUNT
- Sudo rules: $SUDO_RULE_COUNT
- Managed hosts: $HOST_COUNT
- Host groups: $HOSTGROUP_COUNT
- AD users visible through IDM: $AD_USERS_VISIBLE

Classification
--------------
- Current model: $CLASSIFICATION
- Gap to target: $TARGET_GAP

Target Pattern to Compare Against
---------------------------------
- AD trust configured and healthy
- HBAC and sudo rules defined in IDM
- Linux hosts enrolled or consuming policy from IDM
- IDM acting as Linux management plane, not primary user auth authority

What To Review Next
-------------------
- trust-find output and per-trust details
- hbacrule-find and sudorule-find content
- host enrollment scope and hostgroups
- DNS/Kerberos alignment for trust
EOFCHK

printf 'Wrote IDM collector output to %s\n' "$OUTDIR"
