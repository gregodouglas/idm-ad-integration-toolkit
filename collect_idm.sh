#!/usr/bin/env bash
# IdM server collector — assesses fit against FAQ 003 target architecture.
# Signals of interest: cross-forest trust to AD, trust type/direction, ID-range
# type (POSIX vs ID-mapping), ID views, external IdM groups (the SID-bridge),
# two-group pattern (external member of POSIX), HBAC/sudo rule wiring, break-
# glass native admin presence, and DNS forwarder wiring to AD.
#
# Logging:
#   LOG_LEVEL  = debug | info | warn | error   (default: info)
#   LOG_COLOR  = auto | always | never         (default: auto; color only on TTY)
#   Messages >= LOG_LEVEL are mirrored to stderr. Everything goes to $REPORT.
#   WARN/ERROR counts are surfaced in summary.{env,json}.
set -u

OUTDIR="${1:-./collector-output/idm-$(hostname -s 2>/dev/null || hostname)-$(date +%Y%m%d-%H%M%S)}"
REPORT=""
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
    if ! sed -n '1,300p' "$file" >>"$REPORT" 2>&1; then
      log_warn "file read failed: $file"
    fi
  else
    log_info "missing: $file"
  fi
}
exists() { command -v "$1" >/dev/null 2>&1; }
kv() { printf '%s=%q\n' "$1" "$2" >> "$SUMMARY"; }

# Count entries using the canonical "Number of entries returned N" footer that
# ipa CLI appends to all *-find commands. Fallback to 0 on parse failure.
ipa_count() {
  local out
  out="$(bash -lc "$* 2>/dev/null" || true)"
  local n
  n="$(awk -F'returned' '/Number of entries returned/ {gsub(/[^0-9]/,"",$2); print $2; exit}' <<<"$out")"
  printf '%s' "${n:-0}"
}
ipa_values_for() {
  # Extracts the value side of "  <Field>: <value>" lines, given a field name.
  local field="$1"; shift
  bash -lc "$* 2>/dev/null" \
    | awk -v F="$field" -F': ' 'tolower($0) ~ tolower("^[[:space:]]*"F":[[:space:]]") {print $2}'
}

mkdir -p "$OUTDIR" || { echo "ERROR: cannot create $OUTDIR" >&2; exit 2; }
REPORT="$OUTDIR/report.txt"
SUMMARY="$OUTDIR/summary.env"
JSON="$OUTDIR/summary.json"
: > "$REPORT" || die "cannot write to $REPORT"
: > "$SUMMARY" || die "cannot write to $SUMMARY"

HOST_FQDN="$(hostname -f 2>/dev/null || hostname)"
OS_PRETTY="$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"')"

IPA_PRESENT=no
exists ipa && IPA_PRESENT=yes

# Baseline
TRUST_COUNT=0
HBAC_RULE_COUNT=0
SUDO_RULE_COUNT=0
HOST_COUNT=0
HOSTGROUP_COUNT=0
GROUP_COUNT=0
POSIX_GROUP_COUNT=0
EXTERNAL_GROUP_COUNT=0
NATIVE_USER_COUNT=0
ADMIN_MEMBER_COUNT=0
IDVIEW_COUNT=0
DEFAULT_TRUST_OVERRIDES=0
IDRANGE_TYPES=""
TRUST_REALMS=""
TRUST_TYPES=""
TRUST_DIRECTIONS=""
DNS_FORWARDZONES=""
EXTERNAL_GROUPS_IN_POSIX=0
HBAC_RULES_WITH_POSIX_GROUPS=0
SUDO_RULES_WITH_POSIX_GROUPS=0
AD_USERS_VISIBLE=unknown
CLASSIFICATION="idm_present_unknown_state"
TARGET_GAP=""

if [[ "$IPA_PRESENT" == yes ]]; then
  TRUST_COUNT="$(ipa_count 'ipa trust-find --sizelimit=0')"
  HBAC_RULE_COUNT="$(ipa_count 'ipa hbacrule-find --sizelimit=0')"
  SUDO_RULE_COUNT="$(ipa_count 'ipa sudorule-find --sizelimit=0')"
  HOST_COUNT="$(ipa_count 'ipa host-find --sizelimit=0')"
  HOSTGROUP_COUNT="$(ipa_count 'ipa hostgroup-find --sizelimit=0')"
  GROUP_COUNT="$(ipa_count 'ipa group-find --sizelimit=0')"
  POSIX_GROUP_COUNT="$(ipa_count 'ipa group-find --posix --sizelimit=0')"
  EXTERNAL_GROUP_COUNT="$(ipa_count 'ipa group-find --external --sizelimit=0')"
  NATIVE_USER_COUNT="$(ipa_count 'ipa user-find --sizelimit=0')"
  IDVIEW_COUNT="$(ipa_count 'ipa idview-find --sizelimit=0')"

  # admins group members — break-glass signal
  ADMIN_MEMBER_COUNT="$(ipa group-show admins 2>/dev/null \
    | awk -F': ' '/Member users:/ {split($2,a,","); c=0; for (i in a) c++; print c; exit}' )"
  ADMIN_MEMBER_COUNT="${ADMIN_MEMBER_COUNT:-0}"

  # ID range types that imply a trust is wired: ipa-ad-trust / ipa-ad-trust-posix
  IDRANGE_TYPES="$(ipa idrange-find --sizelimit=0 2>/dev/null \
    | awk -F': ' '/Range type:/ {print $2}' | sort -u | paste -sd, - )"

  # Per-trust metadata
  TRUST_REALMS="$(ipa trust-find --sizelimit=0 2>/dev/null \
    | awk -F': ' '/Realm name:/ {print $2}' | paste -sd, - )"
  TRUST_TYPES="$(ipa trust-find --sizelimit=0 2>/dev/null \
    | awk -F': ' '/Trust type:/ {print $2}' | sort -u | paste -sd, - )"
  TRUST_DIRECTIONS="$(ipa trust-find --sizelimit=0 2>/dev/null \
    | awk -F': ' '/Trust direction:/ {print $2}' | sort -u | paste -sd, - )"

  # Default Trust View overrides (AD user ID overrides)
  if [[ "$TRUST_COUNT" -gt 0 ]]; then
    DEFAULT_TRUST_OVERRIDES="$(ipa_count 'ipa idoverrideuser-find "Default Trust View" --sizelimit=0')"
  fi

  # DNS forward zones (AD DNS forwarders live here in the trust pattern)
  DNS_FORWARDZONES="$(ipa dnsforwardzone-find --sizelimit=0 2>/dev/null \
    | awk -F': ' '/Zone name:/ {print $2}' | paste -sd, - )"

  # Two-group-pattern heuristic: count how many external groups have a
  # 'Member of groups' line referencing a POSIX IdM group.
  if [[ "$EXTERNAL_GROUP_COUNT" -gt 0 ]]; then
    EXTERNAL_GROUPS_IN_POSIX="$(bash -lc "ipa group-find --external --all --sizelimit=0 2>/dev/null" \
      | awk '/Member of groups:/ {c++} END{print c+0}')"
  fi

  # HBAC rules referencing groups (any group membership): count rules that have
  # 'User Groups:' line with something after it.
  HBAC_RULES_WITH_POSIX_GROUPS="$(bash -lc 'ipa hbacrule-find --all --sizelimit=0 2>/dev/null' \
    | awk -F': ' '/User Groups:/ { if (length($2)>0) c++ } END{print c+0}')"

  # sudo rules similarly
  SUDO_RULES_WITH_POSIX_GROUPS="$(bash -lc 'ipa sudorule-find --all --sizelimit=0 2>/dev/null' \
    | awk -F': ' '/User Groups:/ { if (length($2)>0) c++ } END{print c+0}')"

  # AD users visible: try a small id_mapping view test via getent.
  if [[ "$TRUST_COUNT" -gt 0 ]]; then
    if getent passwd 2>/dev/null | grep -q '@'; then
      AD_USERS_VISIBLE=yes
    else
      AD_USERS_VISIBLE=no
    fi
  fi
fi

# Classification aligned to FAQ 003
if [[ "$IPA_PRESENT" != yes ]]; then
  CLASSIFICATION="not_idm_server"
  TARGET_GAP="This host does not have the IdM/IPA CLI available. Confirm whether it is actually an IdM server."
elif [[ "$TRUST_COUNT" -eq 0 ]]; then
  CLASSIFICATION="idm_without_ad_trust"
  TARGET_GAP="No AD trust detected. Target requires 'ipa-adtrust-install' followed by 'ipa trust-add' against the AD forest root."
elif [[ "$TRUST_COUNT" -gt 0 && "$EXTERNAL_GROUP_COUNT" -gt 0 \
        && "$EXTERNAL_GROUPS_IN_POSIX" -gt 0 \
        && ( "$HBAC_RULES_WITH_POSIX_GROUPS" -gt 0 || "$SUDO_RULES_WITH_POSIX_GROUPS" -gt 0 ) ]]; then
  CLASSIFICATION="idm_target_aligned"
  TARGET_GAP="Trust + external-in-POSIX two-group pattern + policy rules all present. Validate with an AD user end-to-end login and HBAC/sudo smoke test."
elif [[ "$TRUST_COUNT" -gt 0 && "$EXTERNAL_GROUP_COUNT" -eq 0 ]]; then
  CLASSIFICATION="idm_trust_without_external_groups"
  TARGET_GAP="Trust is in place but no non-POSIX external IdM groups exist. Create 'ipa group-add <name>_external --external --nonposix', populate with AD user/group SIDs, and nest inside POSIX IdM groups."
elif [[ "$TRUST_COUNT" -gt 0 && "$EXTERNAL_GROUP_COUNT" -gt 0 && "$EXTERNAL_GROUPS_IN_POSIX" -eq 0 ]]; then
  CLASSIFICATION="idm_external_groups_not_nested"
  TARGET_GAP="External groups exist but none are nested inside POSIX IdM groups. HBAC/sudo rules cannot reference external groups directly — nest them into POSIX groups first."
elif [[ "$TRUST_COUNT" -gt 0 && "$HBAC_RULES_WITH_POSIX_GROUPS" -eq 0 && "$SUDO_RULES_WITH_POSIX_GROUPS" -eq 0 ]]; then
  CLASSIFICATION="idm_trust_policy_empty"
  TARGET_GAP="Trust and groups exist but no HBAC or sudo rules reference user groups. Author policy rules that target the POSIX groups wrapping AD users."
else
  CLASSIFICATION="idm_trust_partial"
  TARGET_GAP="Trust is in place but one or more pattern elements are missing. Review external-group nesting, HBAC/sudo rule wiring, and DNS forwarders."
fi

# Break-glass sanity: admins group should have at least one native IdM user
# besides the built-in 'admin'; hard to measure safely here, so we just report
# the admin_member_count and the native_user_count for the analyzer to judge.

log_info "Collector started"
log_info "Host: $HOST_FQDN"
log_info "OS: ${OS_PRETTY:-unknown}"
log_info "Classification: $CLASSIFICATION"
[[ "$IPA_PRESENT" != yes ]] && log_warn "ipa CLI not available on this host; IdM-specific probes will be skipped"
[[ "$IPA_PRESENT" == yes && "$TRUST_COUNT" -eq 0 ]] && log_warn "IdM present but no AD trust configured"
[[ "$IPA_PRESENT" == yes && "$TRUST_COUNT" -gt 0 && "$EXTERNAL_GROUP_COUNT" -eq 0 ]] && \
  log_warn "trust exists but no non-POSIX external IdM groups found (FAQ 003 two-group pattern not in place)"

# Detail collection
run "Host identity" hostnamectl
run "OS release" cat /etc/os-release
run "Time status" timedatectl
exists chronyc && run "Chrony sources" chronyc sources -v
file_dump "krb5.conf" /etc/krb5.conf
file_dump "sssd.conf" /etc/sssd/sssd.conf
file_dump "IPA default.conf" /etc/ipa/default.conf
runsh "Installed packages of interest" "rpm -qa | egrep '^(ipa-server|ipa-client|sssd|krb5-server|bind|named|chrony|samba|adcli)-' | sort"
exists ipa && run "ipa env" ipa env
exists ipa && run "ipa config-show" ipa config-show
exists ipa && run "ipa server-role-find" ipa server-role-find
exists ipa && run "ipa topologysegment-find domain" ipa topologysegment-find domain
exists ipa && run "ipa dnsconfig-show" ipa dnsconfig-show
exists ipa && run "ipa dnsforwardzone-find" ipa dnsforwardzone-find --sizelimit=0
exists ipa && run "ipa trust-find" ipa trust-find --sizelimit=0
if [[ "$IPA_PRESENT" == yes && "$TRUST_COUNT" -gt 0 ]]; then
  # Per-trust detail
  for realm in $(tr ',' '\n' <<<"$TRUST_REALMS" | grep -v '^$'); do
    runsh "ipa trust-show $realm" "ipa trust-show '$realm' 2>&1"
  done
fi
exists ipa && run "ipa idrange-find" ipa idrange-find --sizelimit=0
exists ipa && run "ipa idview-find" ipa idview-find --sizelimit=0
if [[ "$TRUST_COUNT" -gt 0 ]]; then
  exists ipa && run "Default Trust View overrides" bash -lc 'ipa idoverrideuser-find "Default Trust View" --sizelimit=0 2>&1 | head -100'
fi
exists ipa && run "ipa group-find --external" ipa group-find --external --all --sizelimit=0
exists ipa && run "ipa group-find --posix (names only)" bash -lc "ipa group-find --posix --sizelimit=0 2>&1 | awk -F': ' '/Group name:/ {print \$2}'"
exists ipa && run "ipa hbacrule-find --all" ipa hbacrule-find --all --sizelimit=0
exists ipa && run "ipa sudorule-find --all" ipa sudorule-find --all --sizelimit=0
exists ipa && run "ipa host-find (names only)" bash -lc "ipa host-find --sizelimit=0 2>&1 | awk -F': ' '/Host name:/ {print \$2}'"
exists ipa && run "ipa hostgroup-find" ipa hostgroup-find --sizelimit=0
exists ipa && run "ipa user-find --in-groups=admins" ipa user-find --in-groups=admins --sizelimit=0
run "Keytab principals" klist -k
run "Ticket cache" klist
run "SSSD service" systemctl status sssd
runsh "Dirsrv services" "systemctl list-units 'dirsrv@*' --type=service --all 2>/dev/null || true"
run "HTTPD service" systemctl status httpd
runsh "named service" "systemctl status named-pkcs11 2>/dev/null || systemctl status named 2>/dev/null || true"
runsh "Samba services" "systemctl status smb 2>/dev/null; echo; systemctl status winbind 2>/dev/null || true"

# Summary env
kv host_fqdn                       "$HOST_FQDN"
kv os_pretty                       "${OS_PRETTY:-unknown}"
kv ipa_present                     "$IPA_PRESENT"
kv trust_count                     "$TRUST_COUNT"
kv trust_realms                    "$TRUST_REALMS"
kv trust_types                     "$TRUST_TYPES"
kv trust_directions                "$TRUST_DIRECTIONS"
kv idrange_types                   "$IDRANGE_TYPES"
kv idview_count                    "$IDVIEW_COUNT"
kv default_trust_overrides         "$DEFAULT_TRUST_OVERRIDES"
kv group_count                     "$GROUP_COUNT"
kv posix_group_count               "$POSIX_GROUP_COUNT"
kv external_group_count            "$EXTERNAL_GROUP_COUNT"
kv external_groups_in_posix        "$EXTERNAL_GROUPS_IN_POSIX"
kv hbac_rule_count                 "$HBAC_RULE_COUNT"
kv sudo_rule_count                 "$SUDO_RULE_COUNT"
kv hbac_rules_with_user_groups     "$HBAC_RULES_WITH_POSIX_GROUPS"
kv sudo_rules_with_user_groups     "$SUDO_RULES_WITH_POSIX_GROUPS"
kv host_count                      "$HOST_COUNT"
kv hostgroup_count                 "$HOSTGROUP_COUNT"
kv native_user_count               "$NATIVE_USER_COUNT"
kv admin_member_count              "$ADMIN_MEMBER_COUNT"
kv dns_forwardzones                "$DNS_FORWARDZONES"
kv ad_users_visible                "$AD_USERS_VISIBLE"
kv classification                  "$CLASSIFICATION"
kv target_gap                      "$TARGET_GAP"
kv warn_count                      "$WARN_COUNT"
kv error_count                     "$ERROR_COUNT"
kv log_level                       "$LOG_LEVEL"

cat > "$JSON" <<EOFJSON
{
  "collector_type": "idm",
  "schema_version": 2,
  "host_fqdn": "${HOST_FQDN}",
  "os_pretty": "${OS_PRETTY:-unknown}",
  "ipa_present": "${IPA_PRESENT}",
  "trust": {
    "count": "${TRUST_COUNT}",
    "realms": "${TRUST_REALMS}",
    "types": "${TRUST_TYPES}",
    "directions": "${TRUST_DIRECTIONS}",
    "idrange_types": "${IDRANGE_TYPES}",
    "default_trust_view_overrides": "${DEFAULT_TRUST_OVERRIDES}",
    "ad_users_visible": "${AD_USERS_VISIBLE}"
  },
  "groups": {
    "total": "${GROUP_COUNT}",
    "posix": "${POSIX_GROUP_COUNT}",
    "external": "${EXTERNAL_GROUP_COUNT}",
    "external_nested_in_posix": "${EXTERNAL_GROUPS_IN_POSIX}"
  },
  "policy": {
    "hbac_rule_count": "${HBAC_RULE_COUNT}",
    "sudo_rule_count": "${SUDO_RULE_COUNT}",
    "hbac_rules_with_user_groups": "${HBAC_RULES_WITH_POSIX_GROUPS}",
    "sudo_rules_with_user_groups": "${SUDO_RULES_WITH_POSIX_GROUPS}"
  },
  "hosts": {
    "host_count": "${HOST_COUNT}",
    "hostgroup_count": "${HOSTGROUP_COUNT}"
  },
  "accounts": {
    "native_user_count": "${NATIVE_USER_COUNT}",
    "admins_member_count": "${ADMIN_MEMBER_COUNT}",
    "idview_count": "${IDVIEW_COUNT}"
  },
  "dns": {
    "forwardzones": "${DNS_FORWARDZONES}"
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
IdM Collector Checklist (aligned with FAQ 003)
==============================================
Host: $HOST_FQDN
OS:   ${OS_PRETTY:-unknown}

Target architecture (FAQ 003)
-----------------------------
- Cross-forest Kerberos trust to AD established and healthy
- Non-POSIX external IdM groups hold AD user/group SIDs
- Those external groups are nested inside POSIX IdM groups
- HBAC and sudo rules reference the POSIX groups (not external directly)
- Linux hosts enrolled into IdM (not AD)
- DNS forward zone for the AD DNS domain present on IdM
- Native IdM admin users beyond 'admin' exist for break-glass

Observed state
--------------
- IdM CLI present:             $IPA_PRESENT
- Trust count:                 $TRUST_COUNT  (realms=${TRUST_REALMS:-none}; types=${TRUST_TYPES:-n/a}; direction=${TRUST_DIRECTIONS:-n/a})
- ID range types:              ${IDRANGE_TYPES:-none}
- ID views:                    $IDVIEW_COUNT
- Default Trust View overrides:$DEFAULT_TRUST_OVERRIDES
- Groups (total/posix/extern): $GROUP_COUNT / $POSIX_GROUP_COUNT / $EXTERNAL_GROUP_COUNT
- External nested in POSIX:    $EXTERNAL_GROUPS_IN_POSIX
- HBAC rules (w/ user groups): $HBAC_RULE_COUNT ($HBAC_RULES_WITH_POSIX_GROUPS)
- Sudo rules (w/ user groups): $SUDO_RULE_COUNT ($SUDO_RULES_WITH_POSIX_GROUPS)
- Managed hosts / groups:      $HOST_COUNT / $HOSTGROUP_COUNT
- Native IdM users:            $NATIVE_USER_COUNT
- admins group members:        $ADMIN_MEMBER_COUNT
- DNS forward zones:           ${DNS_FORWARDZONES:-none}
- AD users visible via NSS:    $AD_USERS_VISIBLE

Classification
--------------
- Current: $CLASSIFICATION
- Gap:     $TARGET_GAP

What to review next
-------------------
- 'ipa trust-show <realm>' for per-trust direction and target NetBIOS
- 'ipa idrange-find' to confirm ipa-ad-trust vs ipa-ad-trust-posix
- external-group → POSIX-group nesting for every AD-backed policy bucket
- HBAC / sudo rules: validate 'ipa hbacrule-show' and 'ipa sudorule-show'
- DNS: conditional forwarder to AD DNS domain
EOFCHK

printf 'Wrote IdM collector output to %s\n' "$OUTDIR"
