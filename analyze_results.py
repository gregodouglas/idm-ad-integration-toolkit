#!/usr/bin/env python3
"""Aggregate collector outputs and score against the FAQ 003 target.

Walks a root directory, loads every `summary.json` produced by one of the
collectors (linux / idm / ad), and emits `assessment-summary.txt` plus
`assessment-summary.json` summarising per-host state and the FAQ 003 gap
checklist.

Target architecture (FAQ 003):
    AD = sole authoritative user store; IdM = sole Linux policy plane,
    bridged by a cross-forest Kerberos trust; Linux hosts enrolled into
    IdM (not AD); AD-user SIDs wrapped in non-POSIX external IdM groups,
    nested inside POSIX IdM groups that HBAC and sudo rules target.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# Classification constants (match the collector scripts)
LINUX_TARGET = "target_idm_enrolled_with_trust"
LINUX_TARGET_TRUST_MISSING = "target_idm_enrolled_trust_not_visible"
LINUX_DIRECT_AD = "direct_ad_no_idm"
LINUX_SPLIT = "split_provider_unusual"
LINUX_NOT_JOINED = "not_joined"

IDM_TARGET = "idm_target_aligned"
IDM_NO_TRUST = "idm_without_ad_trust"
IDM_EXT_MISSING = "idm_trust_without_external_groups"
IDM_EXT_NOT_NESTED = "idm_external_groups_not_nested"
IDM_POLICY_EMPTY = "idm_trust_policy_empty"

AD_TARGET = "ad_target_ready"
AD_NO_IDM_TRUST = "ad_no_idm_trust"
AD_NO_IDM_MATCH = "ad_trust_but_no_idm_match"
AD_FUNCTIONAL_GAP = "ad_idm_trust_with_functional_level_gap"
AD_AES_GAP = "ad_idm_trust_with_aes_gap"
AD_DNS_GAP = "ad_idm_trust_with_dns_gap"
AD_LINUX_IN_AD = "ad_idm_trust_with_linux_in_ad"


@dataclass
class CheckResult:
    key: str
    description: str
    status: str  # "pass" | "fail" | "warn" | "unknown"
    evidence: list[str] = field(default_factory=list)
    citation: str = ""


def classify_path(path: Path) -> str:
    """Determine collector type from the file's parent directory name."""
    p = str(path.parent.name).lower()
    if p.startswith("linux-"):
        return "linux"
    if p.startswith("idm-"):
        return "idm"
    if p.startswith("ad-"):
        return "ad"
    # Fall back to the declared collector_type from the JSON if available
    return ""


def load_summaries(root: Path) -> list[tuple[Path, dict[str, Any]]]:
    out: list[tuple[Path, dict[str, Any]]] = []
    for path in root.rglob("summary.json"):
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        out.append((path, data))
    return out


def bucket(summaries: list[tuple[Path, dict[str, Any]]]):
    linux: list[tuple[Path, dict[str, Any]]] = []
    idm: list[tuple[Path, dict[str, Any]]] = []
    ad: list[tuple[Path, dict[str, Any]]] = []
    for path, data in summaries:
        ctype = data.get("collector_type") or classify_path(path)
        if ctype == "linux":
            linux.append((path, data))
        elif ctype == "idm":
            idm.append((path, data))
        elif ctype == "ad":
            ad.append((path, data))
    return linux, idm, ad


# --------------------------- FAQ 003 checklist ---------------------------

def check_trust_both_sides(idm, ad) -> CheckResult:
    idm_ok = any(int(str(d.get("trust", {}).get("count", 0)) or 0) > 0 for _, d in idm)
    ad_ok = any(bool(d.get("Trusts", {}).get("IdmTrustDetected")) for _, d in ad)
    if idm_ok and ad_ok:
        status = "pass"
    elif idm_ok or ad_ok:
        status = "warn"
    elif not idm and not ad:
        status = "unknown"
    else:
        status = "fail"
    evidence = []
    for _, d in idm:
        evidence.append(f"IdM: trust_count={d.get('trust', {}).get('count')} realms={d.get('trust', {}).get('realms')}")
    for _, d in ad:
        evidence.append(f"AD:  IdmTrustDetected={d.get('Trusts', {}).get('IdmTrustDetected')} total_trusts={d.get('Trusts', {}).get('Count')}")
    return CheckResult(
        key="trust_both_sides",
        description="Cross-forest trust visible from both IdM and AD",
        status=status,
        evidence=evidence,
        citation="installing-idm §35.8; planning-idm §7",
    )


def check_idrange_type(idm) -> CheckResult:
    types = set()
    for _, d in idm:
        v = d.get("trust", {}).get("idrange_types") or ""
        for t in str(v).split(","):
            t = t.strip()
            if t:
                types.add(t)
    trust_types = {t for t in types if t.startswith("ipa-ad-trust")}
    status = "pass" if trust_types else ("unknown" if not idm else "fail")
    return CheckResult(
        key="idrange_type",
        description="IdM has an ipa-ad-trust or ipa-ad-trust-posix ID range",
        status=status,
        evidence=[f"idrange_types={sorted(types) or 'none'}"],
        citation="planning-idm §7.5",
    )


def check_external_groups(idm) -> CheckResult:
    ext_total = sum(int(str(d.get("groups", {}).get("external", 0)) or 0) for _, d in idm)
    status = "pass" if ext_total > 0 else ("unknown" if not idm else "fail")
    return CheckResult(
        key="external_groups",
        description="At least one non-POSIX external IdM group exists (holds AD SIDs)",
        status=status,
        evidence=[f"external_group_count={ext_total}"],
        citation="planning-idm §7.8; managing-idm ch23",
    )


def check_two_group_pattern(idm) -> CheckResult:
    nested = sum(int(str(d.get("groups", {}).get("external_nested_in_posix", 0)) or 0) for _, d in idm)
    ext_total = sum(int(str(d.get("groups", {}).get("external", 0)) or 0) for _, d in idm)
    if ext_total == 0:
        status = "unknown"
    elif nested > 0:
        status = "pass"
    else:
        status = "fail"
    return CheckResult(
        key="two_group_pattern",
        description="External groups nested inside POSIX IdM groups (the two-group pattern)",
        status=status,
        evidence=[f"external_nested_in_posix={nested} / external_total={ext_total}"],
        citation="configuring-and-managing-idm ch56 (sudo for AD users)",
    )


def check_hbac_rules_referencing_groups(idm) -> CheckResult:
    with_groups = sum(int(str(d.get("policy", {}).get("hbac_rules_with_user_groups", 0)) or 0) for _, d in idm)
    total = sum(int(str(d.get("policy", {}).get("hbac_rule_count", 0)) or 0) for _, d in idm)
    if not idm:
        status = "unknown"
    elif with_groups > 0:
        status = "pass"
    elif total == 0:
        status = "fail"
    else:
        status = "warn"
    return CheckResult(
        key="hbac_group_wiring",
        description="HBAC rules reference user groups (so AD users can be targeted via POSIX groups)",
        status=status,
        evidence=[f"hbac_total={total} hbac_with_user_groups={with_groups}"],
        citation="configuring-and-managing-idm ch57",
    )


def check_sudo_rules_referencing_groups(idm) -> CheckResult:
    with_groups = sum(int(str(d.get("policy", {}).get("sudo_rules_with_user_groups", 0)) or 0) for _, d in idm)
    total = sum(int(str(d.get("policy", {}).get("sudo_rule_count", 0)) or 0) for _, d in idm)
    if not idm:
        status = "unknown"
    elif with_groups > 0:
        status = "pass"
    elif total == 0:
        status = "fail"
    else:
        status = "warn"
    return CheckResult(
        key="sudo_group_wiring",
        description="Sudo rules reference user groups",
        status=status,
        evidence=[f"sudo_total={total} sudo_with_user_groups={with_groups}"],
        citation="configuring-and-managing-idm ch56",
    )


def check_linux_enrolled_into_idm(linux) -> CheckResult:
    if not linux:
        return CheckResult(
            key="linux_enrolled",
            description="Linux hosts are enrolled into IdM (not directly into AD)",
            status="unknown",
            evidence=["no Linux collectors present"],
            citation="planning-idm §6; FAQ 003",
        )
    target = [d.get("host_fqdn") for _, d in linux if d.get("classification") == LINUX_TARGET]
    direct = [d.get("host_fqdn") for _, d in linux if d.get("classification") == LINUX_DIRECT_AD]
    split  = [d.get("host_fqdn") for _, d in linux if d.get("classification") == LINUX_SPLIT]
    other  = [d.get("host_fqdn") for _, d in linux if d.get("classification") not in (LINUX_TARGET, LINUX_DIRECT_AD, LINUX_SPLIT)]

    if direct or split:
        status = "fail"
    elif len(target) == len(linux):
        status = "pass"
    else:
        status = "warn"
    evidence = []
    if target: evidence.append(f"target ({len(target)}): {', '.join(str(x) for x in target)}")
    if direct: evidence.append(f"direct-AD (anti-pattern) ({len(direct)}): {', '.join(str(x) for x in direct)}")
    if split:  evidence.append(f"split-provider ({len(split)}): {', '.join(str(x) for x in split)}")
    if other:  evidence.append(f"other ({len(other)}): {', '.join(str(x) for x in other)}")
    return CheckResult(
        key="linux_enrolled",
        description="Linux hosts are enrolled into IdM (not directly into AD)",
        status=status,
        evidence=evidence,
        citation="planning-idm §6; FAQ 003",
    )


def check_break_glass_admin(idm) -> CheckResult:
    # Heuristic: admins group should have 2+ members (the built-in 'admin' + at
    # least one additional native IdM administrator kept for break-glass).
    if not idm:
        return CheckResult(
            key="break_glass_admin",
            description="Native IdM admin user(s) beyond the default 'admin' exist for break-glass",
            status="unknown",
            evidence=["no IdM collectors present"],
            citation="FAQ 003 operational recommendation",
        )
    counts = [int(str(d.get("accounts", {}).get("admins_member_count", 0)) or 0) for _, d in idm]
    native_users = [int(str(d.get("accounts", {}).get("native_user_count", 0)) or 0) for _, d in idm]
    admin_max = max(counts) if counts else 0
    users_max = max(native_users) if native_users else 0
    if admin_max >= 2:
        status = "pass"
    elif users_max > 1:
        status = "warn"   # there are native users; we just can't confirm admins membership
    else:
        status = "fail"
    return CheckResult(
        key="break_glass_admin",
        description="Native IdM admin user(s) beyond the default 'admin' exist for break-glass",
        status=status,
        evidence=[f"admins_member_count_max={admin_max} native_user_count_max={users_max}"],
        citation="FAQ 003 operational recommendation",
    )


def check_aes(ad) -> CheckResult:
    if not ad:
        return CheckResult(
            key="ad_aes",
            description="AES Kerberos encryption enabled on all DCs",
            status="unknown",
            evidence=["no AD collector output"],
            citation="installing-idm §35.4",
        )
    statuses = [d.get("Encryption", {}).get("DcAesSupport") for _, d in ad]
    pass_values = {"aes_enabled_on_all_dcs"}
    if any(s in pass_values for s in statuses):
        status = "pass"
    elif any("missing" in (s or "") for s in statuses):
        status = "fail"
    else:
        status = "warn"
    return CheckResult(
        key="ad_aes",
        description="AES Kerberos encryption enabled on all DCs",
        status=status,
        evidence=[f"dc_aes_support={statuses}"],
        citation="installing-idm §35.4",
    )


def check_functional_level(ad) -> CheckResult:
    if not ad:
        return CheckResult(
            key="ad_functional_level",
            description="AD forest/domain at Windows Server 2012 level or higher",
            status="unknown",
            evidence=["no AD collector output"],
            citation="installing-idm §35.1",
        )
    modes = []
    all_ok = True
    for _, d in ad:
        dok = d.get("Domain", {}).get("ModeOk")
        fok = d.get("Forest", {}).get("ModeOk")
        dmode = d.get("Domain", {}).get("Mode")
        fmode = d.get("Forest", {}).get("Mode")
        modes.append(f"domain={dmode} ok={dok} / forest={fmode} ok={fok}")
        if dok is False or fok is False:
            all_ok = False
        if dok is None or fok is None:
            all_ok = None if all_ok is True else all_ok
    status = "pass" if all_ok is True else ("fail" if all_ok is False else "warn")
    return CheckResult(
        key="ad_functional_level",
        description="AD forest/domain at Windows Server 2012 level or higher",
        status=status,
        evidence=modes,
        citation="installing-idm §35.1",
    )


def check_dns_forwarder_on_ad(ad) -> CheckResult:
    if not ad:
        return CheckResult(
            key="ad_dns_forwarder",
            description="AD has a conditional DNS forwarder to the IdM DNS zone",
            status="unknown",
            evidence=["no AD collector output"],
            citation="installing-idm §35.6",
        )
    any_fwd = any(len(d.get("Dns", {}).get("ConditionalForwardersToIdm") or []) > 0 for _, d in ad)
    status = "pass" if any_fwd else "fail"
    evidence = []
    for _, d in ad:
        evidence.append(f"{d.get('ComputerName')}: {d.get('Dns', {}).get('ConditionalForwardersToIdm')}")
    return CheckResult(
        key="ad_dns_forwarder",
        description="AD has a conditional DNS forwarder to the IdM DNS zone",
        status=status,
        evidence=evidence,
        citation="installing-idm §35.6",
    )


def check_dns_forwarder_on_idm(idm) -> CheckResult:
    if not idm:
        return CheckResult(
            key="idm_dns_forwarder",
            description="IdM has a DNS forward zone for the AD DNS domain",
            status="unknown",
            evidence=["no IdM collector output"],
            citation="installing-idm §35.6",
        )
    zones = []
    for _, d in idm:
        v = d.get("dns", {}).get("forwardzones") or ""
        if v:
            zones.append(v)
    status = "pass" if zones else "fail"
    return CheckResult(
        key="idm_dns_forwarder",
        description="IdM has a DNS forward zone for the AD DNS domain",
        status=status,
        evidence=zones or ["no forwardzones found"],
        citation="installing-idm §35.6",
    )


def check_linux_in_ad(ad) -> CheckResult:
    if not ad:
        return CheckResult(
            key="no_linux_in_ad",
            description="No Linux computer objects in AD (Linux should enroll into IdM)",
            status="unknown",
            evidence=["no AD collector output"],
            citation="planning-idm §6",
        )
    total = 0
    names = []
    for _, d in ad:
        n = int(d.get("Computers", {}).get("LikelyLinuxComputerCount") or 0)
        total += n
        names.extend(d.get("Computers", {}).get("LikelyLinuxNames") or [])
    if total == 0:
        status = "pass"
    else:
        status = "warn"
    return CheckResult(
        key="no_linux_in_ad",
        description="No Linux computer objects in AD (Linux should enroll into IdM)",
        status=status,
        evidence=[f"likely_linux_in_ad={total}"] + ([f"names={names[:10]}"] if names else []),
        citation="planning-idm §6; FAQ 003",
    )


def check_group_scope(ad) -> CheckResult:
    if not ad:
        return CheckResult(
            key="ad_group_scope",
            description="AD groups intended for Linux policy are Global/Universal (not Domain Local)",
            status="unknown",
            evidence=["no AD collector output"],
            citation="configuring-and-managing-idm ch56 (Domain Local can't traverse trust)",
        )
    details = []
    for _, d in ad:
        g = int(d.get("Groups", {}).get("Global")      or 0)
        u = int(d.get("Groups", {}).get("Universal")   or 0)
        dl = int(d.get("Groups", {}).get("DomainLocal") or 0)
        details.append(f"{d.get('ComputerName')}: G={g} U={u} DL={dl}")
    # This is informational; we can't tell from scope alone which groups are
    # _intended_ for Linux, so we warn if domain-local dominates.
    return CheckResult(
        key="ad_group_scope",
        description="AD groups intended for Linux policy are Global/Universal (not Domain Local)",
        status="warn",
        evidence=details,
        citation="configuring-and-managing-idm ch56",
    )


# --------------------------- Overall rollup ---------------------------

def overall_model(checks: list[CheckResult]) -> str:
    statuses = [c.status for c in checks]
    if "fail" in statuses:
        if any(c.status == "pass" for c in checks):
            return "partial_implementation"
        return "gap_heavy"
    if "warn" in statuses and "pass" in statuses:
        return "near_target"
    if all(s == "pass" for s in statuses):
        return "target_aligned"
    if all(s == "unknown" for s in statuses):
        return "insufficient_data"
    return "in_progress"


# --------------------------- Rendering ---------------------------

STATUS_MARK = {
    "pass": "PASS",
    "fail": "FAIL",
    "warn": "WARN",
    "unknown": " ?  ",
}


def render_text(root: Path, linux, idm, ad, checks: list[CheckResult], model: str) -> str:
    lines: list[str] = []
    lines.append("Integrated IdM / AD Assessment")
    lines.append("==============================")
    lines.append(f"Root:               {root}")
    lines.append(f"Overall model:      {model}")
    lines.append(f"Counts:             linux={len(linux)} idm={len(idm)} ad={len(ad)}")
    lines.append("")

    def _qual(d: dict) -> str:
        lg = d.get("logging") or {}
        w = lg.get("warn_count", "-")
        e = lg.get("error_count", "-")
        return f"warn={w} err={e}"

    if linux:
        lines.append("Linux clients")
        lines.append("-------------")
        for path, d in linux:
            lines.append(
                f"  {d.get('host_fqdn','?')}  class={d.get('classification')}  "
                f"enrolled={d.get('enrollment', {}).get('ipa_client_enrolled')}  "
                f"id={d.get('sssd', {}).get('id_provider')}  auth={d.get('sssd', {}).get('auth_provider')}  "
                f"access={d.get('sssd', {}).get('access_provider')}  sudo={d.get('sssd', {}).get('sudo_provider')}  "
                f"ad_subdomain_visible={d.get('sssd', {}).get('ad_subdomain_visible')}  "
                f"{_qual(d)}  [{path.parent.name}]"
            )
        lines.append("")

    if idm:
        lines.append("IdM servers")
        lines.append("-----------")
        for path, d in idm:
            t = d.get("trust", {})
            g = d.get("groups", {})
            p = d.get("policy", {})
            lines.append(
                f"  {d.get('host_fqdn','?')}  class={d.get('classification')}  "
                f"trusts={t.get('count')}({t.get('realms') or 'none'})  "
                f"idrange={t.get('idrange_types') or 'none'}  "
                f"ext_groups={g.get('external')}/nested={g.get('external_nested_in_posix')}  "
                f"hbac={p.get('hbac_rule_count')}/{p.get('hbac_rules_with_user_groups')}  "
                f"sudo={p.get('sudo_rule_count')}/{p.get('sudo_rules_with_user_groups')}  "
                f"{_qual(d)}  [{path.parent.name}]"
            )
        lines.append("")

    if ad:
        lines.append("AD servers")
        lines.append("----------")
        for path, d in ad:
            t = d.get("Trusts", {})
            enc = d.get("Encryption", {})
            comp = d.get("Computers", {})
            lines.append(
                f"  {d.get('ComputerName','?')}  class={d.get('Classification')}  "
                f"trusts={t.get('Count')} idm_match={t.get('IdmTrustDetected')}  "
                f"dc_aes={enc.get('DcAesSupport')}  "
                f"domain_mode={d.get('Domain', {}).get('Mode')} ok={d.get('Domain', {}).get('ModeOk')}  "
                f"linux_in_ad={comp.get('LikelyLinuxComputerCount')}  "
                f"adfs_installed={d.get('Adfs', {}).get('Installed')}  "
                f"[{path.parent.name}]"
            )
        lines.append("")

    lines.append("FAQ 003 checklist")
    lines.append("-----------------")
    for c in checks:
        lines.append(f"[{STATUS_MARK[c.status]}] {c.description}")
        for e in c.evidence:
            lines.append(f"         - {e}")
        if c.citation:
            lines.append(f"         cite: {c.citation}")
    lines.append("")

    lines.append("Next steps")
    lines.append("----------")
    fails = [c for c in checks if c.status == "fail"]
    warns = [c for c in checks if c.status == "warn"]
    unknowns = [c for c in checks if c.status == "unknown"]
    if fails:
        lines.append("Priority (FAIL):")
        for c in fails:
            lines.append(f"  - {c.description}  (see {c.citation})")
    if warns:
        lines.append("Review (WARN):")
        for c in warns:
            lines.append(f"  - {c.description}  (see {c.citation})")
    if unknowns and not fails and not warns:
        lines.append("Incomplete data (UNKNOWN): run missing collectors to populate the checklist.")
    if not fails and not warns and not unknowns:
        lines.append("All checks pass. Validate with a real AD-user login + sudo on a sample IdM-enrolled host.")
    lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    summaries = load_summaries(root)
    linux, idm, ad = bucket(summaries)

    checks: list[CheckResult] = [
        check_trust_both_sides(idm, ad),
        check_idrange_type(idm),
        check_external_groups(idm),
        check_two_group_pattern(idm),
        check_hbac_rules_referencing_groups(idm),
        check_sudo_rules_referencing_groups(idm),
        check_linux_enrolled_into_idm(linux),
        check_break_glass_admin(idm),
        check_functional_level(ad),
        check_aes(ad),
        check_dns_forwarder_on_ad(ad),
        check_dns_forwarder_on_idm(idm),
        check_linux_in_ad(ad),
        check_group_scope(ad),
    ]
    model = overall_model(checks)

    text = render_text(root, linux, idm, ad, checks, model)
    out_txt = root / "assessment-summary.txt"
    out_txt.write_text(text)

    out_json = root / "assessment-summary.json"
    out_json.write_text(json.dumps({
        "root": str(root),
        "overall_model": model,
        "counts": {"linux": len(linux), "idm": len(idm), "ad": len(ad)},
        "checks": [
            {
                "key": c.key,
                "description": c.description,
                "status": c.status,
                "evidence": c.evidence,
                "citation": c.citation,
            }
            for c in checks
        ],
    }, indent=2) + "\n")

    print(f"Wrote {out_txt}")
    print(f"Wrote {out_json}")
    print(f"Overall model: {model}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
