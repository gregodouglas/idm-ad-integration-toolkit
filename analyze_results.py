#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path


def load_jsons(root: Path):
    for path in root.rglob('summary.json'):
        try:
            yield path, json.loads(path.read_text())
        except Exception:
            continue


def summarize(items):
    linux = []
    idm = []
    ad = []
    for path, data in items:
        p = str(path).lower()
        if '/linux-' in p or '\\linux-' in p:
            linux.append((path, data))
        elif '/idm-' in p or '\\idm-' in p:
            idm.append((path, data))
        elif '/ad-' in p or '\\ad-' in p:
            ad.append((path, data))
    return linux, idm, ad


def overall_model(linux, idm, ad):
    l_classes = {d.get('classification') for _, d in linux}
    i_classes = {d.get('classification') for _, d in idm}
    a_classes = {d.get('classification') for _, d in ad}

    if 'hybrid_target_pattern' in l_classes and any('trust' in c for c in i_classes if c):
        return 'hybrid_aligned_with_target'
    if 'direct_ad' in l_classes and not i_classes:
        return 'direct_ad_only'
    if 'indirect_via_idm' in l_classes:
        return 'indirect_via_idm'
    if l_classes or i_classes or a_classes:
        return 'mixed_or_incomplete'
    return 'unknown'


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else '.')
    items = list(load_jsons(root))
    linux, idm, ad = summarize(items)
    model = overall_model(linux, idm, ad)

    lines = []
    lines.append('Integrated IDM / AD Assessment')
    lines.append('==============================')
    lines.append(f'Root: {root}')
    lines.append(f'Overall model: {model}')
    lines.append('')

    if linux:
        lines.append('Linux clients')
        lines.append('-------------')
        for path, d in linux:
            lines.append(f"- {d.get('host_fqdn','unknown')}: {d.get('classification')} | auth={d.get('auth_provider')} access={d.get('access_provider')} sudo={d.get('sudo_provider')} | {path.parent}")
        lines.append('')

    if idm:
        lines.append('IDM servers')
        lines.append('-----------')
        for path, d in idm:
            lines.append(f"- {d.get('host_fqdn','unknown')}: {d.get('classification')} | trusts={d.get('trust_count')} hbac={d.get('hbac_rule_count')} sudo={d.get('sudo_rule_count')} | {path.parent}")
        lines.append('')

    if ad:
        lines.append('AD servers')
        lines.append('----------')
        for path, d in ad:
            lines.append(f"- {d.get('ComputerName','unknown')}: {d.get('classification')} | trusts={d.get('TrustCount')} adfs_installed={d.get('AdfsInstalled')} | {path.parent}")
        lines.append('')

    lines.append('Gap-oriented guidance')
    lines.append('---------------------')
    if model == 'hybrid_aligned_with_target':
        lines.append('- Environment appears close to target. Validate HBAC, sudo, keytabs, and a real user login path.')
    elif model == 'direct_ad_only':
        lines.append('- AD authentication is visible, but IDM Linux policy integration is not. Add or validate IDM trust and SSSD policy providers.')
    elif model == 'indirect_via_idm':
        lines.append('- Authentication appears to terminate in IDM. Revisit whether this conflicts with your AD-as-auth-source goal and future ADFS plans.')
    else:
        lines.append('- Configuration looks mixed or incomplete. Standardize join state, SSSD providers, Kerberos realm, and IDM trust/policy content.')

    out = root / 'assessment-summary.txt'
    out.write_text('\n'.join(lines) + '\n')
    print(f'Wrote {out}')


if __name__ == '__main__':
    main()
