# IDM / AD Collector Toolkit

This toolkit is intended for read-only discovery of a partially configured or partially completed IDM / AD integration.

Target platforms:
- RHEL 8+
- Windows Server 2019+

Included files:
- `collect_linux.sh` - run on Linux clients
- `collect_idm.sh` - run on IDM / FreeIPA servers
- `collect_ad.ps1` - run on a domain controller or management host with RSAT AD cmdlets
- `analyze_results.py` - optional summarizer across collected outputs

## Intended target architecture
- AD = sole source of truth for user authentication
- ADFS = future app / federation SSO
- IDM = Linux policy and host management (HBAC, sudo, host grouping)
- Linux = authenticate to AD, consume policy from IDM where applicable

## Typical usage

### Linux client
```bash
sudo bash collect_linux.sh /var/tmp/linux-collector
```

### IDM server
```bash
sudo bash collect_idm.sh /var/tmp/idm-collector
```

### AD / DC
```powershell
powershell -ExecutionPolicy Bypass -File .\collect_ad.ps1 -OutDir C:\Temp\ad-collector
```

### Aggregate results
Put collected output folders under one root and run:
```bash
python3 analyze_results.py /path/to/root
```

## Notes
- These scripts are intentionally read-only.
- Some commands may still require root or Domain Admin / delegated read access.
- On IDM, the `ipa` CLI must be available and authenticated in the current context for full output.
- The scripts are conservative and classify state based on observable configuration, not on every possible deployment nuance.
