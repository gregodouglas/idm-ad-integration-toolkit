# AD collector — assess fit against FAQ 003 target architecture.
# Signals: domain/forest functional level (>= 2012 required for IdM trust),
# AES Kerberos encryption on DCs, trust specifically to the IdM forest,
# conditional DNS forwarder to IdM, AD group-scope composition (Domain Local
# cannot be referenced through the trust), and Linux computer objects that
# might indicate direct-integration hosts bypassing IdM.

param(
    [string]$OutDir = ".\collector-output\ad-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [string]$IdmRealmHint = ''   # e.g. 'idm.enclave.com'; helps match the trust
)

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$Report    = Join-Path $OutDir 'report.txt'
$Summary   = Join-Path $OutDir 'summary.json'
$Checklist = Join-Path $OutDir 'checklist.txt'

function Add-Section {
    param([string]$Title, [scriptblock]$Script)
    Add-Content -Path $Report -Value "`r`n### $Title"
    try {
        & $Script | Out-String -Width 300 | Add-Content -Path $Report
    } catch {
        Add-Content -Path $Report -Value "[WARN] $($_.Exception.Message)"
    }
}

# --- Raw collection with error tolerance ---
$DomainName              = $null
$ForestName              = $null
$DomainMode              = $null
$ForestMode              = $null
$TrustCount              = 0
$AdfsInstalled           = $false
$AdfsServiceRunning      = $false
$ComputerCount           = 0
$LikelyLinuxComputerCount = 0
$LikelyLinuxNames        = @()
$IdmTrustDetected        = $false
$IdmTrustDetails         = @()
$DcAesSupport            = 'unknown'
$DcEncryptionDetails     = @()
$GroupScopeGlobal        = 0
$GroupScopeUniversal     = 0
$GroupScopeDomainLocal   = 0
$ConditionalForwardersToIdm = @()
$AllConditionalForwarders = @()

try { $Domain = Get-ADDomain; $DomainName = $Domain.DNSRoot; $DomainMode = $Domain.DomainMode.ToString() } catch {}
try { $Forest = Get-ADForest; $ForestName = $Forest.RootDomain; $ForestMode = $Forest.ForestMode.ToString() } catch {}

try {
    $Trusts = Get-ADTrust -Filter * -Properties * -ErrorAction Stop
    if ($Trusts) { $TrustCount = @($Trusts).Count }
    foreach ($t in @($Trusts)) {
        $match = $false
        if ($IdmRealmHint -and $t.Target -like "*$IdmRealmHint*") { $match = $true }
        if (-not $match -and $t.Target -match '(^|\.)(idm|ipa)\.') { $match = $true }
        if (-not $match -and $t.Name   -match '(^|\.)(idm|ipa)\.') { $match = $true }
        if ($match) { $IdmTrustDetected = $true }
        $IdmTrustDetails += [ordered]@{
            Name      = $t.Name
            Target    = $t.Target
            Direction = $t.Direction.ToString()
            TrustType = $t.TrustType.ToString()
            ForestTransitive = $t.ForestTransitive
            SelectiveAuthentication = $t.SelectiveAuthentication
            MatchedIdM = $match
        }
    }
} catch {}

try {
    $Computers = Get-ADComputer -Filter * -Properties OperatingSystem,ServicePrincipalName
    if ($Computers) { $ComputerCount = @($Computers).Count }
} catch {}

try {
    $LinuxComputers = Get-ADComputer -Filter 'OperatingSystem -like "*Linux*" -or OperatingSystem -like "*Red Hat*" -or OperatingSystem -like "*CentOS*" -or Name -like "*rhel*" -or Name -like "*lin*"' `
                        -Properties OperatingSystem,DNSHostName
    $LikelyLinuxComputerCount = @($LinuxComputers).Count
    $LikelyLinuxNames = @($LinuxComputers | Select-Object -ExpandProperty Name)
} catch {}

try { $AdfsFeature = Get-WindowsFeature ADFS-Federation -ErrorAction Stop; if ($AdfsFeature -and $AdfsFeature.Installed) { $AdfsInstalled = $true } } catch {}
try { $Svc = Get-Service adfssrv -ErrorAction Stop; if ($Svc.Status -eq 'Running') { $AdfsServiceRunning = $true } } catch {}

# AES Kerberos encryption on DCs (msDS-SupportedEncryptionTypes).
# Bit values: 0x08 = AES128, 0x10 = AES256 per §35.4.
try {
    $DCs = Get-ADDomainController -Filter * -ErrorAction Stop
    $allAes = $true
    foreach ($dc in $DCs) {
        $cobj = Get-ADComputer $dc.ComputerObjectDN -Properties 'msDS-SupportedEncryptionTypes' -ErrorAction Stop
        $v = $cobj.'msDS-SupportedEncryptionTypes'
        $aesOk = $false
        if ($v -and (($v -band 0x08) -or ($v -band 0x10))) { $aesOk = $true }
        if (-not $aesOk) { $allAes = $false }
        $DcEncryptionDetails += [ordered]@{
            Name = $dc.HostName
            EncTypesBitmask = $v
            HasAES128 = (($v -band 0x08) -ne 0)
            HasAES256 = (($v -band 0x10) -ne 0)
        }
    }
    $DcAesSupport = if ($allAes) { 'aes_enabled_on_all_dcs' } else { 'aes_missing_on_one_or_more_dcs' }
} catch {
    $DcAesSupport = "lookup_failed: $($_.Exception.Message)"
}

# Group scope tally — Domain Local groups can't be referenced across the trust
try {
    $AllGroups = Get-ADGroup -Filter * -Properties GroupScope -ErrorAction Stop
    foreach ($g in $AllGroups) {
        switch ($g.GroupScope.ToString()) {
            'Global'      { $GroupScopeGlobal++ }
            'Universal'   { $GroupScopeUniversal++ }
            'DomainLocal' { $GroupScopeDomainLocal++ }
        }
    }
} catch {}

# DNS conditional forwarders — need one for the IdM DNS zone in the trust pattern
try {
    $fwd = Get-DnsServerZone -ErrorAction Stop | Where-Object { $_.ZoneType -eq 'Forwarder' }
    foreach ($z in $fwd) {
        $AllConditionalForwarders += $z.ZoneName
        $matchIdm = $false
        if ($IdmRealmHint -and $z.ZoneName -like "*$IdmRealmHint*") { $matchIdm = $true }
        if (-not $matchIdm -and $z.ZoneName -match '(^|\.)(idm|ipa)\.') { $matchIdm = $true }
        if ($matchIdm) { $ConditionalForwardersToIdm += $z.ZoneName }
    }
} catch {}

# Functional-level check against §35.1 (trust requires >= Windows Server 2012)
function Test-FunctionalLevelSufficient([string]$mode) {
    if (-not $mode) { return $null }
    # DomainMode / ForestMode strings include e.g. Windows2012Domain, Windows2016Forest
    if ($mode -match 'Windows2000|Windows2003|Windows2008') { return $false }
    if ($mode -match 'Windows2012|Windows2016|Windows2019|Windows2022') { return $true }
    return $null
}
$DomainLevelOk = Test-FunctionalLevelSufficient $DomainMode
$ForestLevelOk = Test-FunctionalLevelSufficient $ForestMode

# --- Classification aligned to FAQ 003 ---
$Classification = 'ad_unknown_state'
$TargetGap = ''

if ($TrustCount -eq 0) {
    $Classification = 'ad_no_idm_trust'
    $TargetGap = 'No trusts detected from AD. Establish cross-forest trust with IdM (ipa trust-add on IdM server).'
} elseif (-not $IdmTrustDetected) {
    $Classification = 'ad_trust_but_no_idm_match'
    $TargetGap = "AD has $TrustCount trust(s) but none match an IdM realm hint. Pass -IdmRealmHint 'idm.enclave.com' and rerun, or inspect trust targets manually."
} elseif ($DomainLevelOk -eq $false -or $ForestLevelOk -eq $false) {
    $Classification = 'ad_idm_trust_with_functional_level_gap'
    $TargetGap = "Trust exists to IdM but functional level is below Windows Server 2012 (domain=$DomainMode, forest=$ForestMode). Raise levels before relying on the trust."
} elseif ($DcAesSupport -eq 'aes_missing_on_one_or_more_dcs') {
    $Classification = 'ad_idm_trust_with_aes_gap'
    $TargetGap = 'Trust exists and matches IdM, but AES is not set on msDS-SupportedEncryptionTypes for all DCs. Enable AES per §35.4 (Default Domain Controller Policy).'
} elseif ($ConditionalForwardersToIdm.Count -eq 0) {
    $Classification = 'ad_idm_trust_with_dns_gap'
    $TargetGap = "Trust to IdM detected, but no conditional forwarder to an IdM DNS zone found. Add a forwarder for the IdM primary DNS domain per §35.6."
} elseif ($LikelyLinuxComputerCount -gt 0) {
    $Classification = 'ad_idm_trust_with_linux_in_ad'
    $TargetGap = "Trust is healthy, but $LikelyLinuxComputerCount Linux-looking computer object(s) exist in AD. In the FAQ 003 model, Linux hosts enroll to IdM, not AD. Review and migrate where appropriate."
} else {
    $Classification = 'ad_target_ready'
    $TargetGap = 'AD side appears aligned: trust to IdM present, functional level OK, AES on DCs, DNS forwarder present, and no Linux objects directly in AD.'
}

# --- Summary JSON ---
$SummaryObject = [ordered]@{
    collector_type             = 'ad'
    schema_version             = 2
    ComputerName               = $env:COMPUTERNAME
    Domain = [ordered]@{
        Name     = $DomainName
        Mode     = $DomainMode
        ModeOk   = $DomainLevelOk
    }
    Forest = [ordered]@{
        Name     = $ForestName
        Mode     = $ForestMode
        ModeOk   = $ForestLevelOk
    }
    Trusts = [ordered]@{
        Count              = $TrustCount
        IdmRealmHint       = $IdmRealmHint
        IdmTrustDetected   = $IdmTrustDetected
        Details            = $IdmTrustDetails
    }
    Encryption = [ordered]@{
        DcAesSupport       = $DcAesSupport
        DcDetails          = $DcEncryptionDetails
    }
    Groups = [ordered]@{
        Global       = $GroupScopeGlobal
        Universal    = $GroupScopeUniversal
        DomainLocal  = $GroupScopeDomainLocal
    }
    Dns = [ordered]@{
        ConditionalForwarders        = $AllConditionalForwarders
        ConditionalForwardersToIdm   = $ConditionalForwardersToIdm
    }
    Computers = [ordered]@{
        TotalCount               = $ComputerCount
        LikelyLinuxComputerCount = $LikelyLinuxComputerCount
        LikelyLinuxNames         = $LikelyLinuxNames
    }
    Adfs = [ordered]@{
        Installed        = $AdfsInstalled
        ServiceRunning   = $AdfsServiceRunning
    }
    Classification   = $Classification
    TargetGap        = $TargetGap
}
$SummaryObject | ConvertTo-Json -Depth 6 | Set-Content -Path $Summary

# --- Verbose report ---
"Collector started on $(Get-Date -Format o)" | Set-Content -Path $Report
"Server: $env:COMPUTERNAME"                  | Add-Content -Path $Report
"IdmRealmHint: $IdmRealmHint"                | Add-Content -Path $Report
"Classification: $Classification"            | Add-Content -Path $Report

Add-Section 'AD Domain'                 { Get-ADDomain | Format-List * }
Add-Section 'AD Forest'                 { Get-ADForest | Format-List * }
Add-Section 'AD Trusts (all)'           { Get-ADTrust -Filter * -Properties * | Format-List * }
Add-Section 'Kerberos policy'           { Get-ADDefaultDomainPasswordPolicy | Format-List * }
Add-Section 'DC encryption types'       {
    foreach ($d in $DcEncryptionDetails) {
        [PSCustomObject]$d
    }
}
Add-Section 'Domain controllers'        { Get-ADDomainController -Filter * | Format-Table -AutoSize HostName,Site,OperatingSystem,IsGlobalCatalog }
Add-Section 'Group scope tally'         {
    [PSCustomObject]@{
        Global      = $GroupScopeGlobal
        Universal   = $GroupScopeUniversal
        DomainLocal = $GroupScopeDomainLocal
    }
}
Add-Section 'All DNS conditional forwarders'    { $AllConditionalForwarders | Sort-Object -Unique }
Add-Section 'ADFS feature'              { Get-WindowsFeature ADFS-Federation | Format-List * }
Add-Section 'ADFS service'              { Get-Service adfssrv -ErrorAction SilentlyContinue | Format-List * }
Add-Section 'Top 50 computer SPNs'      { Get-ADComputer -Filter * -Properties ServicePrincipalName | Select-Object -First 50 Name,OperatingSystem,ServicePrincipalName | Format-List * }
Add-Section 'Likely Linux computer objects' {
    Get-ADComputer -Filter 'OperatingSystem -like "*Linux*" -or OperatingSystem -like "*Red Hat*" -or OperatingSystem -like "*CentOS*" -or Name -like "*rhel*" -or Name -like "*lin*"' `
        -Properties OperatingSystem,DNSHostName,ServicePrincipalName `
    | Select-Object Name,DNSHostName,OperatingSystem,ServicePrincipalName `
    | Format-List *
}
Add-Section 'First 100 groups by name'  { Get-ADGroup -Filter * | Select-Object -First 100 Name,GroupScope,GroupCategory | Format-Table -AutoSize }
Add-Section 'DNS SRV for Kerberos'      { try { Resolve-DnsName -Type SRV "_kerberos._tcp.$DomainName" } catch {} }
Add-Section 'DNS SRV for LDAP'          { try { Resolve-DnsName -Type SRV "_ldap._tcp.$DomainName"     } catch {} }
if ($IdmRealmHint) {
    Add-Section "DNS SRV for IdM Kerberos ($IdmRealmHint)" { try { Resolve-DnsName -Type SRV "_kerberos._tcp.$IdmRealmHint" } catch {} }
}
Add-Section 'Windows Time service'      { Get-Service W32Time | Format-List * }
Add-Section 'SPN query for ADFS'        { try { cmd /c 'setspn -Q */*adfs*' } catch {} }

# --- Checklist ---
@"
AD Collector Checklist (aligned with FAQ 003)
=============================================
Server: $env:COMPUTERNAME
IdM realm hint: $IdmRealmHint

Target architecture (FAQ 003)
-----------------------------
- AD forest functional level >= Windows Server 2012 (§35.1)
- AES Kerberos encryption enabled on DCs (§35.4)
- Cross-forest trust to the IdM realm (§35.8)
- Conditional DNS forwarder to the IdM DNS zone (§35.6)
- AD groups for Linux policy are Global or Universal scope
  (Domain Local cannot traverse the trust — §56 citation in FAQ 001)
- Linux hosts enroll into IdM, not AD

Observed state
--------------
- Domain / Forest:            $DomainName / $ForestName
- Domain mode / ok:           $DomainMode / $DomainLevelOk
- Forest mode / ok:           $ForestMode / $ForestLevelOk
- Total trusts:               $TrustCount
- IdM trust detected:         $IdmTrustDetected
- DC AES encryption:          $DcAesSupport
- Group scope (G/U/DL):       $GroupScopeGlobal / $GroupScopeUniversal / $GroupScopeDomainLocal
- DNS forwarders (all):       $($AllConditionalForwarders -join ', ')
- DNS forwarders to IdM:      $($ConditionalForwardersToIdm -join ', ')
- Total computer objects:     $ComputerCount
- Linux-looking computers:    $LikelyLinuxComputerCount  ($(($LikelyLinuxNames | Select-Object -First 5) -join ', ')...)
- ADFS installed / running:   $AdfsInstalled / $AdfsServiceRunning

Classification
--------------
- Current: $Classification
- Gap:     $TargetGap

What to review next
-------------------
- Trust target and direction; confirm type matches IdM-as-forest (§35.2)
- AES bitmask on msDS-SupportedEncryptionTypes per DC (§35.4)
- Conditional forwarder for the IdM DNS zone on the DC (§35.6)
- Group scopes for any AD groups that need to drive IdM-side policy
- Linux objects in AD: migrate to IdM enrollment or intentionally scope as direct-integration hosts
"@ | Set-Content -Path $Checklist

Write-Host "Wrote AD collector output to $OutDir"
