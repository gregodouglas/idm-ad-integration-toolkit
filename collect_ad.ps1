param(
    [string]$OutDir = ".\collector-output\ad-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$Report = Join-Path $OutDir 'report.txt'
$Summary = Join-Path $OutDir 'summary.json'
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

$DomainName = $null
$ForestName = $null
$TrustCount = 0
$AdfsInstalled = $false
$AdfsServiceRunning = $false
$ComputerCount = 0
$LikelyLinuxComputerCount = 0
$Classification = 'ad_present_unknown_state'
$TargetGap = ''

try { $Domain = Get-ADDomain; $DomainName = $Domain.DNSRoot } catch {}
try { $Forest = Get-ADForest; $ForestName = $Forest.RootDomain } catch {}
try { $Trusts = Get-ADTrust -Filter *; if ($Trusts) { $TrustCount = @($Trusts).Count } } catch {}
try { $Computers = Get-ADComputer -Filter * -Properties OperatingSystem,ServicePrincipalName; if ($Computers) { $ComputerCount = @($Computers).Count } } catch {}
try { $LikelyLinuxComputerCount = @(Get-ADComputer -Filter 'OperatingSystem -like "*Linux*" -or OperatingSystem -like "*Red Hat*" -or Name -like "*rhel*" -or Name -like "*lin*"').Count } catch {}
try { $AdfsFeature = Get-WindowsFeature ADFS-Federation; if ($AdfsFeature -and $AdfsFeature.Installed) { $AdfsInstalled = $true } } catch {}
try { $Svc = Get-Service adfssrv -ErrorAction Stop; if ($Svc.Status -eq 'Running') { $AdfsServiceRunning = $true } } catch {}

if ($TrustCount -gt 0 -and $LikelyLinuxComputerCount -gt 0) {
    $Classification = 'ad_ready_for_hybrid_linux_auth'
    $TargetGap = 'Validate Linux clients authenticate directly to AD and consume IDM policy separately'
} elseif ($TrustCount -gt 0) {
    $Classification = 'ad_trust_present_linux_state_unclear'
    $TargetGap = 'Review Linux client joins and SSSD configs'
} else {
    $Classification = 'ad_without_visible_trusts'
    $TargetGap = 'No trust detected from this host perspective; hybrid target may be incomplete'
}

$SummaryObject = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    DomainName = $DomainName
    ForestName = $ForestName
    TrustCount = $TrustCount
    AdfsInstalled = $AdfsInstalled
    AdfsServiceRunning = $AdfsServiceRunning
    ComputerCount = $ComputerCount
    LikelyLinuxComputerCount = $LikelyLinuxComputerCount
    Classification = $Classification
    TargetGap = $TargetGap
}
$SummaryObject | ConvertTo-Json -Depth 4 | Set-Content -Path $Summary

"Collector started on $(Get-Date -Format o)" | Set-Content -Path $Report
"Server: $env:COMPUTERNAME" | Add-Content -Path $Report

Add-Section 'AD Domain' { Get-ADDomain | Format-List * }
Add-Section 'AD Forest' { Get-ADForest | Format-List * }
Add-Section 'AD Trusts' { Get-ADTrust -Filter * | Format-List * }
Add-Section 'Kerberos Policy' { Get-ADDefaultDomainPasswordPolicy | Format-List * }
Add-Section 'ADFS Feature' { Get-WindowsFeature ADFS-Federation | Format-List * }
Add-Section 'ADFS Service' { Get-Service adfssrv | Format-List * }
Add-Section 'Top Service Principal Names' { Get-ADComputer -Filter * -Properties ServicePrincipalName | Select-Object -First 50 Name,OperatingSystem,ServicePrincipalName | Format-List * }
Add-Section 'Likely Linux computers' { Get-ADComputer -Filter 'OperatingSystem -like "*Linux*" -or OperatingSystem -like "*Red Hat*" -or Name -like "*rhel*" -or Name -like "*lin*"' -Properties OperatingSystem,DNSHostName,ServicePrincipalName | Select-Object Name,DNSHostName,OperatingSystem,ServicePrincipalName | Format-List * }
Add-Section 'Top groups' { Get-ADGroup -Filter * | Select-Object -First 100 Name,GroupScope,GroupCategory | Format-Table -AutoSize }
Add-Section 'DNS SRV records for Kerberos' { Resolve-DnsName -Type SRV "_kerberos._tcp.$((Get-ADDomain).DNSRoot)" }
Add-Section 'DNS SRV records for LDAP' { Resolve-DnsName -Type SRV "_ldap._tcp.$((Get-ADDomain).DNSRoot)" }
Add-Section 'Windows Time service' { Get-Service W32Time | Format-List * }
Add-Section 'SPN query for ADFS' { cmd /c 'setspn -Q */*adfs*' }

@"
AD Collector Checklist
======================
Server: $env:COMPUTERNAME

Observed State
--------------
- Domain: $DomainName
- Forest: $ForestName
- Trust count: $TrustCount
- ADFS installed: $AdfsInstalled
- ADFS service running: $AdfsServiceRunning
- Computer count: $ComputerCount
- Likely Linux computer count: $LikelyLinuxComputerCount

Classification
--------------
- Current model: $Classification
- Gap to target: $TargetGap

Target Pattern to Compare Against
---------------------------------
- AD is authoritative for authentication
- AD trust or integration path exists for IDM/IPA
- Linux hosts represented in AD where expected
- ADFS may be added later for app/web SSO, separate from Linux PAM auth

What To Review Next
-------------------
- Trust details and scope
- Kerberos and LDAP SRV records
- Linux-related computer objects and SPNs
- Whether ADFS exists now or is just future state
"@ | Set-Content -Path $Checklist

Write-Host "Wrote AD collector output to $OutDir"
