# Read-only metadata collector. No hardware operations or GUI startup.
[CmdletBinding()]
param([switch]$DefinitionsOnly)
# No string coercion: arbitrary metadata text can never become numeric evidence.
function ConvertTo-NonnegativeInteger {
    param($Value)
    if (($Value -is [int] -or $Value -is [uint32]) -and $Value -ge 0) { return $Value }
    return $null
}
function New-EnvironmentRecord {
    param([hashtable]$Metadata)
    $build = $null
    if (($Metadata.os_build -is [string] -or $Metadata.os_build -is [int]) -and [string]$Metadata.os_build -match '\A[0-9]+\z' -and ($Metadata.ubr -is [int] -or $Metadata.ubr -is [uint32]) -and $Metadata.ubr -ge 0) {
        $build = '{0}.{1}' -f $Metadata.os_build,$Metadata.ubr
    }
    $policy = $null
    if ($Metadata.fDisableWebAuthn -is [int] -and $Metadata.fDisableWebAuthn -in @(0,1)) { $policy = $Metadata.fDisableWebAuthn }
    $clientVersion = $null
    $binary = $null
    if ($Metadata.client_version -is [string] -and $Metadata.client_version -match '\A[0-9]+(\.[0-9]+)*\z') {
        $clientVersion = $Metadata.client_version
        $binary = 'mstsc.exe'
    }
    $probePid = ConvertTo-NonnegativeInteger $Metadata.pid
    if ($probePid -eq 0) { $probePid = $null }
    $session = ConvertTo-NonnegativeInteger $Metadata.session_id
    $kind = 'unknown'
    if ($null -ne $session -and $session -eq 0) { $kind = 'noninteractive' }
    $api = ConvertTo-NonnegativeInteger $Metadata.api_version
    $supported = $null
    if ($null -ne $api) { $supported = $api -ge 4 }
    [ordered]@{
        schema_version = 1
        os_build = $build
        client = [ordered]@{ binary = $binary; version = $clientVersion }
        probe = [ordered]@{ pid = $probePid; session_id = $session; session_kind = $kind }
        api = [ordered]@{ version = $api; hmac_secret_api_supported = $supported; measured_in = 'collector-process' }
        policy = [ordered]@{ fDisableWebAuthn = $policy }
    }
}
function Get-DefaultMetadataProviders {
    $os = $null
    try { $os = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop } catch { }
    @{
        pid = { $PID }
        session_id = { [System.Diagnostics.Process]::GetCurrentProcess().SessionId }
        os_build = { if ($null -ne $os) { $os.CurrentBuildNumber } }.GetNewClosure()
        ubr = { if ($null -ne $os) { $os.UBR } }.GetNewClosure()
        client_version = {
            $clientPath = Join-Path ([Environment]::GetFolderPath('System')) 'mstsc.exe'
            if (Test-Path -LiteralPath $clientPath -PathType Leaf) {
                $v = (Get-Item -LiteralPath $clientPath -ErrorAction Stop).VersionInfo
                '{0}.{1}.{2}.{3}' -f $v.FileMajorPart,$v.FileMinorPart,$v.FileBuildPart,$v.FilePrivatePart
            }
        }
        fDisableWebAuthn = {
            (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableWebAuthn -ErrorAction Stop).fDisableWebAuthn
        }
        api_version = {
            if ($null -eq ('CollectorWebAuthnMetadata' -as [type])) {
                Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
public static class CollectorWebAuthnMetadata {
    [DllImport("webauthn.dll", ExactSpelling=true)]
    public static extern uint WebAuthNGetApiVersionNumber();
}
"@ -ErrorAction Stop | Out-Null
            }
            [CollectorWebAuthnMetadata]::WebAuthNGetApiVersionNumber()
        }
    }
}
function Get-EnvironmentMetadata {
    param([hashtable]$Providers)
    $ErrorActionPreference = 'Stop'
    if ($null -eq $Providers) { $Providers = Get-DefaultMetadataProviders }
    $metadata = @{}
    foreach ($key in @('pid','session_id','api_version','os_build','ubr','client_version','fDisableWebAuthn')) {
        if ($null -ne $Providers -and $Providers.ContainsKey($key)) {
            try { $metadata[$key] = & $Providers[$key] 2>$null 3>$null 4>$null 5>$null 6>$null }
            catch { $metadata[$key] = $null }
        }
    }
    $metadata
}
if ($DefinitionsOnly) { return }
New-EnvironmentRecord (Get-EnvironmentMetadata) | ConvertTo-Json -Depth 5 -Compress
