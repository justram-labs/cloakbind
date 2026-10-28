<#
.SYNOPSIS
    Remove the Cloakbind service, its firewall rule and (optionally) its data and package.

.EXAMPLE
    .\Uninstall-Cloakbind.ps1                 # keeps C:\ProgramData\Cloakbind (config, cert, logs)
.EXAMPLE
    .\Uninstall-Cloakbind.ps1 -RemoveData -RemovePackage
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $PythonExe,
    [string] $DataDir = (Join-Path $env:ProgramData 'Cloakbind'),
    [switch] $RemoveData,
    [switch] $RemovePackage
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'Cloakbind'
. (Join-Path $PSScriptRoot 'CloakbindCommon.ps1')
Assert-Admin

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force }
    $null = Invoke-Native sc.exe @('delete', $ServiceName)
    Write-Host "Removed service $ServiceName."
}

Get-NetFirewallRule -Group 'Cloakbind' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host 'Removed firewall rule(s).'

$evtKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$ServiceName"
if (Test-Path $evtKey) { Remove-Item -Path $evtKey -Recurse }

if ($RemovePackage) {
    $py = Find-Python -PythonExe $PythonExe
    $null = Invoke-Native $py @('-m', 'pip', 'uninstall', '-y', 'cloakbind') -AllowFailure
}

if ($RemoveData -and (Test-Path $DataDir)) {
    if ($PSCmdlet.ShouldProcess($DataDir, 'Delete config, certificate and logs')) {
        Remove-Item -Path $DataDir -Recurse -Force
        Write-Host "Deleted $DataDir."
    }
} elseif (Test-Path $DataDir) {
    Write-Host "Kept $DataDir (config, certificate, logs). Use -RemoveData to delete it."
}
