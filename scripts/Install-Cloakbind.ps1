<#
.SYNOPSIS
    Install or upgrade Cloakbind (LDAP to LDAPS proxy) as a Windows service.

.DESCRIPTION
    1. Finds an all-users Python 3.11+ install
    2. Installs the cloakbind package and its dependencies (online, or offline from -WheelDir)
    3. Creates C:\ProgramData\Cloakbind\{certs,logs} and config.toml (from the example, first run only)
    4. Creates the Cloakbind service running as the virtual account NT SERVICE\Cloakbind,
       delayed auto-start, restart on failure
    5. Locks down the data folder ACLs, registers the Event Log source
    6. Optionally exports the listener certificate (-CertThumbprint)
    7. Adds an inbound firewall rule scoped to the service
    8. Runs "cloakbind check" and starts the service if the config is ready

    Safe to re-run for upgrades: an existing config.toml and certificate are kept.

.EXAMPLE
    # Central legacy LDAP proxy on LDAPPROXY01 (9001/10389 -> LDAPS 636 to the DCs),
    # firewall limited to the application server and manufacturing panel networks.
    # Re-run after editing config.toml so the firewall rule matches the configured listeners.
    .\Install-Cloakbind.ps1 -FirewallRemoteAddress 10.20.30.0/24,10.40.50.0/24

.EXAMPLE
    # Also offering LDAPS/StartTLS to clients: export the proxy certificate too
    .\Install-Cloakbind.ps1 -CertThumbprint 3F2A...C9 -FirewallRemoteAddress 10.20.0.0/16

.EXAMPLE
    # Offline install from a wheelhouse built on another machine (see README)
    .\Install-Cloakbind.ps1 -WheelDir D:\cloakbind-wheels
#>
[CmdletBinding()]
param(
    [string]   $PythonExe,
    [string]   $SourcePath = (Split-Path -Parent $PSScriptRoot),
    [string]   $WheelDir,
    [string]   $CertThumbprint,
    [int[]]    $FirewallPorts,   # default: the listener ports in config.toml (9001,10389 on a fresh install)
    [string[]] $FirewallRemoteAddress,
    [string]   $DataDir = (Join-Path $env:ProgramData 'Cloakbind'),
    [switch]   $NoStart
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'Cloakbind'
$DisplayName = 'Cloakbind (LDAP to LDAPS proxy)'
$Description = 'Cloakbind: accepts legacy LDAP clients and relays them over verified LDAPS to healthy Active Directory domain controllers, with failover.'
. (Join-Path $PSScriptRoot 'CloakbindCommon.ps1')
Assert-Admin

function Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }

# ------------------------------------------------------------------ Python + package
Step 'Locating Python'
$py = Find-Python -PythonExe $PythonExe
Write-Host "Using $py"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Step 'Stopping existing service for upgrade'
    Stop-Service -Name $ServiceName -Force
}

Step 'Installing cloakbind and dependencies'
if ($WheelDir) {
    $null = Invoke-Native $py @('-m', 'pip', 'install', '--upgrade', '--no-index', '--find-links', $WheelDir, 'cloakbind')
} else {
    $null = Invoke-Native $py @('-m', 'pip', 'install', '--upgrade', '--disable-pip-version-check', $SourcePath)
}
$null = Invoke-Native $py @('-I', '-c', 'import cloakbind, ldaptor, twisted, win32service; print(chr(111)+chr(107), cloakbind.__version__)')

# ------------------------------------------------------------------ data folder
Step "Preparing $DataDir"
Assert-TrustedOwnership -Path $DataDir -ServiceName $ServiceName
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
# Lock the folder down immediately (admins + SYSTEM only); the service gets
# access once it exists, below.
Set-CloakbindAcl -Path $DataDir
foreach ($d in @((Join-Path $DataDir 'certs'), (Join-Path $DataDir 'logs'))) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}
$configPath = Join-Path $DataDir 'config.toml'
$freshConfig = $false
if (-not (Test-Path $configPath)) {
    Copy-Item -Path (Join-Path $SourcePath 'config.example.toml') -Destination $configPath
    $freshConfig = $true
    Write-Host "Created $configPath from the example. Edit it before starting the service."
} else {
    Write-Host "Keeping existing $configPath"
}
Copy-Item -Path (Join-Path $SourcePath 'config.example.toml') -Destination (Join-Path $DataDir 'config.example.toml') -Force

# ------------------------------------------------------------------ service
Step 'Registering the Windows service'
$binPath = "`"$py`" -I -m cloakbind.winservice"
if (-not $existing) {
    New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName $DisplayName `
        -Description $Description `
        -StartupType Automatic | Out-Null
} else {
    # Set ImagePath directly: Windows PowerShell 5.1 mangles embedded quotes in sc.exe arguments.
    $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    Set-ItemProperty -Path $svcKey -Name ImagePath -Value $binPath
    # Same for the name and description shown in services.msc (upgrades from older versions).
    Set-ItemProperty -Path $svcKey -Name DisplayName -Value $DisplayName
    Set-ItemProperty -Path $svcKey -Name Description -Value $Description
}
# Least privilege: per-service virtual account, no password to manage.
$null = Invoke-Native sc.exe @('config', $ServiceName, 'obj=', "NT SERVICE\$ServiceName", 'start=', 'delayed-auto')
$null = Invoke-Native sc.exe @('sidtype', $ServiceName, 'unrestricted')
# Restart after 5s, 15s, then every 60s; reset the failure count daily.
$null = Invoke-Native sc.exe @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/restart/60000')
$null = Invoke-Native sc.exe @('failureflag', $ServiceName, '1')

Step 'Securing folders'
Set-CloakbindAcl -Path $DataDir -ServiceName $ServiceName -ServiceRights 'ReadAndExecute'
Set-CloakbindAcl -Path (Join-Path $DataDir 'logs') -ServiceName $ServiceName -ServiceRights 'Modify'
Set-CloakbindAcl -Path (Join-Path $DataDir 'certs') -ServiceName $ServiceName -ServiceRights 'ReadAndExecute'

Step 'Registering Event Log source'
$null = Invoke-Native $py @('-I', '-c', "import win32evtlogutil; win32evtlogutil.AddSourceToRegistry('$ServiceName')")

# ------------------------------------------------------------------ certificate
if ($CertThumbprint) {
    Step 'Exporting listener certificate'
    & (Join-Path $PSScriptRoot 'Set-CloakbindCertificate.ps1') -Thumbprint $CertThumbprint -DataDir $DataDir -ServiceName $ServiceName
} elseif (-not (Test-Path (Join-Path $DataDir 'certs\proxy.pfx'))) {
    Write-Host 'No proxy certificate exported (only needed for ldaps/starttls listeners).'
}

# ------------------------------------------------------------------ firewall
Step 'Configuring Windows Firewall'
if (-not $FirewallPorts) {
    if ($freshConfig) {
        $FirewallPorts = @(9001, 10389)
    } else {
        $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        $portList = & $py -I -m cloakbind ports --config $configPath 2>$null
        $ErrorActionPreference = $old
        if ($LASTEXITCODE -eq 0 -and $portList) {
            $FirewallPorts = @("$portList".Trim().Split(',') | ForEach-Object { [int]$_ })
        } else {
            Write-Warning 'Could not read listener ports from config.toml; opening 9001 and 10389.'
            $FirewallPorts = @(9001, 10389)
        }
    }
}
Get-NetFirewallRule -Group 'Cloakbind' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$fw = @{
    DisplayName = "Cloakbind (TCP $($FirewallPorts -join ','))"
    Group       = 'Cloakbind'
    Direction   = 'Inbound'
    Protocol    = 'TCP'
    LocalPort   = $FirewallPorts
    Action      = 'Allow'
    Program     = $py
    Service     = $ServiceName
    Profile     = 'Domain,Private'
}
if ($FirewallRemoteAddress) { $fw.RemoteAddress = $FirewallRemoteAddress }
else { Write-Warning 'Firewall rule allows any remote address; pass -FirewallRemoteAddress to scope it.' }
New-NetFirewallRule @fw | Out-Null
Write-Host "Inbound TCP $($FirewallPorts -join ',') allowed for the $ServiceName service only."

# ------------------------------------------------------------------ check + start
if ($freshConfig) {
    Write-Host "`nNext steps:" -ForegroundColor Yellow
    Write-Host "  1. Edit $configPath (listeners, allowed_clients, domain controllers)"
    Write-Host "  2. Export the CA chain that signed your DCs' LDAPS certificates to $DataDir\certs\ca-chain.pem"
    Write-Host "     (see 'Install' step 4 in README.md)"
    Write-Host "  3. Only if you use ldaps/starttls listeners: .\Set-CloakbindCertificate.ps1 -Thumbprint <thumbprint>"
    Write-Host "  4. Test:  & '$py' -I -m cloakbind check --config '$configPath'"
    Write-Host "  5. Re-run this installer so the firewall rule matches your listener ports, then:"
    Write-Host "     Start-Service $ServiceName"
    return
}

Step 'Testing configuration and domain controllers'
$code = Invoke-Native $py @('-I', '-m', 'cloakbind', 'check', '--config', $configPath) -AllowFailure
if ($code -ne 0) {
    Write-Warning "The check failed (exit $code). Fix the problem above, then: Start-Service $ServiceName"
    return
}

if (-not $NoStart) {
    Step 'Starting service'
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 3
    Get-Service -Name $ServiceName | Format-Table -AutoSize Name, Status, StartType
    try {
        $st = Invoke-RestMethod -Uri 'http://127.0.0.1:8636/' -TimeoutSec 5
        Write-Host ("Status: healthy={0}  DCs: {1}" -f $st.healthy,
            (($st.domain_controllers | ForEach-Object { "$($_.name)=$($_.state)" }) -join ', '))
    } catch {
        Write-Host "Status endpoint not reachable yet (see $DataDir\logs\cloakbind.log)."
    }
}
