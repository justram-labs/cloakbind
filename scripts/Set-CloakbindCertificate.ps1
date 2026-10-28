<#
.SYNOPSIS
    Export a certificate from LocalMachine\My for a Cloakbind LDAPS/StartTLS listener.

.DESCRIPTION
    Writes C:\ProgramData\Cloakbind\certs\proxy.pfx (protected with a random
    password) and proxy.pfx.pass, locked down to SYSTEM, Administrators and the
    Cloakbind service account. Run it again after the certificate is renewed;
    use -Restart to pick up the new certificate immediately.

    The certificate needs:
      - a private key that is marked exportable
      - Server Authentication EKU
      - a SAN containing the DNS name clients use to reach the proxy

.EXAMPLE
    .\Set-CloakbindCertificate.ps1 -Thumbprint 3F2A...C9 -Restart
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Thumbprint,
    [string] $DataDir = (Join-Path $env:ProgramData 'Cloakbind'),
    [string] $ServiceName = 'Cloakbind',
    [switch] $Restart
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'CloakbindCommon.ps1')
Assert-Admin

$Thumbprint = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpper()
$cert = Get-Item -Path "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue
if (-not $cert) { throw "No certificate with thumbprint $Thumbprint in LocalMachine\My." }
if (-not $cert.HasPrivateKey) { throw "Certificate $Thumbprint has no private key on this machine." }
if ($cert.NotAfter -lt (Get-Date)) { throw "Certificate $Thumbprint expired on $($cert.NotAfter)." }

$eku = $cert.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId }
if ($eku -and ($eku -notcontains '1.3.6.1.5.5.7.3.1')) {
    throw "Certificate $Thumbprint does not have the Server Authentication EKU."
}
$san = ($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' })
$sanText = if ($san) { $san.Format($false) } else { '(none)' }
Write-Host "Certificate: $($cert.Subject)"
Write-Host "  SAN:     $sanText"
Write-Host "  Expires: $($cert.NotAfter)"
if (-not $san) { Write-Warning "No SAN extension: modern clients will reject this certificate." }

if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    throw "Service $ServiceName does not exist yet; run Install-Cloakbind.ps1 first."
}
$certDir = Join-Path $DataDir 'certs'
Assert-TrustedOwnership -Path $certDir -ServiceName $ServiceName
New-Item -ItemType Directory -Path $certDir -Force | Out-Null
# Lock the folder BEFORE writing the key material into it.
Set-CloakbindAcl -Path $certDir -ServiceName $ServiceName -ServiceRights 'ReadAndExecute'

# Random 32-byte password (Windows PowerShell 5.1 compatible)
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
$plain = [Convert]::ToBase64String($bytes)
$secure = ConvertTo-SecureString -String $plain -AsPlainText -Force

$pfxPath  = Join-Path $certDir 'proxy.pfx'
$passPath = Join-Path $certDir 'proxy.pfx.pass'
$tmpPfx   = "$pfxPath.new"
$tmpPass  = "$passPath.new"

try {
    Export-PfxCertificate -Cert $cert -FilePath $tmpPfx -Password $secure `
        -ChainOption BuildChain -CryptoAlgorithmOption AES256_SHA256 | Out-Null
} catch {
    Remove-Item $tmpPfx -ErrorAction SilentlyContinue
    throw ("Export failed: $($_.Exception.Message)`n" +
           "The private key is probably not exportable. Re-enroll the certificate from a " +
           "template that allows private key export, or import it from a PFX with -Exportable.")
}
[System.IO.File]::WriteAllText($tmpPass, $plain, (New-Object System.Text.UTF8Encoding($false)))

Move-Item -Path $tmpPfx  -Destination $pfxPath  -Force
Move-Item -Path $tmpPass -Destination $passPath -Force

Set-CloakbindAcl -Path $certDir -ServiceName $ServiceName -ServiceRights 'ReadAndExecute'   # re-apply to the new files
Write-Host "Exported to $pfxPath (password in $passPath, readable only by SYSTEM, Administrators and NT SERVICE\$ServiceName)"

if ($Restart) {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Restart-Service -Name $ServiceName
        Write-Host "Restarted $ServiceName."
    }
} else {
    Write-Host "Restart the service to load the new certificate: Restart-Service $ServiceName"
}
