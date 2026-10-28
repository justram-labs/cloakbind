# Shared helpers for the Cloakbind scripts. Dot-source this file.

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell (Run as Administrator).'
    }
}

function Set-CloakbindAcl {
    <#
        Replace the ACL on a folder: SYSTEM and Administrators get Full Control,
        and (if -ServiceName is given) the service's virtual account
        NT SERVICE\<name> gets $ServiceRights. Inheritance from the parent is
        removed, so ordinary users can't read certificates, passwords or logs,
        and every existing child is re-owned by Administrators so nobody else
        keeps the ability to rewrite its permissions.
    #>
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $ServiceName,
        [System.Security.AccessControl.FileSystemRights] $ServiceRights = 'ReadAndExecute'
    )
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $prop    = [System.Security.AccessControl.PropagationFlags]::None
    $allow   = [System.Security.AccessControl.AccessControlType]::Allow

    $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($admins)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $inherit, $prop, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins, 'FullControl', $inherit, $prop, $allow)))
    if ($ServiceName) {
        $svc = New-Object System.Security.Principal.NTAccount("NT SERVICE\$ServiceName")
        try { $null = $svc.Translate([System.Security.Principal.SecurityIdentifier]) }
        catch { throw "NT SERVICE\$ServiceName does not resolve; run Install-Cloakbind.ps1 first." }
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($svc, $ServiceRights, $inherit, $prop, $allow)))
    }
    Set-Acl -Path $Path -AclObject $acl

    # Existing children: owner -> Administrators, drop explicit rules, inherit from the folder.
    Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $a = Get-Acl -Path $_.FullName
        $a.SetOwner($admins)
        $a.SetAccessRuleProtection($false, $false)
        foreach ($r in @($a.Access)) { if (-not $r.IsInherited) { [void]$a.RemoveAccessRule($r) } }
        Set-Acl -Path $_.FullName -AclObject $a
    }
}

function Assert-TrustedOwnership {
    <#
        Refuse to adopt a data folder that a non-administrator could have
        prepared in advance (ProgramData lets ordinary users create folders).
        Such a user could plant a config.toml that points the proxy at a rogue
        "DC" and collect every password that passes through it.
    #>
    param([Parameter(Mandatory)] [string] $Path, [string] $ServiceName)
    if (-not (Test-Path $Path)) { return }
    $trusted = @(
        'S-1-5-18',                                                     # SYSTEM
        'S-1-5-32-544',                                                 # Administrators
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', # TrustedInstaller
        ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)  # the admin running this
    )
    if ($ServiceName) {
        try {
            $trusted += (New-Object System.Security.Principal.NTAccount("NT SERVICE\$ServiceName")).Translate(
                [System.Security.Principal.SecurityIdentifier]).Value
        } catch { }
    }
    $items = @(Get-Item -Path $Path -Force) + @(Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue)
    foreach ($i in $items) {
        $owner = (Get-Acl -Path $i.FullName).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($trusted -notcontains $owner) {
            $name = try { (New-Object System.Security.Principal.SecurityIdentifier($owner)).Translate([System.Security.Principal.NTAccount]).Value } catch { $owner }
            throw ("$($i.FullName) is owned by $name, not by an administrator. Someone may have " +
                   "pre-created it to tamper with the proxy configuration. Inspect it, delete " +
                   "$Path, and run the installer again.")
        }
    }
}

function Invoke-Native {
    <#
        Run a native command and fail on a non-zero exit code. Windows PowerShell 5.1
        turns any stderr output into a terminating error when
        $ErrorActionPreference is 'Stop' (pip prints warnings to stderr), so the
        preference is relaxed for the call.
    #>
    param([Parameter(Mandatory)] [string] $FilePath, [string[]] $Arguments, [switch] $AllowFailure)
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $FilePath @Arguments 2>&1 | ForEach-Object { "$_" } | Write-Host
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $old
    }
    if ($code -ne 0 -and -not $AllowFailure) {
        throw "'$FilePath $($Arguments -join ' ')' failed with exit code $code"
    }
    return $code
}

function Find-Python {
    param([string] $PythonExe)
    $ErrorActionPreference = 'Continue'   # probing writes to stderr for missing versions
    $candidates = @()
    if ($PythonExe) { $candidates += $PythonExe }
    else {
        $py = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($py) {
            foreach ($v in '-3.13', '-3.12', '-3.11', '-3') {
                $exe = & $py.Source $v -c 'import sys; print(sys.executable)' 2>$null
                if ($LASTEXITCODE -eq 0 -and $exe) { $candidates += $exe.Trim() }
            }
        }
        $candidates += Get-ChildItem "$env:ProgramFiles\Python3*\python.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | ForEach-Object FullName
    }
    foreach ($c in ($candidates | Select-Object -Unique)) {
        if (-not (Test-Path $c)) { continue }
        # No double quotes inside -c: Windows PowerShell 5.1 strips them from native arguments.
        $ver = & $c -c 'import sys; print(sys.version_info[0], sys.version_info[1], sep=chr(46))' 2>$null
        if ($LASTEXITCODE -ne 0) { continue }
        if ([version]$ver -lt [version]'3.11') { Write-Warning "$c is Python $ver; 3.11+ is required"; continue }
        $full = (Resolve-Path $c).Path
        if ($full -like "$env:SystemDrive\Users\*") {
            Write-Warning ("$full is a per-user Python install. The service account cannot read " +
                           "user profiles; install Python for all users (InstallAllUsers=1).")
            continue
        }
        return $full
    }
    throw ('No suitable Python found. Install Python 3.12 or 3.13 for all users, e.g.:' +
           "`n  python-3.13.x-amd64.exe /quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1")
}
