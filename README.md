# Cloakbind

**Legacy plain LDAP in, verified LDAPS out to healthy Active Directory domain controllers.**

Windows Server 2025 domain controllers **require LDAP signing by default**. Applications and devices that do a plain, unsigned simple bind on port 389 are refused with `Strong authentication is required` (LDAP result 8). Plenty of them can't be upgraded: older line-of-business apps, appliances, and manufacturing or medical panels with LDAP settings frozen in firmware.

Cloakbind is a small Windows service that sits between those clients and your DCs. It accepts their plain LDAP, wraps ("cloaks") each session in TLS, and relays it over **LDAPS (636)** to a **healthy** domain controller, with automatic failover across as many DCs as you list. The DCs only ever see verified LDAPS, which satisfies the signing requirement.

```
 app servers ───────────┐
                        │  plain LDAP
                        ├─ TCP 9001 ──▶  Cloakbind  ──LDAPS 636 (cert + hostname verified)──▶  DC1  ✔ healthy
 legacy panels /        │                (Windows                                      ╲──▶  DC2  (failover)
 appliances ────────────┘                 service)   health check every 15 s ─────────────▶  DC3 …
```

Clients only change their LDAP **server and port**. The bind account, base DN and filters stay as they are.

Built on [Twisted](https://twisted.org/) and [ldaptor](https://github.com/twisted/ldaptor). It runs on Windows Server 2019, 2022 and 2025 with Python 3.11 or later; the core also runs on Linux for development and testing.

> Cloakbind is an independent open-source project. It is not affiliated with or endorsed by Microsoft.

## Features

- **Multi-DC failover.**
  - `failover` strategy: always use the first healthy DC in the list, e.g. local-site DCs first.
  - `round_robin` strategy: spread new sessions across all healthy DCs.
  - If a DC can't be reached at connect time, the next one is tried within the same client connection, so the client never notices.
- **Health checks.** Every DC gets a TLS handshake and an anonymous RootDSE read on an interval. A DC reporting `isSynchronized=FALSE` (freshly promoted, still replicating) is kept out of rotation. Rise and fall thresholds prevent flapping.
- **Strict TLS to the DCs.** Chain and hostname verification are always on, with TLS 1.2 or higher. Trust is pinned to your enterprise CA file (recommended) or taken from the Windows certificate store, which honours the Disallowed store and per-certificate purposes.
- **Faithful relay.** LDAP messages pass through byte-for-byte, so AD controls (paged results, SD flags, server-side sort), referrals, SASL and Abandon all work. See [Why not ldaptor's ProxyBase?](#why-not-ldaptors-proxybase).
- **Listener modes:**
  - `ldap`: plain LDAP for legacy clients. Must be restricted to known networks with `allowed_clients`. StartTLS is also offered if a proxy certificate is configured.
  - `starttls`: plain port that requires StartTLS before any password bind.
  - `ldaps`: TLS from the first byte.
- **Fail-closed policy per listener:**
  - client IP allow-list (`allowed_clients`)
  - `read_only` mode, allowing only Bind, Search, Compare, Abandon, Unbind and WhoAmI/fast-bind
  - refusal of *unauthenticated binds* (a DN with an empty password), which AD treats as an anonymous success
  - strict parsing of binds and extended requests: anything malformed is refused, never forwarded unchecked
- **Abuse resistance:**
  - STARTTLS command-injection protection
  - no DC connection is opened until a client actually sends a request, so load-balancer probes and port scans cost nothing
  - first-message timeout
  - global and per-IP connection limits
  - request size limits
  - client reads paused until the DC is connected
  - linear-time message framing
- **Useful logs.**
  - Every bind is logged with account, client IP, DC used and result.
  - AD's failure codes are decoded, e.g. `[AD: account locked out]`.
  - DC up/down events and certificate-expiry warnings are logged.
  - Passwords are never logged.
  - Warnings and errors also go to the Windows Application log.
- **Local dashboard.**
  - `http://127.0.0.1:8636/dashboard` shows the route to the DCs, listener counters and recent activity.
  - Account names are masked by default.
  - A JSON status endpoint returns HTTP 503 when no DC is healthy, so monitors and load balancers can use it.
- **Hardened Windows service:**
  - runs as the virtual account `NT SERVICE\Cloakbind` (no password, no admin rights)
  - delayed auto-start, with restart on failure
  - locked-down data folder
  - Windows Firewall rule scoped to the service

## Ports

| Direction | Default | Configurable |
|---|---|---|
| Clients → Cloakbind | **TCP 9001**, plain LDAP (example config also has **10389**) | `[[listener]] port` / `mode`. Add `ldaps` on 636 or a plain listener on 389 if needed. |
| Cloakbind → each DC | **TCP 636**, LDAPS | `[[backends.server]] port` (3269 for the Global Catalog) |
| Status page and dashboard | TCP 8636 on 127.0.0.1 | `[status]` |

A DC already owns 389 and 636, so run Cloakbind on a **member server**, not on a DC.

## Requirements

| Item | Notes |
|---|---|
| Windows Server 2019, 2022 or 2025 member server | Any server that can reach the DCs on 636 |
| Python 3.11+ (3.12 or 3.13 recommended), installed **for all users** | `python-3.13.x-amd64.exe /quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1` |
| Python packages | `ldaptor`, `Twisted[tls]`, `cryptography`, `pyOpenSSL`, `pywin32`, `twisted-iocpsupport` (installed by the script) |
| DCs with working LDAPS | Each DC presents a certificate whose SAN matches its name in the config |
| Your enterprise CA certificate(s) | Root, plus the issuing (intermediate) CA if you have one, as a PEM or DER file |
| A certificate for Cloakbind itself, **optional** | Only for `ldaps`/`starttls` listeners or to offer StartTLS: Server Authentication EKU, a SAN with the name clients use, and an exportable private key |

## Install

Run everything in an **elevated PowerShell** on the member server.

**1. Pre-flight checks.**

```powershell
# Must be a member server (DomainRole 3)
Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, DomainRole

# The DCs in this server's AD site, and whether they answer on LDAPS
$site = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()
foreach ($dc in $site.Servers) { Test-NetConnection $dc.Name -Port 636 | Select-Object ComputerName, TcpTestSucceeded }
```

**2. Install Python for all users** (see Requirements), then open a new elevated PowerShell.

**3. Extract the release, unblock it, and run the installer.**

```powershell
Get-ChildItem C:\Install\cloakbind -Recurse | Unblock-File
Set-Location C:\Install\cloakbind
.\scripts\Install-Cloakbind.ps1 -FirewallRemoteAddress 10.20.30.0/24
```

`-FirewallRemoteAddress` should be the networks your legacy clients live in. On the first run, the installer:
- installs the packages
- creates `C:\ProgramData\Cloakbind`, with `config.toml`, `certs\` and `logs\`
- registers the service
- creates the firewall rule

It then stops, so you can edit the config.

**4. Export the CA chain that signed your DCs' LDAPS certificates.** This reads the chain a DC presents and saves every CA above the DC certificate (issuing and root) into one PEM file:

```powershell
$dc  = 'dc01.corp.example.com'
$tcp = New-Object Net.Sockets.TcpClient($dc, 636)
$ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, [Net.Security.RemoteCertificateValidationCallback]{ $true })
$ssl.AuthenticateAsClient($dc)
$chain = New-Object Security.Cryptography.X509Certificates.X509Chain
$null  = $chain.Build((New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)))
$ssl.Dispose(); $tcp.Close()

$pem = foreach ($el in $chain.ChainElements | Select-Object -Skip 1) {
    "# $($el.Certificate.Subject)"
    "-----BEGIN CERTIFICATE-----"
    [Convert]::ToBase64String($el.Certificate.RawData, 'InsertLineBreaks')
    "-----END CERTIFICATE-----"
}
[IO.File]::WriteAllText('C:\ProgramData\Cloakbind\certs\ca-chain.pem', ($pem -join "`r`n") + "`r`n", [Text.Encoding]::ASCII)
```

Check that each CA in the file is one you expect, before trusting it.

**5. Edit `C:\ProgramData\Cloakbind\config.toml`.** Set the DCs, `allowed_clients` and `ca_sources = ["certs\\ca-chain.pem"]`. Every option is documented in [`config.example.toml`](config.example.toml).

**6. Test, then start.**

```powershell
& 'C:\Program Files\Python313\python.exe' -I -m cloakbind check --config 'C:\ProgramData\Cloakbind\config.toml'
Start-Service Cloakbind
```

`check` validates the config, then makes a verified LDAPS connection to every DC and reads its RootDSE:

```
  [ OK ] dc01.corp.example.com:636  dnsHostName=dc01.corp.example.com cert_days_left=211
  [ OK ] dc02.corp.example.com:636  dnsHostName=dc02.corp.example.com cert_days_left=211
2 of 2 DC(s) reachable over verified LDAPS
```

Re-running the installer upgrades the package and keeps your config, certificates and logs.

### Offline install

On a machine with internet access and the **same Python minor version**:

```powershell
py -3.13 -m pip download -d wheels -r requirements.txt
py -3.13 -m pip wheel --no-deps -w wheels .
```

Copy `wheels` and the project to the server, then run `.\scripts\Install-Cloakbind.ps1 -WheelDir D:\wheels`.

## Pointing clients at it

| Setting | Value |
|---|---|
| LDAP server | the Cloakbind server's IP or DNS name |
| Port | **9001** (or whatever your listener uses) |
| SSL / TLS | **off** for `ldap` listeners |
| Bind account, base DN, filters | **unchanged** |
| Bind name | UPN (`svc-app@corp.example.com`), `CORP\svc-app`, or a full DN. AD rejects bare usernames in simple binds; that's AD, not Cloakbind. |

If a client lists several DCs, replace them all with the Cloakbind server. Failover now happens in the proxy.

## Adding client networks

A client has to pass **two gates**, and a new network must be added to both:

| Gate | Where | If missing |
|---|---|---|
| Windows Firewall | rule group **Cloakbind** | connection dropped; **nothing** in the Cloakbind log |
| Proxy allow-list | `allowed_clients` on each listener in `config.toml` | log shows `rejected <ip> ... not in allowed_clients` |

```powershell
# 1. Edit allowed_clients on every listener in config.toml, then:
Get-NetFirewallRule -Group 'Cloakbind' | Set-NetFirewallRule -RemoteAddress 10.20.30.0/24,10.40.50.0/24   # full list
& 'C:\Program Files\Python313\python.exe' -I -m cloakbind check --config 'C:\ProgramData\Cloakbind\config.toml'
Restart-Service Cloakbind
```

Also check any network firewall between the clients and the Cloakbind server.

## Dashboard

Open **`http://127.0.0.1:8636/dashboard`** in a browser on the Cloakbind server. It refreshes every 5 seconds and shows:

- **A status line:** sign-ins flowing normally, a DC down while sign-ins continue through the other, or no DC reachable.
- **The route:** client listeners → Cloakbind → each DC, with the active DC, the standby DCs, and any down DC with its error and time in that state.
- **Recent activity:** sign-ins, failures with the AD reason, refused clients, blocked writes and DC up/down, with filters.

Account names are **masked by default** (`j•••e@corp.example.com`). The masking happens server-side, so real names never reach the browser unless you set `show_account_names = true` under `[status]`. The page is self-contained: no internet, CDN or web fonts. It's served with a strict Content-Security-Policy, and client-supplied text is only ever displayed as plain text. Raw data is also available at `/` (status JSON, HTTP 503 when no DC is healthy) and `/events`.

## Logs and monitoring

- **Log file:** `C:\ProgramData\Cloakbind\logs\cloakbind.log`, rotated daily and kept for `log_retention_days`.

  ```
  INFO    [812] bind OK dn='svc-wiki@corp.example.com' method=simple client=10.20.4.15:51022 dc=dc01.corp.example.com:636 (4 ms)
  WARNING [813] bind FAILED dn='jdoe@corp.example.com' method=simple client=10.20.4.15:51031 dc=dc01.corp.example.com:636 result=49 [AD: account locked out] ...
  WARNING DC dc01.corp.example.com:636 is DOWN (was up): cannot open a TCP connection to the DC ...
  INFO    DC dc01.corp.example.com:636 is UP (was down) dnsHostName=dc01.corp.example.com
  ```

- **Event Log:** warnings, errors, and service start/stop/crash events go to the Application log, source `Cloakbind`.
- **Status JSON:** `Invoke-RestMethod http://127.0.0.1:8636/` returns per-DC state, sessions, certificate days left and listener counters.

## How it handles failures

| Situation | Behaviour |
|---|---|
| Preferred DC down before a session starts | Session goes straight to the next healthy DC |
| DC unreachable at connect time (health state stale) | Next DC is tried within the same client connection; the client doesn't notice |
| DC dies during a session | The client connection is closed and the client reconnects to a healthy DC. LDAP sessions carry bind state, so they can't be moved transparently. |
| DC certificate untrusted, expired, or name mismatch | DC treated as down and never used; the reason is logged |
| DC reachable but `isSynchronized=FALSE` | Kept out of rotation until AD reports it synchronized |
| DC comes back | Re-enters rotation after `rise` consecutive good checks; `failover` prefers it again |
| All DCs down | Binds get result 52 (unavailable) with a clear message; status endpoint returns 503 |

## High availability

A single Cloakbind server is a single point of dependency for the clients that use it. For production, run two servers with identical config behind a load-balancer VIP, using the status endpoint as the health check (bind it to the server's IP and treat 503 as down). Alternatively, publish two DNS A records, if your clients retry.

## Limitations

- **Simple binds are the supported path,** and most legacy clients use them.
  - **Kerberos (GSSAPI/GSS-SPNEGO) can't work** through any proxy: the client gets a ticket for the proxy's name, not the DC's.
  - **NTLM-based binds** pass through, but fail if the DCs enforce LDAP channel binding (`LdapEnforceChannelBinding=2`).
- **The client-to-Cloakbind leg of an `ldap` listener is unencrypted**, exactly as client-to-DC was before. Keep the proxy close to its clients and keep `allowed_clients` tight. Where a client can do TLS, use `starttls` or `ldaps`.
- **One DC pool per instance.** For the Global Catalog (3269), run a second instance with its own config.
- **Referrals** point at real DC names, as AD sends them. Most legacy clients ignore them.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

Before the first release, an independent review attacked the proxy against test DCs. Every finding was fixed and now has a regression test:

| Finding | Fix |
|---|---|
| A cleartext bind pipelined in the same packet as StartTLS was processed as if it arrived over TLS (STARTTLS injection) | Any data after StartTLS and before the handshake closes the connection |
| A bind the decoder couldn't parse was forwarded unchecked | Strict parser; malformed binds get protocolError and the connection closes |
| Unbounded memory use while the DC connection was being set up | Client reads paused until the DC is ready; hard cap on queued bytes |
| Buffering cost grew with the square of message size | Incremental framer; separate request and response size limits |
| `read_only` blocked a fixed list of operations, so write-type extended operations got through | Changed to an allowed list |
| A late DC connection could tear down an unrelated session | Connect attempts are cancelled or aborted; sessions ignore connections they don't own |
| The installer could adopt a data folder pre-created by a non-admin | Ownership check, immediate lock-down, key folder locked before export |

## Why not ldaptor's ProxyBase?

ldaptor's cookbook proxy (`ldaptor.protocols.ldap.proxybase.ProxyBase`) is a good starting point, but it breaks Active Directory clients in ways that are easy to miss:

1. **LDAP controls are dropped in both directions**, so AD **paged searches** (needed for anything over 1,000 objects), SD-flags and server-side sort silently fail.
2. **Referrals inside results are discarded.**
3. **Only Search and Bind count as complete**, so Modify, Add, Compare and extended operations leave stale handlers behind.
4. **A client whose DC disappears mid-session is left hanging.**
5. **Anything ldaptor can't parse kills the connection,** such as IntermediateResponse.

Cloakbind uses ldaptor where it's solid:
- decoding binds, writes and StartTLS for policy and logging
- the LDAP client used for DC health checks
- building its own error responses

Everything else is relayed at the message level, without re-encoding. The test suite checks the paged-results control end to end.

## Development

```bash
python -m pip install -e .[test]
python -m pytest -v tests
```

The test suite starts fake LDAPS "domain controllers" (ldaptor's in-memory server, made to mimic AD's RootDSE, `data 52e` errors and paging control), runs Cloakbind as a real process, and drives it with `ldap3`. It covers:

- plain LDAP binds, 3,000-entry paged searches and writes through the proxy
- failover and recovery
- rogue-CA and hostname-mismatch DCs, and unsynchronized DCs
- StartTLS and LDAPS listeners, read-only mode and allow-lists
- 40 concurrent clients
- the dashboard and account masking
- a regression test for every security finding above

CI runs the suite on Linux and Windows.

```
cloakbind/
  ber.py         LDAP message framing and strict bind/extended parsing
  proxy.py       client sessions: policy, bind logging, StartTLS, relay
  backends.py    DC pool: TLS connect, failover/round-robin, health checks
  tlsutil.py     trust store (Windows/PEM), Cloakbind's own certificate (PFX/PEM)
  events.py      recent-activity buffer and account-name masking
  dashboard/     local dashboard (HTML/CSS/JS)
  config.py      TOML config and validation
  app.py         logging, reactor, listeners, status endpoint
  winservice.py  Windows service host (pywin32)
  __main__.py    CLI: run | check | ports | version
scripts/         Install / Uninstall / Set-CloakbindCertificate (Windows PowerShell 5.1+)
tests/           end-to-end tests, fake DC, test PKI generator
```

## License

[MIT](LICENSE)
