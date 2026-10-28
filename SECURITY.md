# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repository.

Include the Cloakbind version, your listener configuration (with addresses removed), and steps to reproduce. You'll get an acknowledgement as soon as possible. A fix will be released before the details are made public.

## Scope and design notes

Things that are in scope:
- bypassing a listener's policy (`allowed_clients`, `read_only`, `require_tls_for_bind`, `reject_unauthenticated_bind`)
- weakening or skipping certificate or hostname verification towards the domain controllers
- leaking credentials into logs, the dashboard or the event feed
- crashing or exhausting the service from an allowed or disallowed client
- privilege problems in the installer scripts

Things that are **by design**, and not vulnerabilities:
- **An `ldap` listener receives passwords in clear.** That's its purpose: legacy clients that can't do TLS. Restrict it with `allowed_clients` and the firewall, and prefer `starttls` or `ldaps` listeners for clients that can do TLS.
- **The status page and dashboard listen on 127.0.0.1 by default** and have no login. If you bind them to another address, restrict access with the firewall.
- **With `show_account_names = true`**, the dashboard and `/events` show real account names to anyone who can reach the status port.

## Supported versions

Only the latest release receives security fixes.
