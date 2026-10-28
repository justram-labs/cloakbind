"""
End-to-end tests: real LDAPS "domain controllers" (tests/fake_dc.py), the proxy
running as a separate process, and ldap3 as the client application.

Run:  python -m pytest -v tests
"""

import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

import pytest
from ldap3 import MODIFY_REPLACE, SUBTREE, Connection, Server, Tls

from ldaptor.protocols import pureber, pureldap

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = sys.executable


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    subprocess.check_call([PY, os.path.join(HERE, "make_certs.py"), str(d)])
    return str(d)


class DC:
    def __init__(self, pki, name, cert=None, users=20, unsynced=False, port=None):
        self.pki, self.name, self.cert = pki, name, cert or name
        self.users, self.unsynced = users, unsynced
        self.port = port or free_port()
        self.proc = None

    def start(self):
        args = [PY, os.path.join(HERE, "fake_dc.py"), str(self.port), self.name,
                os.path.join(self.pki, self.cert + ".pem"), os.path.join(self.pki, self.cert + ".key"),
                "--users", str(self.users)]
        if self.unsynced:
            args.append("--unsynced")
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        line = self.proc.stdout.readline()
        assert "listening" in line, line + self.proc.stdout.read()
        threading.Thread(target=self.proc.stdout.read, daemon=True).start()
        return self

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


class Proxy:
    def __init__(self, pki, tmp_path, dcs, strategy="failover", extra_backends=(), service_extra="",
                 status_extra=""):
        self.pki = pki
        self.ports = {k: free_port() for k in ("ldap", "ldaps", "ro", "starttls", "denied", "status")}
        self.log = str(tmp_path / "proxy.log")
        servers = ""
        for host_port, sname in [("127.0.0.1:%d" % d.port, d.cert + ".test.local") for d in dcs] + list(extra_backends):
            host, port = host_port.rsplit(":", 1)
            servers += '[[backends.server]]\nhost = "%s"\nport = %s\nserver_name = "%s"\n\n' % (host, port, sname)
        self.cfg_path = str(tmp_path / "config.toml")
        with open(self.cfg_path, "w") as f:
            f.write(f"""
[service]
log_file = "{self.log}"
log_level = "DEBUG"
reactor = "auto"
{service_extra}

[[listener]]
name = "legacy-ldap"
bind = "127.0.0.1"
port = {self.ports['ldap']}
mode = "ldap"
allowed_clients = ["127.0.0.1/32"]

[[listener]]
name = "ldaps"
bind = "127.0.0.1"
port = {self.ports['ldaps']}
mode = "ldaps"

[[listener]]
name = "ldaps-ro"
bind = "127.0.0.1"
port = {self.ports['ro']}
mode = "ldaps"
read_only = true

[[listener]]
name = "starttls"
bind = "127.0.0.1"
port = {self.ports['starttls']}
mode = "starttls"

[[listener]]
name = "denied"
bind = "127.0.0.1"
port = {self.ports['denied']}
mode = "ldaps"
allowed_clients = ["10.0.0.0/8"]

[server_tls]
pfx_file = "{pki}/proxy.pfx"
pfx_password_file = "{pki}/proxy.pfx.pass"

[backends]
strategy = "{strategy}"
connect_timeout = 2
ca_sources = ["{pki}/ca.pem"]

{servers}
[health]
interval = 1
timeout = 2
rise = 2
fall = 1

[status]
enabled = true
bind = "127.0.0.1"
port = {self.ports['status']}
{status_extra}
""")
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen([PY, "-m", "cloakbind", "run", "--config", self.cfg_path],
                                     cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                self.status()
                return self
            except Exception:
                assert self.proc.poll() is None, "proxy exited:\n" + self.read_log()
                time.sleep(0.2)
        raise AssertionError("proxy did not start:\n" + self.read_log())

    def status(self):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/" % self.ports["status"], timeout=2) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return json.loads(e.read())

    def wait_state(self, dc_name_port, state, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            for b in self.status()["domain_controllers"]:
                if b["name"] == dc_name_port and b["state"] == state:
                    return
            time.sleep(0.2)
        raise AssertionError("%s never became %s: %s" % (dc_name_port, state, self.status()))

    def read_log(self):
        try:
            with open(self.log) as f:
                return f.read()
        except OSError:
            return ""

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def server(self, listener="ldaps"):
        tls = Tls(ca_certs_file=os.path.join(self.pki, "ca.pem"), validate=ssl.CERT_REQUIRED,
                  valid_names=["ldapproxy.test.local"])
        use_ssl = listener not in ("starttls", "ldap")
        return Server("127.0.0.1", port=self.ports[listener], use_ssl=use_ssl, tls=tls,
                      connect_timeout=5)

    def conn(self, listener="ldaps", user="cn=alice,dc=test,dc=local", password="secret"):
        c = Connection(self.server(listener), user, password, receive_timeout=10)
        return c


def whoami(c):
    c.search("ou=whoami,dc=test,dc=local", "(objectClass=*)", search_scope="BASE",
             attributes=["description"])
    return str(c.entries[0].description)


def raw_bind(proxy, dn, password, listener="ldaps"):
    """Send a bind with ldaptor encoding (ldap3 refuses to send empty passwords)."""
    ctx = ssl.create_default_context(cafile=os.path.join(proxy.pki, "ca.pem"))
    with socket.create_connection(("127.0.0.1", proxy.ports[listener]), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname="ldapproxy.test.local") as s:
            msg = pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn=dn, auth=password), id=1)
            s.sendall(msg.toWire())
            data = s.recv(65536)
    decoder = pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
            fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
            inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext())))
    resp, _ = pureber.berDecodeObject(decoder, data)
    return resp.value


@pytest.fixture
def stack(pki, tmp_path):
    """dc1 + dc2 behind the proxy in failover order."""
    created = []

    def make(dcs=None, **kw):
        dcs = dcs if dcs is not None else [DC(pki, "dc1", users=3000).start(), DC(pki, "dc2").start()]
        created.extend(dcs)
        p = Proxy(pki, tmp_path, dcs, **kw).start()
        created.append(p)
        return p, dcs

    yield make
    for x in reversed(created):
        x.stop()


# ------------------------------------------------------------------ tests

def test_bind_search_and_paged_results(stack):
    p, _ = stack()
    c = p.conn()
    assert c.bind(), c.result
    assert whoami(c) == "dc1"           # failover strategy prefers the first DC
    entries = c.extend.standard.paged_search("ou=bulk,dc=test,dc=local", "(cn=*)",
                                             attributes=["cn", "description"],
                                             paged_size=500, generator=False)
    assert len(entries) == 3000          # ~700 KB of results through the relay
    # The paged-results response control must survive the proxy (ldaptor's stock
    # ProxyBase drops it, which breaks AD paging).
    assert "1.2.840.113556.1.4.319" in (c.result.get("controls") or {})
    c.unbind()
    log = p.read_log()
    assert "bind OK dn='cn=alice,dc=test,dc=local' method=simple" in log
    assert "secret" not in log           # passwords never logged


def test_bad_password_logs_ad_reason(stack):
    p, _ = stack()
    c = p.conn(password="wrong")
    assert not c.bind()
    assert c.result["result"] == 49
    assert "data 52e" in c.result["message"]   # AD error text passed through intact
    time.sleep(0.3)
    assert "[AD: invalid credentials]" in p.read_log()


def test_unauthenticated_bind_is_rejected(stack):
    p, _ = stack()
    resp = raw_bind(p, b"cn=alice,dc=test,dc=local", b"")
    assert resp.resultCode == 53
    # truly anonymous binds are still allowed (needed for RootDSE discovery)
    assert raw_bind(p, b"", b"").resultCode == 0


def test_read_only_listener_blocks_writes(stack):
    p, _ = stack()
    ro = p.conn("ro")
    assert ro.bind()
    assert not ro.modify("cn=alice,dc=test,dc=local", {"sn": [(MODIFY_REPLACE, ["Changed"])]})
    assert ro.result["result"] == 53
    assert ro.search("dc=test,dc=local", "(cn=alice)", SUBTREE)   # reads still work
    rw = p.conn()
    assert rw.bind()
    assert rw.modify("cn=alice,dc=test,dc=local", {"sn": [(MODIFY_REPLACE, ["Changed"])]}), rw.result


def test_starttls_listener(stack):
    p, _ = stack()
    c = p.conn("starttls")
    c.open()
    assert not c.bind()                      # password bind before StartTLS is refused
    assert c.result["result"] == 13          # confidentialityRequired
    c = p.conn("starttls")
    c.open()
    assert c.start_tls()
    assert c.bind(), c.result
    assert whoami(c) == "dc1"


def test_client_allowlist(stack):
    p, _ = stack()
    c = p.conn("denied")
    with pytest.raises(Exception):
        c.bind()
    time.sleep(0.3)
    assert "not in allowed_clients" in p.read_log()


def test_failover_existing_session_and_recovery(stack, pki):
    dc1, dc2 = DC(pki, "dc1").start(), DC(pki, "dc2").start()
    p, _ = stack([dc1, dc2])
    p.wait_state("127.0.0.1:%d" % dc1.port, "up")

    held = p.conn()
    assert held.bind() and whoami(held) == "dc1"

    dc1.stop()                                 # DC1 dies
    # A session pinned to the dead DC is closed so the app reconnects.
    with pytest.raises(Exception):
        whoami(held)

    c = p.conn()
    assert c.bind(), c.result                  # new sessions land on DC2 immediately
    assert whoami(c) == "dc2"
    p.wait_state("127.0.0.1:%d" % dc1.port, "down")

    DC(pki, "dc1", port=dc1.port).start()      # DC1 comes back
    p.wait_state("127.0.0.1:%d" % dc1.port, "up")
    c = p.conn()
    assert c.bind() and whoami(c) == "dc1"     # preferred DC is used again
    log = p.read_log()
    assert "is DOWN" in log and "is UP" in log


def test_untrusted_dc_certificate_is_never_used(stack, pki):
    rogue = DC(pki, "dc3").start()             # cert issued by an unknown CA
    good = DC(pki, "dc2").start()
    p, _ = stack([rogue, good])
    c = p.conn()
    assert c.bind() and whoami(c) == "dc2"
    p.wait_state("127.0.0.1:%d" % rogue.port, "down")
    st = [b for b in p.status()["domain_controllers"] if b["name"].endswith(str(rogue.port))][0]
    assert "certificate" in st["last_error"].lower()


def test_dc_name_mismatch_is_rejected(stack, pki):
    dc1 = DC(pki, "dc1").start()
    good = DC(pki, "dc2").start()
    # The proxy is told to expect dc9.test.local, but this DC presents dc1.test.local.
    p, _ = stack([good], extra_backends=[("127.0.0.1:%d" % dc1.port, "dc9.test.local")])
    stack_dcs = [dc1]
    try:
        p.wait_state("127.0.0.1:%d" % dc1.port, "down")
        st = [b for b in p.status()["domain_controllers"] if b["name"].endswith(str(dc1.port))][0]
        assert "certificate" in st["last_error"].lower() or "hostname" in st["last_error"].lower(), st
    finally:
        for d in stack_dcs:
            d.stop()


def test_unsynchronized_dc_is_skipped(stack, pki):
    fresh = DC(pki, "dc1", unsynced=True).start()   # e.g. newly promoted DC
    good = DC(pki, "dc2").start()
    p, _ = stack([fresh, good])
    p.wait_state("127.0.0.1:%d" % fresh.port, "down")
    c = p.conn()
    assert c.bind() and whoami(c) == "dc2"


def test_all_dcs_down_returns_unavailable(stack, pki):
    dead = DC(pki, "dc1")                       # never started
    p, _ = stack([dead])
    c = p.conn()
    assert not c.bind()
    assert c.result["result"] == 52             # unavailable
    s = p.status()
    assert s["healthy"] is False


def test_round_robin(stack, pki):
    dc1, dc2 = DC(pki, "dc1").start(), DC(pki, "dc2").start()
    p, _ = stack([dc1, dc2], strategy="round_robin")
    p.wait_state("127.0.0.1:%d" % dc1.port, "up")
    p.wait_state("127.0.0.1:%d" % dc2.port, "up")
    seen = []
    for _ in range(4):
        c = p.conn()
        assert c.bind()
        seen.append(whoami(c))
        c.unbind()
    assert set(seen) == {"dc1", "dc2"}


def test_concurrent_sessions(stack):
    p, _ = stack()
    errors = []

    def worker():
        try:
            for _ in range(5):
                c = p.conn()
                assert c.bind()
                assert c.search("ou=bulk,dc=test,dc=local", "(cn=user0000*)", attributes=["cn"])
                assert len(c.entries) == 10
                c.unbind()
        except Exception as e:  # pragma: no cover
            errors.append(repr(e))

    threads = [threading.Thread(target=worker) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors[:3]
    assert p.status()["listeners"]["ldaps"]["binds_ok"] == 200


def test_check_command(stack, pki):
    p, dcs = stack()
    out = subprocess.run([PY, "-m", "cloakbind", "check", "--config", p.cfg_path],
                         cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "2 of 2 DC(s) reachable" in out.stdout
    assert "dnsHostName=dc1.test.local" in out.stdout


# ------------------------------------------------------------------ hardening regressions

def _tlv(tag, body):
    n = len(body)
    return bytes([tag]) + (bytes([n]) if n < 128 else b"\x82" + n.to_bytes(2, "big")) + body


def _msg(msg_id, op):
    return _tlv(0x30, b"\x02\x01" + bytes([msg_id]) + op)


def _bind_op(dn, pw, trailing=b""):
    return _tlv(0x60, b"\x02\x01\x03" + _tlv(0x04, dn) + _tlv(0x80, pw) + trailing)


def _ext_op(oid):
    return _tlv(0x77, _tlv(0x80, oid))


def _tls_sock(p, listener):
    ctx = ssl.create_default_context(cafile=os.path.join(p.pki, "ca.pem"))
    raw = socket.create_connection(("127.0.0.1", p.ports[listener]), timeout=5)
    return ctx.wrap_socket(raw, server_hostname="ldapproxy.test.local")


def _recv_all(s, wait=1.5):
    s.settimeout(wait)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                return data, True        # closed by proxy
            data += chunk
    except (socket.timeout, TimeoutError):
        return data, False
    except (ConnectionResetError, ssl.SSLError, OSError):
        return data, True


def _result_code(data):
    decoder = pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
            fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
            inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext())))
    msg, _ = pureber.berDecodeObject(decoder, data)
    return msg.value.resultCode, msg.value.errorMessage


def test_starttls_injection_is_refused(stack):
    """A cleartext bind pipelined right after StartTLS must not be processed."""
    p, _ = stack()
    s = socket.create_connection(("127.0.0.1", p.ports["starttls"]), timeout=5)
    s.sendall(_msg(1, _ext_op(b"1.3.6.1.4.1.1466.20037")) +
              _msg(2, _bind_op(b"cn=alice,dc=test,dc=local", b"secret")))
    data, closed = _recv_all(s)
    assert closed and data == b""
    time.sleep(0.3)
    log = p.read_log()
    assert "sent data after StartTLS" in log
    assert "bind OK" not in log


def test_malformed_bind_fails_closed(stack):
    p, _ = stack()
    s = _tls_sock(p, "ldaps")
    # extra element inside the BindRequest after the credentials
    s.sendall(_msg(1, _bind_op(b"cn=alice,dc=test,dc=local", b"secret", trailing=b"\x04\x00")))
    data, closed = _recv_all(s)
    code, msg = _result_code(data)
    assert code == 2 and b"malformed" in msg
    assert closed


def test_read_only_blocks_extended_writes(stack):
    p, _ = stack()
    s = _tls_sock(p, "ro")
    s.sendall(_msg(1, _ext_op(b"1.3.6.1.4.1.1466.101.119.1")))      # dynamic TTL refresh (a write)
    data, _ = _recv_all(s, 1)
    code, msg = _result_code(data)
    assert code == 53 and b"not allowed" in msg
    s.sendall(_msg(2, _ext_op(b"1.3.6.1.4.1.4203.1.11.3")))         # WhoAmI is allowed through
    data, _ = _recv_all(s, 1)
    _, msg = _result_code(data)
    assert b"Cloakbind" not in (msg or b"")


def test_idle_connection_opens_no_dc_session_and_times_out(stack, pki):
    dc1 = DC(pki, "dc1").start()
    p, _ = stack([dc1], service_extra="first_message_timeout = 1.5")
    p.wait_state("127.0.0.1:%d" % dc1.port, "up")
    s = _tls_sock(p, "ldaps")          # e.g. a load balancer TCP/TLS probe
    time.sleep(0.5)
    st = p.status()
    assert st["active_sessions"] == 1
    assert st["domain_controllers"][0]["active_sessions"] == 0   # no DC connection opened
    data, closed = _recv_all(s, 3)
    assert closed                       # dropped after first_message_timeout


def test_pre_connect_flood_is_bounded(stack, pki):
    """While the DC connection is pending, the proxy stops reading from the client."""
    # A "DC" that accepts TCP but never completes the TLS handshake.
    hang = socket.socket()
    hang.bind(("127.0.0.1", 0))
    hang.listen(50)
    port = hang.getsockname()[1]
    try:
        p, _ = stack([], extra_backends=[("127.0.0.1:%d" % port, "dc1.test.local")])
        s = _tls_sock(p, "ldaps")
        search = _msg(1, _tlv(0x63, _tlv(0x04, b"x" * 60000)))
        sent = 0
        s.settimeout(3)
        try:
            for _ in range(2000):       # up to ~120 MB
                s.sendall(search)
                sent += len(search)
        except (socket.timeout, TimeoutError, OSError, ssl.SSLError):
            pass
        assert sent < 30 * 1024 * 1024, "proxy kept reading %d bytes" % sent
    finally:
        hang.close()


# ------------------------------------------------------------------ legacy plain LDAP (the main use case)

def test_legacy_plain_ldap_bind_search_and_paging(stack):
    """A legacy app doing an unsigned simple bind on plain LDAP gets served over LDAPS to the DC."""
    p, _ = stack()
    c = p.conn("ldap")
    assert c.server.ssl is False
    assert c.bind(), c.result                       # plain simple bind, no TLS, no signing
    assert whoami(c) == "dc1"
    entries = c.extend.standard.paged_search("ou=bulk,dc=test,dc=local", "(cn=*)",
                                             attributes=["cn"], paged_size=500, generator=False)
    assert len(entries) == 3000
    assert c.modify("cn=alice,dc=test,dc=local", {"sn": [(MODIFY_REPLACE, ["Legacy"])]}), c.result
    bad = p.conn("ldap", password="wrong")
    assert not bad.bind() and bad.result["result"] == 49
    time.sleep(0.3)
    log = p.read_log()
    assert "accepts plain LDAP from legacy clients" in log
    assert "bind OK dn='cn=alice,dc=test,dc=local' method=simple" in log


def test_legacy_plain_ldap_failover(stack, pki):
    dc1, dc2 = DC(pki, "dc1").start(), DC(pki, "dc2").start()
    p, _ = stack([dc1, dc2])
    p.wait_state("127.0.0.1:%d" % dc1.port, "up")
    c = p.conn("ldap")
    assert c.bind() and whoami(c) == "dc1"
    dc1.stop()
    c = p.conn("ldap")
    assert c.bind(), c.result
    assert whoami(c) == "dc2"


def test_ldap_listener_offers_starttls_when_cert_configured(stack):
    p, _ = stack()
    c = p.conn("ldap")
    c.open()
    assert c.start_tls()                            # opportunistic StartTLS for capable clients
    assert c.bind() and whoami(c) == "dc1"


def test_plain_listener_requires_allowed_clients(tmp_path):
    from cloakbind.config import ConfigError, load_config
    base = """
[backends]
ca_sources = ["ca.pem"]
[[backends.server]]
host = "dc1.test.local"
"""
    cfg = tmp_path / "c.toml"
    cfg.write_text('[[listener]]\nmode = "ldap"\nbind = "0.0.0.0"\n' + base)
    with pytest.raises(ConfigError, match="allowed_clients"):
        load_config(str(cfg))
    cfg.write_text('[[listener]]\nmode = "ldap"\nbind = "127.0.0.1"\n' + base)
    assert load_config(str(cfg)).listeners[0].port == 9001      # loopback is fine; default port 9001
    cfg.write_text('[[listener]]\nmode = "ldap"\nallowed_clients = ["10.1.2.3"]\n' + base)
    l = load_config(str(cfg)).listeners[0]
    assert (l.mode, l.port, l.require_tls_for_bind) == ("ldap", 9001, False)


# ------------------------------------------------------------------ dashboard (1.3.0)

def _get(p, path):
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/%s" % (p.ports["status"], path), timeout=3) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_dashboard_is_served_with_strict_headers(stack):
    p, _ = stack()
    code, headers, body = _get(p, "dashboard")
    assert code == 200 and b"<title>Cloakbind</title>" in body
    assert headers["Content-Type"].startswith("text/html")
    csp = headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert headers["X-Frame-Options"] == "DENY"
    for asset, ctype in (("dashboard.js", "application/javascript"), ("dashboard.css", "text/css")):
        code, headers, _ = _get(p, asset)
        assert code == 200 and headers["Content-Type"].startswith(ctype)
    assert _get(p, "nope")[0] == 404
    code, _, body = _get(p, "")
    status = json.loads(body)
    assert code == 200 and status["healthy"] and status["active_domain_controllers"]
    assert status["show_account_names"] is False


def test_events_mask_account_names_by_default(stack):
    p, _ = stack()
    c = p.conn("ldap"); assert c.bind(); c.unbind()
    bad = p.conn("ldap", password="wrong"); bad.bind()
    time.sleep(0.3)
    ev = json.loads(_get(p, "events")[2])
    assert ev["show_account_names"] is False
    kinds = [e["kind"] for e in ev["events"]]
    assert "bind_ok" in kinds and "bind_failed" in kinds
    accounts = {e["account"] for e in ev["events"] if e["account"]}
    assert accounts == {"cn=a\u2022\u2022\u2022e,dc=test,dc=local"}
    assert b"alice" not in _get(p, "events")[2]           # real name never leaves the proxy
    failed = [e for e in ev["events"] if e["kind"] == "bind_failed"][0]
    assert failed["detail"] == "invalid credentials" and failed["dc"]


def test_events_show_account_names_when_enabled(stack, pki, tmp_path):
    dc1 = DC(pki, "dc1").start()
    p, _ = stack([dc1], status_extra="show_account_names = true")
    c = p.conn("ldap"); assert c.bind(); c.unbind()
    time.sleep(0.3)
    ev = json.loads(_get(p, "events")[2])
    assert ev["show_account_names"] is True
    assert any(e["account"] == "cn=alice,dc=test,dc=local" for e in ev["events"])


def test_events_record_dc_down_and_up(stack, pki):
    dc1, dc2 = DC(pki, "dc1").start(), DC(pki, "dc2").start()
    p, _ = stack([dc1, dc2])
    p.wait_state("127.0.0.1:%d" % dc2.port, "up")
    dc2.stop()
    p.wait_state("127.0.0.1:%d" % dc2.port, "down", timeout=15)
    DC(pki, "dc2", port=dc2.port).start()
    p.wait_state("127.0.0.1:%d" % dc2.port, "up", timeout=15)
    kinds = [e["kind"] for e in json.loads(_get(p, "events")[2])["events"] if e["dc"] and e["dc"].endswith(str(dc2.port))]
    assert "dc_down" in kinds and "dc_up" in kinds


def test_dashboard_script_never_injects_html():
    """Account names and errors come from clients: the page must only ever set text."""
    js = open(os.path.join(ROOT, "cloakbind", "dashboard", "dashboard.js")).read()
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert bad not in js
