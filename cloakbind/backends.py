"""
Domain controller pool: TLS connections to DCs, selection (failover or
round-robin), and periodic health checks against the RootDSE.
"""

import logging
import time

from twisted.internet import defer, task
from twisted.internet.endpoints import HostnameEndpoint, wrapClientTLS
from twisted.internet.interfaces import IHandshakeListener
from twisted.internet.protocol import Factory, Protocol
from twisted.python.failure import Failure
from zope.interface import implementer

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldapclient import LDAPClient

from .events import EVENTS
from .tlsutil import client_tls_options, days_until_expiry

log = logging.getLogger("cloakbind.backends")

UNKNOWN, UP, DOWN = "unknown", "up", "down"


class NoBackendAvailable(Exception):
    pass


class BackendConnectTimeout(Exception):
    pass


@implementer(IHandshakeListener)
class TLSBackendProtocol(Protocol):
    """
    Base for anything that talks to a DC. `ready` fires with the protocol only
    after the TLS handshake (including certificate and hostname verification)
    has completed, so a bad certificate counts as a connect failure.
    """

    def __init__(self):
        self.ready = defer.Deferred()

    def handshakeCompleted(self):
        d, self.ready = self.ready, None
        if d is not None:
            d.callback(self)

    def connectionLost(self, reason):
        d, self.ready = self.ready, None
        if d is not None:
            d.errback(reason)

    def peer_certificate(self):
        """The DC's leaf certificate as a cryptography object, or None."""
        try:
            c = self.transport.getPeerCertificate()
            return c.to_cryptography() if c is not None else None
        except Exception:
            return None


class _HealthClient(LDAPClient, TLSBackendProtocol):
    def __init__(self):
        LDAPClient.__init__(self)
        TLSBackendProtocol.__init__(self)

    def connectionLost(self, reason):
        TLSBackendProtocol.connectionLost(self, reason)
        LDAPClient.connectionLost(self, reason)


class Backend:
    def __init__(self, cfg, index):
        self.cfg = cfg
        self.index = index
        self.name = "%s:%d" % (cfg.host, cfg.port)
        self.state = UNKNOWN
        self.ok_streak = 0
        self.fail_streak = 0
        self.last_error = None
        self.last_check = None
        self.last_state_change = time.time()
        self.active_sessions = 0
        self.total_sessions = 0
        self.dns_host_name = None
        self.cert_days_left = None
        self.tls_options = None  # set by the pool

    def as_dict(self):
        return {
            "name": self.name,
            "server_name": self.cfg.server_name,
            "state": self.state,
            "dns_host_name": self.dns_host_name,
            "active_sessions": self.active_sessions,
            "total_sessions": self.total_sessions,
            "last_error": self.last_error,
            "last_check": self.last_check,
            "seconds_in_state": int(time.time() - self.last_state_change),
            "cert_days_left": self.cert_days_left,
        }


class BackendPool:
    def __init__(self, reactor, cfg, health_cfg, trust_root):
        self.reactor = reactor
        self.cfg = cfg
        self.health_cfg = health_cfg
        self.backends = [Backend(s, i) for i, s in enumerate(cfg.servers)]
        for b in self.backends:
            b.tls_options = client_tls_options(b.cfg.server_name, trust_root, cfg.min_tls)
        self._rr = 0
        self._health_loop = None
        self._warned_expiry = set()
        self.shutting_down = False

    # ---------- state transitions ----------

    def _set_state(self, b, new_state, reason=None):
        if b.state == new_state:
            return
        old = b.state
        b.state = new_state
        b.last_state_change = time.time()
        if new_state == DOWN:
            log.warning("DC %s is DOWN (was %s): %s", b.name, old, reason)
            EVENTS.add("dc_down", dc=b.name, detail=reason)
        elif new_state == UP:
            if old == DOWN:
                EVENTS.add("dc_up", dc=b.name, detail="back in rotation")
            log.info("DC %s is UP (was %s)%s", b.name, old,
                     " dnsHostName=%s" % b.dns_host_name if b.dns_host_name else "")
        if not any(x.state == UP for x in self.backends):
            if new_state == DOWN:
                log.error("no domain controllers are currently healthy")

    def _record_success(self, b):
        b.last_error = None
        b.fail_streak = 0
        b.ok_streak += 1
        if b.state == UNKNOWN or (b.state == DOWN and b.ok_streak >= self.health_cfg.rise):
            self._set_state(b, UP)

    def _record_failure(self, b, err, immediate=False):
        if self.shutting_down:
            return
        b.last_error = err
        b.ok_streak = 0
        b.fail_streak += 1
        if b.state != DOWN and (immediate or b.fail_streak >= self.health_cfg.fall):
            self._set_state(b, DOWN, err)

    # ---------- selection ----------

    def candidates(self):
        """Order in which to try DCs for a new client session."""
        up = [b for b in self.backends if b.state == UP]
        unknown = [b for b in self.backends if b.state == UNKNOWN]
        down = [b for b in self.backends if b.state == DOWN]
        if self.cfg.strategy == "round_robin" and up:
            start = self._rr % len(up)
            self._rr += 1
            up = up[start:] + up[:start]
        # DCs marked down are still tried as a last resort, so a stale health
        # state never turns a recoverable situation into an outage.
        return up + unknown + down

    def _connect_one(self, b, protocol):
        """
        Connect `protocol` to DC `b`; fires with the protocol once the TLS
        handshake (including certificate verification) completes. On timeout
        the attempt is cancelled, and a connection that still completes late
        is aborted, so it can never leak or be mistaken for a live session.
        """
        endpoint = wrapClientTLS(
            b.tls_options,
            HostnameEndpoint(self.reactor, b.cfg.host, b.cfg.port,
                             timeout=self.cfg.connect_timeout),
        )
        result = defer.Deferred()
        d = _quiet_connect(endpoint, protocol)

        def on_timeout():
            if not result.called:
                result.errback(BackendConnectTimeout(
                    "no TLS handshake within %ss" % self.cfg.connect_timeout))
            d.cancel()   # stops a TCP connect still in progress (no-op once connected)
            if protocol.transport is not None:
                protocol.transport.abortConnection()

        timer = self.reactor.callLater(self.cfg.connect_timeout, on_timeout)

        def connected(_):
            return protocol.ready

        def done(value):
            if timer.active():
                timer.cancel()
            if result.called:
                # We already gave up on this attempt; make sure it doesn't linger.
                if not isinstance(value, Failure) and protocol.transport is not None:
                    protocol.transport.abortConnection()
                if isinstance(value, Failure):
                    value.trap(Exception)
                return None
            if isinstance(value, Failure):
                result.errback(value)
            else:
                result.callback(value)

        d.addCallback(connected)
        d.addBoth(done)
        return result

    @defer.inlineCallbacks
    def connect(self, protocol_factory, client_desc=""):
        """Connect a new session to the best available DC. Returns (backend, protocol)."""
        errors = []
        for b in self.candidates():
            proto = protocol_factory()
            try:
                yield self._connect_one(b, proto)
            except Exception as e:
                msg = _describe_error(e)
                errors.append("%s: %s" % (b.name, msg))
                log.warning("session %s could not reach DC %s: %s", client_desc, b.name, msg)
                self._record_failure(b, msg, immediate=True)
                continue
            if b.state != UP:
                self._record_success(b)
            return b, proto
        raise NoBackendAvailable("; ".join(errors) or "no DCs configured")

    # ---------- health checks ----------

    def start(self):
        self._health_loop = task.LoopingCall(self.check_all)
        self._health_loop.clock = self.reactor
        return self._health_loop.start(self.health_cfg.interval, now=True)

    def stop(self):
        self.shutting_down = True
        if self._health_loop is not None and self._health_loop.running:
            self._health_loop.stop()

    def check_all(self):
        return defer.DeferredList([self.check(b) for b in self.backends], consumeErrors=True)

    @defer.inlineCallbacks
    def check(self, b):
        b.last_check = time.strftime("%Y-%m-%dT%H:%M:%S")
        proto = _HealthClient()
        try:
            yield self._connect_one(b, proto)
            self._check_certificate(b, proto)
            attrs = yield self._root_dse(proto)
        except Exception as e:
            self._record_failure(b, _describe_error(e))
            if proto.transport is not None:
                proto.transport.abortConnection()
            return
        try:
            proto.transport.loseConnection()
        except Exception:
            pass

        b.dns_host_name = _first(attrs.get("dnshostname"))
        synced = _first(attrs.get("issynchronized"))
        if synced is not None and synced.upper() != "TRUE":
            # AD reports isSynchronized=FALSE when a DC has not finished initial
            # replication (e.g. a freshly promoted DC). Don't send clients there.
            self._record_failure(b, "RootDSE isSynchronized=%s" % synced)
            return
        self._record_success(b)

    def _check_certificate(self, b, proto):
        cert = proto.peer_certificate()
        if cert is None:
            return
        b.cert_days_left = days_until_expiry(cert)
        warn = self.health_cfg.cert_expiry_warn_days
        if b.cert_days_left <= warn and b.name not in self._warned_expiry:
            self._warned_expiry.add(b.name)
            log.warning("DC %s certificate expires in %d day(s)", b.name, b.cert_days_left)
        elif b.cert_days_left > warn:
            self._warned_expiry.discard(b.name)

    def _root_dse(self, proto):
        """Anonymous base search of the RootDSE; resolves to {attr_lower: [str values]}."""
        req = pureldap.LDAPSearchRequest(
            baseObject=b"",
            scope=pureldap.LDAP_SCOPE_baseObject,
            filter=pureldap.LDAPFilter_present(b"objectClass"),
            attributes=[b"dnsHostName", b"isSynchronized", b"currentTime"],
        )
        result = defer.Deferred()
        attrs = {}

        def handler(resp):
            if isinstance(resp, pureldap.LDAPSearchResultEntry):
                for name, values in resp.attributes:
                    key = _s(name).lower()
                    attrs[key] = [_s(v) for v in values]
                return False
            if isinstance(resp, pureldap.LDAPSearchResultDone):
                if resp.resultCode == 0:
                    result.callback(attrs)
                else:
                    result.errback(Exception("RootDSE search failed, resultCode=%s %s"
                                             % (resp.resultCode, _s(resp.errorMessage))))
                return True
            return False

        proto.send_multiResponse(req, handler).addErrback(
            lambda f: result.errback(f) if not result.called else None)
        timer = self.reactor.callLater(
            self.health_cfg.timeout,
            lambda: result.errback(Exception("RootDSE search timed out")) if not result.called else None,
        )
        result.addBoth(lambda r: (timer.cancel() if timer.active() else None, r)[1])
        return result

    def status(self):
        return [b.as_dict() for b in self.backends]


def _s(v):
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)


def _first(values):
    return values[0] if values else None


def _describe_error(e):
    if isinstance(e, Failure):
        e = e.value
    text = str(e) or e.__class__.__name__
    # Make the common TLS verification failure obvious in the log.
    if "certificate verify failed" in text or "CERTIFICATE_VERIFY_FAILED" in text:
        return "TLS certificate verification failed (untrusted CA, expired, or name mismatch): " + text
    # The IOCP reactor reports a refused/blocked connect as a bare "5: EIO".
    from twisted.internet import error as terr
    if isinstance(e, (terr.ConnectError, terr.ConnectionRefusedError, terr.TCPTimedOutError)) \
            or "EIO" in text:
        return ("cannot open a TCP connection to the DC (port closed, blocked by a firewall, "
                "or host unreachable): " + text)
    return text


class _OneShotFactory(Factory):
    noisy = False

    def __init__(self, proto):
        self._proto = proto

    def buildProtocol(self, addr):
        return self._proto


def _quiet_connect(endpoint, proto):
    """Like endpoints.connectProtocol, without 'Starting factory' log lines."""
    return endpoint.connect(_OneShotFactory(proto))
