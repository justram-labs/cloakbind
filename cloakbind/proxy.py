"""
The client-facing side of the proxy.

Each client connection gets its own TLS connection to a domain controller,
opened when the client sends its first message that needs one. LDAP messages
are relayed byte-for-byte in both directions (message IDs are preserved, so
Abandon, paging cookies, controls and referrals all work).

Policy-relevant requests (Bind, Extended, and everything on read-only
listeners) are parsed strictly by ber.py; anything malformed is refused,
never forwarded. ldaptor is used to build the proxy's own responses and to
decode bind results for logging.
"""

import ipaddress
import itertools
import logging
import time

from twisted.internet.error import ConnectionDone
from twisted.internet.protocol import Factory, Protocol

from ldaptor.protocols import pureber, pureldap

from . import ber
from .backends import NoBackendAvailable, TLSBackendProtocol
from .events import EVENTS

log = logging.getLogger("cloakbind.session")

STARTTLS_OID = b"1.3.6.1.4.1.1466.20037"
# Extended operations a read-only listener allows (everything else is refused).
READ_ONLY_EXTENDED = {
    b"1.3.6.1.4.1.4203.1.11.3",      # Who am I?
    b"1.2.840.113556.1.4.1781",      # AD fast concurrent bind
}

RESULT_SUCCESS = 0
RESULT_OPERATIONS_ERROR = 1
RESULT_PROTOCOL_ERROR = 2
RESULT_CONFIDENTIALITY_REQUIRED = 13
RESULT_UNAVAILABLE = 52
RESULT_UNWILLING_TO_PERFORM = 53

# Active Directory puts a "data XXX" sub-code in failed-bind error messages.
AD_BIND_SUBCODES = {
    "525": "user not found",
    "52e": "invalid credentials",
    "530": "logon not permitted at this time",
    "531": "logon not permitted from this workstation",
    "532": "password expired",
    "533": "account disabled",
    "568": "too many security IDs",
    "701": "account expired",
    "773": "user must reset password",
    "775": "account locked out",
}

_RESPONSE_FOR_WRITE = {
    ber.MODIFY_REQUEST: pureldap.LDAPModifyResponse,
    ber.ADD_REQUEST: pureldap.LDAPAddResponse,
    ber.DEL_REQUEST: pureldap.LDAPDelResponse,
    ber.MODDN_REQUEST: pureldap.LDAPModifyDNResponse,
}

_decoder = pureldap.LDAPBERDecoderContext_TopLevel(
    inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
        fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
    )
)

_session_ids = itertools.count(1)

# _client_policy outcomes
FORWARD, HANDLED, CLOSE = "forward", "handled", "close"


def decode(raw):
    """Fully decode one LDAPMessage with ldaptor; None if ldaptor can't parse it."""
    try:
        msg, _ = pureber.berDecodeObject(_decoder, raw)
        return msg
    except Exception:
        return None


def _s(v):
    if v is None:
        return ""
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)


def _ad_reason(error_message):
    text = _s(error_message).lower()
    idx = text.find(" data ")
    if idx >= 0:
        code = text[idx + 6:idx + 9]
        if code in AD_BIND_SUBCODES:
            return " [AD: %s]" % AD_BIND_SUBCODES[code]
    return ""


class BackendSide(TLSBackendProtocol):
    """The proxy's connection to one DC on behalf of one client session."""

    def __init__(self, session):
        super().__init__()
        self.session = session
        self.framer = ber.Framer(session.factory.service_cfg.max_response_size)

    def dataReceived(self, data):
        try:
            frames = self.framer.feed(data)
        except ber.FramingError as e:
            log.error("[%s] invalid data from DC %s: %s", self.session.sid,
                      self.session.backend_name, e)
            self.transport.abortConnection()
            return
        for f in frames:
            self.session.from_backend(self, f)

    def connectionLost(self, reason):
        super().connectionLost(reason)
        self.session.backend_lost(self, reason)


class ClientSession(Protocol):
    def __init__(self):
        self.sid = next(_session_ids)
        self.framer = None
        self.backend = None          # BackendSide once connected
        self.backend_obj = None      # pool Backend
        self.backend_name = "-"
        self.connecting = False
        self.queued = []             # frames waiting for the DC connection
        self.queued_bytes = 0
        self.pending_binds = {}      # msg_id -> (dn, method, t0)
        self.closing = False
        self.unbinding = False
        self.tls_active = False
        self.counted = False
        self.ip = None
        self.ops = 0
        self.t0 = time.time()
        self.peer = "?"
        self.first_msg_timer = None

    # ---------- connection lifecycle ----------

    def connectionMade(self):
        f = self.factory
        cfg = f.service_cfg
        peer = self.transport.getPeer()
        self.ip = getattr(peer, "host", None)
        self.peer = "%s:%s" % (self.ip, getattr(peer, "port", "?"))

        reject = None
        if f.listener.allowed_clients and not f.client_allowed(self.ip):
            reject = "not in allowed_clients"
        elif f.registry.active >= cfg.max_connections:
            reject = "max_connections (%d) reached" % cfg.max_connections
        elif cfg.max_connections_per_client and \
                f.registry.per_ip.get(self.ip, 0) >= cfg.max_connections_per_client:
            reject = "max_connections_per_client (%d) reached" % cfg.max_connections_per_client
        if reject:
            log.warning("[%s] rejected %s on %s: %s", self.sid, self.peer, f.listener.name, reject)
            f.stats["rejected"] += 1
            EVENTS.add("client_rejected", client=self.ip, listener=f.listener.name, detail=reject)
            self.closing = True
            self.transport.abortConnection()
            return

        f.registry.active += 1
        f.registry.per_ip[self.ip] = f.registry.per_ip.get(self.ip, 0) + 1
        f.stats["accepted"] += 1
        self.counted = True
        self.tls_active = f.listener.mode == "ldaps"
        self.framer = ber.Framer(cfg.max_request_size)
        if cfg.first_message_timeout > 0:
            self.first_msg_timer = f.reactor.callLater(cfg.first_message_timeout,
                                                       self._first_message_timeout)
        log.debug("[%s] client %s connected on %s", self.sid, self.peer, f.listener.name)

    def _first_message_timeout(self):
        self.first_msg_timer = None
        log.info("[%s] %s sent nothing within %ss; closing", self.sid, self.peer,
                 self.factory.service_cfg.first_message_timeout)
        self._abort()

    def _start_backend(self):
        self.connecting = True
        # Stop reading from the client until the DC connection exists, so a
        # client can't pile unbounded data into memory meanwhile.
        self.transport.pauseProducing()
        d = self.factory.pool.connect(lambda: BackendSide(self),
                                      client_desc="[%s] %s" % (self.sid, self.peer))
        d.addCallbacks(self._backend_ready, self._backend_failed)

    def _backend_ready(self, result):
        backend_obj, proto = result
        self.connecting = False
        if self.closing or not self.connected:
            proto.transport.abortConnection()
            return
        self.backend, self.backend_obj = proto, backend_obj
        self.backend_name = backend_obj.name
        backend_obj.active_sessions += 1
        backend_obj.total_sessions += 1
        log.debug("[%s] %s -> DC %s", self.sid, self.peer, self.backend_name)
        # Flow control: if one side can't keep up, pause the other.
        self.transport.registerProducer(proto.transport, True)
        proto.transport.registerProducer(self.transport, True)
        queued, self.queued, self.queued_bytes = self.queued, [], 0
        for frame in queued:
            self._send_to_backend(frame)
        self.transport.resumeProducing()

    def _backend_failed(self, failure):
        self.connecting = False
        failure.trap(NoBackendAvailable)
        log.error("[%s] no DC available for %s: %s", self.sid, self.peer, failure.value)
        self.factory.stats["no_backend"] += 1
        EVENTS.add("no_dc", client=self.ip, listener=self.factory.listener.name,
                   detail="no domain controller reachable")
        for frame in self.queued:
            if frame.op_tag == ber.BIND_REQUEST:
                self._reply(frame.msg_id, pureldap.LDAPBindResponse(
                    resultCode=RESULT_UNAVAILABLE,
                    errorMessage=b"Cloakbind: no domain controller is reachable"))
        self.queued, self.queued_bytes = [], 0
        self._close()

    def connectionLost(self, reason):
        self.closing = True
        if self.first_msg_timer is not None and self.first_msg_timer.active():
            self.first_msg_timer.cancel()
        self.first_msg_timer = None
        if self.counted:
            reg = self.factory.registry
            reg.active -= 1
            n = reg.per_ip.get(self.ip, 1) - 1
            if n > 0:
                reg.per_ip[self.ip] = n
            else:
                reg.per_ip.pop(self.ip, None)
            self.counted = False
        if self.backend_obj is not None:
            self.backend_obj.active_sessions -= 1
            self.backend_obj = None
        if self.backend is not None and self.backend.transport is not None:
            self.backend.transport.loseConnection()
        log.debug("[%s] client %s closed (%d ops, %.1fs)", self.sid, self.peer,
                  self.ops, time.time() - self.t0)

    def backend_lost(self, proto, reason):
        if proto is not self.backend:
            return  # an abandoned or failed connect attempt; not this session's DC
        if self.closing:
            return
        if self.factory.pool.shutting_down:
            self._close()
            return
        if not self.unbinding:
            log.warning("[%s] DC %s closed the connection for %s; closing client so it "
                        "reconnects (it will be sent to a healthy DC)",
                        self.sid, self.backend_name, self.peer)
            if self.backend_obj is not None and not reason.check(ConnectionDone):
                # An abrupt drop (not a clean close such as AD's idle timeout)
                # counts toward marking the DC down.
                self.factory.pool._record_failure(
                    self.backend_obj, "session connection dropped: %s" % reason.getErrorMessage())
        self._close()

    def _close(self):
        """Close after flushing anything already written (e.g. an error response)."""
        self.closing = True
        self.transport.loseConnection()

    def _abort(self):
        self.closing = True
        self.transport.abortConnection()

    # ---------- client -> DC ----------

    def dataReceived(self, data):
        if self.closing:
            return
        try:
            frames = self.framer.feed(data)
        except ber.FramingError as e:
            log.warning("[%s] invalid LDAP data from %s: %s", self.sid, self.peer, e)
            self._abort()
            return

        if frames and self.first_msg_timer is not None:
            if self.first_msg_timer.active():
                self.first_msg_timer.cancel()
            self.first_msg_timer = None

        for i, frame in enumerate(frames):
            if self.closing:
                return
            self.ops += 1

            if frame.op_tag == ber.EXTENDED_REQUEST:
                try:
                    name = ber.parse_extended_name(frame)
                except ber.FramingError as e:
                    log.warning("[%s] malformed extended request from %s: %s", self.sid, self.peer, e)
                    self._abort()
                    return
                if name == STARTTLS_OID:
                    # Nothing may follow StartTLS until the TLS handshake. Bytes
                    # sent after it in the clear would otherwise be treated as if
                    # they had arrived over TLS (STARTTLS command injection).
                    if i != len(frames) - 1 or len(self.framer):
                        log.warning("[%s] %s sent data after StartTLS before the TLS handshake; "
                                    "closing", self.sid, self.peer)
                        self._abort()
                        return
                    self._handle_starttls(frame)
                    return

            outcome = self._client_policy(frame)
            if outcome == FORWARD:
                self._route(frame)
            elif outcome == CLOSE:
                self._close()
                return

        if self.backend is None:
            limit = self.factory.service_cfg.max_request_size + 1024 * 1024
            if self.queued_bytes + len(self.framer) > limit:
                log.warning("[%s] %s sent too much data before the DC connection was ready; "
                            "closing", self.sid, self.peer)
                self._abort()

    def _route(self, frame):
        if frame.op_tag == ber.UNBIND_REQUEST:
            self.unbinding = True
            if self.backend is None and not self.connecting:
                # Nothing to unbind from; just close.
                self._close()
                return
        if self.backend is not None:
            self._send_to_backend(frame)
            return
        self.queued.append(frame)
        self.queued_bytes += len(frame.raw)
        if not self.connecting:
            self._start_backend()

    def _send_to_backend(self, frame):
        self.backend.transport.write(frame.raw)

    def _client_policy(self, frame):
        """Returns FORWARD, HANDLED (proxy answered it) or CLOSE."""
        tag = frame.op_tag
        listener = self.factory.listener

        if listener.read_only:
            if tag in ber.WRITE_OPS:
                log.info("[%s] blocked %s from %s (listener %s is read-only)",
                         self.sid, ber.WRITE_OPS[tag], self.peer, listener.name)
                self.factory.stats["blocked_writes"] += 1
                EVENTS.add("write_blocked", client=self.ip, listener=listener.name,
                           detail="%s on a read-only listener" % ber.WRITE_OPS[tag])
                self._reply(frame.msg_id, _RESPONSE_FOR_WRITE[tag](
                    resultCode=RESULT_UNWILLING_TO_PERFORM, matchedDN=b"",
                    errorMessage=b"Cloakbind: write operations are disabled on this listener"))
                return HANDLED
            if tag not in ber.READ_ONLY_ALLOWED:
                log.warning("[%s] blocked unknown operation %s from %s on read-only listener %s",
                            self.sid, frame.op_name, self.peer, listener.name)
                self.factory.stats["blocked_writes"] += 1
                EVENTS.add("write_blocked", client=self.ip, listener=listener.name,
                           detail="unknown operation %s on a read-only listener" % frame.op_name)
                return CLOSE
            if tag == ber.EXTENDED_REQUEST:
                name = ber.parse_extended_name(frame)   # already validated by caller
                if name not in READ_ONLY_EXTENDED:
                    log.info("[%s] blocked extended operation %s from %s (read-only listener %s)",
                             self.sid, _s(name), self.peer, listener.name)
                    self.factory.stats["blocked_writes"] += 1
                    EVENTS.add("write_blocked", client=self.ip, listener=listener.name,
                               detail="extended operation %s on a read-only listener" % _s(name))
                    self._reply(frame.msg_id, pureldap.LDAPExtendedResponse(
                        resultCode=RESULT_UNWILLING_TO_PERFORM, responseName=name,
                        errorMessage=b"Cloakbind: extended operation not allowed on this listener"))
                    return HANDLED

        if tag == ber.BIND_REQUEST:
            return self._inspect_bind(frame)
        return FORWARD

    def _inspect_bind(self, frame):
        listener = self.factory.listener
        try:
            b = ber.parse_bind(frame)
        except ber.FramingError as e:
            # Fail closed: a bind the proxy can't parse can't be policy-checked.
            log.warning("[%s] refused malformed bind from %s: %s", self.sid, self.peer, e)
            self.factory.stats["rejected_binds"] += 1
            EVENTS.add("bind_refused", client=self.ip, listener=listener.name,
                       detail="malformed bind request")
            self._reply(frame.msg_id, pureldap.LDAPBindResponse(
                resultCode=RESULT_PROTOCOL_ERROR, errorMessage=b"Cloakbind: malformed bind request"))
            return CLOSE

        dn = _s(b.dn)
        anonymous = b.auth_tag == ber.AUTH_SIMPLE and not b.dn and not b.password

        if not self.tls_active and listener.require_tls_for_bind and not anonymous:
            log.warning("[%s] refused %s bind for %r from %s before StartTLS",
                        self.sid, b.method, dn, self.peer)
            self.factory.stats["rejected_binds"] += 1
            EVENTS.add("bind_refused", account=dn, client=self.ip, listener=listener.name,
                       detail="password bind before StartTLS")
            self._reply(frame.msg_id, pureldap.LDAPBindResponse(
                resultCode=RESULT_CONFIDENTIALITY_REQUIRED,
                errorMessage=b"Cloakbind: use StartTLS before binding"))
            return HANDLED

        if b.auth_tag == ber.AUTH_SIMPLE and b.dn and not b.password \
                and listener.reject_unauthenticated_bind:
            # RFC 4513 "unauthenticated bind": a DN with an empty password. AD
            # reports success but the session is anonymous; applications that
            # treat bind success as authentication can be bypassed this way.
            log.warning("[%s] refused unauthenticated bind (DN with empty password) "
                        "for %r from %s", self.sid, dn, self.peer)
            self.factory.stats["rejected_binds"] += 1
            EVENTS.add("bind_refused", account=dn, client=self.ip, listener=listener.name,
                       detail="empty password (unauthenticated bind)")
            self._reply(frame.msg_id, pureldap.LDAPBindResponse(
                resultCode=RESULT_UNWILLING_TO_PERFORM,
                errorMessage=b"Cloakbind: empty passwords are not accepted"))
            return HANDLED

        self.pending_binds[frame.msg_id] = (dn or "(anonymous)", b.method, time.time())
        return FORWARD

    def _handle_starttls(self, frame):
        listener = self.factory.listener
        offered = listener.mode in ("ldap", "starttls") and self.factory.server_tls_options is not None
        if not offered or self.tls_active:
            code, text = RESULT_UNAVAILABLE, b"Cloakbind: StartTLS is not offered on this listener"
            if self.tls_active:
                code, text = RESULT_OPERATIONS_ERROR, b"Cloakbind: TLS is already active"
            self._reply(frame.msg_id, pureldap.LDAPExtendedResponse(
                resultCode=code, errorMessage=text, responseName=STARTTLS_OID))
            return
        self._reply(frame.msg_id, pureldap.LDAPExtendedResponse(
            resultCode=RESULT_SUCCESS, responseName=STARTTLS_OID))
        self.transport.startTLS(self.factory.server_tls_options)
        self.tls_active = True
        log.debug("[%s] StartTLS negotiated with %s", self.sid, self.peer)

    # ---------- DC -> client ----------

    def from_backend(self, proto, frame):
        if proto is not self.backend:
            return
        if frame.op_tag == ber.BIND_RESPONSE and frame.msg_id in self.pending_binds:
            self._log_bind_result(frame)
        if self.connected and not self.closing:
            self.transport.write(frame.raw)

    def _log_bind_result(self, frame):
        dn, method, t0 = self.pending_binds.pop(frame.msg_id)
        msg = decode(frame.raw)
        ms = (time.time() - t0) * 1000
        if msg is None:
            log.info("[%s] bind dn=%r method=%s client=%s dc=%s result=(undecodable)",
                     self.sid, dn, method, self.peer, self.backend_name)
            return
        rc = msg.value.resultCode
        if rc == RESULT_SUCCESS:
            self.factory.stats["binds_ok"] += 1
            EVENTS.add("bind_ok", account=dn, client=self.ip, dc=self.backend_name,
                       listener=self.factory.listener.name, detail="%.0f ms" % ms)
            log.info("[%s] bind OK dn=%r method=%s client=%s dc=%s (%.0f ms)",
                     self.sid, dn, method, self.peer, self.backend_name, ms)
        elif rc == 14:  # saslBindInProgress: intermediate step, not a failure
            self.pending_binds[frame.msg_id] = (dn, method, t0)
        else:
            self.factory.stats["binds_failed"] += 1
            err = _s(msg.value.errorMessage).rstrip("\x00")   # AD NUL-terminates its error text
            reason = _ad_reason(err).strip(" []").replace("AD: ", "") or ("result %d" % rc)
            EVENTS.add("bind_failed", account=dn, client=self.ip, dc=self.backend_name,
                       listener=self.factory.listener.name, detail=reason)
            log.warning("[%s] bind FAILED dn=%r method=%s client=%s dc=%s result=%d%s msg=%r",
                        self.sid, dn, method, self.peer, self.backend_name, rc,
                        _ad_reason(err), err)

    # ---------- helpers ----------

    def _reply(self, msg_id, response):
        if self.connected:
            self.transport.write(pureldap.LDAPMessage(value=response, id=msg_id).toWire())


class SessionRegistry:
    """Shared across listeners so connection limits are global."""

    def __init__(self):
        self.active = 0
        self.per_ip = {}


class ListenerFactory(Factory):
    protocol = ClientSession
    noisy = False

    def __init__(self, reactor, listener, pool, service_cfg, server_tls_options, registry):
        self.reactor = reactor
        self.listener = listener
        self.pool = pool
        self.service_cfg = service_cfg
        self.server_tls_options = server_tls_options
        self.registry = registry
        self.stats = {k: 0 for k in ("accepted", "rejected", "no_backend", "binds_ok",
                                     "binds_failed", "rejected_binds", "blocked_writes")}

    def client_allowed(self, host):
        try:
            ip = ipaddress.ip_address(host)
        except (TypeError, ValueError):
            return False
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in net for net in self.listener.allowed_clients)
