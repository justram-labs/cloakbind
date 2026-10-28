"""
Minimal BER framing for LDAP messages.

The proxy relays LDAP messages byte-for-byte. It only needs to know where each
LDAPMessage starts and ends, its messageID, and the protocolOp tag. Everything
else (controls, referrals, SASL blobs, AD-specific extensions) passes through
untouched, so nothing is lost by re-encoding.
"""

from dataclasses import dataclass

# protocolOp tags (RFC 4511, APPLICATION class)
BIND_REQUEST = 0x60
BIND_RESPONSE = 0x61
UNBIND_REQUEST = 0x42
SEARCH_REQUEST = 0x63
SEARCH_RESULT_ENTRY = 0x64
SEARCH_RESULT_DONE = 0x65
SEARCH_RESULT_REFERENCE = 0x73
MODIFY_REQUEST = 0x66
MODIFY_RESPONSE = 0x67
ADD_REQUEST = 0x68
ADD_RESPONSE = 0x69
DEL_REQUEST = 0x4A
DEL_RESPONSE = 0x6B
MODDN_REQUEST = 0x6C
MODDN_RESPONSE = 0x6D
COMPARE_REQUEST = 0x6E
COMPARE_RESPONSE = 0x6F
ABANDON_REQUEST = 0x50
EXTENDED_REQUEST = 0x77
EXTENDED_RESPONSE = 0x78
INTERMEDIATE_RESPONSE = 0x79

WRITE_OPS = {
    MODIFY_REQUEST: "Modify",
    ADD_REQUEST: "Add",
    DEL_REQUEST: "Delete",
    MODDN_REQUEST: "ModifyDN",
}

# Operations a read-only listener lets through (Extended requests are further
# restricted by OID in proxy.py). Everything else is refused.
READ_ONLY_ALLOWED = {BIND_REQUEST, UNBIND_REQUEST, SEARCH_REQUEST, COMPARE_REQUEST,
                     ABANDON_REQUEST, EXTENDED_REQUEST}

OP_NAMES = {
    BIND_REQUEST: "Bind",
    BIND_RESPONSE: "BindResponse",
    UNBIND_REQUEST: "Unbind",
    SEARCH_REQUEST: "Search",
    SEARCH_RESULT_ENTRY: "SearchEntry",
    SEARCH_RESULT_DONE: "SearchDone",
    SEARCH_RESULT_REFERENCE: "SearchReference",
    MODIFY_REQUEST: "Modify",
    MODIFY_RESPONSE: "ModifyResponse",
    ADD_REQUEST: "Add",
    ADD_RESPONSE: "AddResponse",
    DEL_REQUEST: "Delete",
    DEL_RESPONSE: "DeleteResponse",
    MODDN_REQUEST: "ModifyDN",
    MODDN_RESPONSE: "ModifyDNResponse",
    COMPARE_REQUEST: "Compare",
    COMPARE_RESPONSE: "CompareResponse",
    ABANDON_REQUEST: "Abandon",
    EXTENDED_REQUEST: "Extended",
    EXTENDED_RESPONSE: "ExtendedResponse",
    INTERMEDIATE_RESPONSE: "IntermediateResponse",
}


class FramingError(Exception):
    """The byte stream is not valid LDAP/BER and the connection must close."""


@dataclass
class Frame:
    raw: bytes        # the complete LDAPMessage, exactly as received
    msg_id: int
    op_tag: int

    @property
    def op_name(self):
        return OP_NAMES.get(self.op_tag, "0x%02x" % self.op_tag)


def _read_length(buf, pos):
    """Return (length, header_bytes_consumed) or None if more data is needed."""
    if pos >= len(buf):
        return None
    first = buf[pos]
    if first < 0x80:
        return first, 1
    n = first & 0x7F
    if n == 0 or n > 4:
        raise FramingError("unsupported BER length encoding")
    if pos + 1 + n > len(buf):
        return None
    return int.from_bytes(buf[pos + 1:pos + 1 + n], "big"), 1 + n


class Framer:
    """
    Incremental LDAPMessage splitter.

    Data is appended to a bytearray and only parsed once the declared length
    of the next message has fully arrived, so a large message delivered in
    many small TCP reads costs O(n), not O(n^2).
    """

    def __init__(self, max_message_size):
        self.max_message_size = max_message_size
        self.buf = bytearray()
        self._need = 0      # total bytes of the next message, once its header is known

    def __len__(self):
        return len(self.buf)

    def feed(self, data):
        self.buf += data
        if self._need and len(self.buf) < self._need:
            return []
        frames = []
        pos = 0
        buf = self.buf
        while pos < len(buf):
            if buf[pos] != 0x30:
                raise FramingError("expected LDAPMessage SEQUENCE, got tag 0x%02x" % buf[pos])
            ln = _read_length(buf, pos + 1)
            if ln is None:
                break
            length, lhdr = ln
            if length > self.max_message_size:
                raise FramingError("message of %d bytes exceeds the %d byte limit"
                                   % (length, self.max_message_size))
            total = 1 + lhdr + length
            if len(buf) - pos < total:
                self._need = total
                break
            raw = bytes(buf[pos:pos + total])
            frames.append(parse_envelope(raw, 1 + lhdr))
            pos += total
            self._need = 0
        if pos:
            del buf[:pos]
        return frames


def extract_frames(buf, max_message_size):
    """One-shot helper: split complete messages off buf. Returns (frames, remaining)."""
    f = Framer(max_message_size)
    frames = f.feed(buf)
    return frames, bytes(f.buf)


def parse_envelope(raw, pos):
    try:
        # messageID  INTEGER
        if raw[pos] != 0x02:
            raise FramingError("expected messageID INTEGER")
        ln = _read_length(raw, pos + 1)
        if ln is None:
            raise FramingError("truncated messageID")
        length, lhdr = ln
        start = pos + 1 + lhdr
        if length < 1 or length > 5 or start + length > len(raw):
            raise FramingError("invalid messageID")
        msg_id = int.from_bytes(raw[start:start + length], "big", signed=True)
        op_pos = start + length
        if op_pos >= len(raw):
            raise FramingError("missing protocolOp")
        return Frame(raw=raw, msg_id=msg_id, op_tag=raw[op_pos])
    except IndexError:
        raise FramingError("truncated LDAPMessage")


def is_final_response(op_tag):
    """True if this response completes its request (no more PDUs for that ID)."""
    return op_tag not in (SEARCH_RESULT_ENTRY, SEARCH_RESULT_REFERENCE, INTERMEDIATE_RESPONSE)


# ---------------------------------------------------------------- strict request parsing
# The proxy enforces policy on binds and extended requests, so it parses them
# itself, strictly, rather than trusting a lenient decoder: anything that does
# not match the RFC 4511 structure exactly is rejected, never forwarded.

AUTH_SIMPLE = 0x80
AUTH_SASL = 0xA3


def _tlv(buf, pos, end):
    """Read one TLV inside buf[pos:end]. Returns (tag, value_start, value_end)."""
    if pos + 2 > end:
        raise FramingError("truncated element")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise FramingError("multi-byte BER tags are not supported")
    ln = _read_length(buf, pos + 1)
    if ln is None:
        raise FramingError("truncated length")
    length, lhdr = ln
    vstart = pos + 1 + lhdr
    vend = vstart + length
    if vend > end:
        raise FramingError("element overruns its container")
    return tag, vstart, vend


def _op_bounds(frame):
    """(value_start, value_end) of the protocolOp inside an LDAPMessage."""
    raw = frame.raw
    _, mstart, mend = _tlv(raw, 0, len(raw))
    _, _, id_end = _tlv(raw, mstart, mend)          # messageID
    tag, ostart, oend = _tlv(raw, id_end, mend)     # protocolOp
    if tag != frame.op_tag:
        raise FramingError("protocolOp tag mismatch")
    return ostart, oend


@dataclass
class BindInfo:
    version: int
    dn: bytes
    auth_tag: int
    password: bytes          # simple binds only
    sasl_mechanism: bytes    # SASL binds only

    @property
    def method(self):
        if self.auth_tag == AUTH_SIMPLE:
            return "simple"
        if self.auth_tag == AUTH_SASL:
            return "SASL/" + self.sasl_mechanism.decode("ascii", "replace")
        return "auth-0x%02x" % self.auth_tag


def parse_bind(frame):
    """
    BindRequest ::= [APPLICATION 0] SEQUENCE {
        version INTEGER, name LDAPDN, authentication AuthenticationChoice }
    """
    raw = frame.raw
    try:
        pos, end = _op_bounds(frame)
        tag, vs, ve = _tlv(raw, pos, end)
        if tag != 0x02 or not 1 <= ve - vs <= 4:
            raise FramingError("bind: bad version")
        version = int.from_bytes(raw[vs:ve], "big", signed=True)
        tag, ds, de = _tlv(raw, ve, end)
        if tag != 0x04:
            raise FramingError("bind: bad name")
        auth_tag, as_, ae = _tlv(raw, de, end)
        if ae != end:
            raise FramingError("bind: unexpected data after authentication")
        password, mech = b"", b""
        if auth_tag == AUTH_SIMPLE:
            password = raw[as_:ae]
        elif auth_tag == AUTH_SASL:
            t, ms, me = _tlv(raw, as_, ae)
            if t != 0x04:
                raise FramingError("bind: bad SASL mechanism")
            mech = raw[ms:me]
        return BindInfo(version, bytes(raw[ds:de]), auth_tag, bytes(password), bytes(mech))
    except IndexError:
        raise FramingError("bind: truncated")


def parse_extended_name(frame):
    """ExtendedRequest ::= [APPLICATION 23] SEQUENCE { requestName [0] LDAPOID, requestValue [1] OCTET STRING OPTIONAL }"""
    raw = frame.raw
    try:
        pos, end = _op_bounds(frame)
        tag, ns, ne = _tlv(raw, pos, end)
        if tag != 0x80:
            raise FramingError("extended: missing requestName")
        if ne != end:
            tag, _, ve = _tlv(raw, ne, end)
            if tag != 0x81 or ve != end:
                raise FramingError("extended: unexpected data")
        return bytes(raw[ns:ne])
    except IndexError:
        raise FramingError("extended: truncated")
