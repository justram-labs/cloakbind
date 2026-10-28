"""Unit tests for the LDAP message framer."""

import pytest
from ldaptor.protocols import pureldap

from cloakbind import ber


def msgs():
    big = pureldap.LDAPSearchResultEntry(
        objectName="cn=x,dc=test", attributes=[("description", ["y" * 70000])])
    return [
        pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn=b"cn=a", auth=b"pw"), id=1).toWire(),
        pureldap.LDAPMessage(big, id=300).toWire(),          # multi-byte length
        pureldap.LDAPMessage(pureldap.LDAPAbandonRequest(id=1), id=2147483647).toWire(),
        pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(resultCode=0), id=300,
                             controls=[(b"1.2.840.113556.1.4.319", None, b"\x30\x03\x02\x01\x00")]).toWire(),
    ]


def test_whole_buffer():
    raw = b"".join(msgs())
    frames, rest = ber.extract_frames(raw, 10 ** 7)
    assert rest == b""
    assert [f.msg_id for f in frames] == [1, 300, 2147483647, 300]
    assert [f.op_tag for f in frames] == [ber.BIND_REQUEST, ber.SEARCH_RESULT_ENTRY,
                                          ber.ABANDON_REQUEST, ber.SEARCH_RESULT_DONE]
    assert b"".join(f.raw for f in frames) == raw     # byte-for-byte


def test_byte_at_a_time():
    raw = b"".join(msgs())
    buf, got = b"", []
    for i in range(len(raw)):
        buf += raw[i:i + 1]
        frames, buf = ber.extract_frames(buf, 10 ** 7)
        got.extend(frames)
    assert buf == b""
    assert b"".join(f.raw for f in got) == raw


def test_size_limit():
    with pytest.raises(ber.FramingError):
        ber.extract_frames(msgs()[1], 1000)


def test_garbage():
    with pytest.raises(ber.FramingError):
        ber.extract_frames(b"GET / HTTP/1.1\r\n\r\n", 10 ** 7)


def test_final_response():
    assert not ber.is_final_response(ber.SEARCH_RESULT_ENTRY)
    assert not ber.is_final_response(ber.SEARCH_RESULT_REFERENCE)
    assert not ber.is_final_response(ber.INTERMEDIATE_RESPONSE)
    for t in (ber.SEARCH_RESULT_DONE, ber.BIND_RESPONSE, ber.MODIFY_RESPONSE, ber.EXTENDED_RESPONSE):
        assert ber.is_final_response(t)


def test_truncated_envelope():
    with pytest.raises(ber.FramingError):
        ber.extract_frames(b"\x30\x00", 100)


def test_incremental_large_message_is_linear():
    import time
    size = 32 * 1024 * 1024
    f = ber.Framer(size + 100)
    t = time.time()
    assert f.feed(b"\x30\x84" + size.to_bytes(4, "big")) == []
    chunk = b"\x00" * 16384
    for _ in range(size // 16384 - 1):
        assert f.feed(chunk) == []
    assert time.time() - t < 5


def test_strict_bind_parser():
    good = pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn=b"cn=a", auth=b"pw"), id=1).toWire()
    frames, _ = ber.extract_frames(good, 1000)
    b = ber.parse_bind(frames[0])
    assert (b.dn, b.password, b.method) == (b"cn=a", b"pw", "simple")
    sasl = pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn=b"", auth=(b"GSSAPI", b"x"), sasl=True), id=2).toWire()
    frames, _ = ber.extract_frames(sasl, 1000)
    assert ber.parse_bind(frames[0]).method == "SASL/GSSAPI"
    # trailing junk inside the bind -> rejected
    def tlv(tag, body):
        return bytes([tag, len(body)]) + body
    bad = tlv(0x30, b"\x02\x01\x01" + tlv(0x60, b"\x02\x01\x03" + tlv(0x04, b"cn=a")
                                          + tlv(0x80, b"pw") + b"\x04\x00"))
    frames, _ = ber.extract_frames(bad, 1000)
    with pytest.raises(ber.FramingError):
        ber.parse_bind(frames[0])
