"""TLS helpers: trust roots for verifying DCs, and the proxy's own server certificate."""

import datetime
import logging
import ssl as stdlib_ssl
import sys

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key
from OpenSSL import crypto
from twisted.internet import ssl

log = logging.getLogger("cloakbind.tls")

_TLS_VERSIONS = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}


class TLSConfigError(Exception):
    pass


def _windows_store_certs():
    """DER certificates from the Windows LocalMachine ROOT and CA stores."""
    if sys.platform != "win32":
        raise TLSConfigError(
            'ca_sources = ["windows"] only works on Windows; use a PEM file path here'
        )
    server_auth = "1.3.6.1.5.5.7.3.1"
    disallowed = set()
    try:
        for der, encoding, _trust in stdlib_ssl.enum_certificates("Disallowed"):
            disallowed.add(der)
    except OSError:
        pass
    ders, skipped = [], 0
    for store in ("ROOT", "CA"):
        for der, encoding, trust in stdlib_ssl.enum_certificates(store):
            if encoding != "x509_asn":
                continue
            # trust is True (all purposes) or the set of EKU OIDs the cert is
            # trusted for; skip roots not trusted for server authentication.
            if der in disallowed or (trust is not True and server_auth not in trust):
                skipped += 1
                continue
            ders.append(der)
    if skipped:
        log.info("skipped %d Windows store certificate(s) not trusted for server authentication", skipped)
    return ders


def _pem_file_certs(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise TLSConfigError("cannot read CA file %s: %s" % (path, e))
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        # maybe a single DER-encoded .cer exported from Windows
        try:
            certs = [x509.load_der_x509_certificate(data)]
        except ValueError:
            raise TLSConfigError("CA file %s is not PEM or DER" % path)
    from cryptography.hazmat.primitives.serialization import Encoding
    return [c.public_bytes(Encoding.DER) for c in certs]


def build_trust_root(ca_sources):
    """Build a Twisted trust root from the configured CA sources."""
    certs = []
    seen = set()
    for src in ca_sources:
        ders = _windows_store_certs() if src.lower() == "windows" else _pem_file_certs(src)
        loaded = 0
        for der in ders:
            if der in seen:
                continue
            seen.add(der)
            try:
                certs.append(ssl.Certificate.load(der, crypto.FILETYPE_ASN1))
                loaded += 1
            except Exception as e:  # odd certs in the Windows store; skip them
                log.debug("skipping unloadable CA certificate from %s: %s", src, e)
        log.info("loaded %d trusted CA certificate(s) from %s", loaded, src)
    if not certs:
        raise TLSConfigError("no trusted CA certificates were loaded; cannot verify DCs")
    return ssl.trustRootFromCertificates(certs)


def client_tls_options(server_name, trust_root, min_tls):
    """TLS options for connecting to one DC, with full chain and hostname checks."""
    return ssl.optionsForClientTLS(
        server_name,
        trustRoot=trust_root,
        extraCertificateOptions={"raiseMinimumTo": _TLS_VERSIONS[min_tls]},
    )


def _read_password(path):
    if not path:
        return None
    with open(path, "rb") as f:
        return f.read().strip()


def server_tls_options(cfg):
    """
    CertificateOptions for the proxy's listener, from a PFX or PEM cert/key.
    Returns (options, leaf_certificate) so expiry can be reported.
    """
    try:
        if cfg.pfx_file:
            with open(cfg.pfx_file, "rb") as f:
                data = f.read()
            key, cert, chain = pkcs12.load_key_and_certificates(
                data, _read_password(cfg.pfx_password_file)
            )
            if key is None or cert is None:
                raise TLSConfigError("PFX %s must contain a certificate and private key" % cfg.pfx_file)
            chain = chain or []
        else:
            with open(cfg.cert_file, "rb") as f:
                pem_certs = x509.load_pem_x509_certificates(f.read())
            cert, chain = pem_certs[0], pem_certs[1:]
            with open(cfg.key_file, "rb") as f:
                key = load_pem_private_key(f.read(), password=None)
    except TLSConfigError:
        raise
    except Exception as e:
        raise TLSConfigError("could not load the proxy's server certificate: %s" % e)

    # The leaf must match the key, otherwise clients get confusing handshake errors.
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    if cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) != \
            key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo):
        raise TLSConfigError("the server certificate does not match its private key")

    options = ssl.CertificateOptions(
        privateKey=crypto.PKey.from_cryptography_key(key),
        certificate=crypto.X509.from_cryptography(cert),
        extraCertChain=[crypto.X509.from_cryptography(c) for c in chain],
        raiseMinimumTo=_TLS_VERSIONS[cfg.min_tls],
    )
    return options, cert


def days_until_expiry(cert):
    """cert: a cryptography x509.Certificate."""
    not_after = cert.not_valid_after_utc
    return (not_after - datetime.datetime.now(datetime.timezone.utc)).days


def describe_cert(cert):
    return "subject=%s expires=%s" % (
        cert.subject.rfc4514_string(), cert.not_valid_after_utc.strftime("%Y-%m-%d"),
    )
