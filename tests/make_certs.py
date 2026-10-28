"""Generate a throwaway test PKI: a CA, DC certificates, a rogue-CA DC cert, and a proxy PFX."""

import datetime
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOW = datetime.datetime.now(datetime.timezone.utc)


def key():
    return ec.generate_private_key(ec.SECP256R1())


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(cn):
    k = key()
    c = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(cn))
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - datetime.timedelta(days=1))
         .not_valid_after(NOW + datetime.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                      content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .sign(k, hashes.SHA256()))
    return k, c


def make_leaf(ca_key, ca_cert, cn, sans, days=365):
    k = key()
    alt = [x509.DNSName(s) for s in sans if not s[0].isdigit()] + \
          [x509.IPAddress(ipaddress.ip_address(s)) for s in sans if s[0].isdigit()]
    c = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca_cert.subject)
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - datetime.timedelta(days=1))
         .not_valid_after(NOW + datetime.timedelta(days=days))
         .add_extension(x509.SubjectAlternativeName(alt), critical=False)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                        critical=False)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .sign(ca_key, hashes.SHA256()))
    return k, c


def pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption())


def pem_cert(c):
    return c.public_bytes(serialization.Encoding.PEM)


def main(out):
    os.makedirs(out, exist_ok=True)

    def w(fn, data):
        with open(os.path.join(out, fn), "wb") as f:
            f.write(data)

    ca_k, ca_c = make_ca("Test Enterprise Root CA")
    w("ca.pem", pem_cert(ca_c))
    for dc, days in (("dc1", 365), ("dc2", 365), ("dc4", 10)):
        k, c = make_leaf(ca_k, ca_c, "%s.test.local" % dc, ["%s.test.local" % dc], days)
        w("%s.pem" % dc, pem_cert(c))
        w("%s.key" % dc, pem_key(k))
    rogue_k, rogue_c = make_ca("Rogue CA")
    k, c = make_leaf(rogue_k, rogue_c, "dc3.test.local", ["dc3.test.local"])
    w("dc3.pem", pem_cert(c))
    w("dc3.key", pem_key(k))
    k, c = make_leaf(ca_k, ca_c, "ldapproxy.test.local", ["ldapproxy.test.local", "127.0.0.1"])
    w("proxy.pfx", pkcs12.serialize_key_and_certificates(
        b"ldapproxy", k, c, [ca_c], serialization.BestAvailableEncryption(b"Pfx-Pass-123")))
    w("proxy.pfx.pass", b"Pfx-Pass-123\n")


if __name__ == "__main__":
    main(sys.argv[1])
