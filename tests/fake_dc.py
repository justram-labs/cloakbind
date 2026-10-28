"""
A stand-in "domain controller" for testing: an ldaptor in-memory LDAP server
listening on LDAPS. It mimics a few AD behaviours the proxy cares about:
  - RootDSE with dnsHostName and isSynchronized
  - AD-style failed-bind messages ("... data 52e ...")
  - paged-results response control (1.2.840.113556.1.4.319) on SearchResultDone
  - an entry (ou=whoami) whose description names the DC, to see who answered

Usage: python fake_dc.py PORT NAME CERT_PEM KEY_PEM [--unsynced] [--users N]
"""

import sys

import io

from ldaptor.inmemory import fromLDIFFile
from ldaptor.interfaces import IConnectedLDAPEntry
from ldaptor.protocols import pureber, pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.ldapserver import LDAPServer
from twisted.internet import defer, reactor, ssl
from twisted.internet.protocol import ServerFactory
from twisted.python.components import registerAdapter

PAGED_OID = b"1.2.840.113556.1.4.319"


def build_ldif(name, n_users):
    lines = [
        "version: 1\n",
        "dn: dc=test,dc=local\nobjectClass: domain\ndc: test\n",
        "dn: ou=whoami,dc=test,dc=local\nobjectClass: organizationalUnit\nou: whoami\n"
        "description: %s\n" % name,
        "dn: cn=alice,dc=test,dc=local\nobjectClass: person\ncn: alice\nsn: A\n"
        "userPassword: secret\n",
        "dn: ou=bulk,dc=test,dc=local\nobjectClass: organizationalUnit\nou: bulk\n",
    ]
    for i in range(n_users):
        lines.append("dn: cn=user%05d,ou=bulk,dc=test,dc=local\nobjectClass: person\n"
                     "cn: user%05d\nsn: U\ndescription: %s\n" % (i, i, "x" * 200))
    return ("\n".join(lines) + "\n").encode()


class FakeDC(LDAPServer):
    dc_name = "dc"
    synced = True

    def __init__(self):
        super().__init__()
        self._paged = set()

    def handle(self, msg):
        if msg.controls:
            if any(c[0] == PAGED_OID for c in msg.controls):
                self._paged.add(msg.id)
            # drop controls so ldaptor's checkControls doesn't reject them
            msg.controls = None
        return super().handle(msg)

    def queue(self, id, op):
        if isinstance(op, pureldap.LDAPSearchResultDone) and id in self._paged:
            self._paged.discard(id)
            # paged results response control: SEQUENCE { size 0, cookie "" }
            value = pureber.BERSequence([pureber.BERInteger(0), pureber.BEROctetString(b"")]).toWire()
            msg = pureldap.LDAPMessage(op, id=id, controls=[(PAGED_OID, None, value)])
            self.transport.write(msg.toWire())
            return
        return super().queue(id, op)

    def getRootDSE(self, request, reply):
        root = IConnectedLDAPEntry(self.factory)
        reply(pureldap.LDAPSearchResultEntry(
            objectName="",
            attributes=[
                ("supportedLDAPVersion", ["3"]),
                ("namingContexts", [root.dn.getText()]),
                ("dnsHostName", ["%s.test.local" % self.dc_name]),
                ("isSynchronized", ["TRUE" if self.synced else "FALSE"]),
            ],
        ))
        return pureldap.LDAPSearchResultDone(resultCode=0)

    def fail_LDAPBindRequest(self, resultCode, errorMessage):
        if resultCode == ldaperrors.LDAPInvalidCredentials.resultCode:
            errorMessage = ("80090308: LdapErr: DSID-0C090569, comment: AcceptSecurityContext "
                            "error, data 52e, v4f7c")
        return pureldap.LDAPBindResponse(resultCode=resultCode, errorMessage=errorMessage)


class Factory(ServerFactory):
    def __init__(self, root, name, synced):
        self.root = root
        self.name, self.synced = name, synced

    def buildProtocol(self, addr):
        p = FakeDC()
        p.dc_name, p.synced, p.factory = self.name, self.synced, self
        return p


registerAdapter(lambda f: f.root, Factory, IConnectedLDAPEntry)


@defer.inlineCallbacks
def main():
    port, name, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
    synced = "--unsynced" not in sys.argv
    users = int(sys.argv[sys.argv.index("--users") + 1]) if "--users" in sys.argv else 3000
    root = yield fromLDIFFile(io.BytesIO(build_ldif(name, users)))
    with open(cert, "rb") as f:
        cert_pem = f.read()
    with open(key, "rb") as f:
        key_pem = f.read()
    opts = ssl.PrivateCertificate.loadPEM(cert_pem + key_pem).options()
    reactor.listenSSL(port, Factory(root, name, synced), opts, interface="127.0.0.1")
    print("fake DC %s listening on %d" % (name, port), flush=True)


if __name__ == "__main__":
    reactor.callWhenRunning(main)
    reactor.run()
