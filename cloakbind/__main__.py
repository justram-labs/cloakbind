"""
Command line:

    python -m cloakbind run   [--config PATH]   run in the foreground (Ctrl+C to stop)
    python -m cloakbind check [--config PATH]   validate config and test every DC once
    python -m cloakbind ports [--config PATH]   print the listener ports (used by the installer)
    python -m cloakbind version
"""

import argparse
import sys

from . import __version__
from .config import DEFAULT_CONFIG_PATH, ConfigError, load_config


def cmd_check(path):
    import logging
    cfg = load_config(path)
    logging.basicConfig(level=logging.WARNING, format="  %(levelname)s %(message)s")
    from twisted.internet import defer, task

    from .backends import BackendPool
    from .tlsutil import TLSConfigError, build_trust_root, describe_cert, server_tls_options

    print("Config OK: %s" % cfg.source_path)
    for l in cfg.listeners:
        print("  listener %-14s %s:%d mode=%s read_only=%s allowed=%s" % (
            l.name, l.bind, l.port, l.mode, l.read_only,
            ",".join(str(n) for n in l.allowed_clients) or "any"))
    try:
        if cfg.server_tls:
            _, leaf = server_tls_options(cfg.server_tls)
            print("Proxy certificate OK: %s" % describe_cert(leaf))
        trust = build_trust_root(cfg.backends.ca_sources)
    except TLSConfigError as e:
        print("TLS ERROR: %s" % e)
        return 2

    @defer.inlineCallbacks
    def main(reactor):
        pool = BackendPool(reactor, cfg.backends, cfg.health, trust)
        print("Testing %d domain controller(s)..." % len(pool.backends))
        yield pool.check_all()
        ok = 0
        for b in pool.backends:
            if b.state == "up":
                ok += 1
                print("  [ OK ] %-32s dnsHostName=%s cert_days_left=%s" % (
                    b.name, b.dns_host_name, b.cert_days_left))
            else:
                print("  [FAIL] %-32s %s" % (b.name, b.last_error))
        print("%d of %d DC(s) reachable over verified LDAPS" % (ok, len(pool.backends)))
        if ok == 0:
            raise SystemExit(1)

    task.react(main)


def main(argv=None):
    p = argparse.ArgumentParser(prog="cloakbind", description="Cloakbind: legacy LDAP to LDAPS proxy for Active Directory")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("run", "check", "ports"):
        sp = sub.add_parser(name)
        sp.add_argument("--config", default=DEFAULT_CONFIG_PATH,
                        help="path to config.toml (default: %(default)s)")
    sub.add_parser("version")
    args = p.parse_args(argv)

    if args.cmd == "version":
        print(__version__)
        return 0
    try:
        if args.cmd == "check":
            return cmd_check(args.config)
        if args.cmd == "ports":
            # Used by the installer to open the firewall for the configured listeners.
            print(",".join(str(l.port) for l in load_config(args.config).listeners))
            return 0
        from .app import run
        run(args.config, console=True)
        return 0
    except ConfigError as e:
        print("CONFIG ERROR: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
