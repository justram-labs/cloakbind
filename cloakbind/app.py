"""Wires configuration, logging, the DC pool, listeners and the status endpoint together."""

import json
import logging
import logging.handlers
import os
import sys
import time

from . import PRODUCT, __version__
from .config import load_config
from .tlsutil import build_trust_root, server_tls_options, days_until_expiry, describe_cert

log = logging.getLogger("cloakbind")

EVENT_SOURCE = "Cloakbind"


# ---------------------------------------------------------------- logging

def setup_logging(cfg, console=True):
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    if cfg.service.log_file:
        os.makedirs(os.path.dirname(cfg.service.log_file), exist_ok=True)
        fh = logging.handlers.TimedRotatingFileHandler(
            cfg.service.log_file, when="midnight",
            backupCount=cfg.service.log_retention_days, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    if console:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        root.addHandler(sh)
    if cfg.service.event_log and sys.platform == "win32" and not console:
        try:
            eh = logging.handlers.NTEventLogHandler(EVENT_SOURCE)
            eh.setLevel(logging.WARNING)
            eh.setFormatter(logging.Formatter("%(name)s: %(message)s"))
            root.addHandler(eh)
        except Exception as e:  # event source not registered, no pywin32, etc.
            sys.stderr.write("event log unavailable: %s\n" % e)
    root.setLevel(cfg.service.log_level)
    # Twisted is chatty at INFO ("Starting factory ..."); keep it to warnings
    # unless we're debugging.
    logging.getLogger("twisted").setLevel(
        logging.DEBUG if cfg.service.log_level == "DEBUG" else logging.WARNING)

    from twisted.logger import STDLibLogObserver, globalLogBeginner
    globalLogBeginner.beginLoggingTo([STDLibLogObserver(name="twisted")],
                                     redirectStandardIO=False, discardBuffer=True)


# ---------------------------------------------------------------- reactor

def install_reactor(choice):
    """
    On Windows the default select() reactor is capped at 512 sockets (about
    250 proxied sessions). The IOCP reactor has no such limit.
    """
    if "twisted.internet.reactor" in sys.modules:
        return
    if choice in ("auto", "iocp") and sys.platform == "win32":
        try:
            from twisted.internet import iocpreactor
            iocpreactor.install()
            return
        except Exception as e:
            if choice == "iocp":
                raise
            logging.getLogger("cloakbind").warning(
                "IOCP reactor unavailable (%s); using select reactor", e)
    if choice == "select":
        from twisted.internet import selectreactor
        selectreactor.install()


# ---------------------------------------------------------------- status endpoint

def _status_body(state):
    import socket
    pool = state["pool"]
    up = [b for b in pool.backends if b.state == "up"]
    if pool.cfg.strategy == "failover":
        active = [up[0].name] if up else []
    else:
        active = [b.name for b in up]
    return {
        "product": PRODUCT,
        "version": __version__,
        "hostname": socket.gethostname(),
        "uptime_seconds": int(time.time() - state["started"]),
        "reactor": state.get("reactor"),
        "healthy": bool(up),
        "strategy": pool.cfg.strategy,
        "active_domain_controllers": active,
        "domain_controllers": pool.status(),
        "active_sessions": state["registry"].active,
        "listeners": {f.listener.name: dict(f.stats) for f in state["factories"]},
        "listener_info": [
            {"name": f.listener.name, "port": f.listener.port, "mode": f.listener.mode,
             "read_only": f.listener.read_only}
            for f in state["factories"]
        ],
        "server_cert_days_left": state.get("server_cert_days_left"),
        "show_account_names": state["status_cfg"].show_account_names,
    }


def _status_site(state):
    """
    Local status web server:
      /            JSON health (HTTP 200 if any DC is healthy, else 503)
      /events      JSON recent activity (account names masked unless configured)
      /dashboard   human-readable dashboard (self-contained, no internet needed)
    """
    from importlib import resources
    from twisted.web import resource, server

    from .events import EVENTS

    def _asset(name):
        return (resources.files("cloakbind") / "dashboard" / name).read_bytes()

    assets = {
        b"dashboard": (_asset("index.html"), b"text/html; charset=utf-8"),
        b"dashboard.css": (_asset("dashboard.css"), b"text/css; charset=utf-8"),
        b"dashboard.js": (_asset("dashboard.js"), b"application/javascript; charset=utf-8"),
    }

    def _common_headers(request):
        request.setHeader(b"Cache-Control", b"no-store")
        request.setHeader(b"X-Content-Type-Options", b"nosniff")
        request.setHeader(b"X-Frame-Options", b"DENY")
        request.setHeader(b"Referrer-Policy", b"no-referrer")
        # Only same-origin resources; no inline script; nothing loaded from the internet.
        request.setHeader(b"Content-Security-Policy",
                          b"default-src 'self'; script-src 'self'; style-src 'self'; "
                          b"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                          b"base-uri 'none'; form-action 'none'")

    class Json(resource.Resource):
        isLeaf = True

        def __init__(self, producer, health_code=False):
            super().__init__()
            self.producer = producer
            self.health_code = health_code

        def render_GET(self, request):
            _common_headers(request)
            body = self.producer()
            request.setHeader(b"Content-Type", b"application/json")
            if self.health_code:
                # 503 when no DC is healthy, so load balancers / monitors can key off the code.
                request.setResponseCode(200 if body["healthy"] else 503)
            return json.dumps(body, indent=2).encode()

    class Static(resource.Resource):
        isLeaf = True

        def __init__(self, content, ctype):
            super().__init__()
            self.content, self.ctype = content, ctype

        def render_GET(self, request):
            _common_headers(request)
            request.setHeader(b"Content-Type", self.ctype)
            return self.content

    status_json = Json(lambda: _status_body(state), health_code=True)
    events_json = Json(lambda: {"show_account_names": state["status_cfg"].show_account_names,
                                "events": EVENTS.snapshot(state["status_cfg"].show_account_names)})

    class Root(resource.Resource):
        def getChild(self, name, request):
            if name == b"":
                return status_json
            if name == b"events":
                return events_json
            if name in assets:
                return Static(*assets[name])
            return resource.NoResource()

        def render_GET(self, request):
            return status_json.render_GET(request)

    site = server.Site(Root())
    site.noisy = False
    site.displayTracebacks = False
    return site


# ---------------------------------------------------------------- startup

def start(cfg, reactor):
    """Start everything on an already-installed reactor. Returns a state dict."""
    from .backends import BackendPool
    from .proxy import ListenerFactory, SessionRegistry

    log.info("%s %s starting (config %s)", PRODUCT, __version__, cfg.source_path)
    trust_root = build_trust_root(cfg.backends.ca_sources)

    srv_opts, srv_cert_days = None, None
    if cfg.server_tls:
        srv_opts, leaf = server_tls_options(cfg.server_tls)
        srv_cert_days = days_until_expiry(leaf)
        log.info("proxy certificate: %s", describe_cert(leaf))
        if srv_cert_days <= cfg.health.cert_expiry_warn_days:
            log.warning("the proxy's own certificate expires in %d day(s)", srv_cert_days)

    pool = BackendPool(reactor, cfg.backends, cfg.health, trust_root)
    registry = SessionRegistry()
    state = {"pool": pool, "registry": registry, "factories": [], "ports": [],
             "started": time.time(), "server_cert_days_left": srv_cert_days,
             "status_cfg": cfg.status, "reactor": reactor.__class__.__name__}
    from .events import EVENTS
    EVENTS.resize(cfg.status.event_history)

    for l in cfg.listeners:
        factory = ListenerFactory(reactor, l, pool, cfg.service, srv_opts, registry)
        if l.mode == "ldaps":
            port = reactor.listenSSL(l.port, factory, srv_opts, interface=l.bind)
        else:
            port = reactor.listenTCP(l.port, factory, interface=l.bind)
            if l.mode == "ldap":
                log.info("listener %s on %s:%d accepts plain LDAP from legacy clients "
                         "(client->proxy is unencrypted%s; proxy->DC is always LDAPS)",
                         l.name, l.bind, l.port,
                         ", StartTLS offered" if srv_opts is not None else "")
        state["factories"].append(factory)
        state["ports"].append(port)
        extras = []
        if l.read_only:
            extras.append("read-only")
        if l.allowed_clients:
            extras.append("allowed=%s" % ",".join(str(n) for n in l.allowed_clients))
        log.info("listening %s on %s:%d (%s)%s", l.name, l.bind, l.port, l.mode,
                 " [%s]" % "; ".join(extras) if extras else "")

    log.info("domain controllers (%s): %s", cfg.backends.strategy,
             ", ".join("%s [verify as %s]" % (b.name, b.cfg.server_name) for b in pool.backends))

    if cfg.status.enabled:
        state["ports"].append(
            reactor.listenTCP(cfg.status.port, _status_site(state), interface=cfg.status.bind))
        log.info("status endpoint http://%s:%d/  dashboard http://%s:%d/dashboard (account names %s)",
                 cfg.status.bind, cfg.status.port, cfg.status.bind, cfg.status.port,
                 "shown" if cfg.status.show_account_names else "masked")

    pool.start().addErrback(lambda f: log.error("health loop stopped: %s", f.getErrorMessage()))
    return state


def stop(state):
    if not state:
        return
    state["pool"].stop()
    for p in state["ports"]:
        try:
            p.stopListening()
        except Exception:
            pass


def run(config_path, console=True, stop_event_hook=None):
    """
    Load config, start, and run the reactor until stopped. `stop_event_hook`
    lets the Windows service wrapper hand back a function that stops us.
    """
    cfg = load_config(config_path)
    setup_logging(cfg, console=console)
    install_reactor(cfg.service.reactor)
    from twisted.internet import reactor
    log.info("using reactor %s", reactor.__class__.__name__)

    state = {}

    def boot():
        try:
            state.update(start(cfg, reactor))
        except Exception as e:
            log.critical("startup failed: %s", e, exc_info=cfg.service.log_level == "DEBUG")
            state["error"] = e
            reactor.stop()

    reactor.callWhenRunning(boot)
    def on_shutdown():
        log.info("shutting down")
        stop(state)

    reactor.addSystemEventTrigger("before", "shutdown", on_shutdown)
    if stop_event_hook is not None:
        stop_event_hook(lambda: reactor.callFromThread(reactor.stop))
    reactor.run(installSignalHandlers=console and stop_event_hook is None)
    log.info("%s stopped", PRODUCT)
    if "error" in state:
        raise SystemExit(1)
