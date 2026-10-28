"""Configuration loading and validation (TOML)."""

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field
from typing import List, Optional


class ConfigError(Exception):
    pass


DEFAULT_CONFIG_PATH = os.path.join(
    os.environ.get("ProgramData", r"C:\ProgramData"), "Cloakbind", "config.toml"
)


@dataclass
class ListenerConfig:
    name: str
    bind: str
    port: int
    mode: str                       # "ldap" | "starttls" | "ldaps"
    allowed_clients: List[ipaddress._BaseNetwork]
    read_only: bool
    require_tls_for_bind: bool
    reject_unauthenticated_bind: bool


@dataclass
class ServerTLSConfig:
    pfx_file: Optional[str] = None
    pfx_password_file: Optional[str] = None
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    min_tls: str = "1.2"


@dataclass
class BackendServerConfig:
    host: str
    port: int
    server_name: str               # name verified against the DC certificate


@dataclass
class BackendsConfig:
    strategy: str                  # "failover" | "round_robin"
    connect_timeout: float
    ca_sources: List[str]          # "windows" and/or paths to PEM files
    min_tls: str
    servers: List[BackendServerConfig]


@dataclass
class HealthConfig:
    interval: float
    timeout: float
    rise: int                      # consecutive successes to mark a DC up
    fall: int                      # consecutive failures to mark a DC down
    cert_expiry_warn_days: int


@dataclass
class StatusConfig:
    enabled: bool
    bind: str
    port: int
    show_account_names: bool   # dashboard/events show real account names (default: masked)
    event_history: int         # how many recent events the dashboard keeps in memory


@dataclass
class ServiceConfig:
    log_file: Optional[str]
    log_level: str
    log_retention_days: int
    max_connections: int
    max_connections_per_client: int   # 0 = unlimited
    first_message_timeout: float      # seconds a new client has to send its first LDAP message
    max_request_size: int             # largest LDAP message accepted from a client
    max_response_size: int            # largest LDAP message accepted from a DC
    reactor: str                   # "auto" | "iocp" | "select" | "default"
    event_log: bool                # warnings/errors also go to the Windows Application log


@dataclass
class Config:
    service: ServiceConfig
    listeners: List[ListenerConfig]
    server_tls: Optional[ServerTLSConfig]
    backends: BackendsConfig
    health: HealthConfig
    status: StatusConfig
    source_path: str = ""


def _get(d, key, default, typ, ctx):
    val = d.get(key, default)
    if val is None:
        return None
    if typ is float and isinstance(val, int):
        val = float(val)
    if not isinstance(val, typ):
        raise ConfigError("%s.%s must be %s" % (ctx, key, typ.__name__))
    return val


def _resolve(path, base_dir):
    if path is None:
        return None
    path = os.path.expandvars(path)
    if not os.path.isabs(path):
        path = os.path.join(base_dir, path)
    return path


def _is_loopback(bind):
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        return bind.lower() == "localhost"


def load_config(path):
    path = os.path.abspath(path)
    try:
        with open(path, "rb") as f:
            # utf-8-sig: tolerate the byte-order mark Notepad / Windows PowerShell may add
            raw = tomllib.loads(f.read().decode("utf-8-sig"))
    except FileNotFoundError:
        raise ConfigError("config file not found: %s" % path)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError("config file %s is not valid TOML: %s" % (path, e))
    base = os.path.dirname(path)

    # [service]
    s = raw.get("service", {})
    service = ServiceConfig(
        log_file=_resolve(_get(s, "log_file", None, str, "service"), base),
        log_level=_get(s, "log_level", "INFO", str, "service").upper(),
        log_retention_days=_get(s, "log_retention_days", 30, int, "service"),
        max_connections=_get(s, "max_connections", 1000, int, "service"),
        max_connections_per_client=_get(s, "max_connections_per_client", 0, int, "service"),
        first_message_timeout=_get(s, "first_message_timeout", 30.0, float, "service"),
        max_request_size=_get(s, "max_request_size", 4 * 1024 * 1024, int, "service"),
        max_response_size=_get(s, "max_response_size", 64 * 1024 * 1024, int, "service"),
        reactor=_get(s, "reactor", "auto", str, "service").lower(),
        event_log=_get(s, "event_log", True, bool, "service"),
    )
    if service.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        raise ConfigError("service.log_level must be DEBUG, INFO, WARNING or ERROR")
    if service.reactor not in ("auto", "iocp", "select", "default"):
        raise ConfigError("service.reactor must be auto, iocp, select or default")

    # [[listener]]
    listeners = []
    raw_listeners = raw.get("listener", [])
    if not raw_listeners:
        raise ConfigError("at least one [[listener]] is required")
    for i, l in enumerate(raw_listeners):
        ctx = "listener[%d]" % i
        mode = _get(l, "mode", "ldap", str, ctx).lower()
        if mode == "plain":
            mode = "ldap"   # older name
        if mode not in ("ldap", "starttls", "ldaps"):
            raise ConfigError("%s.mode must be ldap, starttls or ldaps" % ctx)
        nets = []
        for c in _get(l, "allowed_clients", [], list, ctx):
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                raise ConfigError("%s.allowed_clients: invalid network %r" % (ctx, c))
        bind = _get(l, "bind", "0.0.0.0", str, ctx)
        if mode == "ldap" and not nets and not _is_loopback(bind) \
                and not _get(l, "allow_any_client", False, bool, ctx):
            # Legacy clients send simple-bind passwords in clear to this port, so
            # say exactly who may use it (the app servers), unless deliberately opened.
            raise ConfigError(
                "%s is a plain LDAP listener on %s with no allowed_clients. List the legacy "
                "application servers (IPs/CIDRs) in allowed_clients, or set "
                "allow_any_client = true if you really want any host to use it." % (ctx, bind))
        listeners.append(ListenerConfig(
            name=_get(l, "name", "%s-%s" % (mode, l.get("port", "?")), str, ctx),
            bind=bind,
            port=_get(l, "port", 636 if mode == "ldaps" else 9001, int, ctx),   # 9001: a common unprivileged choice for legacy LDAP proxies
            mode=mode,
            allowed_clients=nets,
            read_only=_get(l, "read_only", False, bool, ctx),
            require_tls_for_bind=_get(l, "require_tls_for_bind", mode == "starttls", bool, ctx),
            reject_unauthenticated_bind=_get(l, "reject_unauthenticated_bind", True, bool, ctx),
        ))

    # [server_tls]
    server_tls = None
    if "server_tls" in raw:
        t = raw["server_tls"]
        server_tls = ServerTLSConfig(
            pfx_file=_resolve(_get(t, "pfx_file", None, str, "server_tls"), base),
            pfx_password_file=_resolve(_get(t, "pfx_password_file", None, str, "server_tls"), base),
            cert_file=_resolve(_get(t, "cert_file", None, str, "server_tls"), base),
            key_file=_resolve(_get(t, "key_file", None, str, "server_tls"), base),
            min_tls=_get(t, "min_tls", "1.2", str, "server_tls"),
        )
        if not server_tls.pfx_file and not (server_tls.cert_file and server_tls.key_file):
            raise ConfigError("server_tls needs pfx_file, or both cert_file and key_file")
    if any(l.mode in ("ldaps", "starttls") for l in listeners) and server_tls is None:
        raise ConfigError("[server_tls] is required for ldaps/starttls listeners "
                          "(plain ldap listeners work without it)")

    # [backends] + [[backends.server]]
    b = raw.get("backends", {})
    servers = []
    for i, srv in enumerate(b.get("server", [])):
        ctx = "backends.server[%d]" % i
        host = _get(srv, "host", None, str, ctx)
        if not host:
            raise ConfigError("%s.host is required" % ctx)
        servers.append(BackendServerConfig(
            host=host,
            port=_get(srv, "port", 636, int, ctx),
            server_name=_get(srv, "server_name", host, str, ctx),
        ))
    if not servers:
        raise ConfigError("at least one [[backends.server]] is required")
    ca_sources = _get(b, "ca_sources", ["windows"], list, "backends")
    ca_sources = [c if c.lower() == "windows" else _resolve(c, base) for c in ca_sources]
    if not ca_sources:
        raise ConfigError("backends.ca_sources must not be empty (certificate verification is mandatory)")
    backends = BackendsConfig(
        strategy=_get(b, "strategy", "failover", str, "backends").lower(),
        connect_timeout=_get(b, "connect_timeout", 5.0, float, "backends"),
        ca_sources=ca_sources,
        min_tls=_get(b, "min_tls", "1.2", str, "backends"),
        servers=servers,
    )
    if backends.strategy not in ("failover", "round_robin"):
        raise ConfigError("backends.strategy must be failover or round_robin")

    h = raw.get("health", {})
    health = HealthConfig(
        interval=_get(h, "interval", 15.0, float, "health"),
        timeout=_get(h, "timeout", 5.0, float, "health"),
        rise=_get(h, "rise", 2, int, "health"),
        fall=_get(h, "fall", 2, int, "health"),
        cert_expiry_warn_days=_get(h, "cert_expiry_warn_days", 30, int, "health"),
    )

    st = raw.get("status", {})
    status = StatusConfig(
        enabled=_get(st, "enabled", True, bool, "status"),
        bind=_get(st, "bind", "127.0.0.1", str, "status"),
        port=_get(st, "port", 8636, int, "status"),
        show_account_names=_get(st, "show_account_names", False, bool, "status"),
        event_history=_get(st, "event_history", 200, int, "status"),
    )

    for v in (backends.min_tls, server_tls.min_tls if server_tls else "1.2"):
        if v not in ("1.2", "1.3"):
            raise ConfigError("min_tls must be \"1.2\" or \"1.3\"")

    return Config(service=service, listeners=listeners, server_tls=server_tls,
                  backends=backends, health=health, status=status, source_path=path)
