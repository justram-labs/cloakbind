"""
Windows service host for Cloakbind (requires pywin32).

The service runs python.exe directly:

    "C:\\Program Files\\Python313\\python.exe" -I -m cloakbind.winservice

so it does not depend on pythonservice.exe or its DLL search quirks. The
installer script (scripts/Install-Cloakbind.ps1) registers it that way.

Config path: %ProgramData%\\Cloakbind\\config.toml, or the CLOAKBIND_CONFIG
environment variable set on the service (registry Environment value).
"""

import os
import sys
import traceback

import servicemanager
import win32evtlog
import win32evtlogutil
import win32service
import win32serviceutil

from .config import DEFAULT_CONFIG_PATH, ConfigError

SERVICE_NAME = "Cloakbind"


def _event(message, error=False):
    """Write to the Application log under the "Cloakbind" source (registered by the installer)."""
    try:
        win32evtlogutil.ReportEvent(
            SERVICE_NAME, 1,
            eventType=win32evtlog.EVENTLOG_ERROR_TYPE if error else win32evtlog.EVENTLOG_INFORMATION_TYPE,
            strings=[message])
    except Exception:
        pass


class CloakbindService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = "Cloakbind (LDAP to LDAPS proxy)"
    _svc_description_ = ("Cloakbind: accepts legacy LDAP clients and relays them over verified LDAPS "
                         "to healthy Active Directory domain controllers, with failover.")
    # Host the service in python.exe itself (see module docstring).
    _exe_name_ = sys.executable
    _exe_args_ = "-I -m cloakbind.winservice"

    def __init__(self, args):
        super().__init__(args)
        self._stopper = None
        self._stop_requested = False

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=15000)
        self._stop_requested = True
        if self._stopper is not None:
            self._stopper()

    def SvcDoRun(self):
        from .app import run

        config_path = os.environ.get("CLOAKBIND_CONFIG", DEFAULT_CONFIG_PATH)
        _event("%s starting with config %s" % (SERVICE_NAME, config_path))

        def hook(stopper):
            self._stopper = stopper
            if self._stop_requested:
                stopper()

        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        try:
            run(config_path, console=False, stop_event_hook=hook)
        except ConfigError as e:
            _event("%s configuration error: %s" % (SERVICE_NAME, e), error=True)
            raise SystemExit(2)
        except SystemExit:
            _event("%s failed to start; see the proxy log file for details" % SERVICE_NAME, error=True)
            raise
        except Exception:
            _event("%s crashed:\n%s" % (SERVICE_NAME, traceback.format_exc()), error=True)
            raise
        _event("%s stopped" % SERVICE_NAME)


def main():
    if len(sys.argv) == 1:
        # Started by the Service Control Manager.
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(CloakbindService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Manual management: install / remove / start / stop / debug
        win32serviceutil.HandleCommandLine(CloakbindService)


if __name__ == "__main__":
    main()
