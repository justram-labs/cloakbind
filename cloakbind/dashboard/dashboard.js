/* Cloakbind dashboard.
 * Everything that can contain client-supplied text (account names, errors) is
 * written with textContent, never as HTML.
 */
(function () {
  "use strict";

  var REFRESH_MS = 5000;
  var filter = "all";
  var lastEvents = [];

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function shortHost(name) {
    // "dc01.corp.example.com:636" -> "DC01"; IP addresses stay whole.
    var s = String(name || "");
    var host = s.replace(/:\d+$/, "");
    if (/^[\d.]+$/.test(host) || host.indexOf(":") >= 0) return host;
    return host.split(".")[0] || host;
  }

  // Let long DNs wrap at commas instead of mid-word.
  function breakable(text) { return String(text || "").replace(/,/g, ",\u200b"); }

  function duration(sec) {
    sec = Math.max(0, Math.floor(sec || 0));
    if (sec < 60) return sec + "s";
    var m = Math.floor(sec / 60);
    if (m < 60) return m + "m";
    var h = Math.floor(m / 60);
    if (h < 48) return h + "h " + (m % 60) + "m";
    return Math.floor(h / 24) + "d " + (h % 24) + "h";
  }

  function clock(ts) {
    var d = new Date(ts * 1000);
    var now = new Date();
    var t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    if (d.toDateString() === now.toDateString()) return t;
    return d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + t;
  }

  function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }

  // ------------------------------------------------------------ status sentence

  function renderStatus(s) {
    var box = $("status");
    var dcs = s.domain_controllers || [];
    var up = dcs.filter(function (d) { return d.state === "up"; });
    var down = dcs.filter(function (d) { return d.state === "down"; });
    var line, detail = "", level;

    if (!up.length) {
      level = "fail";
      line = "No domain controller is reachable. Clients can't sign in through the proxy.";
      var errs = down.map(function (d) { return shortHost(d.name) + ": " + (d.last_error || "down"); });
      detail = errs.join("; ") + (errs.length ? ". " : "") +
        "Check the DCs and port 636 from this server.";
    } else if (down.length) {
      level = "warn";
      line = plural(down.length, "domain controller is", "domain controllers are") + " down. " +
        "Sign-ins continue through " + up.map(function (d) { return shortHost(d.name); }).join(" and ") + ".";
      detail = "Down: " + down.map(function (d) {
        return shortHost(d.name) + " for " + duration(d.seconds_in_state);
      }).join(", ") + ".";
    } else {
      level = "ok";
      var active = (s.active_domain_controllers || []).map(shortHost);
      line = s.strategy === "failover"
        ? "Sign-ins are flowing through " + (active[0] || shortHost(up[0].name)) + "."
        : "Sign-ins are spread across " + active.join(" and ") + ".";
      detail = plural(up.length, "domain controller", "domain controllers") +
        " healthy over LDAPS. Checked every 15 seconds.";
    }
    box.setAttribute("data-level", level);
    $("status-line").textContent = line;
    $("status-detail").textContent = detail;
  }

  // ------------------------------------------------------------ route diagram

  function renderListeners(s) {
    var ul = $("listeners");
    clear(ul);
    (s.listener_info || []).forEach(function (l) {
      var st = (s.listeners || {})[l.name] || {};
      var li = el("li");
      var head = el("div");
      head.appendChild(el("span", "port", l.port));
      head.appendChild(el("span", "port-mode",
        (l.mode === "ldap" ? "plain LDAP" : l.mode === "ldaps" ? "LDAPS" : "StartTLS") +
        (l.read_only ? ", read-only" : "")));
      li.appendChild(head);
      var stats = el("div", "port-stats");
      stats.appendChild(document.createTextNode(plural(st.binds_ok || 0, "sign-in", "sign-ins")));
      var bad = (st.binds_failed || 0) + (st.rejected_binds || 0);
      if (bad) {
        stats.appendChild(document.createTextNode(", "));
        stats.appendChild(el("span", "bad", bad + " failed"));
      }
      if (st.rejected) {
        stats.appendChild(document.createTextNode(", "));
        stats.appendChild(el("span", "bad", plural(st.rejected, "client refused", "clients refused")));
      }
      li.appendChild(stats);
      ul.appendChild(li);
    });
    $("sessions").textContent = s.active_sessions || 0;
  }

  function renderProxy(s) {
    $("proxy-name").textContent = s.hostname || "Proxy";
    var meta = "Up " + duration(s.uptime_seconds) + ", version " + s.version;
    if (s.server_cert_days_left !== null && s.server_cert_days_left !== undefined) {
      meta += ", certificate " + s.server_cert_days_left + " days left";
    }
    $("proxy-meta").textContent = meta;
  }

  function renderDCs(s) {
    var ul = $("dcs");
    clear(ul);
    var active = s.active_domain_controllers || [];
    (s.domain_controllers || []).forEach(function (d, i) {
      var role = d.state === "down" ? "down" : (active.indexOf(d.name) >= 0 ? "active" : "standby");
      if (d.state === "unknown") role = "standby";
      var li = el("li", "dc");
      li.setAttribute("data-role", role);
      if (role === "active") li.appendChild(el("span", "pulse"));

      li.appendChild(el("div", "dc-name", shortHost(d.name)));
      var stateText = role === "active" ? "Active" : role === "down" ? "Down" :
        (d.state === "unknown" ? "Checking" : "Standby");
      li.appendChild(el("div", "dc-state", stateText));
      li.appendChild(el("div", "dc-fqdn", d.name + (s.strategy === "failover" ? "   preference " + (i + 1) : "")));

      var facts = el("div", "dc-facts");
      facts.appendChild(el("span", null, (d.state === "down" ? "Down for " : "Up for ") + duration(d.seconds_in_state)));
      facts.appendChild(el("span", null, (d.active_sessions || 0) + " open, " + (d.total_sessions || 0) + " total sessions"));
      if (d.cert_days_left !== null && d.cert_days_left !== undefined) {
        facts.appendChild(el("span", d.cert_days_left <= 30 ? "cert-soon" : null,
          "LDAPS certificate " + d.cert_days_left + " days left"));
      }
      li.appendChild(facts);
      if (d.last_error) li.appendChild(el("div", "dc-error", d.last_error));
      ul.appendChild(li);
    });
  }

  // ------------------------------------------------------------ activity

  function matches(e) {
    if (filter === "problems") return e.level === "fail" || e.level === "warn";
    if (filter === "dc") return e.kind === "dc_down" || e.kind === "dc_up" || e.kind === "no_dc";
    return true;
  }

  function renderEvents() {
    var body = $("events-body");
    clear(body);
    var shown = lastEvents.filter(matches);
    shown.forEach(function (e) {
      var tr = el("tr");
      tr.setAttribute("data-level", e.level);
      function cell(cls, label, text) {
        var td = el("td", cls, text);
        td.setAttribute("data-label", label);
        if (!text) td.setAttribute("data-empty", "");
        return td;
      }
      tr.appendChild(cell("t", "Time", clock(e.ts)));
      var ev = el("td", "evc");
      ev.appendChild(el("span", "ev", e.label));
      tr.appendChild(ev);
      tr.appendChild(cell("acct", "Account", breakable(e.account)));
      tr.appendChild(cell(null, "Client", e.client || ""));
      tr.appendChild(cell(null, "Domain controller", e.dc ? shortHost(e.dc) : ""));
      tr.appendChild(cell("det", "Detail", e.detail || ""));
      body.appendChild(tr);
    });
    var empty = $("events-empty");
    empty.hidden = shown.length > 0;
    if (!shown.length) {
      empty.textContent = lastEvents.length
        ? "Nothing matches this filter."
        : "No activity yet. Sign-ins and DC changes appear here as they happen.";
    }
  }

  // ------------------------------------------------------------ polling

  function getJSON(url) {
    // 503 from the status endpoint still carries a valid body.
    return fetch(url, { cache: "no-store" }).then(function (r) { return r.json(); });
  }

  function refresh() {
    Promise.all([getJSON("./"), getJSON("events")]).then(function (res) {
      var s = res[0], ev = res[1];
      document.title = (s.healthy ? "" : "Problem: ") + "Cloakbind " + (s.hostname || "");
      $("host").textContent = s.hostname || "";
      renderStatus(s);
      renderListeners(s);
      renderProxy(s);
      renderDCs(s);
      lastEvents = ev.events || [];
      $("masked-note").hidden = !!ev.show_account_names;
      renderEvents();
      $("foot").textContent = "Version " + s.version + ", " + (s.reactor || "") +
        ", failover strategy: " + s.strategy + ".";
      $("updated").textContent = "Updated " + new Date().toLocaleTimeString() + ", refreshes every 5 seconds";
    }).catch(function () {
      $("status").setAttribute("data-level", "fail");
      $("status-line").textContent = "Can't reach the proxy's status service.";
      $("status-detail").textContent =
        "The Cloakbind service may be stopped. Check it with Get-Service Cloakbind.";
      $("updated").textContent = "Last attempt " + new Date().toLocaleTimeString();
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    Array.prototype.forEach.call(document.querySelectorAll(".filters button"), function (b) {
      b.addEventListener("click", function () {
        filter = b.getAttribute("data-filter");
        Array.prototype.forEach.call(document.querySelectorAll(".filters button"), function (o) {
          o.setAttribute("aria-pressed", o === b ? "true" : "false");
        });
        renderEvents();
      });
    });
    refresh();
    setInterval(refresh, REFRESH_MS);
  });
})();
