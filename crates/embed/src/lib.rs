//! `cap-embed` — verified embedding: the cross-origin iframe document, the
//! parent-side loader script and the `frame-ancestors` policy.
//!
//! Everything here is a pure function over strings; no HTTP, no database. The
//! HTTP layer (cap-server) calls [`frame_policy`] to decide the CSP header and
//! [`embed_page`] / [`loader_js`] to produce the two documents.
//!
//! Ported from `standalone/src/embed.js` (`page()`, `loader`, `allowedAncestors`
//! and the frame-policy block of `GET /embed/:siteKey`).

#![deny(missing_debug_implementations)]

// ---------------------------------------------------------------------------
// Site key validation
// ---------------------------------------------------------------------------

/// `[A-Za-z0-9_-]{1,64}` — the same check the JS route applies before it
/// touches Redis. Callers validate first; the escaped interpolation below is
/// defence in depth.
pub fn validate_site_key(key: &str) -> bool {
    let n = key.len();
    (1..=64).contains(&n)
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

/// HTML-escape `& < > " '`. Used for every value interpolated into
/// [`embed_page`], even though callers pre-validate.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Origin parsing (a small, dependency-free WHATWG-flavoured subset)
// ---------------------------------------------------------------------------

fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.'
}

/// Parse `scheme://host[:port]` into a canonical origin string, discarding any
/// path/query/fragment/userinfo and the scheme's default port. Scheme and host
/// are lowercased, so `HTTPS://App.Example.COM:443/x` normalises to
/// `https://app.example.com`.
fn parse_origin(input: &str) -> Option<String> {
    let s = input.trim();
    let (scheme, rest) = s.split_once("://")?;

    let mut scheme_iter = scheme.chars();
    let first = scheme_iter.next()?;
    if !first.is_ascii_alphabetic() || !scheme_iter.all(is_scheme_char) {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();

    // Authority ends at the first path / query / fragment delimiter.
    let authority = match rest.find(['/', '?', '#']) {
        Some(i) => &rest[..i],
        None => rest,
    };

    // Strip userinfo (`user:pass@`).
    let authority = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };

    let (host, port) = split_host_port(authority)?;
    if host.is_empty() {
        return None;
    }

    // The origin ends up verbatim in a `frame-ancestors` CSP header, so only
    // host characters are allowed: anything like `;`, `,`, `'` or a space
    // would inject a directive. IPv6 literals keep their brackets.
    let ipv6 = host.starts_with('[') && host.ends_with(']');
    let ok = if ipv6 {
        host[1..host.len() - 1]
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
    } else {
        host.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    };
    if !ok {
        return None;
    }

    let host = host.to_ascii_lowercase();

    let default_port = match scheme.as_str() {
        "http" | "ws" => Some(80u16),
        "https" | "wss" => Some(443u16),
        _ => None,
    };

    let canonical = match port {
        None => format!("{scheme}://{host}"),
        Some(p) if Some(p) == default_port => format!("{scheme}://{host}"),
        Some(p) => format!("{scheme}://{host}:{p}"),
    };
    Some(canonical)
}

/// Return the hostname of an origin, without its scheme or port.
pub fn origin_hostname(origin: &str) -> Option<String> {
    let canonical = parse_origin(origin)?;
    let (_, authority) = canonical.split_once("://")?;
    let (host, _) = split_host_port(authority)?;
    Some(host.to_string())
}

fn split_host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if let Some(stripped) = authority.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:8080`.
        let close = stripped.find(']')?;
        let host = &authority[..close + 2];
        let tail = &stripped[close + 1..];
        if tail.is_empty() {
            return Some((host, None));
        }
        let port = tail.strip_prefix(':')?;
        return Some((host, parse_port(port)?));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, parse_port(port)?)),
        None => Some((authority, None)),
    }
}

fn parse_port(port: &str) -> Option<Option<u16>> {
    if port.is_empty() {
        return Some(None);
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>().ok().map(Some)
}

// ---------------------------------------------------------------------------
// Frame policy
// ---------------------------------------------------------------------------

/// What to put in the iframe document's `Content-Security-Policy:
/// frame-ancestors` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramePolicy {
    /// Only this origin may frame the document (`"*"` means anyone).
    Allow(String),
    /// Nobody may frame it (`frame-ancestors 'none'`).
    Deny,
}

/// Decide who may embed the widget.
///
/// * no configured origins (or only empty strings) → [`FramePolicy::Allow`]`("*")`
/// * otherwise `parent` must parse as an origin and be listed → `Allow` with the
///   canonical parent origin; anything else (unparseable, empty, not listed,
///   different scheme or port) → [`FramePolicy::Deny`].
pub fn frame_policy(cors_origins: &[String], parent: &str) -> FramePolicy {
    let mut configured = cors_origins
        .iter()
        .filter(|o| !o.trim().is_empty())
        .peekable();

    // Fail closed: without a configured allow-list the embedding parent is
    // unverifiable, and the token would be posted to whatever origin the
    // attacker put in `?parent=`. An operator who really wants any origin can
    // configure `"*"` explicitly.
    if configured.peek().is_none() {
        return FramePolicy::Deny;
    }
    if cors_origins.iter().any(|o| o.trim() == "*") {
        return match parse_origin(parent) {
            Some(origin) => FramePolicy::Allow(origin),
            None => FramePolicy::Deny,
        };
    }

    let Some(parent_origin) = parse_origin(parent) else {
        return FramePolicy::Deny;
    };

    if configured
        .filter_map(|o| parse_origin(o))
        .any(|allowed| allowed == parent_origin)
    {
        FramePolicy::Allow(parent_origin)
    } else {
        FramePolicy::Deny
    }
}

// ---------------------------------------------------------------------------
// The iframe document
// ---------------------------------------------------------------------------

/// Build the cross-origin verification frame for `site_key`.
///
/// Every interpolated value is HTML-escaped. `parent_origin` is the
/// `postMessage` target (empty → `"*"`). The `frame-ancestors` CSP header is the
/// caller's job — see [`frame_policy`]; nothing here depends on it.
pub fn embed_page(site_key: &str, parent_origin: &str, widget_url: &str) -> String {
    embed_page_with_context(site_key, parent_origin, widget_url, "", "dark")
}

/// Build a frame whose challenge fetches carry the server-signed embed context.
///
/// `theme` is the page-declared theme ("light" or "dark"); anything else is
/// treated as the default dark palette. It only selects colours — it carries no
/// trust.
pub fn embed_page_with_context(
    site_key: &str,
    parent_origin: &str,
    widget_url: &str,
    context: &str,
    theme: &str,
) -> String {
    let theme = if theme == "light" { "light" } else { "dark" };
    let context = serde_json::to_string(context)
        .expect("context string")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    let site = esc(site_key);
    // `parent_origin` lands inside a JS string literal, not HTML: JSON
    // encoding is the correct escape there (an attacker-supplied quote must
    // not be able to break out, and HTML entities are not decoded in <script>).
    let target = if parent_origin.is_empty() {
        "\"*\"".to_string()
    } else {
        serde_json::to_string(parent_origin)
            .unwrap_or_else(|_| "\"*\"".to_string())
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026")
    };
    let widget = esc(widget_url);
    // The default self-hosted release is a complete JS/WASM set. Custom
    // widget deployments retain their own asset resolution contract.
    let local_assets = if widget_url == "/assets/widget.js" {
        "window.CAP_CUSTOM_WASM_URL = '/assets/cap_wasm_bg.wasm'; window.CAP_CUSTOM_HASHWX_URL = '/assets/hashwx.wasm';"
    } else { "" };

    format!(
        r#"<!doctype html>
<html lang="en" data-theme="{theme}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Cap</title>
<style>
  html,body{{margin:0;padding:0;background:transparent}}
  /* The widget reads these through the shadow boundary, so the frame follows
     the hosting page's declared theme without rebuilding the widget bundle. */
  html{{color-scheme:dark;
    --cap-background:#17181c;--cap-color:#f2f3f5;--cap-border-color:#ffffff26;
    --cap-checkbox-background:#ffffff12;--cap-checkbox-border:1px solid #ffffff40;
    --cap-spinner-background-color:#33363d;--cap-spinner-color:#f2f3f5;
    --cap-focus-ring:#5aa9ff;--cap-troubleshoot-color:#9cc7ff}}
  html[data-theme="light"]{{color-scheme:light;
    --cap-background:#fdfdfd;--cap-color:#212121;--cap-border-color:#dddddd8f;
    --cap-checkbox-background:#fafafa91;--cap-checkbox-border:1px solid #aaaaaad1;
    --cap-spinner-background-color:#eee;--cap-spinner-color:#000;
    --cap-focus-ring:#0066cc;--cap-troubleshoot-color:#0050a0}}
  #w{{display:flex;justify-content:center;align-items:center;padding:4px}}
</style>
</head>
<body>
<div id="w"></div>
<script>
(function(){{
  {local_assets}
  var SITE = "{site}";
  var PARENT = {target};
  var CONTEXT = {context};
  var THEME = "{theme}";
  var fetch = window.fetch;
  window.fetch = function(input, init) {{
    var url = new URL(input instanceof Request ? input.url : input, location.href);
    var ep = url.pathname;
    if (CONTEXT && url.origin === location.origin && (ep === "/{site}/challenge" || ep === "/{site}/redeem")) {{
      var request = new Request(input, init);
      var headers = new Headers(request.headers);
      headers.set("x-cap-embed-context", CONTEXT);
      return fetch.call(window, new Request(request, {{ headers: headers }}));
    }}
    return fetch.call(window, input, init);
  }};
  var widget = document.createElement("cap-widget");
  widget.setAttribute("data-cap-api-endpoint", "/{site}/");
  widget.setAttribute("data-cap-theme", THEME);
  function applyTheme(t) {{
    THEME = t === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", THEME);
    widget.setAttribute("data-cap-theme", THEME);
  }}
  window.addEventListener("message", function (e) {{
    // The hosting page tells us its theme; it is not a trust signal.
    if (e.source !== parent) return;
    if (PARENT && PARENT !== "*" && e.origin !== PARENT) return;
    var d = e.data;
    if (!d || d.type !== "cap:theme") return;
    applyTheme(d.theme);
  }});
  widget.addEventListener("solve", function (e) {{
    var token = e && e.detail && e.detail.token;
    if (!token) return;
    parent.postMessage({{ type: "cap:token", siteKey: SITE, token: token }}, PARENT || "*");
  }});
  widget.addEventListener("progress", function (e) {{
    parent.postMessage({{ type: "cap:progress", siteKey: SITE, progress: e.detail && e.detail.progress }}, PARENT || "*");
  }});
  widget.addEventListener("error", function (e) {{
    parent.postMessage({{ type: "cap:error", siteKey: SITE, error: String((e && e.detail && e.detail.error) || "error") }}, PARENT || "*");
  }});
  document.getElementById("w").appendChild(widget);
  // Tell the parent we are alive and ready to be interacted with.
  parent.postMessage({{ type: "cap:ready", siteKey: SITE }}, PARENT || "*");
}})();
</script>
<script src="{widget}"></script>
</body>
</html>
"#
    )
}

const LOADER: &str = r#"(function(){
  var HERE = new URL(document.currentScript.src);
  var CAP_ORIGIN = HERE.origin;
  // No script-level override: use the same precedence as standalone widgets.

  // The page owns its theme: read only signals it declares itself (attribute,
  // CSS color-scheme, theme attributes/classes). Nothing here guesses from the
  // background colour or the OS preference, which are unrelated to the page's
  // chosen theme.
  function detectTheme(el){
    var explicit = (el.getAttribute("data-cap-theme") || "").toLowerCase();
    if (explicit === "dark" || explicit === "light") return explicit;

    var root = document.documentElement, body = document.body;
    var attrs = ["data-cap-theme","data-theme","data-bs-theme","data-color-mode","data-mode","data-color-scheme"];
    var nodes = [root, body];
    for (var n = 0; n < nodes.length; n++) {
      if (!nodes[n]) continue;
      for (var i = 0; i < attrs.length; i++) {
        var v = String(nodes[n].getAttribute(attrs[i]) || "").toLowerCase();
        if (v === "dark" || v === "light") return v;
      }
    }

    // Explicit classes outrank CSS declarations on either page node.
    var cls = ((root.className || "") + " " + ((body && body.className) || "")).toLowerCase().split(/\s+/);
    if (cls.indexOf("dark") >= 0 || cls.indexOf("theme-dark") >= 0) return "dark";
    if (cls.indexOf("light") >= 0 || cls.indexOf("theme-light") >= 0) return "light";

    // Only a single CSS scheme is a choice. normal / dual values on html
    // must not hide an explicit scheme on body.
    for (var n = 0; n < nodes.length; n++) {
      if (!nodes[n]) continue;
      try {
        var cs = String(window.getComputedStyle(nodes[n]).colorScheme || "").trim().toLowerCase();
        var tokens = cs.split(/\s+/);
        var schemes = tokens.filter(function(t){ return t === "light" || t === "dark"; });
        if (schemes.length === 1 && tokens.length <= 2 && tokens.every(function(t){ return t === schemes[0] || t === "only"; })) return schemes[0];
      } catch (e) {}
    }

    // No declaration: default dark.
    return "dark";
  }

  var mounted = new Map();
  var paused = new WeakSet();
  var themeAttrs = ["class", "style", "data-cap-theme", "data-theme", "data-bs-theme", "data-color-mode", "data-mode", "data-color-scheme"];
  function destroy(el){
    if (!el) return;
    paused.add(el);
    cleanupInstance(el);
  }
  function cleanupInstance(el){
    var cleanup = mounted.get(el);
    if (cleanup) cleanup();
  }
  function init(el){
    if (el.__capEmbed || !el.isConnected || paused.has(el)) return;
    el.__capEmbed = true;
    var site = el.getAttribute("data-site-key") || "";
    var name = el.getAttribute("data-field-name") || "cap-token";
    var parentOrigin = location.origin;
    var theme = detectTheme(el);
    var iframe = document.createElement("iframe");
    iframe.src = CAP_ORIGIN + "/embed/" + encodeURIComponent(site) +
      "?parent=" + encodeURIComponent(parentOrigin) +
      "&theme=" + encodeURIComponent(theme);
    iframe.title = "Cap verification";
    iframe.setAttribute("allow", "");
    iframe.style.cssText = el.getAttribute("data-style") ||
      "border:0;width:100%;height:74px;background:transparent;color-scheme:normal";
    el.appendChild(iframe);
    var input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    el.appendChild(input);

    function sendTheme(){
      if (!el.isConnected) return;
      var t = detectTheme(el);
      try {
        iframe.contentWindow.postMessage({ type: "cap:theme", theme: t }, CAP_ORIGIN);
      } catch (e) {}
    }
    iframe.addEventListener("load", sendTheme);

    // Theme toggles are almost always attribute/class swaps on <html> or
    // <body>; mirror both. Pages that swap stylesheets can call
    // CapEmbed.refreshTheme().
    try {
      var mo = new MutationObserver(sendTheme);
      mo.observe(document.documentElement, { attributes: true, attributeFilter: themeAttrs });
      if (document.body) mo.observe(document.body, { attributes: true, attributeFilter: themeAttrs });
      mo.observe(el, { attributes: true, attributeFilter: ["data-cap-theme"] });
      el.__capThemeObserver = mo;
    } catch (e) {}

    function onMessage(ev){
      if (!el.isConnected) return;
      if (ev.origin !== CAP_ORIGIN) return;
      if (ev.source !== iframe.contentWindow) return;
      var d = ev.data;
      if (!d || d.siteKey !== site) return;
      if (d.type === "cap:token" && typeof d.token === "string") {
        input.value = d.token;
        el.dispatchEvent(new CustomEvent("cap-token", { detail: { token: d.token } }));
      } else if (d.type === "cap:ready") {
        sendTheme();
        el.dispatchEvent(new CustomEvent("cap-ready"));
      } else if (d.type === "cap:error") {
        el.dispatchEvent(new CustomEvent("cap-error", { detail: d }));
      }
    }
    window.addEventListener("message", onMessage);
    mounted.set(el, function(){
      if (mo) mo.disconnect();
      iframe.removeEventListener("load", sendTheme);
      window.removeEventListener("message", onMessage);
      iframe.remove();
      input.remove();
      delete el.__capThemeObserver;
      delete el.__capEmbed;
      mounted.delete(el);
    });
  }
  function scan(resume){
    mounted.forEach(function(_, el){ if (!el.isConnected) cleanupInstance(el); });
    var nodes = document.querySelectorAll("cap-embed[data-site-key]");
    for (var i = 0; i < nodes.length; i++) {
      if (resume === true) paused.delete(nodes[i]);
      init(nodes[i]);
    }
  }
  // One document-lifetime observer handles dynamically inserted/removed hosts;
  // all instance observers and listeners are disposed when their host leaves.
  var lifecycle = new MutationObserver(scan);
  lifecycle.observe(document.documentElement, { childList: true, subtree: true });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", scan, { once: true });
  else scan();
  window.CapEmbed = {
    scan: function(){ scan(true); },
    mount: function(el){ if (el) { paused.delete(el); init(el); } },
    destroy: destroy,
    // Force a theme for one widget ("dark"/"light") or return to automatic.
    setTheme: function(el, theme){
      if (!el) return;
      if (theme === "dark" || theme === "light") el.setAttribute("data-cap-theme", theme);
      else el.removeAttribute("data-cap-theme");
      var iframe = el.querySelector("iframe");
      if (iframe) {
        var t = detectTheme(el);
        try { iframe.contentWindow.postMessage({ type: "cap:theme", theme: t }, CAP_ORIGIN); } catch (e) {}
      }
    },
    refreshTheme: function(){
      var nodes = document.querySelectorAll("cap-embed[data-site-key]");
      for (var i = 0; i < nodes.length; i++) {
        var el = nodes[i], iframe = el.querySelector("iframe");
        if (!iframe) continue;
        var t = detectTheme(el);
        try { iframe.contentWindow.postMessage({ type: "cap:theme", theme: t }, CAP_ORIGIN); } catch (e) {}
      }
    }
  };
})();"#;

/// The parent-side loader script (verbatim port of `loader` in
/// `standalone/src/embed.js`): turns `<cap-embed data-site-key>` into an iframe,
/// verifies `ev.origin` / `ev.source`, fills the hidden token input and
/// re-dispatches `cap-token` / `cap-ready` / `cap-error` CustomEvents.
pub fn loader_js() -> &'static str {
    LOADER
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_fetch_is_scoped_and_script_safe() {
        let html = embed_page_with_context("site-a", "https://app.example", "/widget.js", "</script>&\"", "light");
        assert!(html.contains("url.origin === location.origin"));
        assert!(html.contains("ep === \"/site-a/challenge\" || ep === \"/site-a/redeem\""));
        assert!(html.contains("headers.set(\"x-cap-embed-context\", CONTEXT)"));
        assert!(html.contains("<html lang=\"en\" data-theme=\"light\">"));
        assert!(html.contains("widget.setAttribute(\"data-cap-theme\", THEME)"));
        assert!(html.contains("d.type !== \"cap:theme\""));
        assert!(html.contains("applyTheme(d.theme)"));
        assert!(html.contains("e.source !== parent"));
        assert!(html.contains("--cap-background:#17181c"));
        assert!(html.contains("--cap-background:#fdfdfd"));
        assert!(html.contains("return fetch.call(window, input, init)"));
        assert!(html.contains("\\u003c/script\\u003e\\u0026\\\""));
        assert_eq!(origin_hostname("https://APP.example:8443"), Some("app.example".into()));
        assert_eq!(origin_hostname("http://[::1]:8080"), Some("[::1]".into()));
    }

    #[test]
    fn parent_cannot_inject_csp() {
        let star = vec!["*".to_string()];
        for bad in [
            "https://a;sandbox",
            "https://a,https://evil",
            "https://a'unsafe-inline'",
            "https://a\"b",
            "https://a b",
        ] {
            assert_eq!(frame_policy(&star, bad), FramePolicy::Deny, "{bad}");
        }
        assert_eq!(
            frame_policy(&star, "https://App.Example.com:443/x"),
            FramePolicy::Allow("https://app.example.com".into())
        );
        assert_eq!(
            frame_policy(&star, "http://[::1]:8080"),
            FramePolicy::Allow("http://[::1]:8080".into())
        );
    }

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_list_denies_by_default() {
        // Fail closed: an unconfigured site cannot verify the embedding parent.
        assert_eq!(frame_policy(&[], "https://app.example.com"), FramePolicy::Deny);
        assert_eq!(frame_policy(&[], "garbage"), FramePolicy::Deny);
        // The JS filters out empty strings, so a list of blanks behaves like empty.
        assert_eq!(frame_policy(&list(&["", "  "]), ""), FramePolicy::Deny);

        // An explicit "*" is the documented way to allow any origin.
        assert_eq!(
            frame_policy(&list(&["*"]), "https://app.example.com"),
            FramePolicy::Allow("https://app.example.com".into())
        );
        assert_eq!(frame_policy(&list(&["*"]), "garbage"), FramePolicy::Deny);
    }

    #[test]
    fn exact_match_allowed() {
        let origins = list(&["https://app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com"),
            FramePolicy::Allow("https://app.example.com".into())
        );
    }

    #[test]
    fn trailing_slash_and_case_are_normalised() {
        let origins = list(&["https://app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com/"),
            FramePolicy::Allow("https://app.example.com".into())
        );
        assert_eq!(
            frame_policy(&origins, "HTTPS://App.Example.COM/embed/path"),
            FramePolicy::Allow("https://app.example.com".into())
        );
        // ...and entries in the list are normalised too.
        let origins = list(&["https://app.example.com/"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com"),
            FramePolicy::Allow("https://app.example.com".into())
        );
    }

    #[test]
    fn default_port_matches_explicit_port_entry() {
        let origins = list(&["https://app.example.com:443"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com"),
            FramePolicy::Allow("https://app.example.com".into())
        );
        let origins = list(&["https://app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com:443"),
            FramePolicy::Allow("https://app.example.com".into())
        );
    }

    #[test]
    fn different_port_denied() {
        let origins = list(&["https://app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com:8443"),
            FramePolicy::Deny
        );
        let origins = list(&["https://app.example.com:8443"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com"),
            FramePolicy::Deny
        );
    }

    #[test]
    fn http_vs_https_denied() {
        let origins = list(&["https://app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "http://app.example.com"),
            FramePolicy::Deny
        );
        let origins = list(&["http://app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com"),
            FramePolicy::Deny
        );
    }

    #[test]
    fn unparseable_parent_denied() {
        let origins = list(&["https://app.example.com"]);
        assert_eq!(frame_policy(&origins, ""), FramePolicy::Deny);
        assert_eq!(frame_policy(&origins, "not a url"), FramePolicy::Deny);
        assert_eq!(frame_policy(&origins, "app.example.com"), FramePolicy::Deny);
        assert_eq!(frame_policy(&origins, "https://"), FramePolicy::Deny);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com:notaport"),
            FramePolicy::Deny
        );
        assert_eq!(
            frame_policy(&origins, "https://app.example.com:999999"),
            FramePolicy::Deny
        );
    }

    #[test]
    fn unrelated_origin_denied() {
        let origins = list(&["https://app.example.com", "https://other.example.org"]);
        assert_eq!(
            frame_policy(&origins, "https://evil.example.com"),
            FramePolicy::Deny
        );
        // Subdomains are distinct origins.
        assert_eq!(
            frame_policy(&origins, "https://sub.app.example.com"),
            FramePolicy::Deny
        );
        // An origin suffix attack via userinfo must not match.
        assert_eq!(
            frame_policy(&origins, "https://app.example.com@evil.example.com"),
            FramePolicy::Deny
        );
    }

    #[test]
    fn second_entry_matches() {
        let origins = list(&["https://a.example.com", "https://b.example.com"]);
        assert_eq!(
            frame_policy(&origins, "https://b.example.com"),
            FramePolicy::Allow("https://b.example.com".into())
        );
    }

    #[test]
    fn embed_page_has_endpoint_and_widget_url() {
        let page = embed_page("abc123", "https://app.example.com", "/assets/widget.js");
        assert!(
            page.contains(r#"widget.setAttribute("data-cap-api-endpoint", "/abc123/");"#),
            "{page}"
        );
        assert!(page.contains(r#"<script src="/assets/widget.js"></script>"#));
        assert!(page.contains("\"https://app.example.com\""));
    }

    #[test]
    fn embed_page_posts_protocol_messages() {
        let page = embed_page("abc123", "https://app.example.com", "/w.js");
        for marker in [
            "cap:token",
            "cap:progress",
            "cap:error",
            "cap:ready",
            "solve",
            "postMessage",
            "parent",
        ] {
            assert!(page.contains(marker), "missing {marker}");
        }
        // CSP is applied by the caller, never baked into the document.
        assert!(!page.contains("frame-ancestors"), "{page}");
    }

    #[test]
    fn embed_page_empty_parent_targets_star() {
        let page = embed_page("abc123", "", "/w.js");
        assert!(page.contains("var PARENT = \"*\";"), "{page}");
        assert!(page.contains("PARENT || \"*\""));
    }

    #[test]
    fn embed_page_escapes_site_key() {
        let evil = "\"><script>alert(1)</script><x y='z'>&";
        let page = embed_page(evil, "https://app.example.com", "/w.js");

        assert!(
            !page.contains("<script>alert"),
            "raw payload leaked: {page}"
        );
        assert!(!page.contains("\"><script"), "raw payload leaked: {page}");
        assert!(page.contains("&quot;&gt;&lt;script&gt;alert(1)"), "{page}");
        assert!(page.contains("&#39;"), "{page}");
        assert!(page.contains("&amp;"), "{page}");
        // Exactly one script tag with src and one inline script.
        assert_eq!(page.matches("<script").count(), 2);
    }

    #[test]
    fn embed_page_escapes_parent_and_widget_url() {
        let page = embed_page("k", "https://a.example.com\"'<&", "/w.js?a=1&b=\"><x");
        // widget_url is HTML-escaped (it is used outside the JS string).
        assert!(!page.contains("\"<x"), "{page}");
        assert!(page.contains("a=1&amp;b="), "{page}");
        // The parent origin is JSON-encoded for the JS literal, with < > &
        // escaped so it can neither close the script nor inject HTML.
        assert!(page.contains(r#"https://a.example.com\"'"#), "{page}");
        assert!(page.contains("\\u003c"), "{page}");
        assert!(!page.contains("</script><"), "{page}");
    }

    #[test]
    fn loader_contains_protocol_markers() {
        let js = loader_js();
        for marker in [
            "cap-embed",
            "data-site-key",
            "data-field-name",
            "cap-token",
            "ev.origin",
            "ev.source",
            "CAP_ORIGIN",
            "cap:token",
            "cap-ready",
            "cap-error",
            "CustomEvent",
            "CapEmbed",
            "scan",
        ] {
            assert!(js.contains(marker), "loader missing {marker}");
        }
        assert!(js.contains(r#"document.querySelectorAll("cap-embed[data-site-key]")"#));
        assert!(js.contains("window.CapEmbed = {"));
        assert!(js.contains("refreshTheme: function()"));
    }

    #[test]
    fn loader_creates_iframe_with_parent_param() {
        let js = loader_js();
        assert!(js.contains(r#"CAP_ORIGIN + "/embed/" + encodeURIComponent(site)"#));
        assert!(js.contains(r#""?parent=" + encodeURIComponent(parentOrigin)"#));
    }

    #[test]
    fn validate_site_key_cases() {
        assert!(validate_site_key("abc"));
        assert!(validate_site_key("A-Z_09"));
        assert!(validate_site_key(&"a".repeat(64)));
        assert!(!validate_site_key(""));
        assert!(!validate_site_key(&"a".repeat(65)));
        assert!(!validate_site_key("has space"));
        assert!(!validate_site_key("dot.dot"));
        assert!(!validate_site_key("slash/"));
        assert!(!validate_site_key("\"><script>"));
        assert!(!validate_site_key("ümlaut"));
        assert!(!validate_site_key("new\nline"));
    }
}
