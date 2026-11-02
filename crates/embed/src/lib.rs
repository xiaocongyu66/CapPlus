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
// Shared domain validation and strict HTTP(S) origin parsing
// ---------------------------------------------------------------------------

/// Validate and canonicalize the single site-domain list (`corsOrigins`).
/// Legacy origins (scheme/port/path), bare `*`, IPs and empty lists are rejected;
/// operators must explicitly migrate them, never strip origin restrictions.
/// Bare domains authorize HTTP(S) on any port; wildcards exclude the apex.
pub fn normalize_domains(domains: &[String]) -> Result<Vec<String>, String> {
    if !(1..=50).contains(&domains.len()) {
        return Err("corsOrigins requires 1–50 bare domains".into());
    }
    domains.iter().enumerate().map(|(i, value)| {
        let (wildcard, host) = match value.strip_prefix("*.") {
            Some(host) => (true, host),
            None => (false, value.as_str()),
        };
        canonical_domain(host)
            .map(|host| if wildcard { format!("*.{host}") } else { host })
            .ok_or_else(|| format!("corsOrigins item {} must be a bare domain or *.domain; legacy origins must be migrated explicitly (no scheme, port, path or bare *)", i + 1))
    }).collect()
}

fn canonical_domain(host: &str) -> Option<String> {
    if host.is_empty() || host.chars().any(|c| c.is_whitespace() || c.is_control())
        || host.contains([':', '/', '\\', '@', '?', '#', '%', '*']) {
        return None;
    }
    let url::Host::Domain(ascii) = url::Host::parse(host).ok()? else { return None; };
    let ascii = ascii.strip_suffix('.').unwrap_or(&ascii);
    if ascii.len() > 253 || !ascii.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63
            && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) { return None; }
    Some(ascii.to_ascii_lowercase())
}

/// Strict HTTP(S) origin parser. Reject URL repair, credentials, paths,
/// queries and fragments rather than silently discarding them.
fn parent_url(input: &str) -> Option<url::Url> {
    if input.chars().any(|c| c.is_whitespace() || c.is_control()) || input.contains('\\') {
        return None;
    }
    let (_, authority) = input.split_once("://")?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty() || authority.contains(['/', '@', '?', '#', '%']) { return None; }
    let parsed = url::Url::parse(input).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() { return None; }
    Some(parsed)
}

/// Canonicalize a strict HTTP(S) origin, including IDNA and default ports.
pub fn parse_origin(input: &str) -> Option<String> {
    parent_url(input).map(|url| url.origin().ascii_serialization())
}

/// Return the hostname of an origin, without its scheme or port.
pub fn origin_hostname(origin: &str) -> Option<String> {
    let parsed = parent_url(origin)?;
    let host = parsed.host_str()?;
    Some(host.strip_suffix('.').unwrap_or(host).to_string())
}

// ---------------------------------------------------------------------------
// Frame policy
// ---------------------------------------------------------------------------

/// What to put in the iframe document's `Content-Security-Policy:
/// frame-ancestors` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramePolicy {
    /// Only this exact HTTP(S) origin may frame the document.
    Allow(String),
    /// Nobody may frame it (`frame-ancestors 'none'`).
    Deny,
}

/// Decide who may embed the widget.
///
/// Empty or invalid lists deny immediately, including legacy origin entries.
/// Exact bare domains match only that hostname; `*.example.com` matches any
/// subdomain depth but not the apex. HTTP(S) and any port are authorized by a
/// domain entry, but CSP always receives only the precise requesting origin.
pub fn frame_policy(cors_origins: &[String], parent: &str) -> FramePolicy {
    let Ok(configured) = normalize_domains(cors_origins) else { return FramePolicy::Deny; };
    let Some(parent_origin) = parse_origin(parent) else { return FramePolicy::Deny; };
    let Some(host) = origin_hostname(parent).and_then(|h| canonical_domain(&h)) else {
        return FramePolicy::Deny;
    };
    if configured.iter().any(|allowed| match allowed.strip_prefix("*.") {
        Some(base) => host.strip_suffix(base).is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1),
        None => allowed == &host,
    }) {
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
        let star = vec!["app.example.com".to_string()];
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
            frame_policy(&star, "https://App.Example.com:443/"),
            FramePolicy::Allow("https://app.example.com".into())
        );
        assert_eq!(
            frame_policy(&star, "http://[::1]:8080"),
            FramePolicy::Deny
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

        // Bare wildcard never opts out of domain validation.
        assert_eq!(
            frame_policy(&list(&["*"]), "https://app.example.com"),
            FramePolicy::Deny
        );
        assert_eq!(frame_policy(&list(&["*"]), "garbage"), FramePolicy::Deny);
    }

    #[test]
    fn domain_matrix() {
        for (domains, parent, allowed) in [
            (vec!["example.com"], "https://example.com", true),
            (vec!["example.com"], "https://login.example.com", false),
            (vec!["login.example.com"], "https://login.example.com", true),
            (vec!["login.example.com"], "https://example.com", false),
            (vec!["*.example.com"], "https://a.b.example.com:8443", true),
            (vec!["*.example.com"], "https://example.com", false),
            (vec!["*.example.com"], "https://badexample.com", false),
            (vec!["*.example.com"], "https://example.com.evil", false),
            (vec!["EXAMPLE.com."], "http://Example.COM.:8080", true),
            (vec!["bücher.example"], "https://xn--bcher-kva.example", true),
            (vec!["xn--bcher-kva.example"], "https://bücher.example", true),
            (vec!["example.com", "*"], "https://example.com", false),
            (vec!["example.com", "https://other.com"], "https://example.com", false),
        ] {
            let policy = frame_policy(&list(&domains), parent);
            assert_eq!(matches!(policy, FramePolicy::Allow(_)), allowed, "{domains:?} {parent}");
            if allowed { assert_eq!(policy, FramePolicy::Allow(parse_origin(parent).unwrap())); }
        }
        for bad in ["", "*", "https://example.com", "example.com:443", "example.com/",
            "a@example.com", "example.com?x", "example.com#x", "a..com", "-a.com",
            "a-.com", "example.com..", "a;script-src.com", "a'unsafe.com", "a\n.com",
            "*.*.example.com", "127.0.0.1", "[::1]", "%65xample.com"] {
            assert!(normalize_domains(&list(&[bad])).is_err(), "{bad}");
        }
        assert!(normalize_domains(&[]).is_err());
        assert!(normalize_domains(&vec!["example.com".into(); 50]).is_ok());
        assert!(normalize_domains(&vec!["example.com".into(); 51]).is_err());
        for bad in ["https://user@example.com", "https://@example.com", "https://example.com/x",
            "https://example.com?", "https://example.com#", "https:///example.com",
            "https://example.com\\evil", "https://example.com\n", "ftp://example.com",
            "https://example.com:99999", "https://example.com.evil"] {
            assert_eq!(frame_policy(&list(&["example.com"]), bad), FramePolicy::Deny, "{bad}");
        }
    }

    #[test]
    fn exact_match_allowed() {
        let origins = list(&["app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com"),
            FramePolicy::Allow("https://app.example.com".into())
        );
    }

    #[test]
    fn trailing_slash_and_case_are_normalised() {
        let origins = list(&["app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com/"),
            FramePolicy::Allow("https://app.example.com".into())
        );
        assert_eq!(
            frame_policy(&origins, "HTTPS://App.Example.COM"),
            FramePolicy::Allow("https://app.example.com".into())
        );
        // ...and entries in the list are normalised too.
        let origins = list(&["App.Example.COM."]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com"),
            FramePolicy::Allow("https://app.example.com".into())
        );
    }

    #[test]
    fn default_port_matches_explicit_port_entry() {
        let origins = list(&["app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com"),
            FramePolicy::Allow("https://app.example.com".into())
        );
        let origins = list(&["app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com:443"),
            FramePolicy::Allow("https://app.example.com".into())
        );
    }

    #[test]
    fn ports_match_domains_but_legacy_entries_deny() {
        let origins = list(&["app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com:8443"),
            FramePolicy::Allow("https://app.example.com:8443".into())
        );
        let origins = list(&["https://app.example.com:8443"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com"),
            FramePolicy::Deny
        );
    }

    #[test]
    fn http_matches_domains_but_legacy_entries_deny() {
        let origins = list(&["app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "http://app.example.com"),
            FramePolicy::Allow("http://app.example.com".into())
        );
        let origins = list(&["http://app.example.com"]);
        assert_eq!(
            frame_policy(&origins, "https://app.example.com"),
            FramePolicy::Deny
        );
    }

    #[test]
    fn unparseable_parent_denied() {
        let origins = list(&["app.example.com"]);
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
        let origins = list(&["app.example.com", "other.example.org"]);
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
        let origins = list(&["a.example.com", "b.example.com"]);
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
