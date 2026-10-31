//! Automatic protection for published widget JavaScript.
//!
//! Two layers, both reversible only at runtime in the browser:
//!
//! 1. **Obfuscation** — comments are removed and per-line indentation is
//!    collapsed. Line breaks are preserved: JavaScript's automatic semicolon
//!    insertion makes newline removal unsafe without a full parser, and a
//!    broken widget is worse than a slightly larger file.
//! 2. **Encryption** — RC4-encrypted, base64'd, behind a small loader that
//!    decrypts synchronously and evaluates it.
//!
//! A protected file starts with [`MARKER`]; files already carrying it are left
//! untouched, so re-publishing a protected bundle is idempotent.

use base64::Engine as _;

/// First bytes of every protected file. Also the "already protected" probe.
pub const MARKER: &str = "/*cappro:protected*/";

/// `true` when `src` was produced by [`protect_js`].
pub fn is_protected(src: &[u8]) -> bool {
    src.starts_with(MARKER.as_bytes())
}

/// Protect a JS file. Non-JS or already-protected input is returned unchanged.
pub fn protect_js(name: &str, src: &[u8]) -> Vec<u8> {
    if !is_js(name) || is_protected(src) {
        return src.to_vec();
    }
    let Ok(text) = std::str::from_utf8(src) else {
        return src.to_vec();
    };
    if text.trim().is_empty() {
        return src.to_vec();
    }
    let obfuscated = strip_comments(text);
    let key = random_key();
    let encrypted = rc4(&key, obfuscated.as_bytes());
    let payload = base64::engine::general_purpose::STANDARD.encode(encrypted);
    let loader = format!(
        "{MARKER}!function(){{var p=\"{payload}\",k=\"{key}\",b=atob(p),o=new Array(b.length),s=[],i=0,j=0,c,x,y;\
for(i=0;i<256;i++){{s[i]=i}}for(i=0;i<256;i++){{j=(j+s[i]+k.charCodeAt(i%k.length))&255;x=s[i];s[i]=s[j];s[j]=x}}\
i=0;j=0;for(c=0;c<b.length;c++){{i=(i+1)&255;j=(j+s[i])&255;x=s[i];s[i]=s[j];s[j]=x;\
o[c]=String.fromCharCode(b.charCodeAt(c)^s[(s[i]+s[j])&255])}}\
(new Function(o.join(\"\")))()}}();"
    );
    loader.into_bytes()
}

fn is_js(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".js") || lower.ends_with(".mjs")
}

fn random_key() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn rc4(key: &str, data: &[u8]) -> Vec<u8> {
    let k = key.as_bytes();
    let mut s: [u8; 256] = [0; 256];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + k[i % k.len()] as usize) & 255;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    data.iter()
        .map(|b| {
            i = (i + 1) & 255;
            j = (j + s[i] as usize) & 255;
            s.swap(i, j);
            b ^ s[(s[i] as usize + s[j] as usize) & 255]
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Comment stripping (string-, template- and regex-aware)
// ---------------------------------------------------------------------------

/// Remove comments and leading/trailing whitespace on each line, while
/// copying string, template and regular-expression literals verbatim.
///
/// Line breaks are preserved so ASI behaves exactly as in the input.
fn strip_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    // Last significant (non-space, non-comment) char emitted, used to tell a
    // regex from a division.
    let mut prev_significant: Option<char> = None;
    let mut line_start = true;

    while i < n {
        let c = chars[i];

        if c == '\n' {
            // Trim trailing spaces on the line we are closing.
            while out.ends_with(' ') || out.ends_with('\t') {
                out.pop();
            }
            out.push('\n');
            line_start = true;
            i += 1;
            continue;
        }

        if line_start && (c == ' ' || c == '\t') {
            i += 1; // drop indentation
            continue;
        }

        // Line comment: `//` can never begin a regex literal.
        if c == '/' && i + 1 < n && chars[i + 1] == '/' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        // Block comment: `/*` likewise.
        if c == '/' && i + 1 < n && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < n && !(chars[i] == '*' && chars[i + 1] == '/') {
                if chars[i] == '\n' {
                    out.push('\n');
                    line_start = true;
                }
                i += 1;
            }
            i = (i + 2).min(n);
            // A comment separates tokens: keep a space so `a/*x*/b` stays `a b`.
            if !out.ends_with(['\n', ' ']) {
                out.push(' ');
            }
            continue;
        }

        // String / template / regex literals: copy verbatim.
        if c == '"' || c == '\'' || c == '`' {
            let quote = c;
            copy_quoted(&chars, &mut i, &mut out);
            prev_significant = Some(quote);
            line_start = false;
            continue;
        }
        if c == '/' && regex_context(prev_significant) {
            copy_regex(&chars, &mut i, &mut out);
            prev_significant = Some('/');
            line_start = false;
            continue;
        }

        out.push(c);
        if !c.is_whitespace() {
            prev_significant = Some(c);
            line_start = false;
        }
        i += 1;
    }

    // Collapse runs of blank lines left by removed comment-only lines.
    let mut collapsed = String::with_capacity(out.len());
    let mut blank = 0;
    for line in out.split('\n') {
        if line.trim().is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        collapsed.push_str(line);
        collapsed.push('\n');
    }
    let trimmed = collapsed.trim_end_matches('\n');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}\n")
    }
}

/// Whether a `/` following `prev` starts a regular expression (true) or is a
/// division operator (false). Mirrors the usual heuristic: after a value it is
/// division, otherwise it begins a regex.
fn regex_context(prev: Option<char>) -> bool {
    match prev {
        None => true,
        Some(c) => {
            !(c.is_alphanumeric()
                || c == '_'
                || c == '$'
                || c == ')'
                || c == ']'
                || c == '}'
                || c == '"'
                || c == '\''
                || c == '`')
        }
    }
}

fn copy_quoted(chars: &[char], i: &mut usize, out: &mut String) {
    let quote = chars[*i];
    out.push(quote);
    *i += 1;
    while *i < chars.len() {
        let ch = chars[*i];
        if ch == '\\' {
            out.push(ch);
            if *i + 1 < chars.len() {
                out.push(chars[*i + 1]);
                *i += 2;
            } else {
                *i += 1;
            }
            continue;
        }
        out.push(ch);
        *i += 1;
        if ch == quote {
            break;
        }
    }
}

fn copy_regex(chars: &[char], i: &mut usize, out: &mut String) {
    out.push('/');
    *i += 1;
    let mut in_class = false;
    while *i < chars.len() {
        let ch = chars[*i];
        if ch == '\\' {
            out.push(ch);
            if *i + 1 < chars.len() {
                out.push(chars[*i + 1]);
                *i += 2;
            } else {
                *i += 1;
            }
            continue;
        }
        if ch == '\n' {
            // Not a regex after all (unterminated): leave the newline to the
            // main loop.
            break;
        }
        out.push(ch);
        *i += 1;
        if ch == '[' {
            in_class = true;
        } else if ch == ']' {
            in_class = false;
        } else if ch == '/' && !in_class {
            break;
        }
    }
    // Flags (gi, m, u, …).
    while *i < chars.len() && chars[*i].is_ascii_alphabetic() {
        out.push(chars[*i]);
        *i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_comments_keeps_lines() {
        let src = "// lead\nfunction add(a, b) {\n  /* block */ return a + b;\n}\n";
        let out = strip_comments(src);
        assert!(!out.contains("// lead"), "{out}");
        assert!(!out.contains("/* block */"), "{out}");
        assert!(out.contains("return a + b;"), "{out}");
        assert_eq!(out.lines().count(), 4, "line breaks preserved: {out:?}");
    }

    #[test]
    fn preserves_asi_sensitive_newlines() {
        let out = strip_comments("function f(){\n  return\n  x\n}\n");
        assert!(out.contains("return\n"), "{out:?}");
    }

    #[test]
    fn string_containing_slashes_survives() {
        let out = strip_comments("var u = \"http://x//y\";\n");
        assert!(out.contains("http://x//y"), "{out}");
    }

    #[test]
    fn regex_literals_survive() {
        let out = strip_comments("var re = /\\/\\//g; var d = a / b;\n");
        assert!(out.contains("/\\/\\//g"), "{out}");
        assert!(out.contains("a / b"), "{out}");
    }

    #[test]
    fn template_literals_survive() {
        let out = strip_comments("var t = `a // not a comment ${1 + 1}`;\n");
        assert!(out.contains("`a // not a comment ${1 + 1}`"), "{out}");
    }

    #[test]
    fn protect_roundtrip_decrypts_to_same_code() {
        let src = b"var total = 1 + 2; // comment\n";
        let protected = protect_js("widget.js", src);
        assert!(is_protected(&protected));
        let text = String::from_utf8(protected.clone()).unwrap();
        let payload = text.split("p=\"").nth(1).unwrap().split('"').next().unwrap();
        let key = text.split("k=\"").nth(1).unwrap().split('"').next().unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .unwrap();
        assert_eq!(rc4(key, &raw), b"var total = 1 + 2;\n");
    }

    #[test]
    fn idempotent_and_non_js_untouched() {
        let once = protect_js("a.js", b"var x=1;");
        let twice = protect_js("a.js", &once);
        assert_eq!(once, twice);
        assert_eq!(protect_js("a.wasm", b"\0asm"), b"\0asm");
    }
}
