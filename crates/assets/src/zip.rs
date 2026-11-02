//! Minimal ZIP reader for release uploads.
//!
//! Supports the two methods every archiver emits by default — `stored` and
//! `deflate` — reading sizes from the central directory (so streamed archives
//! with data descriptors work too). ZIP64 is rejected explicitly rather than
//! mis-parsed.
//!
//! Limits are enforced so a hostile upload cannot exhaust memory or disk:
//! at most [`MAX_ENTRIES`] files, [`MAX_TOTAL`] uncompressed bytes in total and
//! [`MAX_FILE`] per file.

use std::io::Read;

pub const MAX_ENTRIES: usize = 512;
pub const MAX_TOTAL: usize = 32 * 1024 * 1024;
pub const MAX_FILE: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct ZipError(pub String);

impl std::fmt::Display for ZipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ZipError {}

fn err<T>(msg: impl Into<String>) -> Result<T, ZipError> {
    Err(ZipError(msg.into()))
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_EOCD64: u32 = 0x0606_4b50;

/// Normalise separators, drop empty/`.` segments and reject anything that
/// escapes the release directory.
pub fn sanitize_path(name: &str) -> Option<String> {
    if name.contains('\0') || name.contains(':') {
        return None;
    }
    let name = name.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for seg in name.split('/') {
        match seg {
            "" | "." => continue,
            ".." => return None,
            _ => parts.push(seg),
        }
    }
    if parts.is_empty() {
        return None;
    }
    let joined = parts.join("/");
    // Directory entries end with '/'; callers skip those.
    (!joined.starts_with('/')).then_some(joined)
}

/// A file extracted from the archive. `name` is already sanitised.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub data: Vec<u8>,
}

pub fn read_zip(bytes: &[u8]) -> Result<Vec<ZipEntry>, ZipError> {
    // Locate EOCD by scanning backwards (comment may follow it).
    let mut eocd = None;
    let start = bytes.len().saturating_sub(22 + 0xffff);
    for at in (start..=bytes.len().saturating_sub(22)).rev() {
        if u32_at(bytes, at) == Some(SIG_EOCD) {
            eocd = Some(at);
            break;
        }
    }
    let Some(eocd) = eocd else {
        return err("not a zip archive (no end-of-central-directory record)");
    };

    let entries = u16_at(bytes, eocd + 10).ok_or(ZipError("truncated EOCD".into()))? as usize;
    let cd_size = u32_at(bytes, eocd + 12).ok_or(ZipError("truncated EOCD".into()))? as usize;
    let cd_offset = u32_at(bytes, eocd + 16).ok_or(ZipError("truncated EOCD".into()))? as usize;

    if cd_offset == 0xffff_ffff || cd_size == 0xffff_ffff || entries == 0xffff {
        return err("ZIP64 archives are not supported");
    }
    if entries > MAX_ENTRIES {
        return err(format!("archive has {entries} entries, limit is {MAX_ENTRIES}"));
    }
    if eocd >= 20 && u32_at(bytes, eocd - 20) == Some(SIG_EOCD64) {
        return err("ZIP64 archives are not supported");
    }
    if cd_offset.checked_add(cd_size).is_none_or(|end| end > bytes.len()) {
        return err("central directory out of bounds");
    }

    let mut out = Vec::new();
    let mut total = 0usize;
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut pos = cd_offset;

    for _ in 0..entries {
        if u32_at(bytes, pos) != Some(SIG_CENTRAL) {
            return err("bad central directory entry");
        }
        let method = u16_at(bytes, pos + 10).ok_or(ZipError("truncated entry".into()))?;
        let comp_size = u32_at(bytes, pos + 20).ok_or(ZipError("truncated entry".into()))? as usize;
        let uncomp_size =
            u32_at(bytes, pos + 24).ok_or(ZipError("truncated entry".into()))? as usize;
        let name_len = u16_at(bytes, pos + 28).ok_or(ZipError("truncated entry".into()))? as usize;
        let extra_len = u16_at(bytes, pos + 30).ok_or(ZipError("truncated entry".into()))? as usize;
        let comment_len =
            u16_at(bytes, pos + 32).ok_or(ZipError("truncated entry".into()))? as usize;
        let local_offset =
            u32_at(bytes, pos + 42).ok_or(ZipError("truncated entry".into()))? as usize;

        let name_bytes = bytes
            .get(pos + 46..pos + 46 + name_len)
            .ok_or(ZipError("truncated entry name".into()))?;
        let name = String::from_utf8_lossy(name_bytes).to_string();
        pos += 46 + name_len + extra_len + comment_len;

        let is_dir = name.ends_with('/') || name.ends_with('\\');
        let Some(safe) = sanitize_path(&name) else {
            if is_dir {
                continue;
            }
            return err(format!("unsafe path in archive: {name}"));
        };
        if is_dir {
            continue;
        }
        if uncomp_size > MAX_FILE {
            return err(format!("{safe} is {uncomp_size} bytes, limit is {MAX_FILE}"));
        }
        if comp_size > MAX_FILE {
            return err(format!("{safe} stores {comp_size} compressed bytes, limit is {MAX_FILE}"));
        }

        if u32_at(bytes, local_offset) != Some(SIG_LOCAL) {
            return err(format!("bad local header for {safe}"));
        }
        let l_name_len =
            u16_at(bytes, local_offset + 26).ok_or(ZipError("truncated local header".into()))?
                as usize;
        let l_extra_len =
            u16_at(bytes, local_offset + 28).ok_or(ZipError("truncated local header".into()))?
                as usize;
        let data_start = local_offset + 30 + l_name_len + l_extra_len;
        let data_end = data_start.saturating_add(comp_size);
        // Entries may not share bytes: N central-directory records pointing at
        // one local range would otherwise multiply a small upload N times.
        if ranges
            .iter()
            .any(|&(start, end)| data_start < end && start < data_end)
        {
            return err(format!("{safe} overlaps another entry"));
        }
        ranges.push((data_start, data_end));
        let data = bytes
            .get(data_start..data_end)
            .ok_or_else(|| ZipError(format!("truncated data for {safe}")))?;

        let data = match method {
            0 => {
                // Stored entries must be self-consistent: the declared sizes
                // are otherwise attacker-chosen bookkeeping.
                if comp_size != uncomp_size {
                    return err(format!("{safe} stored sizes disagree"));
                }
                data.to_vec()
            }
            8 => {
                let mut out = Vec::with_capacity(uncomp_size.min(MAX_FILE));
                let decoder = flate2::read::DeflateDecoder::new(data);
                decoder
                    .take(MAX_FILE as u64 + 1)
                    .read_to_end(&mut out)
                    .map_err(|e| ZipError(format!("inflate {safe}: {e}")))?;
                if out.len() > MAX_FILE {
                    return err(format!("{safe} inflates past {MAX_FILE} bytes"));
                }
                if out.len() != uncomp_size {
                    return err(format!("{safe} inflates to the wrong size"));
                }
                out
            }
            other => {
                return err(format!(
                    "{safe} uses compression method {other}; only stored and deflate are supported"
                ))
            }
        };

        // Budget the bytes actually produced, not the declared sizes.
        total = total.saturating_add(data.len());
        if total > MAX_TOTAL {
            return err(format!("archive expands past {MAX_TOTAL} bytes"));
        }
        out.push(ZipEntry { name: safe, data });
    }

    if out.is_empty() {
        return err("archive contains no files");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut central = Vec::new();
        for (name, data) in files {
            let offset = body.len() as u32;
            body.extend_from_slice(&SIG_LOCAL.to_le_bytes());
            body.extend_from_slice(&20u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(data);

            central.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = body.len() as u32;
        let cd_size = central.len() as u32;
        body.extend_from_slice(&central);
        body.extend_from_slice(&SIG_EOCD.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&(files.len() as u16).to_le_bytes());
        body.extend_from_slice(&(files.len() as u16).to_le_bytes());
        body.extend_from_slice(&cd_size.to_le_bytes());
        body.extend_from_slice(&cd_offset.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body
    }

    #[test]
    fn reads_stored_entries() {
        let zip = stored_zip(&[("widget.js", b"var a=1;"), ("public/cap.css", b"body{}")]);
        let files = read_zip(&zip).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "widget.js");
        assert_eq!(files[1].name, "public/cap.css");
        assert_eq!(files[0].data, b"var a=1;");
    }

    #[test]
    fn rejects_traversal() {
        let zip = stored_zip(&[("../../etc/passwd", b"x")]);
        assert!(read_zip(&zip).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(read_zip(b"not a zip at all, definitely not").is_err());
        assert!(read_zip(&[]).is_err());
    }

    #[test]
    fn sanitize_paths() {
        assert_eq!(sanitize_path("a\0b.js"), None);
        assert_eq!(sanitize_path("C:/x.js"), None);
        assert_eq!(sanitize_path("./js/a.js").as_deref(), Some("js/a.js"));
        assert_eq!(sanitize_path("public/js/a.js").as_deref(), Some("public/js/a.js"));
        assert_eq!(sanitize_path("../a.js"), None);
        assert_eq!(sanitize_path("a/../../b.js"), None);
        assert_eq!(sanitize_path("C:/x.js"), None);
        assert_eq!(sanitize_path(""), None);
    }
}
