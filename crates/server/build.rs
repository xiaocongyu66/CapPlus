//! Bundle the dashboard front-end into the binary.
//!
//! `../cap/standalone/public` is packed into a stored-only zip at build time
//! and embedded with `include_bytes!`, so a single-binary install still has a
//! login page and the admin panel. The server unpacks it into
//! `cappro/dashboard/` on first start.

use std::io::Write;
use std::path::{Path, PathBuf};

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, out);
        } else if let Ok(rel) = path.strip_prefix(root) {
            if let Ok(bytes) = std::fs::read(&path) {
                out.push((rel.to_string_lossy().replace('\\', "/"), bytes));
            }
        }
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn write_stored_zip(files: &[(String, Vec<u8>)], out: &Path) -> std::io::Result<()> {
    let mut body: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();

    for (name, data) in files {
        let offset = body.len() as u32;
        let crc = crc32(data);
        let size = data.len() as u32;
        let name_len = name.len() as u16;

        // Local file header.
        body.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        body.extend_from_slice(&20u16.to_le_bytes()); // version needed
        body.extend_from_slice(&0u16.to_le_bytes()); // flags
        body.extend_from_slice(&0u16.to_le_bytes()); // method = stored
        body.extend_from_slice(&0u16.to_le_bytes()); // time
        body.extend_from_slice(&0u16.to_le_bytes()); // date
        body.extend_from_slice(&crc.to_le_bytes());
        body.extend_from_slice(&size.to_le_bytes()); // compressed
        body.extend_from_slice(&size.to_le_bytes()); // uncompressed
        body.extend_from_slice(&name_len.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // extra len
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(data);

        // Central directory entry.
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method
        central.extend_from_slice(&0u16.to_le_bytes()); // time
        central.extend_from_slice(&0u16.to_le_bytes()); // date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }

    let cd_offset = body.len() as u32;
    let cd_size = central.len() as u32;
    body.extend_from_slice(&central);
    body.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(files.len() as u16).to_le_bytes());
    body.extend_from_slice(&(files.len() as u16).to_le_bytes());
    body.extend_from_slice(&cd_size.to_le_bytes());
    body.extend_from_slice(&cd_offset.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());

    let mut f = std::fs::File::create(out)?;
    f.write_all(&body)
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // Vendored copy first (what the repo ships), then the neighbouring Cap
    // checkout used during development.
    let vendored = manifest.join("../../frontend");
    let sibling = manifest.join("../../../cap/standalone/public");
    let dashboard = if vendored.join("index.html").is_file() { vendored } else { sibling };
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("dashboard.zip");
    println!("cargo:rerun-if-changed={}", dashboard.display());

    let mut files = Vec::new();
    collect(&dashboard, &dashboard, &mut files);
    if files.is_empty() {
        println!(
            "cargo:warning=dashboard sources not found at {}; the binary will have no admin panel",
            dashboard.display()
        );
    }
    write_stored_zip(&files, &out).expect("write dashboard.zip");
}
