//! Bundle the dashboard front-end into the binary.
//!
//! The repository's `frontend/` is packed into a stored-only zip at build time
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

/// Rebuild with the pure builder when dependencies are installed. Source-only
/// distributions without node_modules use the versioned release artifacts.
/// A requested rebuild must succeed: never silently ship an older bundle.
fn build_widget(manifest: &Path) {
    let widget_dir = manifest.join("../../widget-source");
    if !widget_dir.join("node_modules").is_dir() {
        println!("cargo:warning=using versioned widget-dist (no widget node_modules)");
        return;
    }
    let status = std::process::Command::new("bun")
        .arg("_build_only.mjs")
        .current_dir(&widget_dir)
        .status()
        .expect("run pure widget builder (bun required with node_modules installed)");
    assert!(status.success(), "widget build failed; refusing stale artifacts");
}

fn bundle(name: &str, dir: &Path, out_dir: &Path) -> u64 {
    let mut files = Vec::new();
    collect(dir, dir, &mut files);
    if files.is_empty() {
        println!(
            "cargo:warning={name} sources not found at {}; the binary will not bundle them",
            dir.display()
        );
    }
    bundle_files(name, files, out_dir)
}

fn bundle_files(name: &str, mut files: Vec<(String, Vec<u8>)>, out_dir: &Path) -> u64 {
    files.sort_by(|a, b| a.0.cmp(&b.0));
    write_stored_zip(&files, &out_dir.join(format!("{name}.zip"))).expect("write zip");
    // FNV-1a over sorted (name, bytes) so an upgrade can tell whether the
    // bundle changed and must be re-published (and re-encrypted).
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (name, data) in &files {
        for b in name.as_bytes().iter().chain(data.iter()) {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100_0000_01b3);
        }
    }
    h
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Use repository assets unless an external dashboard is explicitly selected.
    println!("cargo:rerun-if-env-changed=ADMIN_LEGACY_DIR");
    let dashboard = std::env::var_os("ADMIN_LEGACY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../frontend"));
    println!("cargo:rerun-if-changed={}", dashboard.display());
    let dashboard_hash = bundle("dashboard", &dashboard, &out_dir);
    std::fs::write(out_dir.join("dashboard-id.txt"), format!("{dashboard_hash:016x}"))
        .expect("write dashboard-id.txt");

    let widget_src = manifest.join("../../widget-source");
    for input in ["src/src", "_build_only.mjs", "package.json", "bun.lock"] {
        println!("cargo:rerun-if-changed={}", widget_src.join(input).display());
    }
    build_widget(&manifest);
    let dist = manifest.join("../../widget-dist");
    // Never recursively package source trees or arbitrary files from dist.
    let mut files = Vec::new();
    for name in ["widget.js", "floating.js", "cap_wasm.js", "cap_wasm_bg.wasm", "hashwx.wasm"] {
        let path = dist.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("required widget artifact {}: {e}", path.display()));
        assert!(!bytes.is_empty(), "empty widget artifact: {name}");
        files.push((name.to_string(), bytes));
    }
    let widget_hash = bundle_files("widget", files, &out_dir);
    std::fs::write(out_dir.join("widget-id.txt"), format!("{widget_hash:016x}"))
        .expect("write widget-id.txt");
}
