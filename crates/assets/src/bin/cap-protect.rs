//! `cap-protect` — produce the protected (obfuscated + encrypted) form of a
//! widget build.
//!
//! Use this instead of shipping a raw `bun run build` output: the server applies
//! the same transform when a bundle is published, but anything placed on a CDN
//! or served directly must be protected first.
//!
//! ```text
//! cap-protect <input-file-or-dir> [-o <output-dir>]
//! ```
//!
//! Directories are processed recursively; `.js`/`.mjs` files are protected,
//! everything else (wasm, css, images) is copied unchanged. ES modules that use
//! `import.meta` are copied unchanged because they cannot run inside the
//! `new Function` shell.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut input: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-o" | "--out" => match args.next() {
                Some(v) => out = Some(PathBuf::from(v)),
                None => {
                    eprintln!("-o requires an output directory");
                    return ExitCode::FAILURE;
                }
            },
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other if other.starts_with('-') => {
                eprintln!("unknown option: {other} (try --help)");
                return ExitCode::FAILURE;
            }
            other => {
                if input.is_none() {
                    input = Some(PathBuf::from(other));
                } else {
                    eprintln!("unexpected argument: {other}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }

    let Some(input) = input else {
        print_help();
        return ExitCode::FAILURE;
    };
    if !input.is_dir() {
        let name = input
            .file_name()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if !(name.ends_with(".js") || name.ends_with(".mjs")) {
            eprintln!("{name}: only .js and .mjs files can be protected");
            return ExitCode::FAILURE;
        }
    }

    let target = out.unwrap_or_else(|| {
        if input.is_dir() {
            PathBuf::from("protected")
        } else {
            // Keep the extension: `foo.mjs` must not become `foo.js`.
            let file_name = input
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "bundle.js".into());
            input.with_file_name(format!("{file_name}.protected"))
        }
    });

    match run(&input, &target) {
        Ok((js, other, unchanged)) => {
            println!(
                "protected {js} JS file(s), copied {other} other file(s), {unchanged} unchanged (already protected, module, or non-JS)"
            );
            println!("output: {}", target.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "cap-protect — protect a widget build\n\n\
         usage: cap-protect <input-file-or-dir> [-o <output-dir>]\n\n\
         .js/.mjs files are obfuscated + RC4-encrypted; wasm/css/images are copied;\n\
         ES modules (import.meta) stay as-is so wasm-bindgen glue keeps working."
    );
}

fn run(input: &Path, target: &Path) -> Result<(usize, usize, usize), String> {
    if input.is_dir() {
        std::fs::create_dir_all(target).map_err(|e| e.to_string())?;
        let mut stats = (0usize, 0usize, 0usize);
        protect_dir(input, target, &mut stats)?;
        Ok(stats)
    } else {
        let data = std::fs::read(input).map_err(|e| format!("{}: {e}", input.display()))?;
        let name = input
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let served = cap_assets::protect_js(&name, &data);
        std::fs::write(target, &served).map_err(|e| e.to_string())?;
        if served == data {
            // Unchanged: already protected, a module, or empty.
            Ok((0, 0, 1))
        } else {
            Ok((1, 0, 0))
        }
    }
}

fn protect_dir(
    dir: &Path,
    out: &Path,
    stats: &mut (usize, usize, usize),
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let rel = path.strip_prefix(dir).map_err(|e| e.to_string())?;
        let dest = out.join(rel);
        if path.is_dir() {
            std::fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
            protect_dir(&path, &dest, stats)?;
            continue;
        }
        let data = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let served = cap_assets::protect_js(&name, &data);
        if served == data {
            if name.ends_with(".js") || name.ends_with(".mjs") {
                stats.2 += 1;
            } else {
                stats.1 += 1;
            }
        } else {
            stats.0 += 1;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&dest, served).map_err(|e| e.to_string())?;
    }
    Ok(())
}
