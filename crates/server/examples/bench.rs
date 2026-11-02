//! Real-browser business-flow benchmark (not an empty-POST HTTP benchmark).
//! Usage: cargo run -p cap-server --example bench -- <harness arguments>
//! Run `python3 test/business_bench_isolated.py --help` for the interface.
//! The harness owns an isolated Redis and server, and counts only successful
//! challenge -> official widget solve -> redeem -> first siteverify flows.

fn main() {
    let harness = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/business_bench_isolated.py");
    let status = std::process::Command::new("python3")
        .arg(harness)
        .args(std::env::args_os().skip(1))
        .status()
        .expect("start isolated business-flow benchmark");
    std::process::exit(status.code().unwrap_or(1));
}
