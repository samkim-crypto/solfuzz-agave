use std::{env, process::Command};
fn command(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}
fn main() {
    // No rerun-if-changed: capture the source tree's provenance whenever this package is rebuilt.
    for (key, value) in [
        (
            "PERF_RUSTC",
            command(
                &env::var("RUSTC").unwrap_or_else(|_| "rustc".into()),
                &["--version"],
            ),
        ),
        ("PERF_SOURCE_COMMIT", command("git", &["rev-parse", "HEAD"])),
        (
            "PERF_SOURCE_STATUS",
            command("git", &["status", "--porcelain"]),
        ),
        ("PERF_BUILD_PROFILE", env::var("PROFILE").unwrap()),
        (
            "PERF_RUSTFLAGS",
            env::var("CARGO_ENCODED_RUSTFLAGS")
                .unwrap_or_default()
                .replace('\x1f', " "),
        ),
        ("PERF_TARGET", env::var("TARGET").unwrap()),
    ] {
        println!("cargo:rustc-env={key}={}", value.replace('\n', "; "));
    }
}
