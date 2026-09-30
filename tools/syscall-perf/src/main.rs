use clap::{Parser, Subcommand};
use prost::Message;
use protosol::protos::SyscallFixture;
use solfuzz_syscall_perf::{
    engine::{self, Case, Expected, Score, Search},
    measurement,
    modexp::ModExp,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Parser, Debug)]
#[command(about = "Find and remeasure expensive valid syscall inputs; no CU schedule is changed")]
struct Args {
    #[arg(long, global = true)]
    cpu: Option<usize>,
    #[arg(long)]
    out: PathBuf,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand, Debug)]
enum Action {
    /// Search operand contents within one fixed ModExp size bucket.
    Modexp {
        #[arg(long, default_value_t = 128)]
        base_len: usize,
        #[arg(long, default_value_t = 128)]
        exponent_len: usize,
        #[arg(long, default_value_t = 128)]
        modulus_len: usize,
        #[arg(long, default_value_t = 1_400_000)]
        budget: u64,
        #[arg(long, default_value_t = 64)]
        iterations: usize,
        #[arg(long, default_value_t = 7)]
        repeats: usize,
        #[arg(long, default_value_t = 21)]
        confirm_repeats: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, value_enum, default_value_t=Score::CpuNsPerCu)]
        score: Score,
    },
    /// Remeasure any registered syscall's compatible successful SyscallFixture.
    Measure {
        fixture: PathBuf,
        #[arg(long, default_value_t = 21)]
        repeats: usize,
    },
}

fn check_repeats(n: usize) -> Result<(), String> {
    if !(3..=10_001).contains(&n) || n.is_multiple_of(2) {
        Err("repeats must be an odd number from 3 to 10001".into())
    } else {
        Ok(())
    }
}
fn read(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let args = Args::parse();
    if cfg!(debug_assertions) {
        return Err("use cargo build/run --release for performance measurements".into());
    }
    let flags = env!("PERF_RUSTFLAGS");
    if [
        "sanitizer",
        "sancov",
        "instrument-coverage",
        "profile-generate",
    ]
    .iter()
    .any(|s| flags.contains(s))
    {
        return Err(
            "build includes instrumentation; rebuild without fuzz/coverage/profiling flags".into(),
        );
    }
    match &args.command {
        Action::Modexp {
            base_len,
            exponent_len,
            modulus_len,
            budget,
            repeats,
            confirm_repeats,
            iterations,
            ..
        } => {
            ModExp {
                base_len: *base_len,
                exponent_len: *exponent_len,
                modulus_len: *modulus_len,
                budget: *budget,
            }
            .validate()?;
            check_repeats(*repeats)?;
            check_repeats(*confirm_repeats)?;
            if *iterations > 100_000 {
                return Err("iterations must not exceed 100000".into());
            }
        }
        Action::Measure { repeats, .. } => check_repeats(*repeats)?,
    }
    if let Some(cpu) = args.cpu {
        measurement::pin(cpu)?;
    }
    fs::create_dir(&args.out)
        .map_err(|e| format!("create a new output directory {}: {e}", args.out.display()))?;
    // Timer readings include small clock overhead; retain an empty-bracket reference, never subtract it blindly.
    let clock_samples: Vec<_> = (0..21)
        .map(|_| measurement::Timer::start().finish())
        .collect();
    let metadata = serde_json::json!({
        "schema_version":1,"started_unix_ns":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_string(),
        "command":std::env::args().collect::<Vec<_>>(),"requested_cpu":args.cpu,
        "agave_commit":"b0fcf42fde4900c3d5d3d709672d561d4106ab01","protosol":"17.0.0",
        "binary_sha256":fs::read(std::env::current_exe().map_err(|e|e.to_string())?).ok().map(|b| hex(&openssl::sha::sha256(&b))),
        "cargo_lock_sha256":hex(&openssl::sha::sha256(include_bytes!("../Cargo.lock"))),
        "source_commit":env!("PERF_SOURCE_COMMIT"),"source_status_at_build":env!("PERF_SOURCE_STATUS"),
        "rustc":env!("PERF_RUSTC"),"profile":env!("PERF_BUILD_PROFILE"),"rustflags":flags,"target":env!("PERF_TARGET"),
        "cpuinfo":read("/proc/cpuinfo"),"process_status":read("/proc/self/status"),"loadavg":read("/proc/loadavg"),
        "kernel":read("/proc/sys/kernel/osrelease"),"hostname":read("/proc/sys/kernel/hostname"),
        "cpu_governor":args.cpu.and_then(|c|read(format!("/sys/devices/system/cpu/cpu{c}/cpufreq/scaling_governor"))),
        "empty_clock_bracket_samples":clock_samples,
        "timing_scope":"vm.invoke_function only; fresh conformance setup per call; setup, oracle, memory hashing and output excluded",
        "warning":"local isolated native handler search, not SBF transaction or validator replay; not a proven worst case"
    });
    fs::write(
        args.out.join("environment.json"),
        serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    match args.command {
        Action::Modexp {
            base_len,
            exponent_len,
            modulus_len,
            budget,
            iterations,
            repeats,
            confirm_repeats,
            seed,
            score,
        } => {
            engine::search(
                &ModExp {
                    base_len,
                    exponent_len,
                    modulus_len,
                    budget,
                },
                &Search {
                    iterations,
                    repeats,
                    confirm_repeats,
                    seed,
                    score,
                },
                &args.out,
            )?;
        }
        Action::Measure { fixture, repeats } => {
            let fixture =
                SyscallFixture::decode(fs::read(fixture).map_err(|e| e.to_string())?.as_slice())
                    .map_err(|e| e.to_string())?;
            let case = Case {
                context: fixture.input.ok_or("fixture has no input")?,
                expected: Expected::Effects(
                    fixture.output.ok_or("fixture has no expected effects")?,
                ),
            };
            let result = engine::measure(&case, repeats).map_err(|e| format!("{e:?}"))?;
            fs::write(args.out.join("input.fix"), result.fixture.encode_to_vec())
                .map_err(|e| e.to_string())?;
            fs::write(args.out.join("report.json"), serde_json::to_vec_pretty(&serde_json::json!({"schema_version":1,"complete":true,"measurement":result.measurement})).unwrap()).map_err(|e|e.to_string())?;
        }
    }
    println!("Saved fixtures and measurements to {}", args.out.display());
    Ok(())
}
