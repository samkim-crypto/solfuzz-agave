#[cfg(not(target_os = "linux"))]
compile_error!("syscall-perf currently requires Linux thread CPU accounting");

pub mod engine;
pub mod executor;
pub mod measurement;
pub mod modexp;
pub mod workload;
