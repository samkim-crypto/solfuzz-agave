use prost::Message;
use protosol::protos::SyscallFixture;
use solana_program_runtime::solana_sbpf::ebpf::MM_HEAP_START;
use solfuzz_syscall_perf::{
    engine::{self, Case, Expected, Failure, Score, Search},
    executor,
    modexp::ModExp,
    workload::{Rng, Workload, context},
};

#[test]
fn timed_adapter_matches_original_executor_and_independent_modexp_oracle() {
    for (base_len, exponent_len, modulus_len) in
        [(1, 1, 1), (65, 33, 64), (64, 32, 129), (512, 1, 512)]
    {
        let workload = ModExp {
            base_len,
            exponent_len,
            modulus_len,
            budget: 1_400_000,
        };
        workload.validate().unwrap();
        for input in workload.seeds(&mut Rng(7)) {
            let case = workload.prepare(&input);
            let original =
                solana_svm_conformance::syscall::execute_vm_syscall(case.context.clone());
            let measured = engine::measure(&case, 3).unwrap();
            assert_eq!(measured.fixture.output.as_ref(), Some(&original));
            assert_eq!(
                measured.measurement.charged_cu,
                1_400_000 - original.cu_avail
            );
            assert!(
                measured
                    .measurement
                    .samples
                    .iter()
                    .all(|s| s.thread_cpu_ns > 0 && s.wall_ns > 0)
            );
        }
    }
}

#[test]
fn low_budget_never_enters_successful_timing_population() {
    let workload = ModExp {
        base_len: 64,
        exponent_len: 64,
        modulus_len: 64,
        budget: 1,
    };
    let case = workload.prepare(&workload.seeds(&mut Rng(1))[0]);
    assert!(matches!(
        engine::measure(&case, 3),
        Err(Failure::Rejected(_))
    ));
    let original = solana_svm_conformance::syscall::execute_vm_syscall(case.context.clone());
    assert_eq!(executor::execute(case.context).effects, original);
}

#[test]
fn incorrect_oracle_is_a_hard_failure() {
    let workload = ModExp {
        base_len: 16,
        exponent_len: 16,
        modulus_len: 16,
        budget: 1_400_000,
    };
    let mut case = workload.prepare(&workload.seeds(&mut Rng(1))[0]);
    if let Expected::Heap { bytes, .. } = &mut case.expected {
        bytes[0] ^= 1;
    }
    assert!(matches!(
        engine::measure(&case, 3),
        Err(Failure::Mismatch(_))
    ));
}

// A second syscall proves that the search and measurement engine contain no ModExp-specific ABI logic.
struct Memset;
impl Workload for Memset {
    type Input = u8;
    fn seeds(&self, _: &mut Rng) -> Vec<u8> {
        vec![0, 0xff]
    }
    fn mutate(&self, input: &u8, _: &mut Rng) -> u8 {
        input.wrapping_add(1)
    }
    fn prepare(&self, input: &u8) -> Case {
        let mut context = context(b"sol_memset_", vec![0; 1024], 10_000);
        let vm = context.vm_ctx.as_mut().unwrap();
        vm.r1 = MM_HEAP_START;
        vm.r2 = *input as u64;
        vm.r3 = 1024;
        Case {
            context,
            expected: Expected::Heap {
                offset: 0,
                bytes: vec![*input; 1024],
                r0: 0,
            },
        }
    }
}

#[test]
fn generic_search_exports_fixtures_readable_by_original_executor_and_cli() {
    let out = std::env::temp_dir().join(format!("solfuzz-perf-test-{}", std::process::id()));
    std::fs::create_dir(&out).unwrap();
    let search_out = out.join("search");
    std::fs::create_dir(&search_out).unwrap();
    engine::search(
        &Memset,
        &Search {
            iterations: 2,
            repeats: 3,
            confirm_repeats: 3,
            seed: 7,
            score: Score::CpuNs,
        },
        &search_out,
    )
    .unwrap();
    let bytes = std::fs::read(search_out.join("winner.fix")).unwrap();
    let fixture = SyscallFixture::decode(bytes.as_slice()).unwrap();
    assert_eq!(
        fixture.output.unwrap(),
        solana_svm_conformance::syscall::execute_vm_syscall(fixture.input.unwrap())
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(search_out.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["candidates"], 4);
    assert_eq!(report["rejected"], 0);
    assert_eq!(report["confirmations"].as_array().unwrap().len(), 6);
    // Release-only CLI intentionally rejects debug builds for timing.
    if !cfg!(debug_assertions) {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_solfuzz-syscall-perf"))
            .arg("--out")
            .arg(out.join("measure"))
            .arg("measure")
            .arg(search_out.join("winner.fix"))
            .args(["--repeats", "3"])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    std::fs::remove_dir_all(out).unwrap();
}

#[test]
fn mutations_preserve_sizes_and_valid_moduli_and_are_seeded() {
    let workload = ModExp {
        base_len: 8,
        exponent_len: 4,
        modulus_len: 16,
        budget: 1_400_000,
    };
    let mut a = Rng(42);
    let mut b = Rng(42);
    let mut input = workload.seeds(&mut a)[3].clone();
    assert_eq!(input, workload.seeds(&mut b)[3]);
    for i in 0..100 {
        let next = workload.mutate(&input, &mut a);
        assert_eq!(next, workload.mutate(&input, &mut b));
        assert_eq!(
            (next.base.len(), next.exponent.len(), next.modulus.len()),
            (8, 4, 16)
        );
        assert_eq!(next.modulus[0] & 1, 1);
        assert!(next.modulus[15] >= 128);
        if i % 10 == 0 {
            engine::measure(&workload.prepare(&next), 3).unwrap();
        }
        input = next;
    }
}

#[test]
fn standalone_adapter_uses_the_same_agave_pin_as_solfuzz() {
    let pin = "b0fcf42fde4900c3d5d3d709672d561d4106ab01";
    for manifest in [
        include_str!("../../../Cargo.toml"),
        include_str!("../Cargo.toml"),
    ] {
        let agave_lines: Vec<_> = manifest
            .lines()
            .filter(|line| line.contains("https://github.com/firedancer-io/agave"))
            .collect();
        assert!(!agave_lines.is_empty());
        assert!(
            agave_lines.iter().all(|line| line.contains(pin)),
            "update the adapter, provenance and parity tests when the Agave pin changes"
        );
    }
}
