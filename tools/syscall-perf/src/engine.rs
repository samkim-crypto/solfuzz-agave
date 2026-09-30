use crate::{
    executor::{self, Execution},
    measurement::Sample,
    workload::{Rng, Workload},
};
use clap::ValueEnum;
use prost::Message;
use protosol::protos::{SyscallContext, SyscallEffects, SyscallFixture};
use serde::Serialize;
use std::{fs, io::Write, path::Path};

pub struct Case {
    pub context: SyscallContext,
    pub expected: Expected,
}
pub enum Expected {
    Heap {
        offset: usize,
        bytes: Vec<u8>,
        r0: u64,
    },
    Effects(SyscallEffects),
}
impl Case {
    fn validate(&self, result: &Execution) -> Result<(), String> {
        let correct = match &self.expected {
            Expected::Heap { offset, bytes, r0 } => {
                result.effects.r0 == *r0
                    && result.heap.get(*offset..offset + bytes.len()) == Some(bytes.as_slice())
            }
            Expected::Effects(effects) => effects == &result.effects,
        };
        if correct {
            Ok(())
        } else {
            Err("result disagrees with the oracle/fixture; stop and investigate".into())
        }
    }
}

#[derive(Debug)]
pub enum Failure {
    Rejected(String),
    Mismatch(String),
}
#[derive(Clone, Serialize)]
pub struct Measurement {
    pub samples: Vec<Sample>,
    pub median_cpu_ns: u64,
    pub median_wall_ns: u64,
    pub charged_cu: u64,
    pub median_cpu_ns_per_cu: f64,
}
pub struct Measured {
    pub measurement: Measurement,
    pub fixture: SyscallFixture,
}

fn median(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

pub fn measure(case: &Case, repeats: usize) -> Result<Measured, Failure> {
    if repeats == 0 {
        return Err(Failure::Mismatch("repeats must be positive".into()));
    }
    // Untimed setup, warm-up and validation; an error path never wins a successful-call search.
    let warmup = executor::execute(case.context.clone());
    if warmup.effects.error != 0 {
        return Err(Failure::Rejected(format!(
            "error_kind={}, error={}, r0={}",
            warmup.effects.error_kind, warmup.effects.error, warmup.effects.r0
        )));
    }
    case.validate(&warmup).map_err(Failure::Mismatch)?;
    if warmup.sample.charged_cu == 0 {
        return Err(Failure::Rejected("zero CU charge".into()));
    }
    let mut samples = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let result = executor::execute(case.context.clone());
        if result.effects != warmup.effects {
            return Err(Failure::Mismatch(
                "effects changed between repetitions".into(),
            ));
        }
        samples.push(result.sample);
    }
    let median_cpu_ns = median(samples.iter().map(|s| s.thread_cpu_ns).collect());
    let measurement = Measurement {
        median_cpu_ns,
        median_wall_ns: median(samples.iter().map(|s| s.wall_ns).collect()),
        charged_cu: warmup.sample.charged_cu,
        median_cpu_ns_per_cu: median_cpu_ns as f64 / warmup.sample.charged_cu as f64,
        samples,
    };
    Ok(Measured {
        measurement,
        fixture: SyscallFixture {
            input: Some(case.context.clone()),
            output: Some(warmup.effects),
            ..Default::default()
        },
    })
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Score {
    CpuNs,
    CpuNsPerCu,
}
impl Score {
    fn value(self, m: &Measurement) -> f64 {
        match self {
            Self::CpuNs => m.median_cpu_ns as f64,
            Self::CpuNsPerCu => m.median_cpu_ns_per_cu,
        }
    }
}

pub struct Search {
    pub iterations: usize,
    pub repeats: usize,
    pub confirm_repeats: usize,
    pub seed: u64,
    pub score: Score,
}

pub fn search<W: Workload>(workload: &W, config: &Search, out: &Path) -> Result<(), String> {
    let mut rng = Rng(config.seed);
    let seeds = workload.seeds(&mut rng);
    if seeds.is_empty() {
        return Err("workload has no seeds".into());
    }
    let mut log = fs::File::create(out.join("candidates.jsonl")).map_err(|e| e.to_string())?;
    let mut best: Option<(W::Input, f64, usize)> = None;
    let mut reference = None;
    let mut rejected = 0;
    for i in 0..seeds.len() + config.iterations {
        let input = if i < seeds.len() {
            seeds[i].clone()
        } else {
            // Periodic restarts keep the search from only exploring one winning seed.
            let parent = match &best {
                Some((input, _, _)) if i % 4 != 0 => input,
                _ => &seeds[rng.index(seeds.len())],
            };
            workload.mutate(parent, &mut rng)
        };
        let case = workload.prepare(&input);
        let fixture_path = format!("candidate-{i:05}.fix");
        // Persist even an oracle failure so it can be reproduced and minimized.
        fs::write(
            out.join(&fixture_path),
            SyscallFixture {
                input: Some(case.context.clone()),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .map_err(|e| e.to_string())?;
        let record = match measure(&case, config.repeats) {
            Ok(measured) => {
                fs::write(out.join(&fixture_path), measured.fixture.encode_to_vec())
                    .map_err(|e| e.to_string())?;
                let score = config.score.value(&measured.measurement);
                if i < seeds.len() {
                    reference = Some((input.clone(), i));
                }
                if best.as_ref().is_none_or(|b| score > b.1) {
                    best = Some((input, score, i));
                }
                serde_json::json!({"candidate":i,"fixture":fixture_path,"accepted":true,"measurement":measured.measurement})
            }
            Err(Failure::Rejected(reason)) => {
                rejected += 1;
                serde_json::json!({"candidate":i,"fixture":fixture_path,"accepted":false,"reason":reason})
            }
            Err(Failure::Mismatch(reason)) => return Err(format!("{fixture_path}: {reason}")),
        };
        writeln!(log, "{record}").map_err(|e| e.to_string())?;
    }
    let Some((winner, _, index)) = best else {
        return Err("no successful candidate; check CU budget, features and operand sizes; rejected fixtures were saved".into());
    };
    let (reference, reference_index) =
        reference.ok_or("no seed succeeded; no valid reference for confirmation")?;
    // Fresh alternating confirmations distinguish a search winner from a one-off slow sample.
    let mut confirmations = Vec::new();
    for round in 0..3 {
        for is_winner in if round % 2 == 0 {
            [true, false]
        } else {
            [false, true]
        } {
            let input = if is_winner { &winner } else { &reference };
            let measured = measure(&workload.prepare(input), config.confirm_repeats)
                .map_err(|e| format!("confirmation failed: {e:?}"))?;
            let name = if is_winner {
                "winner"
            } else {
                "reference-seed"
            };
            fs::write(
                out.join(format!("{name}.fix")),
                measured.fixture.encode_to_vec(),
            )
            .map_err(|e| e.to_string())?;
            confirmations.push(serde_json::json!({"round":round + 1,"case":name,"measurement":measured.measurement}));
        }
    }
    let report = serde_json::json!({"schema_version":1,"complete":true,"winner_candidate":index,
        "reference_candidate":reference_index,"objective":config.score,"candidates":seeds.len()+config.iterations,"rejected":rejected,
        "confirmations":confirmations,
        "interpretation":"highest observed search score, not a proven worst case or a CU recommendation"});
    fs::write(
        out.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
