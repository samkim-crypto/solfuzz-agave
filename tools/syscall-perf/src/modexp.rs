use crate::{
    engine::{Case, Expected},
    workload::{Rng, Workload, context},
};
use openssl::bn::{BigNum, BigNumContext};
use protosol::protos::FeatureSet;
use solana_program_runtime::solana_sbpf::ebpf::MM_HEAP_START;

#[derive(Clone, Debug, PartialEq)]
pub struct Input {
    pub base: Vec<u8>,
    pub exponent: Vec<u8>,
    pub modulus: Vec<u8>,
}

pub struct ModExp {
    pub base_len: usize,
    pub exponent_len: usize,
    pub modulus_len: usize,
    pub budget: u64,
}
impl ModExp {
    pub fn validate(&self) -> Result<(), String> {
        if [self.base_len, self.exponent_len, self.modulus_len]
            .iter()
            .any(|n| !(1..=512).contains(n))
        {
            return Err("operand lengths must be 1..=512 bytes".into());
        }
        if !(1..=1_400_000).contains(&self.budget) {
            return Err("budget must be 1..=1400000 CU".into());
        }
        Ok(())
    }
}

fn repair_modulus(bytes: &mut [u8]) {
    bytes[0] |= 1; // Odd modulus; the pinned implementation requires odd and > 1.
    *bytes.last_mut().unwrap() |= 0x80;
}

impl Workload for ModExp {
    type Input = Input;
    fn seeds(&self, rng: &mut Rng) -> Vec<Input> {
        let mut base = vec![0; self.base_len];
        let mut modulus = vec![0; self.modulus_len];
        rng.fill(&mut base);
        rng.fill(&mut modulus);
        repair_modulus(&mut modulus);
        let mut random = vec![0; self.exponent_len];
        rng.fill(&mut random);
        let mut sparse = vec![0; self.exponent_len];
        *sparse.last_mut().unwrap() = 0x80;
        let mut one = vec![0; self.exponent_len];
        one[0] = 1;
        // Different density and effective length, all within the same ABI sizes.
        [
            vec![0; self.exponent_len],
            one,
            sparse,
            random,
            vec![0x55; self.exponent_len],
            vec![0xff; self.exponent_len],
        ]
        .into_iter()
        .map(|exponent| Input {
            base: base.clone(),
            exponent,
            modulus: modulus.clone(),
        })
        .collect()
    }
    fn mutate(&self, input: &Input, rng: &mut Rng) -> Input {
        let mut next = input.clone();
        let bytes = match rng.index(3) {
            0 => &mut next.base,
            1 => &mut next.exponent,
            _ => &mut next.modulus,
        };
        match rng.index(5) {
            0 => {
                let i = rng.index(bytes.len());
                bytes[i] ^= 1 << rng.index(8);
            }
            1 => rng.fill(bytes),
            2 => {
                let i = rng.index(bytes.len());
                bytes[i..].fill(0);
            }
            3 => bytes.fill([0, 1, 0x55, 0xaa, 0xff][rng.index(5)]),
            _ => {
                let i = rng.index(bytes.len());
                bytes[i] = rng.next_u64() as u8;
            }
        }
        repair_modulus(&mut next.modulus);
        next
    }
    fn prepare(&self, input: &Input) -> Case {
        // Pinned ABI: six u64 fields, little-endian operands and result.
        let base = 48;
        let exponent = base + input.base.len();
        let modulus = exponent + input.exponent.len();
        let output = modulus + input.modulus.len();
        let mut heap = Vec::new();
        for word in [
            MM_HEAP_START + base as u64,
            input.base.len() as u64,
            MM_HEAP_START + exponent as u64,
            input.exponent.len() as u64,
            MM_HEAP_START + modulus as u64,
            input.modulus.len() as u64,
        ] {
            heap.extend_from_slice(&word.to_le_bytes());
        }
        heap.extend_from_slice(&input.base);
        heap.extend_from_slice(&input.exponent);
        heap.extend_from_slice(&input.modulus);
        heap.resize(output + input.modulus.len(), 0xa5);
        // Agave uses num-bigint; use OpenSSL here to avoid sharing its arithmetic implementation.
        let from_le = |bytes: &[u8]| {
            BigNum::from_slice(&bytes.iter().rev().copied().collect::<Vec<_>>()).unwrap()
        };
        let mut answer = BigNum::new().unwrap();
        answer
            .mod_exp(
                &from_le(&input.base),
                &from_le(&input.exponent),
                &from_le(&input.modulus),
                &mut BigNumContext::new().unwrap(),
            )
            .unwrap();
        let mut answer = answer.to_vec();
        answer.reverse();
        answer.resize(input.modulus.len(), 0);
        let mut context = context(b"sol_big_mod_exp", heap, self.budget);
        let vm = context.vm_ctx.as_mut().unwrap();
        vm.r1 = MM_HEAP_START;
        vm.r2 = MM_HEAP_START + output as u64;
        context.instr_ctx.as_mut().unwrap().features = Some(FeatureSet {
            features: vec![u64::from_le_bytes(
                agave_feature_set::enable_big_mod_exp_syscall::id().to_bytes()[..8]
                    .try_into()
                    .unwrap(),
            )],
        });
        Case {
            context,
            expected: Expected::Heap {
                offset: output,
                bytes: answer,
                r0: 0,
            },
        }
    }
}
