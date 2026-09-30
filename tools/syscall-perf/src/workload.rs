//! Syscall-specific code owns valid inputs and an independent result oracle.
use crate::engine::Case;

pub trait Workload {
    type Input: Clone;
    fn seeds(&self, rng: &mut Rng) -> Vec<Self::Input>;
    fn mutate(&self, input: &Self::Input, rng: &mut Rng) -> Self::Input;
    fn prepare(&self, input: &Self::Input) -> Case;
}

/// SplitMix64, for reproducible input generation, not cryptographic randomness.
pub struct Rng(pub u64);
impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    pub fn index(&mut self, n: usize) -> usize {
        self.next_u64() as usize % n
    }
    pub fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
        }
    }
}

use protosol::protos::{
    AcctState, InstrContext, SyscallContext, SyscallInvocation, VmContext, acct_state::DataRepr,
};
use solana_sdk_ids::sysvar;

/// Minimal ABI-v1 conformance environment. Feature flags are explicit in the fixture.
pub fn context(name: &[u8], heap: Vec<u8>, budget: u64) -> SyscallContext {
    SyscallContext {
        instr_ctx: Some(InstrContext {
            program_id: vec![7; 32],
            accounts: vec![
                AcctState {
                    address: vec![7; 32],
                    lamports: 0,
                    executable: true,
                    owner: vec![0; 32],
                    data_repr: Some(DataRepr::Data(vec![])),
                },
                AcctState {
                    address: sysvar::rent::id().to_bytes().to_vec(),
                    lamports: 1,
                    executable: false,
                    owner: sysvar::id().to_bytes().to_vec(),
                    data_repr: Some(DataRepr::Data(
                        bincode::serialize(&solana_rent::Rent::default()).unwrap(),
                    )),
                },
            ],
            cu_avail: budget,
            ..Default::default()
        }),
        vm_ctx: Some(VmContext {
            heap_max: heap.len().max(1024) as u64,
            ..Default::default()
        }),
        syscall_invocation: Some(SyscallInvocation {
            function_name: name.to_vec(),
            heap_prefix: heap,
            stack_prefix: vec![],
        }),
    }
}
