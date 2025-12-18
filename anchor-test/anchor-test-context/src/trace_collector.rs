use litesvm::InvocationInspectCallback;
use solana_program_runtime::invoke_context::{Executable, InvokeContext, RegisterTrace};
use solana_transaction::sanitized::SanitizedTransaction;
use solana_transaction_context::{IndexOfAccount, InstructionContext};

pub const DEFAULT_MAP_SIZE: usize = 1 << 16;

/// Fuzz trace collector that implements InvocationInspectCallback to feed LibAFL edge coverage.
pub struct FuzzTraceCallback {
    edge_ptr: *mut u8,
    edge_len: usize,
}

unsafe impl Send for FuzzTraceCallback {}
unsafe impl Sync for FuzzTraceCallback {}

impl FuzzTraceCallback {
    pub fn new(edge_ptr: *mut u8, edge_len: usize) -> Self {
        Self { edge_ptr, edge_len }
    }

    fn process_trace(&self, register_trace: RegisterTrace) {
        if register_trace.is_empty() {
            return;
        }

        let mut prev_location = 0usize;
        for regs in register_trace.iter() {
            // The program counter is stored in r11 (index 11)
            let pc = regs[11] as usize;
            let cur_location = (pc >> 4) ^ (pc << 8);

            unsafe {
                let buf = std::slice::from_raw_parts_mut(self.edge_ptr, self.edge_len);
                buf[(cur_location ^ prev_location) % self.edge_len] =
                    buf[(cur_location ^ prev_location) % self.edge_len].wrapping_add(1);
            }
            prev_location = cur_location >> 1;
        }
    }
}

impl InvocationInspectCallback for FuzzTraceCallback {
    fn before_invocation(
        &self,
        _tx: &SanitizedTransaction,
        _program_indices: &[IndexOfAccount],
        _invoke_context: &InvokeContext,
    ) {
        // No-op before invocation
    }

    fn after_invocation(&self, invoke_context: &InvokeContext, register_tracing_enabled: bool) {
        if register_tracing_enabled {
            invoke_context.iterate_vm_traces(
                &|_instruction_context: InstructionContext,
                  _executable: &Executable,
                  register_trace: RegisterTrace| {
                    self.process_trace(register_trace);
                },
            );
        }
    }
}
