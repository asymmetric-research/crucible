pub const DEFAULT_MAP_SIZE: usize = 1 << 16;

/// Trace collector that feeds LibAFL edge coverage only.
/// No PC tracking - source coverage can be done separately if needed.
pub struct FuzzTraceCollector {
    edge_ptr: *mut u8,
    edge_len: usize,
}

unsafe impl Send for FuzzTraceCollector {}

impl FuzzTraceCollector {
    pub fn new(edge_ptr: *mut u8, edge_len: usize) -> Self {
        Self { edge_ptr, edge_len }
    }
}

impl litesvm::types::TraceCollector for FuzzTraceCollector {
    fn trace(&mut self, _m: &solana_message::SanitizedMessage, traces: &[Vec<[u64; 12]>]) {
        for trace in traces {
            let mut prev_location = 0usize;
            for entry in trace {
                let cur_location = ((entry[11] as usize) >> 4) ^ ((entry[11] as usize) << 8);
                 
                unsafe {
                    let buf = std::slice::from_raw_parts_mut(self.edge_ptr, self.edge_len);
                    buf[cur_location ^ prev_location]++;
                }
                prev_location = cur_location >> 1;
            }
        }
    }
}
