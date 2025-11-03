use libafl::prelude::*;
use libafl::monitors::tui::TuiMonitor;
use libafl_bolts::tuples::tuple_list;
use libafl_bolts::{current_nanos, rands::StdRand, AsSlice, AsSliceMut};
use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};
use std::time::Duration;
use std::cell::RefCell;
use std::rc::Rc;
use litesvm::types::TraceCollector;
use solana_message::SanitizedMessage;

pub const MAP_SIZE: usize = 1 << 16;

#[derive(Clone)]
pub struct DefaultTraceCollector {
    pub edges_trace: Vec<u8>,
}

impl Default for DefaultTraceCollector {
    fn default() -> Self {
        Self { 
            edges_trace: vec![0u8; MAP_SIZE],
        }
    }
}

impl DefaultTraceCollector {
    fn hash_edge(prev: usize, cur: usize) -> usize {
        const MULTIPLIER: usize = 16777619;
        ((prev.wrapping_mul(MULTIPLIER)) ^ cur) % MAP_SIZE
    }
}

impl TraceCollector for DefaultTraceCollector {
    fn trace(&mut self, _m: &SanitizedMessage, traces: &[Vec<[u64; 12]>]) {
        if !traces.is_empty() {
            let mut prev_pc = 0;
            for entry in traces[0].iter() {
                let next_pc = entry[11] as usize;
                let edge_hash = Self::hash_edge(prev_pc, next_pc);
                self.edges_trace[edge_hash] = self.edges_trace[edge_hash].saturating_add(1);
                prev_pc = next_pc;
            }
        }
    }
}
thread_local! {
    pub static TRACE_COLLECTOR: Rc<RefCell<DefaultTraceCollector>> = 
        Rc::new(RefCell::new(DefaultTraceCollector::default()));
}

use std::ptr::NonNull;

pub fn run_harness<F>(mut user_target: F)
where
    F: FnMut(&[u8]) -> ExitKind + 'static,
{
    let monitor = TuiMonitor::builder().build();
    let mut mgr = SimpleEventManager::new(monitor);

    let scheduler = QueueScheduler::new();

    let mut shmem_provider = StdShMemProvider::new().expect("failed to create ShMemProvider");
    let mut shmem = shmem_provider
        .new_shmem(MAP_SIZE)
        .expect("failed to allocate shared memory for coverage map");
    
    let cov_buf_ptr = shmem.as_slice_mut().as_mut_ptr();
    let cov_buf = unsafe { 
        core::mem::transmute::<&mut [u8], &'static mut [u8]>(shmem.as_slice_mut()) 
    };

    let std_map = unsafe { StdMapObserver::new("edges", cov_buf) };
    let pc_observer = HitcountsMapObserver::new(std_map);

    let mut feedback = MaxMapFeedback::new(&pc_observer);
    let mut objective = CrashFeedback::new();

    let seed = current_nanos().max(1); // Ensure non-zero seed  
    let rand = StdRand::with_seed(seed);
    let corpus = InMemoryCorpus::<BytesInput>::new();
    let solutions = OnDiskCorpus::new("crashes").expect("failed to create crash dir");
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)
        .expect("failed to create StdState");

    let mut harness_wrapper = |input: &BytesInput| -> ExitKind {
        TRACE_COLLECTOR.with(|tc| {
            tc.borrow_mut().edges_trace.fill(0);
        });
        
        let exit_kind = user_target(input.target_bytes().as_slice());
        
        TRACE_COLLECTOR.with(|tc| {
            let trace = tc.borrow();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    trace.edges_trace.as_ptr(),
                    cov_buf_ptr,
                    MAP_SIZE
                );
            }
        });
        
        exit_kind
    };

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let mut executor = InProcessForkExecutor::new(
        &mut harness_wrapper,
        tuple_list!(pc_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_millis(10000),
        shmem_provider,
    )
    .expect("failed to create InProcessForkExecutor");

    let seeds = vec![
        vec![],
        vec![0u8; 32],
        vec![0u8; 256],
        vec![0xffu8; 32],
        (0..64).collect::<Vec<u8>>(),
    ];
    
    for seed_data in seeds {
        let input = BytesInput::new(seed_data);
        fuzzer
            .add_input(&mut state, &mut executor, &mut mgr, input)
            .expect("failed to add seed input");
    }

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("error in fuzz loop");
}
