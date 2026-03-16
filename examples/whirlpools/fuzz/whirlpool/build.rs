fn main() {
    // Force cargo to recompile when include!()'d action files change.
    // Without this, incremental compilation may miss changes to these files.
    println!("cargo:rerun-if-changed=src/actions/swaps.rs");
    println!("cargo:rerun-if-changed=src/actions/liquidity.rs");
    println!("cargo:rerun-if-changed=src/actions/positions.rs");
    println!("cargo:rerun-if-changed=src/actions/fees.rs");
    println!("cargo:rerun-if-changed=src/actions/rewards.rs");
    println!("cargo:rerun-if-changed=src/actions/two_hop.rs");
    println!("cargo:rerun-if-changed=src/actions/config.rs");
    println!("cargo:rerun-if-changed=src/actions/pool_two.rs");
    println!("cargo:rerun-if-changed=src/actions/pool_three.rs");
    println!("cargo:rerun-if-changed=src/actions/stress.rs");
    println!("cargo:rerun-if-changed=src/invariants.rs");
}
