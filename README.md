


Core fuzzing logic
Currently includes basic helper functions as well as #[anchor_test] and #[anchor_fuzz] macros

Steps to test:

```
cd examples/anchor-counter
anchor build
cd programs/anchor-counter
cargo test
```
