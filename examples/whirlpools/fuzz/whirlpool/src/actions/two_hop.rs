// actions/two_hop.rs — Two-hop swap action methods (included in impl WhirlpoolFixture via include!())

pub fn action_two_hop_swap_v2(
    &mut self,
    #[range(0..3)] user_idx: usize,
    amount: u64,
    direction: bool, // true = A→B→C, false = C→B→A
) -> bool {
    let pool_two = match &self.pool_two {
        Some(p) => p.clone(),
        None => return false,
    };

    let amount = (amount % 1_000_000) + 1;
    let user = &self.users[user_idx];

    if self.pool.tick_arrays.len() < 3 || pool_two.tick_arrays.len() < 3 {
        return false;
    }

    let intermediary_is_pool2_a = pool_two.token_mint_a == self.pool.token_mint_b;

    // TwoHopSwapV2 uses input/intermediate/output token model
    if direction {
        // A→B→C: hop1 = pool_one (A→B), hop2 = pool_two (B→C)
        let a_to_b_one = true;
        let a_to_b_two = intermediary_is_pool2_a;

        let sqrt_price_limit_one = MIN_SQRT_PRICE_X64;
        let sqrt_price_limit_two = if a_to_b_two { MIN_SQRT_PRICE_X64 } else { MAX_SQRT_PRICE_X64 };

        let (ta1_0, ta1_1, ta1_2) = self.get_tick_arrays_for_swap(a_to_b_one);
        let (ta2_0, ta2_1, ta2_2) = self.get_tick_arrays_for_swap_pool(&pool_two, a_to_b_two);

        // Input = mint_a, Intermediate = mint_b, Output = mint_c
        // Vault mapping:
        // Pool one: input=vault_a, intermediate=vault_b
        // Pool two: if intermediary_is_pool2_a: intermediate=vault_a, output=vault_b
        //           else: intermediate=vault_b, output=vault_a
        let (vault_one_input, vault_one_intermediate) = (self.pool.token_vault_a, self.pool.token_vault_b);
        let (vault_two_intermediate, vault_two_output) = if intermediary_is_pool2_a {
            (pool_two.token_vault_a, pool_two.token_vault_b)
        } else {
            (pool_two.token_vault_b, pool_two.token_vault_a)
        };

        // Snapshot intermediate token (mint_b) user balance — should not change
        let user_b_pre = self.ctx.token_balance(&user.token_account_b);
        // Snapshot input (A) and output (C) for direction check
        let user_a_pre = self.ctx.token_balance(&user.token_account_a);
        let user_c_pre = self.ctx.token_balance(&user.token_account_c);
        // Snapshot all vaults for conservation check
        let v1_a_pre = self.ctx.token_balance(&vault_one_input);
        let v1_b_pre = self.ctx.token_balance(&vault_one_intermediate);
        let v2_a_pre = self.ctx.token_balance(&vault_two_intermediate);
        let v2_b_pre = self.ctx.token_balance(&vault_two_output);
        // Snapshot protocol fees + fee_growth for both pools
        let (th_p1_pre_proto_a, th_p1_pre_proto_b, th_p1_fg_a, th_p1_fg_b) =
            self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
            .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b, s.fee_growth_global_a, s.fee_growth_global_b)).unwrap_or((0, 0, 0, 0));
        let (th_p2_pre_proto_a, th_p2_pre_proto_b, th_p2_fg_a, th_p2_fg_b) =
            self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
            .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b, s.fee_growth_global_a, s.fee_growth_global_b)).unwrap_or((0, 0, 0, 0));

        let result = self.ctx.program(self.program_id)
            .call(instruction::TwoHopSwapV2 {
                amount,
                other_amount_threshold: 0,
                amount_specified_is_input: true,
                a_to_b_one,
                a_to_b_two,
                sqrt_price_limit_one,
                sqrt_price_limit_two,
                remaining_accounts_info: None,
            })
            .accounts(accounts::TwoHopSwapV2 {
                whirlpool_one: self.pool.whirlpool,
                whirlpool_two: pool_two.whirlpool,
                token_mint_input: self.pool.token_mint_a,
                token_mint_intermediate: self.pool.token_mint_b,
                token_mint_output: self.token_mint_c,
                token_program_input: spl_token::ID,
                token_program_intermediate: spl_token::ID,
                token_program_output: spl_token::ID,
                token_owner_account_input: user.token_account_a,
                token_vault_one_input: vault_one_input,
                token_vault_one_intermediate: vault_one_intermediate,
                token_vault_two_intermediate: vault_two_intermediate,
                token_vault_two_output: vault_two_output,
                token_owner_account_output: user.token_account_c,
                token_authority: user.keypair.pubkey(),
                tick_array_one_0: ta1_0,
                tick_array_one_1: ta1_1,
                tick_array_one_2: ta1_2,
                tick_array_two_0: ta2_0,
                tick_array_two_1: ta2_1,
                tick_array_two_2: ta2_2,
                oracle_one: self.pool.oracle,
                oracle_two: pool_two.oracle,

            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Verify both pools' sqrt_price↔tick consistency
                if let Ok(p1_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    let lb = harness_sqrt_price_from_tick(p1_state.tick_current_index);
                    let ub = harness_sqrt_price_from_tick(p1_state.tick_current_index + 1);
                    fuzz_assert!(p1_state.sqrt_price >= lb && p1_state.sqrt_price <= ub,
                        "two_hop_v2 pool1: sqrt_price {} not in [{}, {}] for tick {}",
                        p1_state.sqrt_price, lb, ub, p1_state.tick_current_index);
                }
                if let Ok(p2_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                    let lb = harness_sqrt_price_from_tick(p2_state.tick_current_index);
                    let ub = harness_sqrt_price_from_tick(p2_state.tick_current_index + 1);
                    fuzz_assert!(p2_state.sqrt_price >= lb && p2_state.sqrt_price <= ub,
                        "two_hop_v2 pool2: sqrt_price {} not in [{}, {}] for tick {}",
                        p2_state.sqrt_price, lb, ub, p2_state.tick_current_index);
                }
                // Postcondition: user's intermediate token (B) should not change
                let user_b_post = self.ctx.token_balance(&self.users[user_idx].token_account_b);
                fuzz_assert_eq!(user_b_post, user_b_pre,
                    "two_hop A→B→C: user intermediate token B changed {} -> {} (should be unchanged)",
                    user_b_pre, user_b_post);
                // Postcondition: input (A) decreases, output (C) increases
                let user_a_post = self.ctx.token_balance(&self.users[user_idx].token_account_a);
                let user_c_post = self.ctx.token_balance(&self.users[user_idx].token_account_c);
                fuzz_assert!(user_a_post <= user_a_pre,
                    "two_hop A→B→C: user input token A increased {} -> {}", user_a_pre, user_a_post);
                fuzz_assert!(user_c_post >= user_c_pre,
                    "two_hop A→B→C: user output token C decreased {} -> {}", user_c_pre, user_c_post);

                // Vault-user transfer conservation: input user decrease == input vault increase
                let v1_a_post = self.ctx.token_balance(&self.pool.token_vault_a);
                let user_a_delta = user_a_pre.saturating_sub(user_a_post);
                let v1_a_delta = v1_a_post.saturating_sub(v1_a_pre);
                fuzz_assert_eq!(user_a_delta, v1_a_delta,
                    "two_hop A→B→C: input user_a_delta ({}) != vault_one_input_delta ({})", user_a_delta, v1_a_delta);
                // Output user increase == output vault decrease
                let v2_b_post = self.ctx.token_balance(&vault_two_output);
                let user_c_delta = user_c_post.saturating_sub(user_c_pre);
                let v2_b_delta = v2_b_pre.saturating_sub(v2_b_post);
                fuzz_assert_eq!(user_c_delta, v2_b_delta,
                    "two_hop A→B→C: output user_c_delta ({}) != vault_two_output_delta ({})", user_c_delta, v2_b_delta);

                // Intermediate vault conservation: what exits pool_one intermediate vault
                // must enter pool_two intermediate vault (they share the same intermediate token)
                let v1_b_post = self.ctx.token_balance(&vault_one_intermediate);
                let v2_a_post = self.ctx.token_balance(&vault_two_intermediate);
                let v1_b_out = v1_b_pre.saturating_sub(v1_b_post); // exits pool_one
                let v2_a_in = v2_a_post.saturating_sub(v2_a_pre);  // enters pool_two
                fuzz_assert_eq!(v1_b_out, v2_a_in,
                    "two_hop A→B→C: intermediate vault mismatch: pool1_out={} != pool2_in={}",
                    v1_b_out, v2_a_in);

                // Protocol fee side isolation + fee_growth isolation for two-hop A→B→C:
                // Pool one (A→B): protocol_fee_owed_a increases (input side), _b unchanged
                if let Ok(p1_post) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    let p1_pb = p1_post.protocol_fee_owed_b.saturating_sub(th_p1_pre_proto_b);
                    fuzz_assert_eq!(p1_pb, 0,
                        "two_hop A→B→C pool1: proto_fee_b increased by {} (should be 0)", p1_pb);
                    // Fee growth: A→B, input=A side increases, B side frozen
                    fuzz_assert!(p1_post.fee_growth_global_a >= th_p1_fg_a,
                        "two_hop_v2 A→B→C pool1: fee_growth_a decreased {} -> {}",
                        th_p1_fg_a, p1_post.fee_growth_global_a);
                    fuzz_assert_eq!(p1_post.fee_growth_global_b, th_p1_fg_b,
                        "two_hop_v2 A→B→C pool1: fee_growth_b changed {} -> {} (A→B, should be frozen)",
                        th_p1_fg_b, p1_post.fee_growth_global_b);
                }
                // Pool two (B→C): protocol_fee on input side
                if let Ok(p2_post) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                    if intermediary_is_pool2_a {
                        // pool2: a_to_b=true (B→C), input=B=mint_a, fee on A side
                        let p2_pb = p2_post.protocol_fee_owed_b.saturating_sub(th_p2_pre_proto_b);
                        fuzz_assert_eq!(p2_pb, 0,
                            "two_hop A→B→C pool2: proto_fee_b increased by {} (should be 0)", p2_pb);
                        fuzz_assert!(p2_post.fee_growth_global_a >= th_p2_fg_a,
                            "two_hop_v2 A→B→C pool2: fee_growth_a decreased {} -> {}",
                            th_p2_fg_a, p2_post.fee_growth_global_a);
                        fuzz_assert_eq!(p2_post.fee_growth_global_b, th_p2_fg_b,
                            "two_hop_v2 A→B→C pool2: fee_growth_b changed {} -> {} (a_to_b, should be frozen)",
                            th_p2_fg_b, p2_post.fee_growth_global_b);
                    } else {
                        // pool2: a_to_b=false (b_to_a), input=B=mint_b, fee on B side
                        let p2_pa = p2_post.protocol_fee_owed_a.saturating_sub(th_p2_pre_proto_a);
                        fuzz_assert_eq!(p2_pa, 0,
                            "two_hop A→B→C pool2: proto_fee_a increased by {} (should be 0)", p2_pa);
                        fuzz_assert!(p2_post.fee_growth_global_b >= th_p2_fg_b,
                            "two_hop_v2 A→B→C pool2: fee_growth_b decreased {} -> {}",
                            th_p2_fg_b, p2_post.fee_growth_global_b);
                        fuzz_assert_eq!(p2_post.fee_growth_global_a, th_p2_fg_a,
                            "two_hop_v2 A→B→C pool2: fee_growth_a changed {} -> {} (b_to_a, should be frozen)",
                            th_p2_fg_a, p2_post.fee_growth_global_a);
                    }
                }

                // Zero intermediate → pool_two noop: if pool_one emitted zero
                // intermediate tokens, pool_two must be completely unchanged.
                // Catches phantom fee accrual on zero-amount swap legs.
                if v1_b_out == 0 {
                    if let Ok(p2_post) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                        fuzz_assert_eq!(p2_post.protocol_fee_owed_a, th_p2_pre_proto_a,
                            "two_hop A→B→C: zero intermediate but pool2 protocol_fee_a changed {} -> {}",
                            th_p2_pre_proto_a, p2_post.protocol_fee_owed_a);
                        fuzz_assert_eq!(p2_post.protocol_fee_owed_b, th_p2_pre_proto_b,
                            "two_hop A→B→C: zero intermediate but pool2 protocol_fee_b changed {} -> {}",
                            th_p2_pre_proto_b, p2_post.protocol_fee_owed_b);
                        fuzz_assert_eq!(p2_post.fee_growth_global_a, th_p2_fg_a,
                            "two_hop A→B→C: zero intermediate but pool2 fee_growth_a changed {} -> {}",
                            th_p2_fg_a, p2_post.fee_growth_global_a);
                        fuzz_assert_eq!(p2_post.fee_growth_global_b, th_p2_fg_b,
                            "two_hop A→B→C: zero intermediate but pool2 fee_growth_b changed {} -> {}",
                            th_p2_fg_b, p2_post.fee_growth_global_b);
                    }
                }

                debug_print!("[TWO_HOP_SWAP_V2] SUCCESS: A→B→C amount={} user={}", amount, user_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[TWO_HOP_SWAP_V2] TX_FAILED: A→B→C amount={} user={}", amount, user_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[TWO_HOP_SWAP_V2] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::TWO_HOP_SWAP_V2, success);
        return success;
    }

    // C→B→A: whirlpool_one = pool_two (C→B), whirlpool_two = pool_one (B→A)
    let a_to_b_one = !intermediary_is_pool2_a;
    let a_to_b_two = false;

    let sqrt_price_limit_one = if a_to_b_one { MIN_SQRT_PRICE_X64 } else { MAX_SQRT_PRICE_X64 };
    let sqrt_price_limit_two = MAX_SQRT_PRICE_X64;

    let (ta1_0, ta1_1, ta1_2) = self.get_tick_arrays_for_swap_pool(&pool_two, a_to_b_one);
    let (ta2_0, ta2_1, ta2_2) = self.get_tick_arrays_for_swap(a_to_b_two);

    // Input = mint_c, Intermediate = mint_b, Output = mint_a
    // Pool two processes first (C→B), pool one second (B→A)
    let (vault_one_input, vault_one_intermediate) = if intermediary_is_pool2_a {
        // pool_two: mint_a=mint_b, mint_b=mint_c. C is mint_b side, B is mint_a side
        // a_to_b_one = false (b_to_a on pool_two). Input goes into vault_b, intermediary comes from vault_a
        (pool_two.token_vault_b, pool_two.token_vault_a)
    } else {
        // pool_two: mint_a=mint_c, mint_b=mint_b. C is mint_a side, B is mint_b side
        // a_to_b_one = true (a_to_b on pool_two). Input goes into vault_a, intermediary comes from vault_b
        (pool_two.token_vault_a, pool_two.token_vault_b)
    };
    let (vault_two_intermediate, vault_two_output) = (self.pool.token_vault_b, self.pool.token_vault_a);

    // Snapshot intermediate token (mint_b) user balance — should not change
    let user_b_pre = self.ctx.token_balance(&user.token_account_b);
    // Snapshot input (C) and output (A) for direction check
    let user_c_pre = self.ctx.token_balance(&user.token_account_c);
    let user_a_pre = self.ctx.token_balance(&user.token_account_a);
    // Snapshot vaults for conservation check
    let v1_input_pre = self.ctx.token_balance(&vault_one_input);
    let v1_inter_pre = self.ctx.token_balance(&vault_one_intermediate);
    let v2_inter_pre = self.ctx.token_balance(&vault_two_intermediate);
    let v2_output_pre = self.ctx.token_balance(&vault_two_output);
    // Snapshot protocol fees + fee_growth for both pools (C→B→A)
    let (th2_p1_pre_proto_a, th2_p1_pre_proto_b, th2_p1_fg_a, th2_p1_fg_b) =
        self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
        .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b, s.fee_growth_global_a, s.fee_growth_global_b)).unwrap_or((0, 0, 0, 0));
    let (th2_p2_pre_proto_a, th2_p2_pre_proto_b, th2_p2_fg_a, th2_p2_fg_b) =
        self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
        .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b, s.fee_growth_global_a, s.fee_growth_global_b)).unwrap_or((0, 0, 0, 0));

    let result = self.ctx.program(self.program_id)
        .call(instruction::TwoHopSwapV2 {
            amount,
            other_amount_threshold: 0,
            amount_specified_is_input: true,
            a_to_b_one,
            a_to_b_two,
            sqrt_price_limit_one,
            sqrt_price_limit_two,
            remaining_accounts_info: None,
        })
        .accounts(accounts::TwoHopSwapV2 {
            whirlpool_one: pool_two.whirlpool,
            whirlpool_two: self.pool.whirlpool,
            token_mint_input: self.token_mint_c,
            token_mint_intermediate: self.pool.token_mint_b,
            token_mint_output: self.pool.token_mint_a,
            token_program_input: spl_token::ID,
            token_program_intermediate: spl_token::ID,
            token_program_output: spl_token::ID,
            token_owner_account_input: user.token_account_c,
            token_vault_one_input: vault_one_input,
            token_vault_one_intermediate: vault_one_intermediate,
            token_vault_two_intermediate: vault_two_intermediate,
            token_vault_two_output: vault_two_output,
            token_owner_account_output: user.token_account_a,
            token_authority: user.keypair.pubkey(),
            tick_array_one_0: ta1_0,
            tick_array_one_1: ta1_1,
            tick_array_one_2: ta1_2,
            tick_array_two_0: ta2_0,
            tick_array_two_1: ta2_1,
            tick_array_two_2: ta2_2,
            oracle_one: pool_two.oracle,
            oracle_two: self.pool.oracle,

        })
        .signers(&[&*user.keypair])
        .send();

    let success = match &result {
        Ok(TxOutcome::Success { .. }) => {
            if let Ok(p1_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                let lb = harness_sqrt_price_from_tick(p1_state.tick_current_index);
                let ub = harness_sqrt_price_from_tick(p1_state.tick_current_index + 1);
                fuzz_assert!(p1_state.sqrt_price >= lb && p1_state.sqrt_price <= ub,
                    "two_hop_v2 pool1: sqrt_price {} not in [{}, {}] for tick {}",
                    p1_state.sqrt_price, lb, ub, p1_state.tick_current_index);
            }
            if let Ok(p2_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                let lb = harness_sqrt_price_from_tick(p2_state.tick_current_index);
                let ub = harness_sqrt_price_from_tick(p2_state.tick_current_index + 1);
                fuzz_assert!(p2_state.sqrt_price >= lb && p2_state.sqrt_price <= ub,
                    "two_hop_v2 pool2: sqrt_price {} not in [{}, {}] for tick {}",
                    p2_state.sqrt_price, lb, ub, p2_state.tick_current_index);
            }
            // Postcondition: user's intermediate token (B) should not change
            let user_b_post = self.ctx.token_balance(&self.users[user_idx].token_account_b);
            fuzz_assert_eq!(user_b_post, user_b_pre,
                "two_hop C→B→A: user intermediate token B changed {} -> {} (should be unchanged)",
                user_b_pre, user_b_post);
            // Postcondition: input (C) decreases, output (A) increases
            let user_c_post = self.ctx.token_balance(&self.users[user_idx].token_account_c);
            let user_a_post = self.ctx.token_balance(&self.users[user_idx].token_account_a);
            fuzz_assert!(user_c_post <= user_c_pre,
                "two_hop C→B→A: user input token C increased {} -> {}", user_c_pre, user_c_post);
            fuzz_assert!(user_a_post >= user_a_pre,
                "two_hop C→B→A: user output token A decreased {} -> {}", user_a_pre, user_a_post);

            // Vault-user transfer conservation: input user decrease == input vault increase
            let v1_input_post = self.ctx.token_balance(&vault_one_input);
            let user_c_delta = user_c_pre.saturating_sub(user_c_post);
            let v1_input_delta = v1_input_post.saturating_sub(v1_input_pre);
            fuzz_assert_eq!(user_c_delta, v1_input_delta,
                "two_hop C→B→A: input user_c_delta ({}) != vault_one_input_delta ({})", user_c_delta, v1_input_delta);
            // Output user increase == output vault decrease
            let v2_output_post = self.ctx.token_balance(&vault_two_output);
            let user_a_delta = user_a_post.saturating_sub(user_a_pre);
            let v2_output_delta = v2_output_pre.saturating_sub(v2_output_post);
            fuzz_assert_eq!(user_a_delta, v2_output_delta,
                "two_hop C→B→A: output user_a_delta ({}) != vault_two_output_delta ({})", user_a_delta, v2_output_delta);

            // Intermediate vault conservation: what exits pool_two's intermediate vault
            // must enter pool_one's intermediate vault
            let v1_inter_post = self.ctx.token_balance(&vault_one_intermediate);
            let v2_inter_post = self.ctx.token_balance(&vault_two_intermediate);
            let v1_inter_out = v1_inter_pre.saturating_sub(v1_inter_post); // exits pool_two (whirlpool_one)
            let v2_inter_in = v2_inter_post.saturating_sub(v2_inter_pre);  // enters pool_one (whirlpool_two)
            fuzz_assert_eq!(v1_inter_out, v2_inter_in,
                "two_hop C→B→A: intermediate vault mismatch: pool1_out={} != pool2_in={}",
                v1_inter_out, v2_inter_in);

            // Protocol fee side isolation for two-hop C→B→A:
            // whirlpool_one = pool_two (C→B): proto_fee on input side (C)
            // whirlpool_two = pool_one (B→A): proto_fee on input side (B)
            // Protocol fee + fee_growth isolation for C→B→A
            if let Ok(p2_post) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                if intermediary_is_pool2_a {
                    // pool2 a_to_b_one=false: b_to_a. Input=C=mint_b. proto_fee on B, A stays
                    let p2_pa = p2_post.protocol_fee_owed_a.saturating_sub(th2_p2_pre_proto_a);
                    fuzz_assert_eq!(p2_pa, 0,
                        "two_hop C→B→A pool2: proto_fee_a increased by {} (should be 0)", p2_pa);
                    fuzz_assert!(p2_post.fee_growth_global_b >= th2_p2_fg_b,
                        "two_hop_v2 C→B→A pool2: fee_growth_b decreased {} -> {}",
                        th2_p2_fg_b, p2_post.fee_growth_global_b);
                    fuzz_assert_eq!(p2_post.fee_growth_global_a, th2_p2_fg_a,
                        "two_hop_v2 C→B→A pool2: fee_growth_a changed {} -> {} (b_to_a, should be frozen)",
                        th2_p2_fg_a, p2_post.fee_growth_global_a);
                } else {
                    // pool2 a_to_b_one=true: a_to_b. Input=C=mint_a. proto_fee on A, B stays
                    let p2_pb = p2_post.protocol_fee_owed_b.saturating_sub(th2_p2_pre_proto_b);
                    fuzz_assert_eq!(p2_pb, 0,
                        "two_hop C→B→A pool2: proto_fee_b increased by {} (should be 0)", p2_pb);
                    fuzz_assert!(p2_post.fee_growth_global_a >= th2_p2_fg_a,
                        "two_hop_v2 C→B→A pool2: fee_growth_a decreased {} -> {}",
                        th2_p2_fg_a, p2_post.fee_growth_global_a);
                    fuzz_assert_eq!(p2_post.fee_growth_global_b, th2_p2_fg_b,
                        "two_hop_v2 C→B→A pool2: fee_growth_b changed {} -> {} (a_to_b, should be frozen)",
                        th2_p2_fg_b, p2_post.fee_growth_global_b);
                }
            }
            // Pool one: a_to_b_two=false (b_to_a). Input=B=mint_b. proto_fee on B, A stays
            if let Ok(p1_post) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                let p1_pa = p1_post.protocol_fee_owed_a.saturating_sub(th2_p1_pre_proto_a);
                fuzz_assert_eq!(p1_pa, 0,
                    "two_hop C→B→A pool1: proto_fee_a increased by {} (should be 0)", p1_pa);
                fuzz_assert!(p1_post.fee_growth_global_b >= th2_p1_fg_b,
                    "two_hop_v2 C→B→A pool1: fee_growth_b decreased {} -> {}",
                    th2_p1_fg_b, p1_post.fee_growth_global_b);
                fuzz_assert_eq!(p1_post.fee_growth_global_a, th2_p1_fg_a,
                    "two_hop_v2 C→B→A pool1: fee_growth_a changed {} -> {} (B→A, should be frozen)",
                    th2_p1_fg_a, p1_post.fee_growth_global_a);
            }

            // Zero intermediate → pool_one noop: if pool_two (whirlpool_one in CBA) emitted
            // zero intermediate tokens, pool_one (whirlpool_two) must be completely unchanged.
            if v1_inter_out == 0 {
                if let Ok(p1_post) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    fuzz_assert_eq!(p1_post.protocol_fee_owed_a, th2_p1_pre_proto_a,
                        "two_hop C→B→A: zero intermediate but pool1 protocol_fee_a changed {} -> {}",
                        th2_p1_pre_proto_a, p1_post.protocol_fee_owed_a);
                    fuzz_assert_eq!(p1_post.protocol_fee_owed_b, th2_p1_pre_proto_b,
                        "two_hop C→B→A: zero intermediate but pool1 protocol_fee_b changed {} -> {}",
                        th2_p1_pre_proto_b, p1_post.protocol_fee_owed_b);
                    fuzz_assert_eq!(p1_post.fee_growth_global_a, th2_p1_fg_a,
                        "two_hop C→B→A: zero intermediate but pool1 fee_growth_a changed {} -> {}",
                        th2_p1_fg_a, p1_post.fee_growth_global_a);
                    fuzz_assert_eq!(p1_post.fee_growth_global_b, th2_p1_fg_b,
                        "two_hop C→B→A: zero intermediate but pool1 fee_growth_b changed {} -> {}",
                        th2_p1_fg_b, p1_post.fee_growth_global_b);
                }
            }

            debug_print!("[TWO_HOP_SWAP_V2] SUCCESS: C→B→A amount={} user={}", amount, user_idx);
            true
        }
        Ok(TxOutcome::ProgramError { logs, .. }) => {
            debug_print!("[TWO_HOP_SWAP_V2] TX_FAILED: C→B→A amount={} user={}", amount, user_idx);
            for log in logs { debug_print!("  {}", log); }
            false
        }
        Err(e) => {
            debug_print!("[TWO_HOP_SWAP_V2] SEND_FAILED: {:?}", e);
            false
        }
    };
    action_stats::record(&action_stats::TWO_HOP_SWAP_V2, success);
    success
}

pub fn action_two_hop_swap(
    &mut self,
    #[range(0..3)] user_idx: usize,
    amount: u64,
    direction: bool, // true = A→B→C, false = C→B→A
) -> bool {
    let pool_two = match &self.pool_two {
        Some(p) => p.clone(),
        None => return false,
    };

    let amount = (amount % 1_000_000) + 1;
    let user = &self.users[user_idx];

    // Pool one tick arrays (3 needed)
    if self.pool.tick_arrays.len() < 3 || pool_two.tick_arrays.len() < 3 {
        return false;
    }

    // The TwoHopSwap processes whirlpool_one FIRST, then whirlpool_two.
    // Output of hop1 feeds into hop2. The intermediary is mint_b (shared between pools).
    //
    // For A→B→C direction: hop1 = pool_one (A→B), hop2 = pool_two (B→C)
    // For C→B→A direction: hop1 = pool_two (C→B), hop2 = pool_one (B→A)
    let intermediary_is_pool2_a = pool_two.token_mint_a == self.pool.token_mint_b;

    // Map user accounts to pool_two's mint ordering
    let (user_two_a, user_two_b) = if intermediary_is_pool2_a {
        (user.token_account_b, user.token_account_c)
    } else {
        (user.token_account_c, user.token_account_b)
    };

    // Snapshot intermediate token (mint_b) user balance — should not change in two-hop
    let user_b_pre = self.ctx.token_balance(&user.token_account_b);
    // Snapshot input and output for direction check
    let user_a_pre_legacy = self.ctx.token_balance(&user.token_account_a);
    let user_c_pre_legacy = self.ctx.token_balance(&user.token_account_c);

    if direction {
        // A→B→C: whirlpool_one = pool_one (A→B), whirlpool_two = pool_two (B→C)
        let a_to_b_one = true; // A→B in pool_one
        // In pool_two: input is mint_b. If pool2.mint_a = mint_b → a_to_b, else b_to_a
        let a_to_b_two = intermediary_is_pool2_a;

        // Vault snapshots for conservation
        let leg_v1_a_pre = self.ctx.token_balance(&self.pool.token_vault_a);
        let leg_v1_b_pre = self.ctx.token_balance(&self.pool.token_vault_b);
        let leg_v2_a_pre = self.ctx.token_balance(&pool_two.token_vault_a);
        let leg_v2_b_pre = self.ctx.token_balance(&pool_two.token_vault_b);
        // Protocol fee snapshots
        let (leg_p1_pre_pa, leg_p1_pre_pb) =
            self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
            .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b)).unwrap_or((0, 0));
        let (leg_p2_pre_pa, leg_p2_pre_pb) =
            self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
            .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b)).unwrap_or((0, 0));
        // Fee growth snapshots for monotonicity
        let (leg_fg_a_pre, leg_fg_b_pre) =
            self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
            .map(|s| (s.fee_growth_global_a, s.fee_growth_global_b)).unwrap_or((0, 0));
        let (leg_p2_fg_a_pre, leg_p2_fg_b_pre) =
            self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
            .map(|s| (s.fee_growth_global_a, s.fee_growth_global_b)).unwrap_or((0, 0));

        let sqrt_price_limit_one = MIN_SQRT_PRICE_X64;
        let sqrt_price_limit_two = if a_to_b_two { MIN_SQRT_PRICE_X64 } else { MAX_SQRT_PRICE_X64 };

        let (ta1_0, ta1_1, ta1_2) = self.get_tick_arrays_for_swap(a_to_b_one);
        let (ta2_0, ta2_1, ta2_2) = self.get_tick_arrays_for_swap_pool(&pool_two, a_to_b_two);

        let result = self.ctx.program(self.program_id)
            .call(instruction::TwoHopSwap {
                amount,
                other_amount_threshold: 0,
                amount_specified_is_input: true,
                a_to_b_one,
                a_to_b_two,
                sqrt_price_limit_one,
                sqrt_price_limit_two,
            })
            .accounts(accounts::TwoHopSwap {
                token_authority: user.keypair.pubkey(),
                whirlpool_one: self.pool.whirlpool,
                whirlpool_two: pool_two.whirlpool,
                token_owner_account_one_a: user.token_account_a,
                token_vault_one_a: self.pool.token_vault_a,
                token_owner_account_one_b: user.token_account_b,
                token_vault_one_b: self.pool.token_vault_b,
                token_owner_account_two_a: user_two_a,
                token_vault_two_a: pool_two.token_vault_a,
                token_owner_account_two_b: user_two_b,
                token_vault_two_b: pool_two.token_vault_b,
                tick_array_one_0: ta1_0,
                tick_array_one_1: ta1_1,
                tick_array_one_2: ta1_2,
                tick_array_two_0: ta2_0,
                tick_array_two_1: ta2_1,
                tick_array_two_2: ta2_2,
                oracle_one: self.pool.oracle,
                oracle_two: pool_two.oracle,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Step 8: Verify both pools' sqrt_price↔tick consistency after two-hop swap
                if let Ok(p1_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    let lb = harness_sqrt_price_from_tick(p1_state.tick_current_index);
                    let ub = harness_sqrt_price_from_tick(p1_state.tick_current_index + 1);
                    fuzz_assert!(p1_state.sqrt_price >= lb && p1_state.sqrt_price <= ub,
                        "two_hop pool1: sqrt_price {} not in [{}, {}] for tick {}",
                        p1_state.sqrt_price, lb, ub, p1_state.tick_current_index);
                }
                if let Ok(p2_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                    let lb = harness_sqrt_price_from_tick(p2_state.tick_current_index);
                    let ub = harness_sqrt_price_from_tick(p2_state.tick_current_index + 1);
                    fuzz_assert!(p2_state.sqrt_price >= lb && p2_state.sqrt_price <= ub,
                        "two_hop pool2: sqrt_price {} not in [{}, {}] for tick {}",
                        p2_state.sqrt_price, lb, ub, p2_state.tick_current_index);
                }
                // Postcondition: user's intermediate token (B) should not change
                let user_b_post = self.ctx.token_balance(&self.users[user_idx].token_account_b);
                fuzz_assert_eq!(user_b_post, user_b_pre,
                    "two_hop_legacy A→B→C: user intermediate token B changed {} -> {} (should be unchanged)",
                    user_b_pre, user_b_post);
                // Postcondition: input (A) decreases, output (C) increases
                let user_a_post = self.ctx.token_balance(&self.users[user_idx].token_account_a);
                let user_c_post = self.ctx.token_balance(&self.users[user_idx].token_account_c);
                fuzz_assert!(user_a_post <= user_a_pre_legacy,
                    "two_hop_legacy A→B→C: input A increased {} -> {}", user_a_pre_legacy, user_a_post);
                fuzz_assert!(user_c_post >= user_c_pre_legacy,
                    "two_hop_legacy A→B→C: output C decreased {} -> {}", user_c_pre_legacy, user_c_post);

                // Vault-user transfer conservation (input side): user A decrease == pool1 vault_a increase
                let leg_v1_a_post = self.ctx.token_balance(&self.pool.token_vault_a);
                let leg_ua_delta = user_a_pre_legacy.saturating_sub(self.ctx.token_balance(&self.users[user_idx].token_account_a));
                let leg_va_delta = leg_v1_a_post.saturating_sub(leg_v1_a_pre);
                fuzz_assert_eq!(leg_ua_delta, leg_va_delta,
                    "two_hop_legacy A→B→C: input user_a_delta ({}) != vault_one_a_delta ({})", leg_ua_delta, leg_va_delta);

                // Intermediate vault conservation: pool1 vault_b outflow == pool2 intermediate inflow
                let leg_v1_b_post = self.ctx.token_balance(&self.pool.token_vault_b);
                let leg_v1_b_out = leg_v1_b_pre.saturating_sub(leg_v1_b_post);
                let (leg_v2_int_pre, leg_v2_int_post) = if intermediary_is_pool2_a {
                    (leg_v2_a_pre, self.ctx.token_balance(&pool_two.token_vault_a))
                } else {
                    (leg_v2_b_pre, self.ctx.token_balance(&pool_two.token_vault_b))
                };
                let leg_v2_int_in = leg_v2_int_post.saturating_sub(leg_v2_int_pre);
                fuzz_assert_eq!(leg_v1_b_out, leg_v2_int_in,
                    "two_hop_legacy A→B→C: intermediate vault mismatch: pool1_out={} != pool2_in={}",
                    leg_v1_b_out, leg_v2_int_in);

                // Output vault conservation: pool2 output vault decrease == user C increase
                let (leg_v2_out_pre, leg_v2_out_post) = if intermediary_is_pool2_a {
                    (leg_v2_b_pre, self.ctx.token_balance(&pool_two.token_vault_b))
                } else {
                    (leg_v2_a_pre, self.ctx.token_balance(&pool_two.token_vault_a))
                };
                let leg_uc_delta = self.ctx.token_balance(&self.users[user_idx].token_account_c).saturating_sub(user_c_pre_legacy);
                let leg_v2_out_delta = leg_v2_out_pre.saturating_sub(leg_v2_out_post);
                fuzz_assert_eq!(leg_uc_delta, leg_v2_out_delta,
                    "two_hop_legacy A→B→C: output user_c_delta ({}) != vault_two_out_delta ({})", leg_uc_delta, leg_v2_out_delta);

                // Protocol fee side isolation: pool1 (A→B) => fee on A side, B stays
                if let Ok(p1_post) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    let p1_pb_delta = p1_post.protocol_fee_owed_b.saturating_sub(leg_p1_pre_pb);
                    fuzz_assert_eq!(p1_pb_delta, 0,
                        "two_hop_legacy A→B→C pool1: proto_fee_b increased by {} (should be 0)", p1_pb_delta);
                    // Fee growth monotonicity: input side (A) should increase
                    fuzz_assert!(p1_post.fee_growth_global_a >= leg_fg_a_pre,
                        "two_hop_legacy A→B→C pool1: fee_growth_a decreased {} -> {}",
                        leg_fg_a_pre, p1_post.fee_growth_global_a);
                    fuzz_assert_eq!(p1_post.fee_growth_global_b, leg_fg_b_pre,
                        "two_hop_legacy A→B→C pool1: fee_growth_b changed {} -> {} (should be frozen for A→B)",
                        leg_fg_b_pre, p1_post.fee_growth_global_b);
                }
                // Pool2: fee on input side (B), opposite side stays
                if let Ok(p2_post) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                    if intermediary_is_pool2_a {
                        // a_to_b on pool2: input=A side. proto_fee on A, B unchanged
                        let p2_pb_delta = p2_post.protocol_fee_owed_b.saturating_sub(leg_p2_pre_pb);
                        fuzz_assert_eq!(p2_pb_delta, 0,
                            "two_hop_legacy A→B→C pool2: proto_fee_b increased by {} (should be 0)", p2_pb_delta);
                        fuzz_assert!(p2_post.fee_growth_global_a >= leg_p2_fg_a_pre,
                            "two_hop_legacy A→B→C pool2: fee_growth_a decreased {} -> {}",
                            leg_p2_fg_a_pre, p2_post.fee_growth_global_a);
                        fuzz_assert_eq!(p2_post.fee_growth_global_b, leg_p2_fg_b_pre,
                            "two_hop_legacy A→B→C pool2: fee_growth_b changed {} -> {} (a_to_b, should be frozen)",
                            leg_p2_fg_b_pre, p2_post.fee_growth_global_b);
                    } else {
                        // b_to_a on pool2: input=B side. proto_fee on B, A unchanged
                        let p2_pa_delta = p2_post.protocol_fee_owed_a.saturating_sub(leg_p2_pre_pa);
                        fuzz_assert_eq!(p2_pa_delta, 0,
                            "two_hop_legacy A→B→C pool2: proto_fee_a increased by {} (should be 0)", p2_pa_delta);
                        fuzz_assert!(p2_post.fee_growth_global_b >= leg_p2_fg_b_pre,
                            "two_hop_legacy A→B→C pool2: fee_growth_b decreased {} -> {}",
                            leg_p2_fg_b_pre, p2_post.fee_growth_global_b);
                        fuzz_assert_eq!(p2_post.fee_growth_global_a, leg_p2_fg_a_pre,
                            "two_hop_legacy A→B→C pool2: fee_growth_a changed {} -> {} (b_to_a, should be frozen)",
                            leg_p2_fg_a_pre, p2_post.fee_growth_global_a);
                    }
                }

                debug_print!("[TWO_HOP_SWAP] SUCCESS: A→B→C amount={} user={}", amount, user_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[TWO_HOP_SWAP] TX_FAILED: A→B→C amount={} user={}", amount, user_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[TWO_HOP_SWAP] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::TWO_HOP_SWAP, success);
        return success;
    }

    // C→B→A: whirlpool_one = pool_two (C→B), whirlpool_two = pool_one (B→A)
    // In pool_two: output is mint_b. If pool2.mint_a = mint_b → b_to_a (output=A side), else a_to_b (output=B side=mint_b)
    let a_to_b_one = !intermediary_is_pool2_a; // on pool_two, to get mint_b as output
    let a_to_b_two = false; // on pool_one, B→A

    let sqrt_price_limit_one = if a_to_b_one { MIN_SQRT_PRICE_X64 } else { MAX_SQRT_PRICE_X64 };
    let sqrt_price_limit_two = MAX_SQRT_PRICE_X64;

    let (ta1_0, ta1_1, ta1_2) = self.get_tick_arrays_for_swap_pool(&pool_two, a_to_b_one);
    let (ta2_0, ta2_1, ta2_2) = self.get_tick_arrays_for_swap(a_to_b_two);

    // Vault snapshots for conservation
    let leg2_v1_a_pre = self.ctx.token_balance(&self.pool.token_vault_a);
    let leg2_v1_b_pre = self.ctx.token_balance(&self.pool.token_vault_b);
    let leg2_v2_a_pre = self.ctx.token_balance(&pool_two.token_vault_a);
    let leg2_v2_b_pre = self.ctx.token_balance(&pool_two.token_vault_b);
    // Protocol fee + fee_growth snapshots
    let (leg2_p1_pre_pa, leg2_p1_pre_pb, leg2_p1_fg_a, leg2_p1_fg_b) =
        self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
        .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b, s.fee_growth_global_a, s.fee_growth_global_b))
        .unwrap_or((0, 0, 0, 0));
    let (leg2_p2_pre_pa, leg2_p2_pre_pb, leg2_p2_fg_a, leg2_p2_fg_b) =
        self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
        .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b, s.fee_growth_global_a, s.fee_growth_global_b))
        .unwrap_or((0, 0, 0, 0));

    let result = self.ctx.program(self.program_id)
        .call(instruction::TwoHopSwap {
            amount,
            other_amount_threshold: 0,
            amount_specified_is_input: true,
            a_to_b_one,
            a_to_b_two,
            sqrt_price_limit_one,
            sqrt_price_limit_two,
        })
        .accounts(accounts::TwoHopSwap {
            token_authority: user.keypair.pubkey(),
            whirlpool_one: pool_two.whirlpool,  // pool_two is hop1 for C→B
            whirlpool_two: self.pool.whirlpool,  // pool_one is hop2 for B→A
            token_owner_account_one_a: user_two_a,
            token_vault_one_a: pool_two.token_vault_a,
            token_owner_account_one_b: user_two_b,
            token_vault_one_b: pool_two.token_vault_b,
            token_owner_account_two_a: user.token_account_a,
            token_vault_two_a: self.pool.token_vault_a,
            token_owner_account_two_b: user.token_account_b,
            token_vault_two_b: self.pool.token_vault_b,
            tick_array_one_0: ta1_0,
            tick_array_one_1: ta1_1,
            tick_array_one_2: ta1_2,
            tick_array_two_0: ta2_0,
            tick_array_two_1: ta2_1,
            tick_array_two_2: ta2_2,
            oracle_one: pool_two.oracle,
            oracle_two: self.pool.oracle,
        })
        .signers(&[&*user.keypair])
        .send();

    let success = match &result {
        Ok(TxOutcome::Success { .. }) => {
            // Step 8: Verify both pools' sqrt_price↔tick consistency after two-hop swap
            if let Ok(p1_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                let lb = harness_sqrt_price_from_tick(p1_state.tick_current_index);
                let ub = harness_sqrt_price_from_tick(p1_state.tick_current_index + 1);
                fuzz_assert!(p1_state.sqrt_price >= lb && p1_state.sqrt_price < ub,
                    "two_hop pool1: sqrt_price {} not in [{}, {}) for tick {}",
                    p1_state.sqrt_price, lb, ub, p1_state.tick_current_index);
            }
            if let Ok(p2_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                let lb = harness_sqrt_price_from_tick(p2_state.tick_current_index);
                let ub = harness_sqrt_price_from_tick(p2_state.tick_current_index + 1);
                fuzz_assert!(p2_state.sqrt_price >= lb && p2_state.sqrt_price < ub,
                    "two_hop pool2: sqrt_price {} not in [{}, {}) for tick {}",
                    p2_state.sqrt_price, lb, ub, p2_state.tick_current_index);
            }
            // Postcondition: user's intermediate token (B) should not change
            let user_b_post = self.ctx.token_balance(&self.users[user_idx].token_account_b);
            fuzz_assert_eq!(user_b_post, user_b_pre,
                "two_hop_legacy C→B→A: user intermediate token B changed {} -> {} (should be unchanged)",
                user_b_pre, user_b_post);
            // Postcondition: input (C) decreases, output (A) increases
            let user_c_post = self.ctx.token_balance(&self.users[user_idx].token_account_c);
            let user_a_post = self.ctx.token_balance(&self.users[user_idx].token_account_a);
            fuzz_assert!(user_c_post <= user_c_pre_legacy,
                "two_hop_legacy C→B→A: input C increased {} -> {}", user_c_pre_legacy, user_c_post);
            fuzz_assert!(user_a_post >= user_a_pre_legacy,
                "two_hop_legacy C→B→A: output A decreased {} -> {}", user_a_pre_legacy, user_a_post);

            // Vault-user transfer conservation: input user C decrease == pool2 input vault increase
            // C→B→A: whirlpool_one = pool_two, whirlpool_two = pool_one
            // Input token is C, goes into pool_two's vault.
            let (leg2_v2_in_pre, leg2_v2_in_post) = if intermediary_is_pool2_a {
                // a_to_b_one=false (b_to_a on pool2): input=C=mint_b, goes to vault_b
                (leg2_v2_b_pre, self.ctx.token_balance(&pool_two.token_vault_b))
            } else {
                // a_to_b_one=true (a_to_b on pool2): input=C=mint_a, goes to vault_a
                (leg2_v2_a_pre, self.ctx.token_balance(&pool_two.token_vault_a))
            };
            let leg2_uc_delta = user_c_pre_legacy.saturating_sub(self.ctx.token_balance(&self.users[user_idx].token_account_c));
            let leg2_v2_in_delta = leg2_v2_in_post.saturating_sub(leg2_v2_in_pre);
            fuzz_assert_eq!(leg2_uc_delta, leg2_v2_in_delta,
                "two_hop_legacy C→B→A: input user_c_delta ({}) != vault_input_delta ({})", leg2_uc_delta, leg2_v2_in_delta);

            // Intermediate vault conservation: pool2 intermediate outflow == pool1 vault_b inflow
            let (leg2_v2_int_pre, leg2_v2_int_post) = if intermediary_is_pool2_a {
                // pool2 a_to_b_one=false: output is mint_a (=mint_b) side → vault_a
                (leg2_v2_a_pre, self.ctx.token_balance(&pool_two.token_vault_a))
            } else {
                // pool2 a_to_b_one=true: output is mint_b side → vault_b
                (leg2_v2_b_pre, self.ctx.token_balance(&pool_two.token_vault_b))
            };
            let leg2_v2_int_out = leg2_v2_int_pre.saturating_sub(leg2_v2_int_post);
            let leg2_v1_b_post = self.ctx.token_balance(&self.pool.token_vault_b);
            let leg2_v1_b_in = leg2_v1_b_post.saturating_sub(leg2_v1_b_pre);
            fuzz_assert_eq!(leg2_v2_int_out, leg2_v1_b_in,
                "two_hop_legacy C→B→A: intermediate vault mismatch: pool2_out={} != pool1_in={}",
                leg2_v2_int_out, leg2_v1_b_in);

            // Output vault conservation: pool1 vault_a decrease == user A increase
            let leg2_v1_a_post = self.ctx.token_balance(&self.pool.token_vault_a);
            let leg2_ua_delta = self.ctx.token_balance(&self.users[user_idx].token_account_a).saturating_sub(user_a_pre_legacy);
            let leg2_v1_a_out = leg2_v1_a_pre.saturating_sub(leg2_v1_a_post);
            fuzz_assert_eq!(leg2_ua_delta, leg2_v1_a_out,
                "two_hop_legacy C→B→A: output user_a_delta ({}) != vault_one_a_delta ({})", leg2_ua_delta, leg2_v1_a_out);

            // Protocol fee side isolation + fee_growth monotonicity
            // Pool one (whirlpool_two, B→A): a_to_b_two=false, input=B, fee on B side, A stays
            if let Ok(p1_post) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                let p1_pa_delta = p1_post.protocol_fee_owed_a.saturating_sub(leg2_p1_pre_pa);
                fuzz_assert_eq!(p1_pa_delta, 0,
                    "two_hop_legacy C→B→A pool1: proto_fee_a increased by {} (should be 0, B→A)", p1_pa_delta);
                fuzz_assert!(p1_post.fee_growth_global_b >= leg2_p1_fg_b,
                    "two_hop_legacy C→B→A pool1: fee_growth_b decreased {} -> {}",
                    leg2_p1_fg_b, p1_post.fee_growth_global_b);
                fuzz_assert_eq!(p1_post.fee_growth_global_a, leg2_p1_fg_a,
                    "two_hop_legacy C→B→A pool1: fee_growth_a changed {} -> {} (B→A, should be frozen)",
                    leg2_p1_fg_a, p1_post.fee_growth_global_a);
            }
            // Pool two (whirlpool_one, C→B): fee on input side (C)
            if let Ok(p2_post) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                if intermediary_is_pool2_a {
                    // a_to_b_one=false (b_to_a): input=B side=mint_b. proto_fee on B, A stays
                    let p2_pa_delta = p2_post.protocol_fee_owed_a.saturating_sub(leg2_p2_pre_pa);
                    fuzz_assert_eq!(p2_pa_delta, 0,
                        "two_hop_legacy C→B→A pool2: proto_fee_a increased by {} (should be 0, b_to_a)", p2_pa_delta);
                    fuzz_assert!(p2_post.fee_growth_global_b >= leg2_p2_fg_b,
                        "two_hop_legacy C→B→A pool2: fee_growth_b decreased {} -> {}",
                        leg2_p2_fg_b, p2_post.fee_growth_global_b);
                    fuzz_assert_eq!(p2_post.fee_growth_global_a, leg2_p2_fg_a,
                        "two_hop_legacy C→B→A pool2: fee_growth_a changed {} -> {} (b_to_a, should be frozen)",
                        leg2_p2_fg_a, p2_post.fee_growth_global_a);
                } else {
                    // a_to_b_one=true (a_to_b): input=A side=mint_a=mint_c. proto_fee on A, B stays
                    let p2_pb_delta = p2_post.protocol_fee_owed_b.saturating_sub(leg2_p2_pre_pb);
                    fuzz_assert_eq!(p2_pb_delta, 0,
                        "two_hop_legacy C→B→A pool2: proto_fee_b increased by {} (should be 0, a_to_b)", p2_pb_delta);
                    fuzz_assert!(p2_post.fee_growth_global_a >= leg2_p2_fg_a,
                        "two_hop_legacy C→B→A pool2: fee_growth_a decreased {} -> {}",
                        leg2_p2_fg_a, p2_post.fee_growth_global_a);
                    fuzz_assert_eq!(p2_post.fee_growth_global_b, leg2_p2_fg_b,
                        "two_hop_legacy C→B→A pool2: fee_growth_b changed {} -> {} (a_to_b, should be frozen)",
                        leg2_p2_fg_b, p2_post.fee_growth_global_b);
                }
            }

            debug_print!("[TWO_HOP_SWAP] SUCCESS: C→B→A amount={} user={}", amount, user_idx);
            true
        }
        Ok(TxOutcome::ProgramError { logs, .. }) => {
            debug_print!("[TWO_HOP_SWAP] TX_FAILED: C→B→A amount={} user={}", amount, user_idx);
            for log in logs { debug_print!("  {}", log); }
            false
        }
        Err(e) => {
            debug_print!("[TWO_HOP_SWAP] SEND_FAILED: {:?}", e);
            false
        }
    };
    action_stats::record(&action_stats::TWO_HOP_SWAP, success);
    success
}
