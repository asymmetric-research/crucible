// actions/swaps.rs — Swap action methods (included in impl WhirlpoolFixture via include!())

    // ========================================================================
    // Swap Actions
    // ========================================================================

    /// Swap token A for token B (small amounts)
    pub fn action_swap_a_to_b(&mut self, #[range(0..3)] user_idx: usize, amount: u64) -> bool {
        let amount = (amount % 1_000_000) + 1; // Cap at 1M tokens, min 1
        self.do_swap(user_idx, amount, true, None, true, 0)
    }

    /// Swap token B for token A (small amounts)
    pub fn action_swap_b_to_a(&mut self, #[range(0..3)] user_idx: usize, amount: u64) -> bool {
        let amount = (amount % 1_000_000) + 1;
        self.do_swap(user_idx, amount, false, None, true, 0)
    }

    /// Large swap that can cross multiple ticks (to trigger tick crossing logic)
    pub fn action_large_swap_a_to_b(&mut self, #[range(0..3)] user_idx: usize, amount: u64) -> bool {
        // Large amounts: 100M - 1B tokens
        let amount = (amount % 900_000_000) + 100_000_000;
        self.do_swap(user_idx, amount, true, None, true, 0)
    }

    /// Large swap B to A (to trigger tick crossing logic)
    pub fn action_large_swap_b_to_a(&mut self, #[range(0..3)] user_idx: usize, amount: u64) -> bool {
        let amount = (amount % 900_000_000) + 100_000_000;
        self.do_swap(user_idx, amount, false, None, true, 0)
    }

    /// Tiny swap (edge case - minimum amounts)
    pub fn action_tiny_swap(&mut self, #[range(0..3)] user_idx: usize, a_to_b: bool) -> bool {
        self.do_swap(user_idx, 1, a_to_b, None, true, 0)
    }

    /// Drain-swap: use the user's entire balance to push price to the boundary.
    /// Exercises swap_tick_sequence boundary paths (min/max tick arrays, array exhaustion).
    pub fn action_drain_swap(&mut self, #[range(0..3)] user_idx: usize, a_to_b: bool) -> bool {
        let user = &self.users[user_idx];
        let amount = if a_to_b {
            self.ctx.token_balance(&user.token_account_a)
        } else {
            self.ctx.token_balance(&user.token_account_b)
        };
        if amount == 0 { return false; }
        self.do_swap(user_idx, amount, a_to_b, None, true, 0)
    }

    /// Swap with a partial price limit (not all the way to MIN/MAX)
    /// This can trigger different code paths when the swap stops early
    pub fn action_swap_with_limit(
        &mut self,
        #[range(0..3)] user_idx: usize,
        amount: u64,
        a_to_b: bool,
        limit_pct: u64,  // 0-100 percentage of the way to the limit
    ) -> bool {
        let amount = (amount % 1_000_000) + 1;
        let limit_pct = (limit_pct % 101) as u128;

        // Read actual current sqrt_price from on-chain state
        let current_sqrt_price = self.read_pool_sqrt_price().unwrap_or(INITIAL_SQRT_PRICE);

        // Calculate a sqrt_price_limit between current price and min/max
        let sqrt_price_limit = if a_to_b {
            // Going down: limit between current and MIN
            let range = current_sqrt_price.saturating_sub(MIN_SQRT_PRICE_X64);
            let offset = (range * limit_pct) / 100;
            current_sqrt_price.saturating_sub(offset)
        } else {
            // Going up: limit between current and MAX
            let range = MAX_SQRT_PRICE_X64.saturating_sub(current_sqrt_price);
            let offset = (range * limit_pct) / 100;
            current_sqrt_price + offset
        };

        self.do_swap(user_idx, amount, a_to_b, Some(sqrt_price_limit), true, 0)
    }

    /// Exact-output swap (amount specifies desired output, accepts any input)
    pub fn action_exact_out_swap(
        &mut self,
        #[range(0..3)] user_idx: usize,
        amount: u64,
        a_to_b: bool,
    ) -> bool {
        let amount = (amount % 1_000_000) + 1;
        let success = self.do_swap(user_idx, amount, a_to_b, None, false, u64::MAX);
        action_stats::record(&action_stats::EXACT_OUT_SWAP, success);
        success
    }

    fn do_swap(
        &mut self,
        user_idx: usize,
        amount: u64,
        a_to_b: bool,
        custom_limit: Option<u128>,
        amount_specified_is_input: bool,
        other_amount_threshold: u64,
    ) -> bool {
        self.total_swaps += 1;

        let user = &self.users[user_idx];
        let pool = &self.pool;

        // Need at least 3 tick arrays for swap
        if pool.tick_arrays.len() < 3 {
            debug_print!("[SWAP] ERROR: Not enough tick arrays ({})", pool.tick_arrays.len());
            return false;
        }

        let sqrt_price_limit = custom_limit.unwrap_or(if a_to_b {
            MIN_SQRT_PRICE_X64
        } else {
            MAX_SQRT_PRICE_X64
        });

        // Select tick arrays based on swap direction and actual on-chain tick
        let (tick_array_0, tick_array_1, tick_array_2) = self.get_tick_arrays_for_swap(a_to_b);

        // Pre-swap snapshots for per-swap invariants (Steps 2, 3, 10)
        let vault_a_pre = self.ctx.token_balance(&pool.token_vault_a);
        let vault_b_pre = self.ctx.token_balance(&pool.token_vault_b);
        let price_pre = self.read_pool_sqrt_price().unwrap_or(0);
        let user_a_pre = self.ctx.token_balance(&user.token_account_a);
        let user_b_pre = self.ctx.token_balance(&user.token_account_b);
        // Pre-swap protocol fee + fee_growth + fee_rate + reward_timestamp snapshot
        let (pre_proto_fee_a, pre_proto_fee_b, pre_fee_growth_a, pre_fee_growth_b, pre_liquidity,
             pre_fee_rate, pre_proto_fee_rate, pre_reward_ts) =
            self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool.whirlpool)
            .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b,
                       s.fee_growth_global_a, s.fee_growth_global_b, s.liquidity,
                       s.fee_rate, s.protocol_fee_rate, s.reward_last_updated_timestamp))
            .unwrap_or((0, 0, 0, 0, 0, 0, 0, 0));

        let result = self.ctx.program(self.program_id)
            .call(instruction::Swap {
                amount,
                other_amount_threshold,
                sqrt_price_limit,
                amount_specified_is_input,
                a_to_b,
            })
            .accounts(accounts::Swap {
                token_authority: user.keypair.pubkey(),
                whirlpool: pool.whirlpool,
                token_owner_account_a: user.token_account_a,
                token_vault_a: pool.token_vault_a,
                token_owner_account_b: user.token_account_b,
                token_vault_b: pool.token_vault_b,
                tick_array_0,
                tick_array_1,
                tick_array_2,
                oracle: pool.oracle,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.successful_swaps += 1;

                // Step 2: Per-swap vault balance direction check
                let vault_a_post = self.ctx.token_balance(&self.pool.token_vault_a);
                let vault_b_post = self.ctx.token_balance(&self.pool.token_vault_b);
                if a_to_b {
                    fuzz_assert!(vault_a_post >= vault_a_pre,
                        "a_to_b swap: vault_a decreased {} -> {}", vault_a_pre, vault_a_post);
                    fuzz_assert!(vault_b_post <= vault_b_pre,
                        "a_to_b swap: vault_b increased {} -> {}", vault_b_pre, vault_b_post);
                } else {
                    fuzz_assert!(vault_b_post >= vault_b_pre,
                        "b_to_a swap: vault_b decreased {} -> {}", vault_b_pre, vault_b_post);
                    fuzz_assert!(vault_a_post <= vault_a_pre,
                        "b_to_a swap: vault_a increased {} -> {}", vault_a_pre, vault_a_post);
                }

                // Step 3: Per-swap price direction check
                let price_post = self.read_pool_sqrt_price().unwrap_or(0);
                if price_pre > 0 && price_post > 0 {
                    if a_to_b {
                        fuzz_assert!(price_post <= price_pre,
                            "a_to_b swap: sqrt_price increased {} -> {}", price_pre, price_post);
                    } else {
                        fuzz_assert!(price_post >= price_pre,
                            "b_to_a swap: sqrt_price decreased {} -> {}", price_pre, price_post);
                    }
                }

                // Step 10: Swap amount bounds check (exact-input only)
                if amount_specified_is_input {
                    let user_a_post = self.ctx.token_balance(&self.users[user_idx].token_account_a);
                    let user_b_post = self.ctx.token_balance(&self.users[user_idx].token_account_b);
                    let consumed = if a_to_b {
                        user_a_pre.saturating_sub(user_a_post)
                    } else {
                        user_b_pre.saturating_sub(user_b_post)
                    };
                    fuzz_assert!(consumed <= amount,
                        "Swap consumed {} > specified amount {}", consumed, amount);

                    // Note: We intentionally do NOT check for non-zero output on exact-input swaps.
                    // With tiny amounts, fees or rounding can legitimately consume the entire input.
                    // The exact-out check below already covers the more interesting case.
                }

                // Exact-out swap output verification: user must receive tokens
                // Catches rounding bugs in get_amount_unfixed_delta that produce
                // zero output while consuming input.
                if !amount_specified_is_input {
                    let user_a_post = self.ctx.token_balance(&self.users[user_idx].token_account_a);
                    let user_b_post = self.ctx.token_balance(&self.users[user_idx].token_account_b);
                    let received = if a_to_b {
                        user_b_post.saturating_sub(user_b_pre)
                    } else {
                        user_a_post.saturating_sub(user_a_pre)
                    };
                    fuzz_assert!(received > 0,
                        "Exact-out swap succeeded but received 0 tokens (requested={})", amount);
                    // Exact-out: received should equal requested amount (or less if partial fill)
                    fuzz_assert!(received <= amount,
                        "Exact-out swap over-delivered: received {} > requested {} (a_to_b={})",
                        received, amount, a_to_b);
                }

                // Per-swap user-vault transfer conservation:
                // Token A: vault_delta must exactly equal user_delta (opposite sign)
                // Token B: vault_delta must exactly equal user_delta (opposite sign)
                {
                    let user_a_post_chk = self.ctx.token_balance(&self.users[user_idx].token_account_a);
                    let user_b_post_chk = self.ctx.token_balance(&self.users[user_idx].token_account_b);
                    // For token A: if vault increased, user should have decreased by same amount
                    let vault_a_delta = (vault_a_post as i128) - (vault_a_pre as i128);
                    let user_a_delta = (user_a_post_chk as i128) - (user_a_pre as i128);
                    fuzz_assert_eq!(vault_a_delta, -user_a_delta,
                        "swap: token A vault_delta ({}) != -user_delta ({})",
                        vault_a_delta, -user_a_delta);
                    let vault_b_delta = (vault_b_post as i128) - (vault_b_pre as i128);
                    let user_b_delta = (user_b_post_chk as i128) - (user_b_pre as i128);
                    fuzz_assert_eq!(vault_b_delta, -user_b_delta,
                        "swap: token B vault_delta ({}) != -user_delta ({})",
                        vault_b_delta, -user_b_delta);
                }

                // Per-swap protocol fee side isolation + bounded by input + rate ratio
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    let proto_a_delta = post_pool.protocol_fee_owed_a.saturating_sub(pre_proto_fee_a);
                    let proto_b_delta = post_pool.protocol_fee_owed_b.saturating_sub(pre_proto_fee_b);
                    let fee_rate = post_pool.fee_rate as u64;
                    if a_to_b {
                        // a_to_b: fees are on input side (A), so protocol_fee_owed_b must not increase
                        fuzz_assert_eq!(proto_b_delta, 0,
                            "a_to_b swap: protocol_fee_owed_b increased by {} (should be 0)", proto_b_delta);
                        // protocol fee <= total input to vault
                        let vault_a_input = vault_a_post.saturating_sub(vault_a_pre);
                        fuzz_assert!(proto_a_delta <= vault_a_input,
                            "a_to_b swap: protocol_fee_delta_a ({}) > vault_a_input ({})", proto_a_delta, vault_a_input);
                        // Protocol fee bounded by fee_rate fraction of input:
                        // total_fee = floor(input * fee_rate / 1_000_000) across steps
                        // protocol_fee <= total_fee, and total_fee <= input * fee_rate / 1_000_000 + num_steps
                        // Conservative upper bound: input * fee_rate / 1_000_000 + 1
                        if vault_a_input > 0 && fee_rate > 0 {
                            let max_total_fee = (vault_a_input as u128) * (fee_rate as u128) / 1_000_000 + 100;
                            fuzz_assert!((proto_a_delta as u128) <= max_total_fee,
                                "a_to_b swap: proto_fee {} > max_total_fee {} (input={} fee_rate={})",
                                proto_a_delta, max_total_fee, vault_a_input, fee_rate);
                        }
                    } else {
                        // b_to_a: fees are on input side (B), so protocol_fee_owed_a must not increase
                        fuzz_assert_eq!(proto_a_delta, 0,
                            "b_to_a swap: protocol_fee_owed_a increased by {} (should be 0)", proto_a_delta);
                        let vault_b_input = vault_b_post.saturating_sub(vault_b_pre);
                        fuzz_assert!(proto_b_delta <= vault_b_input,
                            "b_to_a swap: protocol_fee_delta_b ({}) > vault_b_input ({})", proto_b_delta, vault_b_input);
                        if vault_b_input > 0 && fee_rate > 0 {
                            let max_total_fee = (vault_b_input as u128) * (fee_rate as u128) / 1_000_000 + 100;
                            fuzz_assert!((proto_b_delta as u128) <= max_total_fee,
                                "b_to_a swap: proto_fee {} > max_total_fee {} (input={} fee_rate={})",
                                proto_b_delta, max_total_fee, vault_b_input, fee_rate);
                        }
                    }
                }

                // Per-swap fee_growth delta: input-side fee_growth must increase (or stay if 0-liquidity),
                // output-side fee_growth must not change. fee_growth increase must be bounded.
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    if a_to_b {
                        // Input side is A: fee_growth_a should increase (or stay if 0 liquidity)
                        fuzz_assert!(post_pool.fee_growth_global_a >= pre_fee_growth_a,
                            "a_to_b swap: fee_growth_a decreased {} -> {}",
                            pre_fee_growth_a, post_pool.fee_growth_global_a);
                        // Output side B: fee_growth_b must not change from swap
                        fuzz_assert_eq!(post_pool.fee_growth_global_b, pre_fee_growth_b,
                            "a_to_b swap: fee_growth_b changed {} -> {} (should be unchanged)",
                            pre_fee_growth_b, post_pool.fee_growth_global_b);
                    } else {
                        // Input side is B: fee_growth_b should increase
                        fuzz_assert!(post_pool.fee_growth_global_b >= pre_fee_growth_b,
                            "b_to_a swap: fee_growth_b decreased {} -> {}",
                            pre_fee_growth_b, post_pool.fee_growth_global_b);
                        // Output side A: fee_growth_a must not change
                        fuzz_assert_eq!(post_pool.fee_growth_global_a, pre_fee_growth_a,
                            "b_to_a swap: fee_growth_a changed {} -> {} (should be unchanged)",
                            pre_fee_growth_a, post_pool.fee_growth_global_a);
                    }
                }

                // Postcondition: fee_rate and protocol_fee_rate must NOT change during swap
                // Only set_fee_rate/set_protocol_fee_rate can change these
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    fuzz_assert_eq!(post_pool.fee_rate, pre_fee_rate,
                        "swap: fee_rate changed {} -> {} (should be immutable during swap)",
                        pre_fee_rate, post_pool.fee_rate);
                    fuzz_assert_eq!(post_pool.protocol_fee_rate, pre_proto_fee_rate,
                        "swap: protocol_fee_rate changed {} -> {} (should be immutable during swap)",
                        pre_proto_fee_rate, post_pool.protocol_fee_rate);
                    // reward_last_updated_timestamp must not decrease during swap
                    fuzz_assert!(post_pool.reward_last_updated_timestamp >= pre_reward_ts,
                        "swap: reward_last_updated_timestamp decreased {} -> {}",
                        pre_reward_ts, post_pool.reward_last_updated_timestamp);
                    // tick/price bracket consistency
                    let lb = harness_sqrt_price_from_tick(post_pool.tick_current_index);
                    let ub = harness_sqrt_price_from_tick(post_pool.tick_current_index + 1);
                    fuzz_assert!(post_pool.sqrt_price >= lb && post_pool.sqrt_price <= ub,
                        "swap: sqrt_price {} not in [{}, {}] for tick {}",
                        post_pool.sqrt_price, lb, ub, post_pool.tick_current_index);
                }

                debug_print!("[SWAP] SUCCESS: {} {} (user {})",
                    if a_to_b { "A->B" } else { "B->A" },
                    amount, user_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SWAP] TX_FAILED: {} amount={} user={}",
                    if a_to_b { "A->B" } else { "B->A" },
                    amount, user_idx);
                for log in logs {
                    debug_print!("[SWAP]   {}", log);
                }
                false
            }
            Err(e) => {
                debug_print!("[SWAP] SEND_FAILED: {} amount={} user={}: {:?}",
                    if a_to_b { "A->B" } else { "B->A" },
                    amount, user_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::SWAP, success);
        success
    }

    // ========================================================================
    // Pool Two Swap Actions
    // ========================================================================

    /// Direct swap on pool two (exercises pool two independently from TwoHopSwap)
    pub fn action_swap_pool_two(
        &mut self,
        #[range(0..3)] user_idx: usize,
        amount: u64,
        a_to_b: bool,
    ) -> bool {
        let pool_two = match &self.pool_two {
            Some(p) => p.clone(),
            None => return false,
        };

        let amount = (amount % 1_000_000) + 1;
        let user = &self.users[user_idx];

        if pool_two.tick_arrays.len() < 3 {
            return false;
        }

        let sqrt_price_limit = if a_to_b { MIN_SQRT_PRICE_X64 } else { MAX_SQRT_PRICE_X64 };

        // Map user token accounts to pool two's mint ordering
        let intermediary_is_pool2_a = pool_two.token_mint_a == self.pool.token_mint_b;
        let (user_account_a, user_account_b) = if intermediary_is_pool2_a {
            (user.token_account_b, user.token_account_c)
        } else {
            (user.token_account_c, user.token_account_b)
        };

        let (tick_array_0, tick_array_1, tick_array_2) = self.get_tick_arrays_for_swap_pool(&pool_two, a_to_b);

        // Pre-swap snapshots for pool two per-swap invariants (Steps 2, 3)
        let p2_vault_a_pre = self.ctx.token_balance(&pool_two.token_vault_a);
        let p2_vault_b_pre = self.ctx.token_balance(&pool_two.token_vault_b);
        let p2_user_a_pre = self.ctx.token_balance(&user_account_a);
        let p2_user_b_pre = self.ctx.token_balance(&user_account_b);
        let p2_price_pre = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
            .ok().map(|s| s.sqrt_price).unwrap_or(0);
        let (p2_pre_proto_a, p2_pre_proto_b, p2_pre_fg_a, p2_pre_fg_b) =
            self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
            .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b,
                       s.fee_growth_global_a, s.fee_growth_global_b))
            .unwrap_or((0, 0, 0, 0));

        let result = self.ctx.program(self.program_id)
            .call(instruction::Swap {
                amount,
                other_amount_threshold: 0,
                sqrt_price_limit,
                amount_specified_is_input: true,
                a_to_b,
            })
            .accounts(accounts::Swap {
                token_authority: user.keypair.pubkey(),
                whirlpool: pool_two.whirlpool,
                token_owner_account_a: user_account_a,
                token_vault_a: pool_two.token_vault_a,
                token_owner_account_b: user_account_b,
                token_vault_b: pool_two.token_vault_b,
                tick_array_0,
                tick_array_1,
                tick_array_2,
                oracle: pool_two.oracle,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Step 2: Per-swap vault balance direction check (pool two)
                let p2_vault_a_post = self.ctx.token_balance(&pool_two.token_vault_a);
                let p2_vault_b_post = self.ctx.token_balance(&pool_two.token_vault_b);
                if a_to_b {
                    fuzz_assert!(p2_vault_a_post >= p2_vault_a_pre,
                        "pool2 a_to_b: vault_a decreased {} -> {}", p2_vault_a_pre, p2_vault_a_post);
                    fuzz_assert!(p2_vault_b_post <= p2_vault_b_pre,
                        "pool2 a_to_b: vault_b increased {} -> {}", p2_vault_b_pre, p2_vault_b_post);
                } else {
                    fuzz_assert!(p2_vault_b_post >= p2_vault_b_pre,
                        "pool2 b_to_a: vault_b decreased {} -> {}", p2_vault_b_pre, p2_vault_b_post);
                    fuzz_assert!(p2_vault_a_post <= p2_vault_a_pre,
                        "pool2 b_to_a: vault_a increased {} -> {}", p2_vault_a_pre, p2_vault_a_post);
                }

                // Step 3: Per-swap price direction check (pool two)
                let p2_price_post = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
                    .ok().map(|s| s.sqrt_price).unwrap_or(0);
                if p2_price_pre > 0 && p2_price_post > 0 {
                    if a_to_b {
                        fuzz_assert!(p2_price_post <= p2_price_pre,
                            "pool2 a_to_b: sqrt_price increased {} -> {}", p2_price_pre, p2_price_post);
                    } else {
                        fuzz_assert!(p2_price_post >= p2_price_pre,
                            "pool2 b_to_a: sqrt_price decreased {} -> {}", p2_price_pre, p2_price_post);
                    }
                }

                // Protocol fee side isolation + fee_rate fraction bound for pool two
                if let Ok(post_p2) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                    let pa = post_p2.protocol_fee_owed_a.saturating_sub(p2_pre_proto_a);
                    let pb = post_p2.protocol_fee_owed_b.saturating_sub(p2_pre_proto_b);
                    let p2_fee_rate = post_p2.fee_rate as u64;
                    if a_to_b {
                        fuzz_assert_eq!(pb, 0, "pool2 a_to_b: protocol_fee_owed_b increased by {}", pb);
                        let input = p2_vault_a_post.saturating_sub(p2_vault_a_pre);
                        fuzz_assert!(pa <= input, "pool2 a_to_b: proto_fee_a ({}) > input ({})", pa, input);
                        if input > 0 && p2_fee_rate > 0 {
                            let max_fee = (input as u128) * (p2_fee_rate as u128) / 1_000_000 + 100;
                            fuzz_assert!((pa as u128) <= max_fee,
                                "pool2 a_to_b: proto_fee {} > max_fee {} (input={} rate={})", pa, max_fee, input, p2_fee_rate);
                        }
                    } else {
                        fuzz_assert_eq!(pa, 0, "pool2 b_to_a: protocol_fee_owed_a increased by {}", pa);
                        let input = p2_vault_b_post.saturating_sub(p2_vault_b_pre);
                        fuzz_assert!(pb <= input, "pool2 b_to_a: proto_fee_b ({}) > input ({})", pb, input);
                        if input > 0 && p2_fee_rate > 0 {
                            let max_fee = (input as u128) * (p2_fee_rate as u128) / 1_000_000 + 100;
                            fuzz_assert!((pb as u128) <= max_fee,
                                "pool2 b_to_a: proto_fee {} > max_fee {} (input={} rate={})", pb, max_fee, input, p2_fee_rate);
                        }
                    }
                }

                // Fee_growth side isolation for pool two
                if let Ok(post_p2) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                    if a_to_b {
                        fuzz_assert!(post_p2.fee_growth_global_a >= p2_pre_fg_a,
                            "pool2 a_to_b: fee_growth_a decreased {} -> {}", p2_pre_fg_a, post_p2.fee_growth_global_a);
                        fuzz_assert_eq!(post_p2.fee_growth_global_b, p2_pre_fg_b,
                            "pool2 a_to_b: fee_growth_b changed {} -> {}", p2_pre_fg_b, post_p2.fee_growth_global_b);
                    } else {
                        fuzz_assert!(post_p2.fee_growth_global_b >= p2_pre_fg_b,
                            "pool2 b_to_a: fee_growth_b decreased {} -> {}", p2_pre_fg_b, post_p2.fee_growth_global_b);
                        fuzz_assert_eq!(post_p2.fee_growth_global_a, p2_pre_fg_a,
                            "pool2 b_to_a: fee_growth_a changed {} -> {}", p2_pre_fg_a, post_p2.fee_growth_global_a);
                    }
                }

                // Per-swap user-vault transfer conservation (pool two)
                {
                    let p2_user_a_post = self.ctx.token_balance(&user_account_a);
                    let p2_user_b_post = self.ctx.token_balance(&user_account_b);
                    let va_d = (p2_vault_a_post as i128) - (p2_vault_a_pre as i128);
                    let ua_d = (p2_user_a_post as i128) - (p2_user_a_pre as i128);
                    fuzz_assert_eq!(va_d, -ua_d,
                        "pool2 swap: token A vault_delta ({}) != -user_delta ({})", va_d, -ua_d);
                    let vb_d = (p2_vault_b_post as i128) - (p2_vault_b_pre as i128);
                    let ub_d = (p2_user_b_post as i128) - (p2_user_b_pre as i128);
                    fuzz_assert_eq!(vb_d, -ub_d,
                        "pool2 swap: token B vault_delta ({}) != -user_delta ({})", vb_d, -ub_d);
                }

                debug_print!("[SWAP_POOL_TWO] SUCCESS: {} amount={} user={}",
                    if a_to_b { "A->B" } else { "B->A" }, amount, user_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SWAP_POOL_TWO] TX_FAILED: {} amount={} user={}",
                    if a_to_b { "A->B" } else { "B->A" }, amount, user_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SWAP_POOL_TWO] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::SWAP_POOL_TWO, success);
        success
    }

    /// Exact-out swap on pool two (exercises ExactOut code path with different tick layout)
    pub fn action_exact_out_swap_pool_two(
        &mut self,
        #[range(0..3)] user_idx: usize,
        amount: u64,
        a_to_b: bool,
    ) -> bool {
        let pool_two = match &self.pool_two {
            Some(p) => p.clone(),
            None => return false,
        };

        let amount = (amount % 500_000) + 1; // Smaller amounts for exact-out
        let user = &self.users[user_idx];

        if pool_two.tick_arrays.len() < 3 {
            return false;
        }

        let sqrt_price_limit = if a_to_b { MIN_SQRT_PRICE_X64 } else { MAX_SQRT_PRICE_X64 };

        // Map user token accounts to pool two's mint ordering
        let intermediary_is_pool2_a = pool_two.token_mint_a == self.pool.token_mint_b;
        let (user_account_a, user_account_b) = if intermediary_is_pool2_a {
            (user.token_account_b, user.token_account_c)
        } else {
            (user.token_account_c, user.token_account_b)
        };

        let (tick_array_0, tick_array_1, tick_array_2) = self.get_tick_arrays_for_swap_pool(&pool_two, a_to_b);

        // Pre-swap snapshots for per-swap invariants
        let p2_vault_a_pre = self.ctx.token_balance(&pool_two.token_vault_a);
        let p2_vault_b_pre = self.ctx.token_balance(&pool_two.token_vault_b);
        let p2_price_pre = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
            .ok().map(|s| s.sqrt_price).unwrap_or(0);
        let user_a_pre = self.ctx.token_balance(&user_account_a);
        let user_b_pre = self.ctx.token_balance(&user_account_b);
        let (p2_eo_pre_proto_a, p2_eo_pre_proto_b) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
            .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b))
            .unwrap_or((0, 0));

        let result = self.ctx.program(self.program_id)
            .call(instruction::Swap {
                amount,
                other_amount_threshold: u64::MAX, // No slippage limit for exact-out
                sqrt_price_limit,
                amount_specified_is_input: false,
                a_to_b,
            })
            .accounts(accounts::Swap {
                token_authority: user.keypair.pubkey(),
                whirlpool: pool_two.whirlpool,
                token_owner_account_a: user_account_a,
                token_vault_a: pool_two.token_vault_a,
                token_owner_account_b: user_account_b,
                token_vault_b: pool_two.token_vault_b,
                tick_array_0,
                tick_array_1,
                tick_array_2,
                oracle: pool_two.oracle,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Per-swap vault balance direction check (pool two)
                let p2_vault_a_post = self.ctx.token_balance(&pool_two.token_vault_a);
                let p2_vault_b_post = self.ctx.token_balance(&pool_two.token_vault_b);
                if a_to_b {
                    fuzz_assert!(p2_vault_a_post >= p2_vault_a_pre,
                        "pool2 exact-out a_to_b: vault_a decreased {} -> {}", p2_vault_a_pre, p2_vault_a_post);
                    fuzz_assert!(p2_vault_b_post <= p2_vault_b_pre,
                        "pool2 exact-out a_to_b: vault_b increased {} -> {}", p2_vault_b_pre, p2_vault_b_post);
                } else {
                    fuzz_assert!(p2_vault_b_post >= p2_vault_b_pre,
                        "pool2 exact-out b_to_a: vault_b decreased {} -> {}", p2_vault_b_pre, p2_vault_b_post);
                    fuzz_assert!(p2_vault_a_post <= p2_vault_a_pre,
                        "pool2 exact-out b_to_a: vault_a increased {} -> {}", p2_vault_a_pre, p2_vault_a_post);
                }

                // Per-swap price direction check (pool two)
                let p2_price_post = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
                    .ok().map(|s| s.sqrt_price).unwrap_or(0);
                if p2_price_pre > 0 && p2_price_post > 0 {
                    if a_to_b {
                        fuzz_assert!(p2_price_post <= p2_price_pre,
                            "pool2 exact-out a_to_b: sqrt_price increased {} -> {}", p2_price_pre, p2_price_post);
                    } else {
                        fuzz_assert!(p2_price_post >= p2_price_pre,
                            "pool2 exact-out b_to_a: sqrt_price decreased {} -> {}", p2_price_pre, p2_price_post);
                    }
                }

                // Exact-out output verification: user must receive tokens
                // a_to_b: output is token_b (user_b increases)
                // b_to_a: output is token_a (user_a increases)
                let user_a_post = self.ctx.token_balance(&user_account_a);
                let user_b_post = self.ctx.token_balance(&user_account_b);
                let received_output = if a_to_b {
                    user_b_post.saturating_sub(user_b_pre)
                } else {
                    user_a_post.saturating_sub(user_a_pre)
                };
                fuzz_assert!(received_output > 0,
                    "Pool2 exact-out swap succeeded but received 0 tokens (requested={})", amount);
                // Exact-out: received should not exceed requested
                fuzz_assert!(received_output <= amount,
                    "Pool2 exact-out over-delivered: received {} > requested {} (a_to_b={})",
                    received_output, amount, a_to_b);

                // Protocol fee side isolation + fee_rate fraction bound for exact-out pool two
                if let Ok(post_p2) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                    let pa = post_p2.protocol_fee_owed_a.saturating_sub(p2_eo_pre_proto_a);
                    let pb = post_p2.protocol_fee_owed_b.saturating_sub(p2_eo_pre_proto_b);
                    let p2_fee_rate = post_p2.fee_rate as u64;
                    if a_to_b {
                        fuzz_assert_eq!(pb, 0, "p2 exact-out a_to_b: protocol_fee_owed_b increased by {}", pb);
                        let input = p2_vault_a_post.saturating_sub(p2_vault_a_pre);
                        fuzz_assert!(pa <= input, "p2 exact-out a_to_b: proto_fee_a ({}) > input ({})", pa, input);
                        if input > 0 && p2_fee_rate > 0 {
                            let max_fee = (input as u128) * (p2_fee_rate as u128) / 1_000_000 + 100;
                            fuzz_assert!((pa as u128) <= max_fee,
                                "p2 exact-out a_to_b: proto_fee {} > max_fee {} (input={} rate={})", pa, max_fee, input, p2_fee_rate);
                        }
                    } else {
                        fuzz_assert_eq!(pa, 0, "p2 exact-out b_to_a: protocol_fee_owed_a increased by {}", pa);
                        let input = p2_vault_b_post.saturating_sub(p2_vault_b_pre);
                        fuzz_assert!(pb <= input, "p2 exact-out b_to_a: proto_fee_b ({}) > input ({})", pb, input);
                        if input > 0 && p2_fee_rate > 0 {
                            let max_fee = (input as u128) * (p2_fee_rate as u128) / 1_000_000 + 100;
                            fuzz_assert!((pb as u128) <= max_fee,
                                "p2 exact-out b_to_a: proto_fee {} > max_fee {} (input={} rate={})", pb, max_fee, input, p2_fee_rate);
                        }
                    }
                }

                // Per-swap user-vault transfer conservation (exact-out pool two)
                {
                    let va_d = (p2_vault_a_post as i128) - (p2_vault_a_pre as i128);
                    let ua_d = (user_a_post as i128) - (user_a_pre as i128);
                    fuzz_assert_eq!(va_d, -ua_d,
                        "p2 exact-out: token A vault_delta ({}) != -user_delta ({})", va_d, -ua_d);
                    let vb_d = (p2_vault_b_post as i128) - (p2_vault_b_pre as i128);
                    let ub_d = (user_b_post as i128) - (user_b_pre as i128);
                    fuzz_assert_eq!(vb_d, -ub_d,
                        "p2 exact-out: token B vault_delta ({}) != -user_delta ({})", vb_d, -ub_d);
                }

                debug_print!("[EXACT_OUT_P2] SUCCESS: {} amount={} user={}",
                    if a_to_b { "A->B" } else { "B->A" }, amount, user_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[EXACT_OUT_P2] TX_FAILED: {} amount={} user={}",
                    if a_to_b { "A->B" } else { "B->A" }, amount, user_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[EXACT_OUT_P2] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::EXACT_OUT_SWAP_POOL_TWO, success);
        success
    }

    // ========================================================================
    // Swap V2 Actions (Token-2022 code paths)
    // ========================================================================

    /// V2 swap on pool one (exercises Token-2022 code path with memo program)
    pub fn action_swap_v2(
        &mut self,
        #[range(0..3)] user_idx: usize,
        amount: u64,
        a_to_b: bool,
    ) -> bool {
        let amount = (amount % 1_000_000) + 1;
        self.do_swap_v2(user_idx, amount, a_to_b)
    }

    fn do_swap_v2(
        &mut self,
        user_idx: usize,
        amount: u64,
        a_to_b: bool,
    ) -> bool {
        self.total_swaps += 1;

        let user = &self.users[user_idx];
        let pool = &self.pool;

        if pool.tick_arrays.len() < 3 {
            return false;
        }

        let sqrt_price_limit = if a_to_b { MIN_SQRT_PRICE_X64 } else { MAX_SQRT_PRICE_X64 };
        let (tick_array_0, tick_array_1, tick_array_2) = self.get_tick_arrays_for_swap(a_to_b);

        // Pre-swap snapshots for per-swap invariants
        let vault_a_pre = self.ctx.token_balance(&pool.token_vault_a);
        let vault_b_pre = self.ctx.token_balance(&pool.token_vault_b);
        let user_a_pre = self.ctx.token_balance(&user.token_account_a);
        let user_b_pre = self.ctx.token_balance(&user.token_account_b);
        let price_pre = self.read_pool_sqrt_price().unwrap_or(0);
        let (pre_proto_fee_a, pre_proto_fee_b, pre_fg_a_v2, pre_fg_b_v2,
             pre_fee_rate_v2, pre_proto_rate_v2, pre_reward_ts_v2) =
            self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool.whirlpool)
            .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b,
                       s.fee_growth_global_a, s.fee_growth_global_b,
                       s.fee_rate, s.protocol_fee_rate, s.reward_last_updated_timestamp))
            .unwrap_or((0, 0, 0, 0, 0, 0, 0));

        let result = self.ctx.program(self.program_id)
            .call(instruction::SwapV2 {
                amount,
                other_amount_threshold: 0,
                sqrt_price_limit,
                amount_specified_is_input: true,
                a_to_b,
                remaining_accounts_info: None,
            })
            .accounts(accounts::SwapV2 {
                token_program_a: spl_token::ID,
                token_program_b: spl_token::ID,

                token_authority: user.keypair.pubkey(),
                whirlpool: pool.whirlpool,
                token_mint_a: pool.token_mint_a,
                token_mint_b: pool.token_mint_b,
                token_owner_account_a: user.token_account_a,
                token_vault_a: pool.token_vault_a,
                token_owner_account_b: user.token_account_b,
                token_vault_b: pool.token_vault_b,
                tick_array_0,
                tick_array_1,
                tick_array_2,
                oracle: pool.oracle,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.successful_swaps += 1;

                // Per-swap vault balance direction check
                let vault_a_post = self.ctx.token_balance(&self.pool.token_vault_a);
                let vault_b_post = self.ctx.token_balance(&self.pool.token_vault_b);
                if a_to_b {
                    fuzz_assert!(vault_a_post >= vault_a_pre,
                        "swap_v2 a_to_b: vault_a decreased {} -> {}", vault_a_pre, vault_a_post);
                    fuzz_assert!(vault_b_post <= vault_b_pre,
                        "swap_v2 a_to_b: vault_b increased {} -> {}", vault_b_pre, vault_b_post);
                } else {
                    fuzz_assert!(vault_b_post >= vault_b_pre,
                        "swap_v2 b_to_a: vault_b decreased {} -> {}", vault_b_pre, vault_b_post);
                    fuzz_assert!(vault_a_post <= vault_a_pre,
                        "swap_v2 b_to_a: vault_a increased {} -> {}", vault_a_pre, vault_a_post);
                }

                // Per-swap price direction check
                let price_post = self.read_pool_sqrt_price().unwrap_or(0);
                if price_pre > 0 && price_post > 0 {
                    if a_to_b {
                        fuzz_assert!(price_post <= price_pre,
                            "swap_v2 a_to_b: sqrt_price increased {} -> {}", price_pre, price_post);
                    } else {
                        fuzz_assert!(price_post >= price_pre,
                            "swap_v2 b_to_a: sqrt_price decreased {} -> {}", price_pre, price_post);
                    }
                }

                // Protocol fee side isolation + bounded by input + fee_rate fraction
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    let proto_a_delta = post_pool.protocol_fee_owed_a.saturating_sub(pre_proto_fee_a);
                    let proto_b_delta = post_pool.protocol_fee_owed_b.saturating_sub(pre_proto_fee_b);
                    let fee_rate = post_pool.fee_rate as u64;
                    if a_to_b {
                        fuzz_assert_eq!(proto_b_delta, 0,
                            "swap_v2 a_to_b: protocol_fee_owed_b increased by {}", proto_b_delta);
                        let vault_a_input = vault_a_post.saturating_sub(vault_a_pre);
                        fuzz_assert!(proto_a_delta <= vault_a_input,
                            "swap_v2 a_to_b: proto_fee_a ({}) > vault_a_input ({})", proto_a_delta, vault_a_input);
                        if vault_a_input > 0 && fee_rate > 0 {
                            let max_fee = (vault_a_input as u128) * (fee_rate as u128) / 1_000_000 + 100;
                            fuzz_assert!((proto_a_delta as u128) <= max_fee,
                                "swap_v2 a_to_b: proto_fee {} > max_fee {} (input={} rate={})",
                                proto_a_delta, max_fee, vault_a_input, fee_rate);
                        }
                    } else {
                        fuzz_assert_eq!(proto_a_delta, 0,
                            "swap_v2 b_to_a: protocol_fee_owed_a increased by {}", proto_a_delta);
                        let vault_b_input = vault_b_post.saturating_sub(vault_b_pre);
                        fuzz_assert!(proto_b_delta <= vault_b_input,
                            "swap_v2 b_to_a: proto_fee_b ({}) > vault_b_input ({})", proto_b_delta, vault_b_input);
                        if vault_b_input > 0 && fee_rate > 0 {
                            let max_fee = (vault_b_input as u128) * (fee_rate as u128) / 1_000_000 + 100;
                            fuzz_assert!((proto_b_delta as u128) <= max_fee,
                                "swap_v2 b_to_a: proto_fee {} > max_fee {} (input={} rate={})",
                                proto_b_delta, max_fee, vault_b_input, fee_rate);
                        }
                    }
                }

                // Fee_growth side isolation for swap_v2
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    if a_to_b {
                        fuzz_assert!(post_pool.fee_growth_global_a >= pre_fg_a_v2,
                            "swap_v2 a_to_b: fee_growth_a decreased {} -> {}", pre_fg_a_v2, post_pool.fee_growth_global_a);
                        fuzz_assert_eq!(post_pool.fee_growth_global_b, pre_fg_b_v2,
                            "swap_v2 a_to_b: fee_growth_b changed {} -> {}", pre_fg_b_v2, post_pool.fee_growth_global_b);
                    } else {
                        fuzz_assert!(post_pool.fee_growth_global_b >= pre_fg_b_v2,
                            "swap_v2 b_to_a: fee_growth_b decreased {} -> {}", pre_fg_b_v2, post_pool.fee_growth_global_b);
                        fuzz_assert_eq!(post_pool.fee_growth_global_a, pre_fg_a_v2,
                            "swap_v2 b_to_a: fee_growth_a changed {} -> {}", pre_fg_a_v2, post_pool.fee_growth_global_a);
                    }
                }

                // Per-swap user-vault transfer conservation (swap_v2)
                {
                    let user_a_post = self.ctx.token_balance(&self.users[user_idx].token_account_a);
                    let user_b_post = self.ctx.token_balance(&self.users[user_idx].token_account_b);
                    let va_delta = (vault_a_post as i128) - (vault_a_pre as i128);
                    let ua_delta = (user_a_post as i128) - (user_a_pre as i128);
                    fuzz_assert_eq!(va_delta, -ua_delta,
                        "swap_v2: token A vault_delta ({}) != -user_delta ({})", va_delta, -ua_delta);
                    let vb_delta = (vault_b_post as i128) - (vault_b_pre as i128);
                    let ub_delta = (user_b_post as i128) - (user_b_pre as i128);
                    fuzz_assert_eq!(vb_delta, -ub_delta,
                        "swap_v2: token B vault_delta ({}) != -user_delta ({})", vb_delta, -ub_delta);

                    // Consumed <= amount (exact-input, always true for swap_v2)
                    let consumed = if a_to_b {
                        user_a_pre.saturating_sub(user_a_post)
                    } else {
                        user_b_pre.saturating_sub(user_b_post)
                    };
                    fuzz_assert!(consumed <= amount,
                        "swap_v2: consumed {} > specified amount {}", consumed, amount);
                }

                // fee_rate, protocol_fee_rate immutability + reward_timestamp monotonicity + tick/price consistency
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    fuzz_assert_eq!(post_pool.fee_rate, pre_fee_rate_v2,
                        "swap_v2: fee_rate changed {} -> {}", pre_fee_rate_v2, post_pool.fee_rate);
                    fuzz_assert_eq!(post_pool.protocol_fee_rate, pre_proto_rate_v2,
                        "swap_v2: protocol_fee_rate changed {} -> {}", pre_proto_rate_v2, post_pool.protocol_fee_rate);
                    fuzz_assert!(post_pool.reward_last_updated_timestamp >= pre_reward_ts_v2,
                        "swap_v2: reward_timestamp decreased {} -> {}",
                        pre_reward_ts_v2, post_pool.reward_last_updated_timestamp);
                    // tick/price bracket consistency
                    let lb = harness_sqrt_price_from_tick(post_pool.tick_current_index);
                    let ub = harness_sqrt_price_from_tick(post_pool.tick_current_index + 1);
                    fuzz_assert!(post_pool.sqrt_price >= lb && post_pool.sqrt_price <= ub,
                        "swap_v2: sqrt_price {} not in [{}, {}] for tick {}",
                        post_pool.sqrt_price, lb, ub, post_pool.tick_current_index);
                }

                debug_print!("[SWAP_V2] SUCCESS: {} {} (user {})",
                    if a_to_b { "A->B" } else { "B->A" }, amount, user_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SWAP_V2] TX_FAILED: {} amount={} user={}",
                    if a_to_b { "A->B" } else { "B->A" }, amount, user_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SWAP_V2] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::SWAP_V2, success);
        success
    }
