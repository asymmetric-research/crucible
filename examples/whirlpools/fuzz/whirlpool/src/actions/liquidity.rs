// actions/liquidity.rs — Liquidity action methods (included in impl WhirlpoolFixture via include!())

    // ========================================================================
    // Pool One: Increase / Decrease Liquidity (V1)
    // ========================================================================

    pub fn action_increase_liquidity(
        &mut self,
        #[range(0..5)] position_idx: usize,
        liquidity_amount: u64,  // Use u64 for arbitrary compatibility
    ) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }

        let liquidity_amount = ((liquidity_amount % 1_000_000_000) + 1000) as u128; // Min 1000
        self.do_increase_liquidity(position_idx, liquidity_amount)
    }

    /// Add very large liquidity (edge case - near u128 overflow regions)
    pub fn action_massive_liquidity(
        &mut self,
        #[range(0..5)] position_idx: usize,
    ) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }

        // Very large liquidity: 10^18 (1 quintillion)
        let liquidity_amount = 1_000_000_000_000_000_000u128;
        self.do_increase_liquidity(position_idx, liquidity_amount)
    }

    /// Add minimum liquidity (edge case)
    pub fn action_tiny_liquidity(
        &mut self,
        #[range(0..5)] position_idx: usize,
    ) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }

        self.do_increase_liquidity(position_idx, 1)
    }

    fn do_increase_liquidity(&mut self, position_idx: usize, liquidity_amount: u128) -> bool {
        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];
        let pool = &self.pool;

        // Pre-check: user must have non-zero balance for at least one token
        let bal_a = self.ctx.token_balance(&user.token_account_a);
        let bal_b = self.ctx.token_balance(&user.token_account_b);
        if bal_a == 0 && bal_b == 0 {
            return false;
        }

        // Pre-check: tick arrays must exist (not just fallback)
        let target_lower = self.get_start_tick_index(position.tick_lower_index);
        let target_upper = self.get_start_tick_index(position.tick_upper_index);
        let has_lower = pool.tick_arrays.iter().any(|(s, _)| *s == target_lower);
        let has_upper = pool.tick_arrays.iter().any(|(s, _)| *s == target_upper);
        if !has_lower || !has_upper {
            return false;
        }

        // Snapshot pre-state for postcondition checks
        let pre_vault_a = self.ctx.token_balance(&pool.token_vault_a);
        let pre_vault_b = self.ctx.token_balance(&pool.token_vault_b);
        let pre_user_a = self.ctx.token_balance(&user.token_account_a);
        let pre_user_b = self.ctx.token_balance(&user.token_account_b);
        let (pre_liquidity, pre_fee_owed_a_inc, pre_fee_owed_b_inc) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&position.position)
            .map(|s| (s.liquidity, s.fee_owed_a, s.fee_owed_b))
            .unwrap_or((0, 0, 0));
        let (pre_pool_liquidity, pre_pool_tick, pre_sqrt_price) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool.whirlpool)
            .map(|s| (s.liquidity, s.tick_current_index, s.sqrt_price))
            .unwrap_or((0, 0, 0));

        // Get tick arrays for position's tick range
        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        let result = self.ctx.program(self.program_id)
            .call(instruction::IncreaseLiquidity {
                liquidity_amount,
                token_max_a: u64::MAX,
                token_max_b: u64::MAX,
            })
            .accounts(accounts::IncreaseLiquidity {
                whirlpool: pool.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_owner_account_a: user.token_account_a,
                token_owner_account_b: user.token_account_b,
                token_vault_a: pool.token_vault_a,
                token_vault_b: pool.token_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: position liquidity increased by exact amount
                if let Ok(post_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
                    let expected = pre_liquidity + liquidity_amount;
                    fuzz_assert_eq!(post_state.liquidity, expected,
                        "increase_liquidity postcondition: pos {} liquidity {} != expected {} (pre={} + delta={})",
                        position_idx, post_state.liquidity, expected, pre_liquidity, liquidity_amount);
                }
                // Postcondition: pool.liquidity coupling — in-range positions change pool liquidity
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    let pos = &self.positions[position_idx];
                    let in_range = pos.tick_lower_index <= pre_pool_tick && pre_pool_tick < pos.tick_upper_index;
                    if in_range {
                        let expected_pool_liq = pre_pool_liquidity + liquidity_amount;
                        fuzz_assert_eq!(post_pool.liquidity, expected_pool_liq,
                            "increase_liq: in-range pos {} but pool liq {} != expected {} (pre={} + delta={})",
                            position_idx, post_pool.liquidity, expected_pool_liq, pre_pool_liquidity, liquidity_amount);
                    } else {
                        fuzz_assert_eq!(post_pool.liquidity, pre_pool_liquidity,
                            "increase_liq: out-of-range pos {} changed pool liq {} -> {}",
                            position_idx, pre_pool_liquidity, post_pool.liquidity);
                    }
                }
                // Postcondition: sqrt_price and tick_current_index must NOT change during liquidity ops
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    fuzz_assert_eq!(post_pool.sqrt_price, pre_sqrt_price,
                        "increase_liq: sqrt_price changed {} -> {} (must be immutable during liquidity ops)",
                        pre_sqrt_price, post_pool.sqrt_price);
                    fuzz_assert_eq!(post_pool.tick_current_index, pre_pool_tick,
                        "increase_liq: tick_current_index changed {} -> {} (must be immutable during liquidity ops)",
                        pre_pool_tick, post_pool.tick_current_index);
                }
                // Postcondition: fee_owed monotonicity — increase_liquidity triggers fee checkpoint,
                // which can only add to fee_owed (wrapping_add of non-negative delta)
                if let Ok(post_pos) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
                    fuzz_assert!(post_pos.fee_owed_a >= pre_fee_owed_a_inc,
                        "increase_liq: fee_owed_a decreased {} -> {} (checkpoint should only accrue)",
                        pre_fee_owed_a_inc, post_pos.fee_owed_a);
                    fuzz_assert!(post_pos.fee_owed_b >= pre_fee_owed_b_inc,
                        "increase_liq: fee_owed_b decreased {} -> {} (checkpoint should only accrue)",
                        pre_fee_owed_b_inc, post_pos.fee_owed_b);
                }
                // Postcondition: vault increase == user decrease (exact token transfer conservation)
                let post_vault_a = self.ctx.token_balance(&self.pool.token_vault_a);
                let post_vault_b = self.ctx.token_balance(&self.pool.token_vault_b);
                let post_user_a = self.ctx.token_balance(&self.users[self.positions[position_idx].owner_idx].token_account_a);
                let post_user_b = self.ctx.token_balance(&self.users[self.positions[position_idx].owner_idx].token_account_b);
                let vault_delta_a = post_vault_a.saturating_sub(pre_vault_a);
                let vault_delta_b = post_vault_b.saturating_sub(pre_vault_b);
                let user_delta_a = pre_user_a.saturating_sub(post_user_a);
                let user_delta_b = pre_user_b.saturating_sub(post_user_b);
                fuzz_assert_eq!(vault_delta_a, user_delta_a,
                    "increase_liq: vault_a delta ({}) != user_a delta ({})",
                    vault_delta_a, user_delta_a);
                fuzz_assert_eq!(vault_delta_b, user_delta_b,
                    "increase_liq: vault_b delta ({}) != user_b delta ({})",
                    vault_delta_b, user_delta_b);

                // ----------------------------------------------------------------
                // CETUS-STYLE FREE LIQUIDITY MINT DETECTION
                // ----------------------------------------------------------------
                // Cetus (May 2025, ~$223M loss): `checked_shlw` had wrong overflow
                // mask, letting attackers mint huge liquidity for ~0 tokens. The
                // INTERNAL liquidity math can silently return a near-zero amount
                // for a huge L, bypassing the vault_delta == user_delta check
                // (both would be 0). This invariant independently bounds the
                // required token amounts from L using Whirlpool's own math formulas.
                //
                // Whirlpool formulas (from math/token_math.rs):
                //   amount_a = L × (√upper − √current) × 2^64 / (√current × √upper)  (above-tick contribution)
                //   amount_b = L × (√current − √lower) / 2^64                         (below-tick contribution)
                //
                // For a non-trivial L and non-degenerate range, at least one of
                // these must be strictly positive. A zero-token mint of positive
                // liquidity is a direct free-mint exploit signal.
                if liquidity_amount >= 1_000_000 {
                    let pos = &self.positions[position_idx];
                    let sqrt_lower = harness_sqrt_price_from_tick(pos.tick_lower_index);
                    let sqrt_upper = harness_sqrt_price_from_tick(pos.tick_upper_index);
                    let sqrt_current = pre_sqrt_price;
                    let in_range = pos.tick_lower_index <= pre_pool_tick && pre_pool_tick < pos.tick_upper_index;
                    let above_range = pre_pool_tick >= pos.tick_upper_index;
                    let below_range = pre_pool_tick < pos.tick_lower_index;

                    // For an in-range position with non-degenerate range,
                    // at least one vault delta MUST be non-zero.
                    if in_range && sqrt_upper > sqrt_lower && sqrt_current > 0 {
                        let both_zero = vault_delta_a == 0 && vault_delta_b == 0;
                        fuzz_assert!(!both_zero,
                            "CETUS-STYLE FREE MINT: in-range pos {} minted L={} (ticks=[{},{}] cur={}) but deposited 0 tokens in both vaults",
                            position_idx, liquidity_amount, pos.tick_lower_index, pos.tick_upper_index, pre_pool_tick);

                        // Additional: compute expected token_b lower bound and compare
                        // amount_b >= L × (√current − √lower) / 2^64
                        // Use saturating math; only check when no overflow possible
                        if sqrt_current > sqrt_lower {
                            let sqrt_diff_b = sqrt_current - sqrt_lower;
                            // Guard against overflow: only check when L × diff fits in u128
                            if sqrt_diff_b > 0 && liquidity_amount <= u128::MAX / sqrt_diff_b.max(1) {
                                let expected_b_min = (liquidity_amount.saturating_mul(sqrt_diff_b)) >> 64;
                                // Apply ~10% safety margin + 100 token absolute floor for rounding
                                let required_b = expected_b_min.saturating_mul(9) / 10;
                                if required_b > 100 {
                                    fuzz_assert!((vault_delta_b as u128) + 100 >= required_b,
                                        "CETUS-STYLE: in-range pos {} L={} needs vault_b>={} got {} (ticks=[{},{}])",
                                        position_idx, liquidity_amount, required_b, vault_delta_b,
                                        pos.tick_lower_index, pos.tick_upper_index);
                                }
                            }
                        }
                    } else if below_range && sqrt_upper > sqrt_lower {
                        // Below range → only token_a needed, token_b must be 0.
                        // If vault_delta_a is 0 for L > 1M, it's a free mint.
                        fuzz_assert!(vault_delta_a > 0,
                            "CETUS-STYLE FREE MINT: below-range pos {} L={} but vault_a delta=0 (ticks=[{},{}])",
                            position_idx, liquidity_amount, pos.tick_lower_index, pos.tick_upper_index);
                        fuzz_assert_eq!(vault_delta_b, 0u64,
                            "below-range pos {} erroneously took token_b delta={}", position_idx, vault_delta_b);
                    } else if above_range && sqrt_upper > sqrt_lower {
                        // Above range → only token_b needed, token_a must be 0.
                        fuzz_assert!(vault_delta_b > 0,
                            "CETUS-STYLE FREE MINT: above-range pos {} L={} but vault_b delta=0 (ticks=[{},{}])",
                            position_idx, liquidity_amount, pos.tick_lower_index, pos.tick_upper_index);
                        fuzz_assert_eq!(vault_delta_a, 0u64,
                            "above-range pos {} erroneously took token_a delta={}", position_idx, vault_delta_a);
                    }
                }

                self.total_liquidity_added += liquidity_amount;
                self.positions[position_idx].has_liquidity = true;
                debug_print!("[INCREASE_LIQ] SUCCESS: pos={} liq={}", position_idx, liquidity_amount);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[INCREASE_LIQ] TX_FAILED: pos={} liq={}", position_idx, liquidity_amount);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[INCREASE_LIQ] SEND_FAILED: pos={} liq={}: {:?}", position_idx, liquidity_amount, e);
                false
            }
        };
        action_stats::record(&action_stats::INCREASE_LIQUIDITY, success);
        success
    }

    /// Decrease liquidity from an existing position
    pub fn action_decrease_liquidity(
        &mut self,
        #[range(0..5)] position_idx: usize,
        liquidity_amount: u64,  // Use u64 for arbitrary compatibility
    ) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }

        // Only try to decrease if position has liquidity
        if !self.positions[position_idx].has_liquidity {
            return false;
        }

        // Read on-chain liquidity to ensure valid amount (avoids LiquidityUnderflow errors)
        let on_chain_liquidity = match self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
            Ok(pos_state) => pos_state.liquidity,
            Err(_) => return false,
        };
        if on_chain_liquidity == 0 {
            self.positions[position_idx].has_liquidity = false;
            return false;
        }

        let liquidity_amount = ((liquidity_amount as u128) % on_chain_liquidity) + 1;
        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];
        let pool = &self.pool;

        // Pre-snapshot for pool liquidity coupling postcondition
        let (pre_pool_liquidity, pre_pool_tick, pre_sqrt_price_dec) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool.whirlpool)
            .map(|s| (s.liquidity, s.tick_current_index, s.sqrt_price))
            .unwrap_or((0, 0, 0));

        // Pre-snapshot for fee_owed monotonicity during decrease_liquidity
        let (pre_fee_owed_a, pre_fee_owed_b) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position)
            .map(|p| (p.fee_owed_a, p.fee_owed_b))
            .unwrap_or((0, 0));

        // Pre-snapshot for token transfer conservation postcondition
        let pre_vault_a = self.ctx.token_balance(&pool.token_vault_a);
        let pre_vault_b = self.ctx.token_balance(&pool.token_vault_b);
        let pre_user_a = self.ctx.token_balance(&user.token_account_a);
        let pre_user_b = self.ctx.token_balance(&user.token_account_b);

        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        let result = self.ctx.program(self.program_id)
            .call(instruction::DecreaseLiquidity {
                liquidity_amount,
                token_min_a: 0,
                token_min_b: 0,
            })
            .accounts(accounts::DecreaseLiquidity {
                whirlpool: pool.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_owner_account_a: user.token_account_a,
                token_owner_account_b: user.token_account_b,
                token_vault_a: pool.token_vault_a,
                token_vault_b: pool.token_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: position liquidity decreased by exact amount
                if let Ok(post_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
                    let expected = on_chain_liquidity - liquidity_amount;
                    fuzz_assert_eq!(post_state.liquidity, expected,
                        "decrease_liquidity postcondition: pos {} liquidity {} != expected {} (pre={} - delta={})",
                        position_idx, post_state.liquidity, expected, on_chain_liquidity, liquidity_amount);
                    self.positions[position_idx].has_liquidity = post_state.liquidity > 0;
                }
                // Postcondition: pool.liquidity coupling — in-range decrease should reduce pool liquidity
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    let pos = &self.positions[position_idx];
                    let in_range = pos.tick_lower_index <= pre_pool_tick && pre_pool_tick < pos.tick_upper_index;
                    if in_range {
                        let expected_pool_liq = pre_pool_liquidity - liquidity_amount;
                        fuzz_assert_eq!(post_pool.liquidity, expected_pool_liq,
                            "decrease_liq: in-range pos {} but pool liq {} != expected {} (pre={} - delta={})",
                            position_idx, post_pool.liquidity, expected_pool_liq, pre_pool_liquidity, liquidity_amount);
                    } else {
                        fuzz_assert_eq!(post_pool.liquidity, pre_pool_liquidity,
                            "decrease_liq: out-of-range pos {} changed pool liq {} -> {}",
                            position_idx, pre_pool_liquidity, post_pool.liquidity);
                    }
                }
                // Postcondition: sqrt_price and tick must NOT change during liquidity ops
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    fuzz_assert_eq!(post_pool.sqrt_price, pre_sqrt_price_dec,
                        "decrease_liq: sqrt_price changed {} -> {} (must be immutable during liquidity ops)",
                        pre_sqrt_price_dec, post_pool.sqrt_price);
                    fuzz_assert_eq!(post_pool.tick_current_index, pre_pool_tick,
                        "decrease_liq: tick_current_index changed {} -> {} (must be immutable during liquidity ops)",
                        pre_pool_tick, post_pool.tick_current_index);
                }
                // Postcondition: fee_owed monotonicity — decrease_liquidity triggers fee checkpoint,
                // which can only add to fee_owed (wrapping_add of non-negative delta)
                if let Ok(post_pos) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
                    fuzz_assert!(post_pos.fee_owed_a >= pre_fee_owed_a,
                        "decrease_liq: fee_owed_a decreased {} -> {} (checkpoint should only accrue)",
                        pre_fee_owed_a, post_pos.fee_owed_a);
                    fuzz_assert!(post_pos.fee_owed_b >= pre_fee_owed_b,
                        "decrease_liq: fee_owed_b decreased {} -> {} (checkpoint should only accrue)",
                        pre_fee_owed_b, post_pos.fee_owed_b);
                }
                // Postcondition: vault-user token transfer conservation
                // Tokens leaving vaults must equal tokens arriving at user (no creation/destruction)
                {
                    let post_vault_a = self.ctx.token_balance(&self.pool.token_vault_a);
                    let post_vault_b = self.ctx.token_balance(&self.pool.token_vault_b);
                    let post_user_a = self.ctx.token_balance(&self.users[self.positions[position_idx].owner_idx].token_account_a);
                    let post_user_b = self.ctx.token_balance(&self.users[self.positions[position_idx].owner_idx].token_account_b);
                    let vault_delta_a = pre_vault_a.saturating_sub(post_vault_a);
                    let user_delta_a = post_user_a.saturating_sub(pre_user_a);
                    let vault_delta_b = pre_vault_b.saturating_sub(post_vault_b);
                    let user_delta_b = post_user_b.saturating_sub(pre_user_b);
                    fuzz_assert_eq!(vault_delta_a, user_delta_a,
                        "decrease_liq: token A vault outflow {} != user inflow {} (pos={})",
                        vault_delta_a, user_delta_a, position_idx);
                    fuzz_assert_eq!(vault_delta_b, user_delta_b,
                        "decrease_liq: token B vault outflow {} != user inflow {} (pos={})",
                        vault_delta_b, user_delta_b, position_idx);

                    // ----------------------------------------------------------------
                    // CETUS-INVERSE: INFLATED WITHDRAWAL DETECTION
                    // ----------------------------------------------------------------
                    // Classical CLMM drain: attacker removes L units and gets MORE
                    // tokens than their liquidity should yield (via overflow / rounding
                    // bug in get_amount_delta_a/b). Upper-bound the withdrawal using
                    // Whirlpool's own formulas:
                    //   amount_b_max = L × (√upper − √lower) / 2^64
                    //   amount_a_max = L × (√upper − √lower) × 2^64 / (√lower × √upper)
                    // Applies the full-range bound (overestimate safe) for each side.
                    if liquidity_amount >= 1_000_000 {
                        let pos = &self.positions[position_idx];
                        let sqrt_lower = harness_sqrt_price_from_tick(pos.tick_lower_index);
                        let sqrt_upper = harness_sqrt_price_from_tick(pos.tick_upper_index);

                        if sqrt_upper > sqrt_lower && sqrt_lower > 0 {
                            let sqrt_diff = sqrt_upper - sqrt_lower;

                            // Upper bound on token_b withdrawal: L × sqrt_diff / 2^64
                            // Only check when multiplication won't overflow u128
                            if liquidity_amount <= u128::MAX / sqrt_diff.max(1) {
                                let max_b = (liquidity_amount.saturating_mul(sqrt_diff)) >> 64;
                                // 20% margin + 100-token absolute slack for arithmetic
                                let max_b_with_slack = max_b.saturating_mul(12) / 10 + 100;
                                fuzz_assert!((vault_delta_b as u128) <= max_b_with_slack,
                                    "CETUS-INVERSE: inflated withdrawal — pos {} L={} gave vault_b={} but max is {} (ticks=[{},{}])",
                                    position_idx, liquidity_amount, vault_delta_b, max_b_with_slack,
                                    pos.tick_lower_index, pos.tick_upper_index);
                            }

                            // Upper bound on token_a withdrawal: L × sqrt_diff × 2^64 / (sqrt_lower × sqrt_upper)
                            // Simplified bound: L × (1/sqrt_lower - 1/sqrt_upper) × 2^64
                            //                 = L × sqrt_diff / (sqrt_lower × sqrt_upper / 2^64) × 2^64 / 2^64
                            // To avoid overflow, use: token_a ≤ L / sqrt_lower × 2^64 (loosest safe bound)
                            // when sqrt_lower >= some threshold
                            if sqrt_lower > (1u128 << 32) {
                                // Bound: token_a ≤ L × 2^64 / sqrt_lower (only holds for sqrt_lower > 1)
                                let max_a = liquidity_amount.saturating_mul(1u128 << 32) / (sqrt_lower >> 32).max(1);
                                let max_a_with_slack = max_a.saturating_mul(12) / 10 + 100;
                                fuzz_assert!((vault_delta_a as u128) <= max_a_with_slack,
                                    "CETUS-INVERSE: inflated withdrawal — pos {} L={} gave vault_a={} but max is {} (ticks=[{},{}] sqrt_lower={})",
                                    position_idx, liquidity_amount, vault_delta_a, max_a_with_slack,
                                    pos.tick_lower_index, pos.tick_upper_index, sqrt_lower);
                            }
                        }
                    }
                }
                if liquidity_amount >= on_chain_liquidity {
                    self.positions[position_idx].has_liquidity = false;
                }
                debug_print!("[DECREASE_LIQ] SUCCESS: pos={} liq={}", position_idx, liquidity_amount);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[DECREASE_LIQ] TX_FAILED: pos={} liq={}", position_idx, liquidity_amount);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[DECREASE_LIQ] SEND_FAILED: pos={} liq={}: {:?}", position_idx, liquidity_amount, e);
                false
            }
        };
        action_stats::record(&action_stats::DECREASE_LIQUIDITY, success);
        success
    }

    // ========================================================================
    // Pool One: Increase / Decrease Liquidity (V2 — Token-2022 code paths)
    // ========================================================================

    /// V2 increase liquidity
    pub fn action_increase_liquidity_v2(
        &mut self,
        #[range(0..5)] position_idx: usize,
        liquidity_amount: u64,
    ) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }

        let liquidity_amount = ((liquidity_amount % 1_000_000_000) + 1000) as u128;
        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];
        let pool = &self.pool;

        let bal_a = self.ctx.token_balance(&user.token_account_a);
        let bal_b = self.ctx.token_balance(&user.token_account_b);
        if bal_a == 0 && bal_b == 0 {
            return false;
        }

        let target_lower = self.get_start_tick_index(position.tick_lower_index);
        let target_upper = self.get_start_tick_index(position.tick_upper_index);
        let has_lower = pool.tick_arrays.iter().any(|(s, _)| *s == target_lower);
        let has_upper = pool.tick_arrays.iter().any(|(s, _)| *s == target_upper);
        if !has_lower || !has_upper {
            return false;
        }

        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        let result = self.ctx.program(self.program_id)
            .call(instruction::IncreaseLiquidityV2 {
                liquidity_amount,
                token_max_a: u64::MAX,
                token_max_b: u64::MAX,
                remaining_accounts_info: None,
            })
            .accounts(accounts::IncreaseLiquidityV2 {
                whirlpool: pool.whirlpool,
                token_program_a: spl_token::ID,
                token_program_b: spl_token::ID,

                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_mint_a: pool.token_mint_a,
                token_mint_b: pool.token_mint_b,
                token_owner_account_a: user.token_account_a,
                token_owner_account_b: user.token_account_b,
                token_vault_a: pool.token_vault_a,
                token_vault_b: pool.token_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.total_liquidity_added += liquidity_amount;
                self.positions[position_idx].has_liquidity = true;
                debug_print!("[INCREASE_LIQ_V2] SUCCESS: pos={} liq={}", position_idx, liquidity_amount);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[INCREASE_LIQ_V2] TX_FAILED: pos={} liq={}", position_idx, liquidity_amount);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[INCREASE_LIQ_V2] SEND_FAILED: pos={} liq={}: {:?}", position_idx, liquidity_amount, e);
                false
            }
        };
        action_stats::record(&action_stats::INCREASE_LIQUIDITY_V2, success);
        success
    }

    /// V2 decrease liquidity
    pub fn action_decrease_liquidity_v2(
        &mut self,
        #[range(0..5)] position_idx: usize,
        liquidity_amount: u64,
    ) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }

        if !self.positions[position_idx].has_liquidity {
            return false;
        }

        let on_chain_liquidity = match self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
            Ok(pos_state) => pos_state.liquidity,
            Err(_) => return false,
        };
        if on_chain_liquidity == 0 {
            self.positions[position_idx].has_liquidity = false;
            return false;
        }

        let liquidity_amount = ((liquidity_amount as u128) % on_chain_liquidity) + 1;
        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];
        let pool = &self.pool;

        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        let result = self.ctx.program(self.program_id)
            .call(instruction::DecreaseLiquidityV2 {
                liquidity_amount,
                token_min_a: 0,
                token_min_b: 0,
                remaining_accounts_info: None,
            })
            .accounts(accounts::DecreaseLiquidityV2 {
                whirlpool: pool.whirlpool,
                token_program_a: spl_token::ID,
                token_program_b: spl_token::ID,

                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_mint_a: pool.token_mint_a,
                token_mint_b: pool.token_mint_b,
                token_owner_account_a: user.token_account_a,
                token_owner_account_b: user.token_account_b,
                token_vault_a: pool.token_vault_a,
                token_vault_b: pool.token_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                if liquidity_amount >= on_chain_liquidity {
                    self.positions[position_idx].has_liquidity = false;
                }
                debug_print!("[DECREASE_LIQ_V2] SUCCESS: pos={} liq={}", position_idx, liquidity_amount);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[DECREASE_LIQ_V2] TX_FAILED: pos={} liq={}", position_idx, liquidity_amount);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[DECREASE_LIQ_V2] SEND_FAILED: pos={} liq={}: {:?}", position_idx, liquidity_amount, e);
                false
            }
        };
        action_stats::record(&action_stats::DECREASE_LIQUIDITY_V2, success);
        success
    }

    // ========================================================================
    // Drain & Close Position
    // ========================================================================

    /// Drain all liquidity from a position (decrease to zero), making it closeable/resettable
    pub fn action_drain_position(&mut self, #[range(0..5)] position_idx: usize) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }
        if !self.positions[position_idx].has_liquidity {
            return false;
        }

        // Read on-chain liquidity to know how much to drain
        let liquidity = match self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
            Ok(pos_state) => pos_state.liquidity,
            Err(_) => return false,
        };

        if liquidity == 0 {
            self.positions[position_idx].has_liquidity = false;
            return true;
        }

        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];
        let pool = &self.pool;

        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        let result = self.ctx.program(self.program_id)
            .call(instruction::DecreaseLiquidity {
                liquidity_amount: liquidity,
                token_min_a: 0,
                token_min_b: 0,
            })
            .accounts(accounts::DecreaseLiquidity {
                whirlpool: pool.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_owner_account_a: user.token_account_a,
                token_owner_account_b: user.token_account_b,
                token_vault_a: pool.token_vault_a,
                token_vault_b: pool.token_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: after drain, position liquidity must be 0
                if let Ok(post_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
                    fuzz_assert_eq!(post_state.liquidity, 0u128,
                        "drain_position postcondition: pos {} liquidity {} != 0 after draining {}",
                        position_idx, post_state.liquidity, liquidity);
                }
                self.positions[position_idx].has_liquidity = false;
                debug_print!("[DRAIN_POS] SUCCESS: pos={} drained liq={}", position_idx, liquidity);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[DRAIN_POS] TX_FAILED: pos={}", position_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[DRAIN_POS] SEND_FAILED: pos={}: {:?}", position_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::DECREASE_LIQUIDITY, success);
        success
    }

    /// Drain all liquidity, collect all fees/rewards, and close a position.
    /// Uses sequential sends so partial progress is kept even if later steps fail.
    pub fn action_drain_and_close(&mut self, #[range(0..5)] position_idx: usize) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }
        // Skip bundled positions (they use close_bundled_position)
        if self.positions[position_idx].bundle_info.is_some() {
            return false;
        }

        // Pre-check: tick arrays must exist (not fallback) for update_fees_and_rewards
        let target_lower = self.get_start_tick_index(self.positions[position_idx].tick_lower_index);
        let target_upper = self.get_start_tick_index(self.positions[position_idx].tick_upper_index);
        let has_lower = self.pool.tick_arrays.iter().any(|(s, _)| *s == target_lower);
        let has_upper = self.pool.tick_arrays.iter().any(|(s, _)| *s == target_upper);
        if !has_lower || !has_upper {
            return false;
        }

        // Read on-chain position state
        let pos_state = match self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
            Ok(s) => s,
            Err(_) => {
                action_stats::record(&action_stats::DRAIN_AND_CLOSE, false);
                return false;
            }
        };

        let pos_pubkey = self.positions[position_idx].position;
        let pos_mint = self.positions[position_idx].position_mint;
        let pos_token_account = self.positions[position_idx].position_token_account;
        let tick_lower = self.positions[position_idx].tick_lower_index;
        let tick_upper = self.positions[position_idx].tick_upper_index;
        let owner_idx = self.positions[position_idx].owner_idx;
        let user_keypair = self.users[owner_idx].keypair.clone();
        let user_token_a = self.users[owner_idx].token_account_a;
        let user_token_b = self.users[owner_idx].token_account_b;
        let user_reward_accounts = self.users[owner_idx].reward_accounts.clone();
        let pool_whirlpool = self.pool.whirlpool;
        let pool_vault_a = self.pool.token_vault_a;
        let pool_vault_b = self.pool.token_vault_b;
        let pool_reward_vaults = self.pool.reward_vaults.clone();
        let pool_reward_init = self.pool.reward_initialized;
        let tick_array_lower = self.get_tick_array_for_tick(tick_lower);
        let tick_array_upper = self.get_tick_array_for_tick(tick_upper);

        // Step 1: If liquidity > 0, decrease all liquidity
        if pos_state.liquidity > 0 {
            let result = self.ctx.program(self.program_id)
                .call(instruction::DecreaseLiquidity {
                    liquidity_amount: pos_state.liquidity,
                    token_min_a: 0,
                    token_min_b: 0,
                })
                .accounts(accounts::DecreaseLiquidity {
                    whirlpool: pool_whirlpool,
                    position_authority: user_keypair.pubkey(),
                    position: pos_pubkey,
                    position_token_account: pos_token_account,
                    token_owner_account_a: user_token_a,
                    token_owner_account_b: user_token_b,
                    token_vault_a: pool_vault_a,
                    token_vault_b: pool_vault_b,
                    tick_array_lower,
                    tick_array_upper,
                })
                .signers(&[&*user_keypair])
                .send();
            match &result {
                Ok(TxOutcome::Success { .. }) => {
                    self.positions[position_idx].has_liquidity = false;
                }
                _ => {
                    action_stats::record(&action_stats::DRAIN_AND_CLOSE, false);
                    return false;
                }
            }
        }

        // Step 2: Update fees and rewards
        let _ = self.ctx.program(self.program_id)
            .call(instruction::UpdateFeesAndRewards {})
            .accounts(accounts::UpdateFeesAndRewards {
                whirlpool: pool_whirlpool,
                position: pos_pubkey,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user_keypair])
            .send();

        // Step 3: Collect fees
        let fee_result = self.ctx.program(self.program_id)
            .call(instruction::CollectFees {})
            .accounts(accounts::CollectFees {
                whirlpool: pool_whirlpool,
                position_authority: user_keypair.pubkey(),
                position: pos_pubkey,
                position_token_account: pos_token_account,
                token_owner_account_a: user_token_a,
                token_vault_a: pool_vault_a,
                token_owner_account_b: user_token_b,
                token_vault_b: pool_vault_b,
            })
            .signers(&[&*user_keypair])
            .send();
        if matches!(&fee_result, Ok(TxOutcome::Success { .. })) {
            self.positions[position_idx].fees_just_collected = true;
            self.positions[position_idx].prev_fee_owed_a = 0;
            self.positions[position_idx].prev_fee_owed_b = 0;
        }

        // Step 4: Collect all initialized rewards
        for i in 0..3 {
            if pool_reward_init[i] && i < user_reward_accounts.len() {
                let _ = self.ctx.program(self.program_id)
                    .call(instruction::CollectReward {
                        reward_index: i as u8,
                    })
                    .accounts(accounts::CollectReward {
                        whirlpool: pool_whirlpool,
                        position_authority: user_keypair.pubkey(),
                        position: pos_pubkey,
                        position_token_account: pos_token_account,
                        reward_owner_account: user_reward_accounts[i],
                        reward_vault: pool_reward_vaults[i],
                    })
                    .signers(&[&*user_keypair])
                    .send();
            }
        }

        // Step 5: Close position
        let result = self.ctx.program(self.program_id)
            .call(instruction::ClosePosition {})
            .accounts(accounts::ClosePosition {
                position_authority: user_keypair.pubkey(),
                receiver: user_keypair.pubkey(),
                position: pos_pubkey,
                position_mint: pos_mint,
                position_token_account: pos_token_account,
            })
            .signers(&[&*user_keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                debug_print!("[DRAIN_AND_CLOSE] SUCCESS: pos={}", position_idx);
                self.positions.remove(position_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[DRAIN_AND_CLOSE] TX_FAILED at close: pos={}", position_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[DRAIN_AND_CLOSE] SEND_FAILED: pos={}: {:?}", position_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::DRAIN_AND_CLOSE, success);
        success
    }

    // ========================================================================
    // Increase/Decrease Roundtrip (rounding asymmetry test)
    // ========================================================================

    /// Increase then immediately decrease the same liquidity amount on a position.
    /// Asserts that the pool never loses tokens (rounding asymmetry: increase rounds UP, decrease rounds DOWN).
    pub fn action_increase_decrease_roundtrip(
        &mut self,
        #[range(0..5)] position_idx: usize,
        liquidity_raw: u64,
    ) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }
        // Skip bundled positions (simplifies token account mapping)
        if self.positions[position_idx].bundle_info.is_some() {
            return false;
        }

        let liquidity_amount = ((liquidity_raw % 10_000) + 100) as u128; // 100-10099

        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];

        // Pre-check: user must have tokens to deposit
        let bal_a = self.ctx.token_balance(&user.token_account_a);
        let bal_b = self.ctx.token_balance(&user.token_account_b);
        if bal_a == 0 && bal_b == 0 {
            return false;
        }

        // Pre-check: tick arrays must exist
        let target_lower = self.get_start_tick_index(position.tick_lower_index);
        let target_upper = self.get_start_tick_index(position.tick_upper_index);
        let has_lower = self.pool.tick_arrays.iter().any(|(s, _)| *s == target_lower);
        let has_upper = self.pool.tick_arrays.iter().any(|(s, _)| *s == target_upper);
        if !has_lower || !has_upper {
            return false;
        }

        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        // Snapshot vault balances before roundtrip
        let vault_a_pre = self.ctx.token_balance(&self.pool.token_vault_a);
        let vault_b_pre = self.ctx.token_balance(&self.pool.token_vault_b);

        let pos_pubkey = position.position;
        let pos_token_account = position.position_token_account;
        let user_keypair = self.users[position.owner_idx].keypair.clone();
        let user_token_a = self.users[position.owner_idx].token_account_a;
        let user_token_b = self.users[position.owner_idx].token_account_b;
        let pool_whirlpool = self.pool.whirlpool;
        let pool_vault_a = self.pool.token_vault_a;
        let pool_vault_b = self.pool.token_vault_b;

        // Step 1: Increase liquidity
        let inc_result = self.ctx.program(self.program_id)
            .call(instruction::IncreaseLiquidity {
                liquidity_amount,
                token_max_a: u64::MAX,
                token_max_b: u64::MAX,
            })
            .accounts(accounts::IncreaseLiquidity {
                whirlpool: pool_whirlpool,
                position_authority: user_keypair.pubkey(),
                position: pos_pubkey,
                position_token_account: pos_token_account,
                token_owner_account_a: user_token_a,
                token_owner_account_b: user_token_b,
                token_vault_a: pool_vault_a,
                token_vault_b: pool_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user_keypair])
            .send();

        match &inc_result {
            Ok(TxOutcome::Success { .. }) => {
                self.positions[position_idx].has_liquidity = true;
            }
            _ => {
                action_stats::record(&action_stats::ROUNDTRIP_LIQUIDITY, false);
                return false;
            }
        }

        // Step 2: Immediately decrease the same amount
        let dec_result = self.ctx.program(self.program_id)
            .call(instruction::DecreaseLiquidity {
                liquidity_amount,
                token_min_a: 0,
                token_min_b: 0,
            })
            .accounts(accounts::DecreaseLiquidity {
                whirlpool: pool_whirlpool,
                position_authority: user_keypair.pubkey(),
                position: pos_pubkey,
                position_token_account: pos_token_account,
                token_owner_account_a: user_token_a,
                token_owner_account_b: user_token_b,
                token_vault_a: pool_vault_a,
                token_vault_b: pool_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user_keypair])
            .send();

        let success = match &dec_result {
            Ok(TxOutcome::Success { .. }) => {
                // Assert pool never loses tokens from the roundtrip
                let vault_a_post = self.ctx.token_balance(&self.pool.token_vault_a);
                let vault_b_post = self.ctx.token_balance(&self.pool.token_vault_b);
                fuzz_assert!(vault_a_post >= vault_a_pre,
                    "Roundtrip: pool lost token A: {} -> {}", vault_a_pre, vault_a_post);
                fuzz_assert!(vault_b_post >= vault_b_pre,
                    "Roundtrip: pool lost token B: {} -> {}", vault_b_pre, vault_b_post);

                // Update has_liquidity from on-chain state
                if let Ok(pos_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&pos_pubkey) {
                    self.positions[position_idx].has_liquidity = pos_state.liquidity > 0;
                }

                debug_print!("[ROUNDTRIP_LIQ] SUCCESS: pos={} liq={}", position_idx, liquidity_amount);
                true
            }
            _ => {
                debug_print!("[ROUNDTRIP_LIQ] decrease failed: pos={}", position_idx);
                false
            }
        };
        action_stats::record(&action_stats::ROUNDTRIP_LIQUIDITY, success);
        success
    }
