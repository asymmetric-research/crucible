// actions/pool_two.rs — Pool two position and behavioral action methods (included in impl WhirlpoolFixture via include!())

    /// Open a new position on pool two
    pub fn action_open_position_pool_two(&mut self, #[range(0..3)] user_idx: usize) -> bool {
        let pool_two = match &self.pool_two {
            Some(p2) => p2,
            None => return false,
        };
        if self.pool_two_positions.len() >= 10 {
            return false;
        }

        let user = &self.users[user_idx];

        // Random-ish tick range around current price
        let tick_lower_index = -((user_idx as i32 + 5) * (TICK_SPACING as i32));
        let tick_upper_index = (user_idx as i32 + 5) * (TICK_SPACING as i32);

        let position_mint = Keypair::new();
        let (position, position_bump) = Pubkey::find_program_address(
            &[b"position", position_mint.pubkey().as_ref()],
            &self.program_id,
        );
        let position_token_account = associated_token::get_associated_token_address(
            &user.keypair.pubkey(),
            &position_mint.pubkey(),
        );

        let result = self.ctx.program(self.program_id)
            .call(instruction::OpenPosition {
                bumps: OpenPositionBumps { position_bump },
                tick_lower_index,
                tick_upper_index,
            })
            .accounts(accounts::OpenPosition {
                funder: user.keypair.pubkey(),
                owner: user.keypair.pubkey(),
                position,
                position_mint: position_mint.pubkey(),
                position_token_account,
                whirlpool: pool_two.whirlpool,
            })
            .signers(&[&*user.keypair, &position_mint])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.pool_two_positions.push(PositionData {
                    position,
                    position_mint: position_mint.pubkey(),
                    position_token_account,
                    tick_lower_index,
                    tick_upper_index,
                    owner_idx: user_idx,
                    has_liquidity: false,
                    bundle_info: None,
                    prev_fee_owed_a: 0,
                    prev_fee_owed_b: 0,
                    fees_just_collected: false,
                });
                debug_print!("[OPEN_POS_P2] SUCCESS: ticks=[{},{}]", tick_lower_index, tick_upper_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[OPEN_POS_P2] TX_FAILED");
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[OPEN_POS_P2] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::OPEN_POSITION_P2, success);
        success
    }

    /// Increase liquidity on a pool two position
    pub fn action_increase_liquidity_pool_two(
        &mut self,
        #[range(0..10)] pos_idx: usize,
        liquidity_amount: u64,
    ) -> bool {
        let pool_two = match &self.pool_two {
            Some(p2) => p2.clone(),
            None => return false,
        };
        if pos_idx >= self.pool_two_positions.len() {
            return false;
        }

        let liquidity_amount = ((liquidity_amount % 1_000_000_000) + 1_000) as u128;
        let position = &self.pool_two_positions[pos_idx];
        let user = &self.users[position.owner_idx];

        // Map user token accounts to pool two's mint ordering
        let (user_account_a, user_account_b) = if pool_two.token_mint_a == self.pool.token_mint_b {
            (user.token_account_b, user.token_account_c)
        } else {
            (user.token_account_c, user.token_account_b)
        };

        let tick_array_lower = self.get_tick_array_for_tick_pool(&pool_two, position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick_pool(&pool_two, position.tick_upper_index);

        // Pre-snapshots for postconditions
        let pre_pos_p2 = self.ctx.read_anchor_account::<whirlpool::state::Position>(&position.position).ok();
        let pre_liq = pre_pos_p2.as_ref().map(|s| s.liquidity).unwrap_or(0);
        let (pre_fee_a_p2, pre_fee_b_p2) = pre_pos_p2.as_ref()
            .map(|s| (s.fee_owed_a, s.fee_owed_b)).unwrap_or((0, 0));
        let (pre_pool_liq, pre_pool_tick, pre_sqrt_price_p2) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
            .map(|s| (s.liquidity, s.tick_current_index, s.sqrt_price)).unwrap_or((0, 0, 0));
        let pre_vault_a = self.ctx.token_balance(&pool_two.token_vault_a);
        let pre_vault_b = self.ctx.token_balance(&pool_two.token_vault_b);
        let pre_user_a = self.ctx.token_balance(&user_account_a);
        let pre_user_b = self.ctx.token_balance(&user_account_b);

        let result = self.ctx.program(self.program_id)
            .call(instruction::IncreaseLiquidity {
                liquidity_amount,
                token_max_a: u64::MAX,
                token_max_b: u64::MAX,
            })
            .accounts(accounts::IncreaseLiquidity {
                whirlpool: pool_two.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_owner_account_a: user_account_a,
                token_owner_account_b: user_account_b,
                token_vault_a: pool_two.token_vault_a,
                token_vault_b: pool_two.token_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: liquidity increased + fee_owed monotonicity
                if let Ok(post_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.pool_two_positions[pos_idx].position) {
                    fuzz_assert!(post_state.liquidity >= pre_liq,
                        "p2 increase_liq: liquidity decreased {} -> {}", pre_liq, post_state.liquidity);
                    fuzz_assert_eq!(post_state.liquidity, pre_liq + liquidity_amount,
                        "p2 increase_liq: expected {} got {}", pre_liq + liquidity_amount, post_state.liquidity);
                    // Fee checkpoint monotonicity: fee_owed can only increase during increase_liq
                    fuzz_assert!(post_state.fee_owed_a >= pre_fee_a_p2,
                        "p2 increase_liq: fee_owed_a decreased {} -> {}", pre_fee_a_p2, post_state.fee_owed_a);
                    fuzz_assert!(post_state.fee_owed_b >= pre_fee_b_p2,
                        "p2 increase_liq: fee_owed_b decreased {} -> {}", pre_fee_b_p2, post_state.fee_owed_b);
                }
                // Transfer conservation: vault increase == user decrease
                let post_vault_a = self.ctx.token_balance(&pool_two.token_vault_a);
                let post_vault_b = self.ctx.token_balance(&pool_two.token_vault_b);
                let post_user_a = self.ctx.token_balance(&user_account_a);
                let post_user_b = self.ctx.token_balance(&user_account_b);
                let va_delta = post_vault_a.saturating_sub(pre_vault_a);
                let ua_delta = pre_user_a.saturating_sub(post_user_a);
                fuzz_assert_eq!(va_delta, ua_delta,
                    "p2 increase_liq: vault_a_delta ({}) != user_a_delta ({})", va_delta, ua_delta);
                let vb_delta = post_vault_b.saturating_sub(pre_vault_b);
                let ub_delta = pre_user_b.saturating_sub(post_user_b);
                fuzz_assert_eq!(vb_delta, ub_delta,
                    "p2 increase_liq: vault_b_delta ({}) != user_b_delta ({})", vb_delta, ub_delta);
                // Pool liquidity coupling: in-range increase changes pool.liquidity
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                    // sqrt_price and tick must NOT change during liquidity ops
                    fuzz_assert_eq!(post_pool.sqrt_price, pre_sqrt_price_p2,
                        "p2 increase_liq: sqrt_price changed {} -> {}",
                        pre_sqrt_price_p2, post_pool.sqrt_price);
                    fuzz_assert_eq!(post_pool.tick_current_index, pre_pool_tick,
                        "p2 increase_liq: tick changed {} -> {}",
                        pre_pool_tick, post_pool.tick_current_index);
                    let pos = &self.pool_two_positions[pos_idx];
                    let in_range = pos.tick_lower_index <= pre_pool_tick && pre_pool_tick < pos.tick_upper_index;
                    if in_range {
                        fuzz_assert_eq!(post_pool.liquidity, pre_pool_liq + liquidity_amount,
                            "p2 increase_liq: in-range pos {} but pool liq {} != expected {}",
                            pos_idx, post_pool.liquidity, pre_pool_liq + liquidity_amount);
                    } else {
                        fuzz_assert_eq!(post_pool.liquidity, pre_pool_liq,
                            "p2 increase_liq: out-of-range pos {} changed pool liq {} -> {}",
                            pos_idx, pre_pool_liq, post_pool.liquidity);
                    }
                }

                self.pool_two_positions[pos_idx].has_liquidity = true;
                debug_print!("[INCREASE_LIQ_P2] SUCCESS: pos={} liq={}", pos_idx, liquidity_amount);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[INCREASE_LIQ_P2] TX_FAILED");
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[INCREASE_LIQ_P2] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::INCREASE_LIQ_P2, success);
        success
    }

    /// Decrease liquidity on a pool two position
    pub fn action_decrease_liquidity_pool_two(
        &mut self,
        #[range(0..10)] pos_idx: usize,
        liquidity_amount: u64,
    ) -> bool {
        let pool_two = match &self.pool_two {
            Some(p2) => p2.clone(),
            None => return false,
        };
        if pos_idx >= self.pool_two_positions.len() || !self.pool_two_positions[pos_idx].has_liquidity {
            return false;
        }

        // Read on-chain liquidity to cap the decrease
        let on_chain_liq = self.ctx.read_anchor_account::<whirlpool::state::Position>(
            &self.pool_two_positions[pos_idx].position
        ).ok().map(|s| s.liquidity).unwrap_or(0);

        if on_chain_liq == 0 {
            return false;
        }

        let liquidity_amount = ((liquidity_amount as u128 % on_chain_liq) + 1).min(on_chain_liq);
        let position = &self.pool_two_positions[pos_idx];
        let user = &self.users[position.owner_idx];

        let (user_account_a, user_account_b) = if pool_two.token_mint_a == self.pool.token_mint_b {
            (user.token_account_b, user.token_account_c)
        } else {
            (user.token_account_c, user.token_account_b)
        };

        let tick_array_lower = self.get_tick_array_for_tick_pool(&pool_two, position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick_pool(&pool_two, position.tick_upper_index);

        // Pre-snapshots for transfer conservation and pool liquidity coupling
        let pre_vault_a = self.ctx.token_balance(&pool_two.token_vault_a);
        let pre_vault_b = self.ctx.token_balance(&pool_two.token_vault_b);
        let pre_user_a = self.ctx.token_balance(&user_account_a);
        let pre_user_b = self.ctx.token_balance(&user_account_b);
        let (pre_pool_liq, pre_pool_tick, pre_sqrt_price_p2) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool)
            .map(|s| (s.liquidity, s.tick_current_index, s.sqrt_price)).unwrap_or((0, 0, 0));
        let (pre_fee_a_dec_p2, pre_fee_b_dec_p2) = self.ctx.read_anchor_account::<whirlpool::state::Position>(
            &self.pool_two_positions[pos_idx].position
        ).ok().map(|s| (s.fee_owed_a, s.fee_owed_b)).unwrap_or((0, 0));

        let result = self.ctx.program(self.program_id)
            .call(instruction::DecreaseLiquidity {
                liquidity_amount,
                token_min_a: 0,
                token_min_b: 0,
            })
            .accounts(accounts::DecreaseLiquidity {
                whirlpool: pool_two.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_owner_account_a: user_account_a,
                token_owner_account_b: user_account_b,
                token_vault_a: pool_two.token_vault_a,
                token_vault_b: pool_two.token_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: liquidity decreased correctly + fee_owed monotonicity
                if let Ok(post_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.pool_two_positions[pos_idx].position) {
                    fuzz_assert_eq!(post_state.liquidity, on_chain_liq - liquidity_amount,
                        "p2 decrease_liq: expected {} got {}", on_chain_liq - liquidity_amount, post_state.liquidity);
                    // Fee checkpoint monotonicity: fee_owed can only increase during decrease_liq
                    fuzz_assert!(post_state.fee_owed_a >= pre_fee_a_dec_p2,
                        "p2 decrease_liq: fee_owed_a decreased {} -> {}", pre_fee_a_dec_p2, post_state.fee_owed_a);
                    fuzz_assert!(post_state.fee_owed_b >= pre_fee_b_dec_p2,
                        "p2 decrease_liq: fee_owed_b decreased {} -> {}", pre_fee_b_dec_p2, post_state.fee_owed_b);
                }
                // Transfer conservation: vault decrease == user increase
                let post_vault_a = self.ctx.token_balance(&pool_two.token_vault_a);
                let post_vault_b = self.ctx.token_balance(&pool_two.token_vault_b);
                let post_user_a = self.ctx.token_balance(&user_account_a);
                let post_user_b = self.ctx.token_balance(&user_account_b);
                let va_out = pre_vault_a.saturating_sub(post_vault_a);
                let ua_in = post_user_a.saturating_sub(pre_user_a);
                fuzz_assert_eq!(va_out, ua_in,
                    "p2 decrease_liq: vault_a outflow ({}) != user_a inflow ({})", va_out, ua_in);
                let vb_out = pre_vault_b.saturating_sub(post_vault_b);
                let ub_in = post_user_b.saturating_sub(pre_user_b);
                fuzz_assert_eq!(vb_out, ub_in,
                    "p2 decrease_liq: vault_b outflow ({}) != user_b inflow ({})", vb_out, ub_in);
                // Pool liquidity coupling: in-range decrease changes pool.liquidity
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                    // sqrt_price and tick must NOT change during liquidity ops
                    fuzz_assert_eq!(post_pool.sqrt_price, pre_sqrt_price_p2,
                        "p2 decrease_liq: sqrt_price changed {} -> {}",
                        pre_sqrt_price_p2, post_pool.sqrt_price);
                    fuzz_assert_eq!(post_pool.tick_current_index, pre_pool_tick,
                        "p2 decrease_liq: tick changed {} -> {}",
                        pre_pool_tick, post_pool.tick_current_index);
                    let pos = &self.pool_two_positions[pos_idx];
                    let in_range = pos.tick_lower_index <= pre_pool_tick && pre_pool_tick < pos.tick_upper_index;
                    if in_range {
                        fuzz_assert_eq!(post_pool.liquidity, pre_pool_liq - liquidity_amount,
                            "p2 decrease_liq: in-range pos {} but pool liq {} != expected {}",
                            pos_idx, post_pool.liquidity, pre_pool_liq - liquidity_amount);
                    } else {
                        fuzz_assert_eq!(post_pool.liquidity, pre_pool_liq,
                            "p2 decrease_liq: out-of-range pos {} changed pool liq {} -> {}",
                            pos_idx, pre_pool_liq, post_pool.liquidity);
                    }
                }

                // Update has_liquidity if we drained all
                if liquidity_amount == on_chain_liq {
                    self.pool_two_positions[pos_idx].has_liquidity = false;
                }
                debug_print!("[DECREASE_LIQ_P2] SUCCESS: pos={} liq={}", pos_idx, liquidity_amount);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[DECREASE_LIQ_P2] TX_FAILED");
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[DECREASE_LIQ_P2] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::DECREASE_LIQ_P2, success);
        success
    }

    /// V2 exact-out swap on pool one
    pub fn action_swap_exact_out_v2(
        &mut self,
        #[range(0..3)] user_idx: usize,
        amount: u64,
        a_to_b: bool,
    ) -> bool {
        let amount = (amount % 100_000) + 1;
        self.total_swaps += 1;

        let user = &self.users[user_idx];
        let pool = &self.pool;

        if pool.tick_arrays.len() < 3 {
            return false;
        }

        let sqrt_price_limit = if a_to_b { MIN_SQRT_PRICE_X64 } else { MAX_SQRT_PRICE_X64 };
        let (tick_array_0, tick_array_1, tick_array_2) = self.get_tick_arrays_for_swap(a_to_b);

        // Pre-snapshots for postcondition
        let pre_vault_a = self.ctx.token_balance(&pool.token_vault_a);
        let pre_vault_b = self.ctx.token_balance(&pool.token_vault_b);
        let pre_user_a = self.ctx.token_balance(&user.token_account_a);
        let pre_user_b = self.ctx.token_balance(&user.token_account_b);
        let (pre_fee_rate_eo, pre_proto_rate_eo, eo_pre_fg_a, eo_pre_fg_b, eo_pre_sqrt) =
            self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool.whirlpool)
            .map(|s| (s.fee_rate, s.protocol_fee_rate, s.fee_growth_global_a, s.fee_growth_global_b, s.sqrt_price))
            .unwrap_or((0, 0, 0, 0, 0));

        let result = self.ctx.program(self.program_id)
            .call(instruction::SwapV2 {
                amount,
                other_amount_threshold: u64::MAX,
                sqrt_price_limit,
                amount_specified_is_input: false, // exact-out
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
                let post_vault_a = self.ctx.token_balance(&self.pool.token_vault_a);
                let post_vault_b = self.ctx.token_balance(&self.pool.token_vault_b);
                let post_user_a = self.ctx.token_balance(&self.users[user_idx].token_account_a);
                let post_user_b = self.ctx.token_balance(&self.users[user_idx].token_account_b);
                // Vault direction check
                if a_to_b {
                    fuzz_assert!(post_vault_a >= pre_vault_a,
                        "exact_out_v2 a_to_b: vault_a decreased {} -> {}", pre_vault_a, post_vault_a);
                    fuzz_assert!(post_vault_b <= pre_vault_b,
                        "exact_out_v2 a_to_b: vault_b increased {} -> {}", pre_vault_b, post_vault_b);
                } else {
                    fuzz_assert!(post_vault_b >= pre_vault_b,
                        "exact_out_v2 b_to_a: vault_b decreased {} -> {}", pre_vault_b, post_vault_b);
                    fuzz_assert!(post_vault_a <= pre_vault_a,
                        "exact_out_v2 b_to_a: vault_a increased {} -> {}", pre_vault_a, post_vault_a);
                }
                // Exact-out: user must receive tokens
                let received = if a_to_b {
                    post_user_b.saturating_sub(pre_user_b)
                } else {
                    post_user_a.saturating_sub(pre_user_a)
                };
                fuzz_assert!(received > 0,
                    "exact_out_v2: succeeded but received 0 tokens (requested={})", amount);
                // Exact-out: received should not exceed requested
                fuzz_assert!(received <= amount,
                    "exact_out_v2: over-delivered received {} > requested {} (a_to_b={})",
                    received, amount, a_to_b);
                // Transfer conservation: vault_delta == -user_delta
                let va_d = (post_vault_a as i128) - (pre_vault_a as i128);
                let ua_d = (post_user_a as i128) - (pre_user_a as i128);
                fuzz_assert_eq!(va_d, -ua_d,
                    "exact_out_v2: token A vault_delta ({}) != -user_delta ({})", va_d, -ua_d);
                let vb_d = (post_vault_b as i128) - (pre_vault_b as i128);
                let ub_d = (post_user_b as i128) - (pre_user_b as i128);
                fuzz_assert_eq!(vb_d, -ub_d,
                    "exact_out_v2: token B vault_delta ({}) != -user_delta ({})", vb_d, -ub_d);
                // Fee rate immutability + fee_growth side isolation during swap
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    fuzz_assert_eq!(post_pool.fee_rate, pre_fee_rate_eo,
                        "exact_out_v2: fee_rate changed {} -> {}",
                        pre_fee_rate_eo, post_pool.fee_rate);
                    fuzz_assert_eq!(post_pool.protocol_fee_rate, pre_proto_rate_eo,
                        "exact_out_v2: protocol_fee_rate changed {} -> {}",
                        pre_proto_rate_eo, post_pool.protocol_fee_rate);
                    // Fee growth side isolation
                    if a_to_b {
                        fuzz_assert!(post_pool.fee_growth_global_a >= eo_pre_fg_a,
                            "exact_out_v2 a_to_b: fee_growth_a decreased {} -> {}", eo_pre_fg_a, post_pool.fee_growth_global_a);
                        fuzz_assert_eq!(post_pool.fee_growth_global_b, eo_pre_fg_b,
                            "exact_out_v2 a_to_b: fee_growth_b changed {} -> {} (should be frozen)",
                            eo_pre_fg_b, post_pool.fee_growth_global_b);
                    } else {
                        fuzz_assert!(post_pool.fee_growth_global_b >= eo_pre_fg_b,
                            "exact_out_v2 b_to_a: fee_growth_b decreased {} -> {}", eo_pre_fg_b, post_pool.fee_growth_global_b);
                        fuzz_assert_eq!(post_pool.fee_growth_global_a, eo_pre_fg_a,
                            "exact_out_v2 b_to_a: fee_growth_a changed {} -> {} (should be frozen)",
                            eo_pre_fg_a, post_pool.fee_growth_global_a);
                    }
                    // sqrt_price ↔ tick consistency
                    let lb = harness_sqrt_price_from_tick(post_pool.tick_current_index);
                    let ub = harness_sqrt_price_from_tick(post_pool.tick_current_index + 1);
                    fuzz_assert!(post_pool.sqrt_price >= lb && post_pool.sqrt_price <= ub,
                        "exact_out_v2: sqrt_price {} not in [{}, {}] for tick {}",
                        post_pool.sqrt_price, lb, ub, post_pool.tick_current_index);
                    // sqrt_price direction
                    if a_to_b {
                        fuzz_assert!(post_pool.sqrt_price <= eo_pre_sqrt,
                            "exact_out_v2 a_to_b: sqrt_price increased {} -> {}",
                            eo_pre_sqrt, post_pool.sqrt_price);
                    } else {
                        fuzz_assert!(post_pool.sqrt_price >= eo_pre_sqrt,
                            "exact_out_v2 b_to_a: sqrt_price decreased {} -> {}",
                            eo_pre_sqrt, post_pool.sqrt_price);
                    }
                }
                debug_print!("[SWAP_EXACT_OUT_V2] SUCCESS: {} {} (user {})",
                    if a_to_b { "A->B" } else { "B->A" }, amount, user_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SWAP_EXACT_OUT_V2] TX_FAILED");
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SWAP_EXACT_OUT_V2] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::SWAP_EXACT_OUT_V2, success);
        success
    }

    /// Execute 3-5 tiny swaps in alternating directions to stress rounding/fees
    pub fn action_sequential_micro_swaps(
        &mut self,
        #[range(0..3)] user_idx: usize,
        count: u8,
    ) -> bool {
        let count = ((count % 3) + 3) as usize; // 3-5 swaps
        let mut any_success = false;

        for i in 0..count {
            let a_to_b = i % 2 == 0;
            let amount = (i as u64 + 1) * 10; // 10, 20, 30, 40, 50
            let ok = self.do_swap(user_idx, amount, a_to_b, None, true, 0);
            if ok { any_success = true; }
        }

        action_stats::record(&action_stats::SEQUENTIAL_MICRO_SWAPS, any_success);
        any_success
    }

    /// Execute a swap large enough to cross a tick array boundary
    pub fn action_cross_tick_boundary_swap(
        &mut self,
        #[range(0..3)] user_idx: usize,
        a_to_b: bool,
    ) -> bool {
        // Use a moderate amount to try crossing tick boundaries without exceeding balance
        let user = &self.users[user_idx];
        let balance = if a_to_b {
            self.ctx.token_balance(&user.token_account_a)
        } else {
            self.ctx.token_balance(&user.token_account_b)
        };
        if balance < 10_000 { return false; }
        // Use 10% of balance — large enough to potentially cross ticks, but small enough to succeed
        let amount = (balance / 10).max(10_000);
        let ok = self.do_swap(user_idx, amount, a_to_b, None, true, 0);
        action_stats::record(&action_stats::CROSS_TICK_SWAP, ok);
        ok
    }

    /// Migration instruction to repurpose reward authority space (permissionless)
    pub fn action_migrate_repurpose_reward_authority_space(&mut self) -> bool {
        let result = self.ctx.program(self.program_id)
            .call(instruction::MigrateRepurposeRewardAuthoritySpace {})
            .accounts(accounts::MigrateRepurposeRewardAuthoritySpace {
                whirlpool: self.pool.whirlpool,
            })
            .signers(&[&*self.admin]) // need fee payer
            .send();
        let success = matches!(&result, Ok(TxOutcome::Success { .. }));
        if success {
            debug_print!("[MIGRATE_REWARD_AUTH] SUCCESS");
        } else {
            debug_print!("[MIGRATE_REWARD_AUTH] FAILED");
        }
        action_stats::record(&action_stats::MIGRATE_REWARD_AUTH, success);
        success
    }
