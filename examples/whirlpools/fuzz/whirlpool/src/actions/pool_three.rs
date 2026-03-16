// actions/pool_three.rs — Pool three (adaptive fee) action methods (included in impl WhirlpoolFixture via include!())

    // ========================================================================
    // Dynamic Tick Arrays
    // ========================================================================

    /// Initialize a dynamic tick array (idempotent — won't fail if already exists)
    pub fn action_initialize_dynamic_tick_array(&mut self, array_offset: i32) -> bool {
        // Pick pool one or pool two randomly based on offset sign
        let (pool_key, tick_spacing) = if array_offset >= 0 {
            (self.pool.whirlpool, TICK_SPACING)
        } else if let Some(ref p2) = self.pool_two {
            (p2.whirlpool, TICK_SPACING)
        } else {
            (self.pool.whirlpool, TICK_SPACING)
        };

        let span = TICK_ARRAY_SIZE * tick_spacing as i32;
        let current_tick = self.read_pool_tick();
        let base_start = self.get_start_tick_index(current_tick);
        let offset = ((array_offset as i32).wrapping_abs() % 10) - 5; // -5..+4
        let start_tick_index = base_start + offset * span;

        let (tick_array_pda, _) = Pubkey::find_program_address(
            &[b"tick_array", pool_key.as_ref(), start_tick_index.to_string().as_bytes()],
            &self.program_id,
        );

        let result = self.ctx.program(self.program_id)
            .call(instruction::InitializeDynamicTickArray {
                start_tick_index,
                idempotent: true,
            })
            .accounts(accounts::InitializeDynamicTickArray {
                whirlpool: pool_key,
                funder: self.admin.pubkey(),
                tick_array: tick_array_pda,
            })
            .signers(&[&*self.admin])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Track if not already tracked
                if !self.dynamic_tick_arrays.iter().any(|(pk, _)| *pk == tick_array_pda) {
                    self.dynamic_tick_arrays.push((tick_array_pda, start_tick_index));
                }
                debug_print!("[INIT_DYN_TA] SUCCESS: start={} pool={}", start_tick_index, pool_key);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[INIT_DYN_TA] TX_FAILED: start={}", start_tick_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[INIT_DYN_TA] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::INIT_DYNAMIC_TICK_ARRAY, success);
        success
    }

    // ========================================================================
    // Pool Three Swaps
    // ========================================================================

    /// Swap on pool three (adaptive fee pool)
    pub fn action_swap_pool_three(
        &mut self,
        #[range(0..3)] user_idx: usize,
        amount: u64,
        a_to_b: bool,
    ) -> bool {
        let pool_three = match &self.pool_three {
            Some(p) => p.clone(),
            None => return false,
        };

        let amount = (amount % 1_000_000) + 1;
        let user = &self.users[user_idx];

        if pool_three.tick_arrays.len() < 3 {
            return false;
        }

        let sqrt_price_limit = if a_to_b { MIN_SQRT_PRICE_X64 } else { MAX_SQRT_PRICE_X64 };

        // Map user token accounts to pool three's mint ordering
        // Pool three uses mint_a and mint_d (sorted by pubkey)
        let (user_account_a, user_account_b) = if pool_three.token_mint_a == self.pool.token_mint_a {
            // p3.mint_a == mint_a, p3.mint_b == mint_d
            (user.token_account_a, user.token_account_d)
        } else {
            // p3.mint_a == mint_d, p3.mint_b == mint_a
            (user.token_account_d, user.token_account_a)
        };

        let (tick_array_0, tick_array_1, tick_array_2) = self.get_tick_arrays_for_swap_pool(&pool_three, a_to_b);

        // Pre-swap snapshots for per-swap invariants
        let vault_a_pre = self.ctx.token_balance(&pool_three.token_vault_a);
        let vault_b_pre = self.ctx.token_balance(&pool_three.token_vault_b);
        let pre_user_a = self.ctx.token_balance(&user_account_a);
        let pre_user_b = self.ctx.token_balance(&user_account_b);
        let price_pre = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool)
            .ok().map(|s| s.sqrt_price).unwrap_or(0);
        let (p3_pre_proto_a, p3_pre_proto_b, p3_pre_fg_a, p3_pre_fg_b, p3_pre_fee_rate, p3_pre_proto_rate) =
            self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool)
            .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b,
                       s.fee_growth_global_a, s.fee_growth_global_b,
                       s.fee_rate, s.protocol_fee_rate))
            .unwrap_or((0, 0, 0, 0, 0, 0));

        // Adaptive fee pools require SwapV2 (v1 Swap doesn't support adaptive fee oracle)
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
                whirlpool: pool_three.whirlpool,
                token_mint_a: pool_three.token_mint_a,
                token_mint_b: pool_three.token_mint_b,
                token_owner_account_a: user_account_a,
                token_vault_a: pool_three.token_vault_a,
                token_owner_account_b: user_account_b,
                token_vault_b: pool_three.token_vault_b,
                tick_array_0,
                tick_array_1,
                tick_array_2,
                oracle: pool_three.oracle,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Per-swap vault balance direction check
                let vault_a_post = self.ctx.token_balance(&pool_three.token_vault_a);
                let vault_b_post = self.ctx.token_balance(&pool_three.token_vault_b);
                if a_to_b {
                    fuzz_assert!(vault_a_post >= vault_a_pre,
                        "p3 a_to_b: vault_a decreased {} -> {}", vault_a_pre, vault_a_post);
                    fuzz_assert!(vault_b_post <= vault_b_pre,
                        "p3 a_to_b: vault_b increased {} -> {}", vault_b_pre, vault_b_post);
                } else {
                    fuzz_assert!(vault_b_post >= vault_b_pre,
                        "p3 b_to_a: vault_b decreased {} -> {}", vault_b_pre, vault_b_post);
                    fuzz_assert!(vault_a_post <= vault_a_pre,
                        "p3 b_to_a: vault_a increased {} -> {}", vault_a_pre, vault_a_post);
                }

                // Per-swap price direction check
                let price_post = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool)
                    .ok().map(|s| s.sqrt_price).unwrap_or(0);
                if price_pre > 0 && price_post > 0 {
                    if a_to_b {
                        fuzz_assert!(price_post <= price_pre,
                            "p3 a_to_b: sqrt_price increased {} -> {}", price_pre, price_post);
                    } else {
                        fuzz_assert!(price_post >= price_pre,
                            "p3 b_to_a: sqrt_price decreased {} -> {}", price_pre, price_post);
                    }
                }

                // Protocol fee side isolation + fee_rate fraction bound for pool three
                // Note: pool_three uses adaptive fees, so effective rate can be up to FEE_RATE_HARD_LIMIT (100_000)
                if let Ok(post_p3) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
                    let pa = post_p3.protocol_fee_owed_a.saturating_sub(p3_pre_proto_a);
                    let pb = post_p3.protocol_fee_owed_b.saturating_sub(p3_pre_proto_b);
                    if a_to_b {
                        fuzz_assert_eq!(pb, 0, "p3 a_to_b: protocol_fee_owed_b increased by {}", pb);
                        let input = vault_a_post.saturating_sub(vault_a_pre);
                        fuzz_assert!(pa <= input, "p3 a_to_b: proto_fee_a ({}) > input ({})", pa, input);
                        if input > 0 {
                            // Adaptive fee hard limit: 100_000 / 1_000_000 = 10% max
                            let max_fee = (input as u128) * 100_000 / 1_000_000 + 100;
                            fuzz_assert!((pa as u128) <= max_fee,
                                "p3 a_to_b: proto_fee {} > max_fee {} (input={} hard_limit=100000)", pa, max_fee, input);
                        }
                    } else {
                        fuzz_assert_eq!(pa, 0, "p3 b_to_a: protocol_fee_owed_a increased by {}", pa);
                        let input = vault_b_post.saturating_sub(vault_b_pre);
                        fuzz_assert!(pb <= input, "p3 b_to_a: proto_fee_b ({}) > input ({})", pb, input);
                        if input > 0 {
                            let max_fee = (input as u128) * 100_000 / 1_000_000 + 100;
                            fuzz_assert!((pb as u128) <= max_fee,
                                "p3 b_to_a: proto_fee {} > max_fee {} (input={} hard_limit=100000)", pb, max_fee, input);
                        }
                    }
                }

                // Per-swap fee_growth side isolation for pool_three
                if let Ok(post_p3) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
                    if a_to_b {
                        fuzz_assert!(post_p3.fee_growth_global_a >= p3_pre_fg_a,
                            "p3 a_to_b: fee_growth_a decreased {} -> {}", p3_pre_fg_a, post_p3.fee_growth_global_a);
                        fuzz_assert_eq!(post_p3.fee_growth_global_b, p3_pre_fg_b,
                            "p3 a_to_b: fee_growth_b changed {} -> {}", p3_pre_fg_b, post_p3.fee_growth_global_b);
                    } else {
                        fuzz_assert!(post_p3.fee_growth_global_b >= p3_pre_fg_b,
                            "p3 b_to_a: fee_growth_b decreased {} -> {}", p3_pre_fg_b, post_p3.fee_growth_global_b);
                        fuzz_assert_eq!(post_p3.fee_growth_global_a, p3_pre_fg_a,
                            "p3 b_to_a: fee_growth_a changed {} -> {}", p3_pre_fg_a, post_p3.fee_growth_global_a);
                    }
                }

                // Per-swap user-vault transfer conservation
                {
                    let user_a_post = self.ctx.token_balance(&user_account_a);
                    let user_b_post = self.ctx.token_balance(&user_account_b);
                    let va_delta = (vault_a_post as i128) - (vault_a_pre as i128);
                    let ua_delta = (user_a_post as i128) - (pre_user_a as i128);
                    fuzz_assert_eq!(va_delta, -ua_delta,
                        "p3 swap: token A vault_delta ({}) != -user_delta ({})", va_delta, -ua_delta);
                    let vb_delta = (vault_b_post as i128) - (vault_b_pre as i128);
                    let ub_delta = (user_b_post as i128) - (pre_user_b as i128);
                    fuzz_assert_eq!(vb_delta, -ub_delta,
                        "p3 swap: token B vault_delta ({}) != -user_delta ({})", vb_delta, -ub_delta);
                }

                // Postcondition: protocol_fee_rate must NOT change during swap
                // (fee_rate CAN change for adaptive fee pools — it's dynamic based on volatility)
                if let Ok(post_p3) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
                    fuzz_assert_eq!(post_p3.protocol_fee_rate, p3_pre_proto_rate,
                        "p3 swap: protocol_fee_rate changed {} -> {} (should be immutable during swap)",
                        p3_pre_proto_rate, post_p3.protocol_fee_rate);
                }

                debug_print!("[SWAP_P3] SUCCESS: {} amount={} user={}",
                    if a_to_b { "A->B" } else { "B->A" }, amount, user_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SWAP_P3] TX_FAILED: {} amount={} user={}",
                    if a_to_b { "A->B" } else { "B->A" }, amount, user_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SWAP_P3] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::SWAP_P3, success);
        success
    }

    /// SwapV2 on pool three (exercises V2 code path on adaptive fee pool)
    pub fn action_swap_v2_pool_three(
        &mut self,
        #[range(0..3)] user_idx: usize,
        amount: u64,
        a_to_b: bool,
    ) -> bool {
        let pool_three = match &self.pool_three {
            Some(p) => p.clone(),
            None => return false,
        };

        let amount = (amount % 1_000_000) + 1;
        let user = &self.users[user_idx];

        if pool_three.tick_arrays.len() < 3 {
            return false;
        }

        let sqrt_price_limit = if a_to_b { MIN_SQRT_PRICE_X64 } else { MAX_SQRT_PRICE_X64 };

        let (user_account_a, user_account_b) = if pool_three.token_mint_a == self.pool.token_mint_a {
            (user.token_account_a, user.token_account_d)
        } else {
            (user.token_account_d, user.token_account_a)
        };

        let (tick_array_0, tick_array_1, tick_array_2) = self.get_tick_arrays_for_swap_pool(&pool_three, a_to_b);

        // Pre-swap snapshots for postconditions
        let v2_va_pre = self.ctx.token_balance(&pool_three.token_vault_a);
        let v2_vb_pre = self.ctx.token_balance(&pool_three.token_vault_b);
        let v2_ua_pre = self.ctx.token_balance(&user_account_a);
        let v2_ub_pre = self.ctx.token_balance(&user_account_b);
        let (v2_p3_pre_proto_a, v2_p3_pre_proto_b, v2_p3_pre_sqrt_price, v2_p3_pre_fg_a, v2_p3_pre_fg_b,
             v2_p3_pre_proto_rate, v2_p3_pre_reward_ts) =
            self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool)
            .map(|s| (s.protocol_fee_owed_a, s.protocol_fee_owed_b, s.sqrt_price,
                       s.fee_growth_global_a, s.fee_growth_global_b,
                       s.protocol_fee_rate, s.reward_last_updated_timestamp))
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
                token_authority: user.keypair.pubkey(),
                whirlpool: pool_three.whirlpool,
                token_mint_a: pool_three.token_mint_a,
                token_mint_b: pool_three.token_mint_b,
                token_owner_account_a: user_account_a,
                token_vault_a: pool_three.token_vault_a,
                token_owner_account_b: user_account_b,
                token_vault_b: pool_three.token_vault_b,
                tick_array_0,
                tick_array_1,
                tick_array_2,
                oracle: pool_three.oracle,
                token_program_a: spl_token::ID,
                token_program_b: spl_token::ID,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Per-swap vault direction + transfer conservation
                let v2_va_post = self.ctx.token_balance(&pool_three.token_vault_a);
                let v2_vb_post = self.ctx.token_balance(&pool_three.token_vault_b);
                let v2_ua_post = self.ctx.token_balance(&user_account_a);
                let v2_ub_post = self.ctx.token_balance(&user_account_b);
                if a_to_b {
                    fuzz_assert!(v2_va_post >= v2_va_pre,
                        "p3_v2 a_to_b: vault_a decreased {} -> {}", v2_va_pre, v2_va_post);
                    fuzz_assert!(v2_vb_post <= v2_vb_pre,
                        "p3_v2 a_to_b: vault_b increased {} -> {}", v2_vb_pre, v2_vb_post);
                } else {
                    fuzz_assert!(v2_vb_post >= v2_vb_pre,
                        "p3_v2 b_to_a: vault_b decreased {} -> {}", v2_vb_pre, v2_vb_post);
                    fuzz_assert!(v2_va_post <= v2_va_pre,
                        "p3_v2 b_to_a: vault_a increased {} -> {}", v2_va_pre, v2_va_post);
                }
                // Transfer conservation: vault delta == -user delta
                let va_d = (v2_va_post as i128) - (v2_va_pre as i128);
                let ua_d = (v2_ua_post as i128) - (v2_ua_pre as i128);
                fuzz_assert_eq!(va_d, -ua_d,
                    "p3_v2 swap: token A vault_delta ({}) != -user_delta ({})", va_d, -ua_d);
                let vb_d = (v2_vb_post as i128) - (v2_vb_pre as i128);
                let ub_d = (v2_ub_post as i128) - (v2_ub_pre as i128);
                fuzz_assert_eq!(vb_d, -ub_d,
                    "p3_v2 swap: token B vault_delta ({}) != -user_delta ({})", vb_d, -ub_d);
                // Protocol fee side isolation + fee_rate fraction bound
                if let Ok(post_p3) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
                    let pa = post_p3.protocol_fee_owed_a.saturating_sub(v2_p3_pre_proto_a);
                    let pb = post_p3.protocol_fee_owed_b.saturating_sub(v2_p3_pre_proto_b);
                    if a_to_b {
                        fuzz_assert_eq!(pb, 0, "p3_v2 a_to_b: protocol_fee_owed_b increased by {}", pb);
                        let input = v2_va_post.saturating_sub(v2_va_pre);
                        fuzz_assert!(pa <= input, "p3_v2 a_to_b: proto_fee_a ({}) > input ({})", pa, input);
                        if input > 0 {
                            let max_fee = (input as u128) * 100_000 / 1_000_000 + 100;
                            fuzz_assert!((pa as u128) <= max_fee,
                                "p3_v2 a_to_b: proto_fee {} > max_fee {} (input={})", pa, max_fee, input);
                        }
                    } else {
                        fuzz_assert_eq!(pa, 0, "p3_v2 b_to_a: protocol_fee_owed_a increased by {}", pa);
                        let input = v2_vb_post.saturating_sub(v2_vb_pre);
                        fuzz_assert!(pb <= input, "p3_v2 b_to_a: proto_fee_b ({}) > input ({})", pb, input);
                        if input > 0 {
                            let max_fee = (input as u128) * 100_000 / 1_000_000 + 100;
                            fuzz_assert!((pb as u128) <= max_fee,
                                "p3_v2 b_to_a: proto_fee {} > max_fee {} (input={})", pb, max_fee, input);
                        }
                    }
                }
                // sqrt_price direction check
                if let Ok(post_p3) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
                    if v2_p3_pre_sqrt_price > 0 && post_p3.sqrt_price > 0 {
                        if a_to_b {
                            fuzz_assert!(post_p3.sqrt_price <= v2_p3_pre_sqrt_price,
                                "p3_v2 a_to_b: sqrt_price increased {} -> {}", v2_p3_pre_sqrt_price, post_p3.sqrt_price);
                        } else {
                            fuzz_assert!(post_p3.sqrt_price >= v2_p3_pre_sqrt_price,
                                "p3_v2 b_to_a: sqrt_price decreased {} -> {}", v2_p3_pre_sqrt_price, post_p3.sqrt_price);
                        }
                    }
                    // fee_growth side isolation
                    if a_to_b {
                        fuzz_assert!(post_p3.fee_growth_global_a >= v2_p3_pre_fg_a,
                            "p3_v2 a_to_b: fee_growth_a decreased");
                        fuzz_assert_eq!(post_p3.fee_growth_global_b, v2_p3_pre_fg_b,
                            "p3_v2 a_to_b: fee_growth_b changed");
                    } else {
                        fuzz_assert!(post_p3.fee_growth_global_b >= v2_p3_pre_fg_b,
                            "p3_v2 b_to_a: fee_growth_b decreased");
                        fuzz_assert_eq!(post_p3.fee_growth_global_a, v2_p3_pre_fg_a,
                            "p3_v2 b_to_a: fee_growth_a changed");
                    }
                    // tick/price consistency
                    let lb = harness_sqrt_price_from_tick(post_p3.tick_current_index);
                    let ub = harness_sqrt_price_from_tick(post_p3.tick_current_index + 1);
                    fuzz_assert!(post_p3.sqrt_price >= lb && post_p3.sqrt_price <= ub,
                        "p3_v2 swap: sqrt_price {} not in [{}, {}] for tick {}",
                        post_p3.sqrt_price, lb, ub, post_p3.tick_current_index);
                    // protocol_fee_rate immutability (fee_rate CAN change due to adaptive fees)
                    fuzz_assert_eq!(post_p3.protocol_fee_rate, v2_p3_pre_proto_rate,
                        "p3_v2 swap: protocol_fee_rate changed {} -> {}",
                        v2_p3_pre_proto_rate, post_p3.protocol_fee_rate);
                    // reward_last_updated_timestamp monotonicity
                    fuzz_assert!(post_p3.reward_last_updated_timestamp >= v2_p3_pre_reward_ts,
                        "p3_v2 swap: reward_timestamp decreased {} -> {}",
                        v2_p3_pre_reward_ts, post_p3.reward_last_updated_timestamp);
                }
                // consumed <= amount check (exact-input)
                {
                    let consumed_p3 = if a_to_b {
                        v2_ua_pre.saturating_sub(self.ctx.token_balance(&user_account_a))
                    } else {
                        v2_ub_pre.saturating_sub(self.ctx.token_balance(&user_account_b))
                    };
                    fuzz_assert!(consumed_p3 <= amount,
                        "p3_v2 swap: consumed {} > amount {}", consumed_p3, amount);
                }
                debug_print!("[SWAP_V2_P3] SUCCESS: {} amount={}", if a_to_b { "A->B" } else { "B->A" }, amount);
                true
            }
            _ => {
                debug_print!("[SWAP_V2_P3] FAILED");
                false
            }
        };
        action_stats::record(&action_stats::SWAP_V2_P3, success);
        success
    }

    // ========================================================================
    // Adaptive Fee Management
    // ========================================================================

    /// Set default base fee rate on the adaptive fee tier
    pub fn action_set_default_base_fee_rate(&mut self, default_base_fee_rate: u16) -> bool {
        let adaptive_fee_tier = match self.adaptive_fee_tier {
            Some(aft) => aft,
            None => return false,
        };

        let default_base_fee_rate = (default_base_fee_rate % 10000) + 1; // 1-10000

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetDefaultBaseFeeRate {
                default_base_fee_rate,
            })
            .accounts(accounts::SetDefaultBaseFeeRate {
                whirlpools_config: self.config,
                adaptive_fee_tier,
                fee_authority: self.fee_authority.pubkey(),
            })
            .signers(&[&*self.fee_authority])
            .send();

        let success = matches!(&result, Ok(TxOutcome::Success { .. }));
        if success {
            debug_print!("[SET_DEFAULT_BASE_FEE] SUCCESS: rate={}", default_base_fee_rate);
        } else {
            debug_print!("[SET_DEFAULT_BASE_FEE] FAILED");
        }
        action_stats::record(&action_stats::SET_DEFAULT_BASE_FEE, success);
        success
    }

    /// Set delegated fee authority on the adaptive fee tier
    pub fn action_set_delegated_fee_authority(&mut self) -> bool {
        let adaptive_fee_tier = match self.adaptive_fee_tier {
            Some(aft) => aft,
            None => return false,
        };

        let new_authority = Rc::new(Keypair::new());
        // Fund the new authority
        let _ = self.ctx.create_account()
            .pubkey(new_authority.pubkey())
            .lamports(1_000_000_000)
            .owner(system_program::ID)
            .create();

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetDelegatedFeeAuthority {})
            .accounts(accounts::SetDelegatedFeeAuthority {
                whirlpools_config: self.config,
                adaptive_fee_tier,
                fee_authority: self.fee_authority.pubkey(),
                new_delegated_fee_authority: new_authority.pubkey(),
            })
            .signers(&[&*self.fee_authority])
            .send();

        let success = matches!(&result, Ok(TxOutcome::Success { .. }));
        if success {
            self.delegated_fee_authority = new_authority;
            debug_print!("[SET_DELEGATED_FEE_AUTH] SUCCESS");
        } else {
            debug_print!("[SET_DELEGATED_FEE_AUTH] FAILED");
        }
        action_stats::record(&action_stats::SET_DELEGATED_FEE_AUTH, success);
        success
    }

    /// Set fee rate on pool three via delegated fee authority
    pub fn action_fee_rate_by_delegated_authority(&mut self, fee_rate: u16) -> bool {
        let pool_three = match &self.pool_three {
            Some(p) => p,
            None => return false,
        };
        let adaptive_fee_tier = match self.adaptive_fee_tier {
            Some(aft) => aft,
            None => return false,
        };

        let fee_rate = (fee_rate % 10000) + 1; // 1-10000

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetFeeRateByDelegatedFeeAuthority {
                fee_rate,
            })
            .accounts(accounts::SetFeeRateByDelegatedFeeAuthority {
                whirlpool: pool_three.whirlpool,
                adaptive_fee_tier,
                delegated_fee_authority: self.delegated_fee_authority.pubkey(),
            })
            .signers(&[&*self.delegated_fee_authority])
            .send();

        let success = matches!(&result, Ok(TxOutcome::Success { .. }));
        if success {
            debug_print!("[FEE_RATE_BY_DELEGATED] SUCCESS: rate={}", fee_rate);
        } else {
            debug_print!("[FEE_RATE_BY_DELEGATED] FAILED");
        }
        action_stats::record(&action_stats::FEE_RATE_BY_DELEGATED, success);
        success
    }

    /// Set preset adaptive fee constants on the adaptive fee tier
    pub fn action_set_preset_adaptive_fee_constants(
        &mut self,
        filter_period: u16,
        decay_period: u16,
        reduction_factor: u16,
    ) -> bool {
        let adaptive_fee_tier = match self.adaptive_fee_tier {
            Some(aft) => aft,
            None => return false,
        };

        let filter_period = (filter_period % 100) + 1;
        let decay_period = (decay_period % 600) + 10;
        let reduction_factor = (reduction_factor % 100) + 1;

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetPresetAdaptiveFeeConstants {
                filter_period,
                decay_period,
                reduction_factor,
                adaptive_fee_control_factor: 100,
                max_volatility_accumulator: 1000,
                tick_group_size: 1,
                major_swap_threshold_ticks: 10,
            })
            .accounts(accounts::SetPresetAdaptiveFeeConstants {
                whirlpools_config: self.config,
                adaptive_fee_tier,
                fee_authority: self.fee_authority.pubkey(),
            })
            .signers(&[&*self.fee_authority])
            .send();

        let success = matches!(&result, Ok(TxOutcome::Success { .. }));
        if success {
            debug_print!("[SET_PRESET_ADAPTIVE] SUCCESS: fp={} dp={} rf={}", filter_period, decay_period, reduction_factor);
        } else {
            debug_print!("[SET_PRESET_ADAPTIVE] FAILED");
        }
        action_stats::record(&action_stats::SET_PRESET_ADAPTIVE_FEE, success);
        success
    }

    /// Set initialize pool authority on the adaptive fee tier
    pub fn action_set_initialize_pool_authority(&mut self) -> bool {
        let adaptive_fee_tier = match self.adaptive_fee_tier {
            Some(aft) => aft,
            None => return false,
        };

        // Set to default (permissionless) or a random authority
        let new_authority = Pubkey::default();

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetInitializePoolAuthority {})
            .accounts(accounts::SetInitializePoolAuthority {
                whirlpools_config: self.config,
                adaptive_fee_tier,
                fee_authority: self.fee_authority.pubkey(),
                new_initialize_pool_authority: new_authority,
            })
            .signers(&[&*self.fee_authority])
            .send();

        let success = matches!(&result, Ok(TxOutcome::Success { .. }));
        if success {
            debug_print!("[SET_INIT_POOL_AUTH] SUCCESS");
        } else {
            debug_print!("[SET_INIT_POOL_AUTH] FAILED");
        }
        action_stats::record(&action_stats::SET_INIT_POOL_AUTH, success);
        success
    }

    // ========================================================================
    // Pool Three Positions & Liquidity
    // ========================================================================

    /// Open a position on pool three (adaptive fee pool)
    pub fn action_open_position_pool_three(&mut self, #[range(0..3)] user_idx: usize) -> bool {
        let pool_three = match &self.pool_three {
            Some(p3) => p3,
            None => return false,
        };
        if self.pool_three_positions.len() >= 10 {
            return false;
        }

        let user = &self.users[user_idx];

        let tick_lower_index = -((user_idx as i32 + 3) * (TICK_SPACING as i32));
        let tick_upper_index = (user_idx as i32 + 3) * (TICK_SPACING as i32);

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
                whirlpool: pool_three.whirlpool,
            })
            .signers(&[&*user.keypair, &position_mint])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.pool_three_positions.push(PositionData {
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
                debug_print!("[OPEN_POS_P3] SUCCESS: ticks=[{},{}]", tick_lower_index, tick_upper_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[OPEN_POS_P3] TX_FAILED");
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[OPEN_POS_P3] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::OPEN_POSITION_P3, success);
        success
    }

    /// Increase liquidity on a pool three position
    pub fn action_increase_liquidity_pool_three(
        &mut self,
        #[range(0..10)] pos_idx: usize,
        liquidity_amount: u64,
    ) -> bool {
        let pool_three = match &self.pool_three {
            Some(p3) => p3.clone(),
            None => return false,
        };
        if pos_idx >= self.pool_three_positions.len() {
            return false;
        }

        let liquidity_amount = ((liquidity_amount % 1_000_000_000) + 1_000) as u128;
        let position = &self.pool_three_positions[pos_idx];
        let user = &self.users[position.owner_idx];

        // Map user token accounts to pool three's mint ordering
        let (user_account_a, user_account_b) = if pool_three.token_mint_a == self.pool.token_mint_a {
            (user.token_account_a, user.token_account_d)
        } else {
            (user.token_account_d, user.token_account_a)
        };

        let tick_array_lower = self.get_tick_array_for_tick_pool(&pool_three, position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick_pool(&pool_three, position.tick_upper_index);

        // Pre-snapshots for postconditions
        let pre_vault_a = self.ctx.token_balance(&pool_three.token_vault_a);
        let pre_vault_b = self.ctx.token_balance(&pool_three.token_vault_b);
        let pre_user_a = self.ctx.token_balance(&user_account_a);
        let pre_user_b = self.ctx.token_balance(&user_account_b);
        let pre_pos_p3 = self.ctx.read_anchor_account::<whirlpool::state::Position>(&position.position).ok();
        let pre_liq = pre_pos_p3.as_ref().map(|p| p.liquidity).unwrap_or(0);
        let (pre_fee_a_p3, pre_fee_b_p3) = pre_pos_p3.as_ref()
            .map(|p| (p.fee_owed_a, p.fee_owed_b)).unwrap_or((0, 0));
        let (pre_pool_liq, pre_pool_tick, pre_sqrt_price_p3) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool)
            .map(|s| (s.liquidity, s.tick_current_index, s.sqrt_price)).unwrap_or((0, 0, 0));

        let result = self.ctx.program(self.program_id)
            .call(instruction::IncreaseLiquidity {
                liquidity_amount,
                token_max_a: u64::MAX,
                token_max_b: u64::MAX,
            })
            .accounts(accounts::IncreaseLiquidity {
                whirlpool: pool_three.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_owner_account_a: user_account_a,
                token_owner_account_b: user_account_b,
                token_vault_a: pool_three.token_vault_a,
                token_vault_b: pool_three.token_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Transfer conservation postcondition
                let post_vault_a = self.ctx.token_balance(&pool_three.token_vault_a);
                let post_vault_b = self.ctx.token_balance(&pool_three.token_vault_b);
                let post_user_a = self.ctx.token_balance(&user_account_a);
                let post_user_b = self.ctx.token_balance(&user_account_b);
                fuzz_assert_eq!(post_vault_a.saturating_sub(pre_vault_a), pre_user_a.saturating_sub(post_user_a),
                    "p3 increase_liq: vault_a/user_a mismatch");
                fuzz_assert_eq!(post_vault_b.saturating_sub(pre_vault_b), pre_user_b.saturating_sub(post_user_b),
                    "p3 increase_liq: vault_b/user_b mismatch");

                // Exact liquidity amount + fee_owed monotonicity postcondition
                if let Ok(post_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.pool_three_positions[pos_idx].position) {
                    fuzz_assert!(post_state.liquidity >= pre_liq,
                        "p3 increase_liq: liquidity decreased {} -> {}", pre_liq, post_state.liquidity);
                    fuzz_assert_eq!(post_state.liquidity, pre_liq + liquidity_amount,
                        "p3 increase_liq: expected {} got {}", pre_liq + liquidity_amount, post_state.liquidity);
                    fuzz_assert!(post_state.fee_owed_a >= pre_fee_a_p3,
                        "p3 increase_liq: fee_owed_a decreased {} -> {}", pre_fee_a_p3, post_state.fee_owed_a);
                    fuzz_assert!(post_state.fee_owed_b >= pre_fee_b_p3,
                        "p3 increase_liq: fee_owed_b decreased {} -> {}", pre_fee_b_p3, post_state.fee_owed_b);
                }
                // Pool liquidity coupling: in-range increase changes pool.liquidity
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
                    // sqrt_price and tick must NOT change during liquidity ops
                    fuzz_assert_eq!(post_pool.sqrt_price, pre_sqrt_price_p3,
                        "p3 increase_liq: sqrt_price changed {} -> {}",
                        pre_sqrt_price_p3, post_pool.sqrt_price);
                    fuzz_assert_eq!(post_pool.tick_current_index, pre_pool_tick,
                        "p3 increase_liq: tick changed {} -> {}",
                        pre_pool_tick, post_pool.tick_current_index);
                    let pos = &self.pool_three_positions[pos_idx];
                    let in_range = pos.tick_lower_index <= pre_pool_tick && pre_pool_tick < pos.tick_upper_index;
                    if in_range {
                        fuzz_assert_eq!(post_pool.liquidity, pre_pool_liq + liquidity_amount,
                            "p3 increase_liq: in-range pos {} but pool liq {} != expected {}",
                            pos_idx, post_pool.liquidity, pre_pool_liq + liquidity_amount);
                    } else {
                        fuzz_assert_eq!(post_pool.liquidity, pre_pool_liq,
                            "p3 increase_liq: out-of-range pos {} changed pool liq {} -> {}",
                            pos_idx, pre_pool_liq, post_pool.liquidity);
                    }
                }

                self.pool_three_positions[pos_idx].has_liquidity = true;
                debug_print!("[INCREASE_LIQ_P3] SUCCESS: pos={} liq={}", pos_idx, liquidity_amount);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[INCREASE_LIQ_P3] TX_FAILED");
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[INCREASE_LIQ_P3] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::INCREASE_LIQ_P3, success);
        success
    }

    /// Decrease liquidity on a pool three position
    pub fn action_decrease_liquidity_pool_three(
        &mut self,
        #[range(0..10)] pos_idx: usize,
        liquidity_amount: u64,
    ) -> bool {
        let pool_three = match &self.pool_three {
            Some(p3) => p3.clone(),
            None => return false,
        };
        if pos_idx >= self.pool_three_positions.len() {
            return false;
        }
        if !self.pool_three_positions[pos_idx].has_liquidity {
            return false;
        }

        let liquidity_amount = ((liquidity_amount % 100_000) + 1) as u128;
        let position = &self.pool_three_positions[pos_idx];
        let user = &self.users[position.owner_idx];

        let (user_account_a, user_account_b) = if pool_three.token_mint_a == self.pool.token_mint_a {
            (user.token_account_a, user.token_account_d)
        } else {
            (user.token_account_d, user.token_account_a)
        };

        let tick_array_lower = self.get_tick_array_for_tick_pool(&pool_three, position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick_pool(&pool_three, position.tick_upper_index);

        // Pre-snapshots for transfer conservation and pool liquidity coupling
        let pre_vault_a = self.ctx.token_balance(&pool_three.token_vault_a);
        let pre_vault_b = self.ctx.token_balance(&pool_three.token_vault_b);
        let pre_user_a = self.ctx.token_balance(&user_account_a);
        let pre_user_b = self.ctx.token_balance(&user_account_b);
        let pre_pos_p3d = self.ctx.read_anchor_account::<whirlpool::state::Position>(&position.position).ok();
        let pre_liq = pre_pos_p3d.as_ref().map(|p| p.liquidity).unwrap_or(0);
        let (pre_fee_a_p3d, pre_fee_b_p3d) = pre_pos_p3d.as_ref()
            .map(|p| (p.fee_owed_a, p.fee_owed_b)).unwrap_or((0, 0));
        let (pre_pool_liq, pre_pool_tick, pre_sqrt_price_p3d) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool)
            .map(|s| (s.liquidity, s.tick_current_index, s.sqrt_price)).unwrap_or((0, 0, 0));

        let result = self.ctx.program(self.program_id)
            .call(instruction::DecreaseLiquidity {
                liquidity_amount,
                token_min_a: 0,
                token_min_b: 0,
            })
            .accounts(accounts::DecreaseLiquidity {
                whirlpool: pool_three.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_owner_account_a: user_account_a,
                token_owner_account_b: user_account_b,
                token_vault_a: pool_three.token_vault_a,
                token_vault_b: pool_three.token_vault_b,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Transfer conservation postcondition
                let post_vault_a = self.ctx.token_balance(&pool_three.token_vault_a);
                let post_vault_b = self.ctx.token_balance(&pool_three.token_vault_b);
                let post_user_a = self.ctx.token_balance(&user_account_a);
                let post_user_b = self.ctx.token_balance(&user_account_b);
                fuzz_assert_eq!(pre_vault_a.saturating_sub(post_vault_a), post_user_a.saturating_sub(pre_user_a),
                    "p3 decrease_liq: vault_a/user_a mismatch");
                fuzz_assert_eq!(pre_vault_b.saturating_sub(post_vault_b), post_user_b.saturating_sub(pre_user_b),
                    "p3 decrease_liq: vault_b/user_b mismatch");

                // Exact liquidity amount + fee_owed monotonicity postcondition + check if drained
                if let Ok(pos_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.pool_three_positions[pos_idx].position) {
                    fuzz_assert!(pos_state.liquidity <= pre_liq,
                        "p3 decrease_liq: liquidity increased {} -> {}", pre_liq, pos_state.liquidity);
                    // If position had enough liquidity, exact delta should match
                    if pre_liq >= liquidity_amount {
                        fuzz_assert_eq!(pos_state.liquidity, pre_liq - liquidity_amount,
                            "p3 decrease_liq: expected {} got {}", pre_liq - liquidity_amount, pos_state.liquidity);
                    }
                    // Fee checkpoint monotonicity: fee_owed can only increase during liquidity ops
                    fuzz_assert!(pos_state.fee_owed_a >= pre_fee_a_p3d,
                        "p3 decrease_liq: fee_owed_a decreased {} -> {}", pre_fee_a_p3d, pos_state.fee_owed_a);
                    fuzz_assert!(pos_state.fee_owed_b >= pre_fee_b_p3d,
                        "p3 decrease_liq: fee_owed_b decreased {} -> {}", pre_fee_b_p3d, pos_state.fee_owed_b);
                    if pos_state.liquidity == 0 {
                        self.pool_three_positions[pos_idx].has_liquidity = false;
                    }
                }
                // Pool liquidity coupling: in-range decrease changes pool.liquidity
                if let Ok(post_pool) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
                    // sqrt_price and tick must NOT change during liquidity ops
                    fuzz_assert_eq!(post_pool.sqrt_price, pre_sqrt_price_p3d,
                        "p3 decrease_liq: sqrt_price changed {} -> {}",
                        pre_sqrt_price_p3d, post_pool.sqrt_price);
                    fuzz_assert_eq!(post_pool.tick_current_index, pre_pool_tick,
                        "p3 decrease_liq: tick changed {} -> {}",
                        pre_pool_tick, post_pool.tick_current_index);
                    let pos = &self.pool_three_positions[pos_idx];
                    let in_range = pos.tick_lower_index <= pre_pool_tick && pre_pool_tick < pos.tick_upper_index;
                    if in_range {
                        fuzz_assert_eq!(post_pool.liquidity, pre_pool_liq - liquidity_amount,
                            "p3 decrease_liq: in-range pos {} but pool liq {} != expected {}",
                            pos_idx, post_pool.liquidity, pre_pool_liq - liquidity_amount);
                    } else {
                        fuzz_assert_eq!(post_pool.liquidity, pre_pool_liq,
                            "p3 decrease_liq: out-of-range pos {} changed pool liq {} -> {}",
                            pos_idx, pre_pool_liq, post_pool.liquidity);
                    }
                }
                debug_print!("[DECREASE_LIQ_P3] SUCCESS: pos={} liq={}", pos_idx, liquidity_amount);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[DECREASE_LIQ_P3] TX_FAILED");
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[DECREASE_LIQ_P3] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::DECREASE_LIQ_P3, success);
        success
    }
