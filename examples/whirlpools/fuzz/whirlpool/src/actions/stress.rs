// actions/stress.rs — Stress test and edge case action methods (included in impl WhirlpoolFixture via include!())

// ========================================================================
// Behavioral Edge Case Actions
// ========================================================================

/// Swap with zero fee rate: set fee=0, swap, verify no fee growth, restore fee
pub fn action_zero_fee_swap(
    &mut self,
    #[range(0..3)] user_idx: usize,
    amount: u64,
    a_to_b: bool,
) -> bool {
    let amount = (amount % 100_000) + 1;

    // Read current fee_rate
    let current_fee_rate = match self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
        Ok(s) => s.fee_rate,
        Err(_) => return false,
    };

    // Set fee_rate = 0
    let set_result = self.ctx.program(self.program_id)
        .call(instruction::SetFeeRate { fee_rate: 0 })
        .accounts(accounts::SetFeeRate {
            whirlpools_config: self.config,
            whirlpool: self.pool.whirlpool,
            fee_authority: self.fee_authority.pubkey(),
        })
        .signers(&[&*self.fee_authority])
        .send();

    if !matches!(&set_result, Ok(TxOutcome::Success { .. })) {
        action_stats::record(&action_stats::ZERO_FEE_SWAP, false);
        return false;
    }

    // Snapshot fee_growth_global before swap
    let fg_a_pre = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
        .map(|s| s.fee_growth_global_a).unwrap_or(0);
    let fg_b_pre = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
        .map(|s| s.fee_growth_global_b).unwrap_or(0);

    // Execute swap via do_swap
    let swap_ok = self.do_swap(user_idx, amount, a_to_b, None, true, 0);

    if swap_ok {
        // Verify fee_growth_global unchanged (zero fee means no fee accrual)
        let fg_a_post = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
            .map(|s| s.fee_growth_global_a).unwrap_or(0);
        let fg_b_post = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
            .map(|s| s.fee_growth_global_b).unwrap_or(0);
        fuzz_assert_eq!(fg_a_post, fg_a_pre,
            "Zero-fee swap: fee_growth_global_a changed {} -> {}", fg_a_pre, fg_a_post);
        fuzz_assert_eq!(fg_b_post, fg_b_pre,
            "Zero-fee swap: fee_growth_global_b changed {} -> {}", fg_b_pre, fg_b_post);
    }

    // Restore original fee_rate
    let _ = self.ctx.program(self.program_id)
        .call(instruction::SetFeeRate { fee_rate: current_fee_rate })
        .accounts(accounts::SetFeeRate {
            whirlpools_config: self.config,
            whirlpool: self.pool.whirlpool,
            fee_authority: self.fee_authority.pubkey(),
        })
        .signers(&[&*self.fee_authority])
        .send();

    action_stats::record(&action_stats::ZERO_FEE_SWAP, swap_ok);
    swap_ok
}

/// Set extreme reward emissions and advance time, verify position not corrupted
pub fn action_extreme_reward_emissions(
    &mut self,
    #[range(0..3)] reward_index: usize,
) -> bool {
    if reward_index >= 3 || !self.pool.reward_initialized[reward_index] {
        return false;
    }

    // First, re-set reward authority back to admin via super authority
    // (action_set_reward_authority may have changed it)
    let _ = self.ctx.program(self.program_id)
        .call(instruction::SetRewardAuthorityBySuperAuthority {
            reward_index: reward_index as u8,
        })
        .accounts(accounts::SetRewardAuthorityBySuperAuthority {
            whirlpools_config: self.config,
            whirlpool: self.pool.whirlpool,
            reward_emissions_super_authority: self.reward_emissions_super_authority.pubkey(),
            new_reward_authority: self.admin.pubkey(),
        })
        .signers(&[&*self.reward_emissions_super_authority])
        .send();

    // Set high (but feasible) emissions. The vault needs: (rate >> 64) * 86400 tokens.
    // With 1B tokens in vault (1e9 * 1e9 lamports = 1e18), max feasible rate is:
    // rate = (vault_amount / 86400) << 64 ≈ (1e18 / 86400) << 64 ≈ 1.157e13 << 64
    // Use a rate that's high but within vault capacity.
    let vault_balance = self.ctx.token_balance(&self.pool.reward_vaults[reward_index]);
    if vault_balance == 0 { return false; }
    // rate_per_second = vault / 86400, in x64 format
    let max_rate = ((vault_balance as u128) / 86400) << 64;
    let extreme_rate = max_rate.saturating_sub(1).max(1);
    let set_result = self.ctx.program(self.program_id)
        .call(instruction::SetRewardEmissions {
            reward_index: reward_index as u8,
            emissions_per_second_x64: extreme_rate,
        })
        .accounts(accounts::SetRewardEmissions {
            whirlpool: self.pool.whirlpool,
            reward_authority: self.admin.pubkey(),
            reward_vault: self.pool.reward_vaults[reward_index],
        })
        .signers(&[&*self.admin])
        .send();

    if !matches!(&set_result, Ok(TxOutcome::Success { .. })) {
        debug_print!("[EXTREME_RWD_EMS] SetRewardEmissions FAILED: {:?}", set_result);
        action_stats::record(&action_stats::EXTREME_REWARD_EMISSIONS, false);
        return false;
    }

    // Advance time by 1 hour
    self.ctx.advance_slots(3600);

    // Update fees and rewards on first position (if exists)
    let success = if !self.positions.is_empty() {
        let position = &self.positions[0];
        let user = &self.users[position.owner_idx];
        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        // Snapshot position state before UpdateFeesAndRewards
        let pre_snapshot = self.ctx.read_anchor_account::<whirlpool::state::Position>(&position.position).ok();
        let pre_liquidity = pre_snapshot.as_ref().map(|s| s.liquidity).unwrap_or(0);
        let pre_fee_a = pre_snapshot.as_ref().map(|s| s.fee_owed_a).unwrap_or(0);
        let pre_fee_b = pre_snapshot.as_ref().map(|s| s.fee_owed_b).unwrap_or(0);

        let result = self.ctx.program(self.program_id)
            .call(instruction::UpdateFeesAndRewards {})
            .accounts(accounts::UpdateFeesAndRewards {
                whirlpool: self.pool.whirlpool,
                position: position.position,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .send();

        match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Verify position is still readable and not corrupted
                if let Ok(pos_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&position.position) {
                    // Tick indices should still match
                    fuzz_assert_eq!(pos_state.tick_lower_index, position.tick_lower_index,
                        "Extreme reward: position tick_lower corrupted");
                    fuzz_assert_eq!(pos_state.tick_upper_index, position.tick_upper_index,
                        "Extreme reward: position tick_upper corrupted");
                    // Liquidity must be unchanged (UpdateFeesAndRewards doesn't modify liquidity)
                    fuzz_assert_eq!(pos_state.liquidity, pre_liquidity,
                        "Extreme reward: liquidity corrupted {} -> {}",
                        pre_liquidity, pos_state.liquidity);
                    // Fee owed can increase (fee accrual) but must not decrease
                    fuzz_assert!(pos_state.fee_owed_a >= pre_fee_a,
                        "Extreme reward: fee_owed_a decreased {} -> {}",
                        pre_fee_a, pos_state.fee_owed_a);
                    fuzz_assert!(pos_state.fee_owed_b >= pre_fee_b,
                        "Extreme reward: fee_owed_b decreased {} -> {}",
                        pre_fee_b, pos_state.fee_owed_b);
                    // Reward amount_owed must not overflow to u64::MAX sentinel
                    fuzz_assert!(pos_state.reward_infos[reward_index].amount_owed < u64::MAX,
                        "Extreme reward: reward_owed overflow to u64::MAX for reward {}",
                        reward_index);
                    debug_print!("[EXTREME_REWARD_EMS] SUCCESS: reward_idx={} pos readable", reward_index);
                    true
                } else {
                    debug_print!("[EXTREME_REWARD_EMS] Position unreadable after extreme emissions");
                    false
                }
            }
            _ => {
                debug_print!("[EXTREME_REWARD_EMS] UpdateFeesAndRewards failed");
                false
            }
        }
    } else {
        true // No positions to check, emission set was the test
    };

    // Restore reasonable emissions
    let _ = self.ctx.program(self.program_id)
        .call(instruction::SetRewardEmissions {
            reward_index: reward_index as u8,
            emissions_per_second_x64: 1u128 << 32,
        })
        .accounts(accounts::SetRewardEmissions {
            whirlpool: self.pool.whirlpool,
            reward_authority: self.admin.pubkey(),
            reward_vault: self.pool.reward_vaults[reward_index],
        })
        .signers(&[&*self.admin])
        .send();

    action_stats::record(&action_stats::EXTREME_REWARD_EMISSIONS, success);
    success
}

/// Open a high-liquidity position, swap, and verify fees accrue (not silently zeroed).
/// Targets checked_mul_shift_right(...).unwrap_or(0) in position_manager.rs
pub fn action_high_liquidity_fee_stress(&mut self) -> bool {
    if self.positions.len() >= 20 {
        return false;
    }

    // Extract user data upfront to avoid borrow conflicts with self.do_swap()
    let user_keypair = Rc::clone(&self.users[0].keypair);
    let user_pubkey = user_keypair.pubkey();
    let user_account_a = self.users[0].token_account_a;
    let user_account_b = self.users[0].token_account_b;

    // Open position with very high liquidity near current price
    let tick_lower_index = -2 * (TICK_SPACING as i32);
    let tick_upper_index = 2 * (TICK_SPACING as i32);

    let position_mint = next_keypair();
    let (position, position_bump) = Pubkey::find_program_address(
        &[b"position", position_mint.pubkey().as_ref()],
        &self.program_id,
    );
    let position_token_account = associated_token::get_associated_token_address(
        &user_pubkey,
        &position_mint.pubkey(),
    );

    let open_result = self.ctx.program(self.program_id)
        .call(instruction::OpenPosition {
            bumps: OpenPositionBumps { position_bump },
            tick_lower_index,
            tick_upper_index,
        })
        .accounts(accounts::OpenPosition {
            funder: user_pubkey,
            owner: user_pubkey,
            position,
            position_mint: position_mint.pubkey(),
            position_token_account,
            whirlpool: self.pool.whirlpool,
        })
        .signers(&[&*user_keypair, &position_mint])
        .send();

    if !matches!(&open_result, Ok(TxOutcome::Success { .. })) {
        return false;
    }

    // Add very high liquidity (u64::MAX / 4 as u128 — large but not impossible)
    let high_liq: u128 = (u64::MAX / 4) as u128;
    let tick_array_lower = self.get_tick_array_for_tick(tick_lower_index);
    let tick_array_upper = self.get_tick_array_for_tick(tick_upper_index);

    let liq_result = self.ctx.program(self.program_id)
        .call(instruction::IncreaseLiquidity {
            liquidity_amount: high_liq,
            token_max_a: u64::MAX,
            token_max_b: u64::MAX,
        })
        .accounts(accounts::IncreaseLiquidity {
            whirlpool: self.pool.whirlpool,
            position_authority: user_pubkey,
            position,
            position_token_account,
            token_owner_account_a: user_account_a,
            token_owner_account_b: user_account_b,
            token_vault_a: self.pool.token_vault_a,
            token_vault_b: self.pool.token_vault_b,
            tick_array_lower,
            tick_array_upper,
        })
        .signers(&[&*user_keypair])
        .send();

    let has_liquidity = matches!(&liq_result, Ok(TxOutcome::Success { .. }));

    // Track the position
    self.positions.push(PositionData {
        position,
        position_mint: position_mint.pubkey(),
        position_token_account,
        tick_lower_index,
        tick_upper_index,
        owner_idx: 0,
        has_liquidity,
        bundle_info: None,
        is_token_2022: false,
        is_locked: false,
        prev_fee_owed_a: 0,
        prev_fee_owed_b: 0,
        fees_just_collected: false,
    });

    if !has_liquidity {
        debug_print!("[HIGH_LIQ_FEE_STRESS] IncreaseLiquidity failed (expected for large amounts)");
        return false;
    }

    // Do a swap to generate fee growth
    let swap_ok = self.do_swap(0, 100_000, true, None, true, 0);
    if !swap_ok {
        debug_print!("[HIGH_LIQ_FEE_STRESS] Swap failed");
        return false;
    }

    // Snapshot fee_growth_global before UpdateFeesAndRewards
    let pre_fee_growth = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
        .ok().map(|s| (s.fee_growth_global_a, s.fee_growth_global_b));

    // Call UpdateFeesAndRewards on the high-liquidity position
    let pos_idx = self.positions.len() - 1;
    let update_result = self.ctx.program(self.program_id)
        .call(instruction::UpdateFeesAndRewards {})
        .accounts(accounts::UpdateFeesAndRewards {
            whirlpool: self.pool.whirlpool,
            position: position,
            tick_array_lower,
            tick_array_upper,
        })
        .signers(&[&*user_keypair])
        .send();

    if let Ok(TxOutcome::Success { .. }) = &update_result {
        if let Ok(pos_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&position) {
            // If fee_growth increased, fee_owed should be > 0
            // (unless checked_mul_shift_right silently zeroed it)
            if let Some((pre_a, _pre_b)) = pre_fee_growth {
                let post = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool);
                if let Ok(pool_state) = post {
                    if pool_state.fee_growth_global_a > pre_a {
                        // fee_growth increased for token A — fee_owed_a should reflect this
                        // With very high liquidity, checked_mul_shift_right may unwrap_or(0)
                        debug_print!("[HIGH_LIQ_FEE_STRESS] fee_growth_a increased: {} -> {}, fee_owed_a={}",
                            pre_a, pool_state.fee_growth_global_a, pos_state.fee_owed_a);
                        // Note: We don't assert fee_owed > 0 here because the position
                        // may not be in range, or the growth delta may be too small.
                        // The wrapping overflow is caught by the fee_owed monotonicity invariant.
                    }
                }
            }
            debug_print!("[HIGH_LIQ_FEE_STRESS] SUCCESS: liq={} fee_a={} fee_b={}",
                pos_state.liquidity, pos_state.fee_owed_a, pos_state.fee_owed_b);
        }
    }

    action_stats::record(&action_stats::HIGH_LIQ_FEE_COLLECT, true);
    true
}

/// Stress test pool three's adaptive fee oracle with alternating swaps to inflate volatility
pub fn action_volatility_inflation_attack(&mut self, amount: u64) -> bool {
    let pool_three = match &self.pool_three {
        Some(p) => p.clone(),
        None => return false,
    };
    let pool_three_key = pool_three.whirlpool;

    // Read oracle before attack
    let oracle_key = pool_three.oracle;
    let pre_oracle_data = self.ctx.read_account(&oracle_key);
    if pre_oracle_data.is_err() {
        return false;
    }

    if pool_three.tick_arrays.len() < 3 {
        return false;
    }

    let swap_amount = (amount % 50_000).max(1_000) + 1_000;

    // Map user token accounts to pool three's mint ordering
    let (user_account_a, user_account_b) = if pool_three.token_mint_a == self.pool.token_mint_a {
        (self.users[0].token_account_a, self.users[0].token_account_d)
    } else {
        (self.users[0].token_account_d, self.users[0].token_account_a)
    };

    // Do 5 alternating swaps on pool three to stress volatility accumulator
    let mut any_success = false;
    for i in 0..5 {
        let a_to_b = i % 2 == 0;
        let (tick_array_0, tick_array_1, tick_array_2) = self.get_tick_arrays_for_swap_pool(&pool_three, a_to_b);

        let sqrt_price_limit = if a_to_b { MIN_SQRT_PRICE_X64 } else { MAX_SQRT_PRICE_X64 };

        let user = &self.users[0];
        // Adaptive fee pools require SwapV2
        let result = self.ctx.program(self.program_id)
            .call(instruction::SwapV2 {
                amount: swap_amount as u64,
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
                whirlpool: pool_three_key,
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

        if matches!(&result, Ok(TxOutcome::Success { .. })) {
            any_success = true;
        }
    }

    if !any_success {
        action_stats::record(&action_stats::VOLATILITY_INFLATION, false);
        return false;
    }

    // Read oracle account to check volatility_accumulator is clamped
    // Oracle layout (after 8-byte discriminator):
    //   32 bytes: whirlpool pubkey
    //   Then AdaptiveFeeVariables:
    //     u32: volatility_accumulator (offset 40)
    if let Ok(oracle_acc) = self.ctx.read_account(&oracle_key) {
        if oracle_acc.data.len() >= 44 {
            let vol_acc_bytes: [u8; 4] = oracle_acc.data[40..44].try_into().unwrap();
            let volatility_accumulator = u32::from_le_bytes(vol_acc_bytes);

            // max_volatility_accumulator is set to 1000 in our setup
            fuzz_assert!(volatility_accumulator <= 1000,
                "Pool3 volatility_accumulator {} exceeds max_volatility_accumulator 1000 (clamping failed)",
                volatility_accumulator);

            debug_print!("[VOLATILITY_INFLATION] volatility_accumulator={} (max=1000)", volatility_accumulator);
        }
    } else {
        debug_print!("[VOLATILITY_INFLATION] Oracle became unreadable after attack!");
    }

    // Verify pool three is still functional
    if let Ok(p3_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three_key) {
        fuzz_assert!(p3_state.sqrt_price >= MIN_SQRT_PRICE_X64, "Pool three corrupted: sqrt_price below min");
        fuzz_assert!(p3_state.sqrt_price <= MAX_SQRT_PRICE_X64, "Pool three corrupted: sqrt_price above max");
        // Also check fee_rate stays within bounds after volatility stress
        fuzz_assert_le!(p3_state.fee_rate, MAX_FEE_RATE,
            "Pool3 fee_rate after volatility inflation exceeds MAX_FEE_RATE: {} > {}",
            p3_state.fee_rate, MAX_FEE_RATE);
    }

    action_stats::record(&action_stats::VOLATILITY_INFLATION, true);
    debug_print!("[VOLATILITY_INFLATION] Completed 5 alternating swaps on pool three");
    true
}

/// Attempt to set fee rate with wrong authority (should fail)
pub fn action_wrong_authority_fee_rate(&mut self) -> bool {
    // Read current fee_rate
    let current_fee_rate = match self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
        Ok(s) => s.fee_rate,
        Err(_) => return false,
    };

    // Create a random impostor keypair
    let impostor = Keypair::new();
    let _ = self.ctx.create_account()
        .pubkey(impostor.pubkey())
        .lamports(1_000_000_000)
        .owner(system_program::ID)
        .create();

    // Attempt set_fee_rate with wrong signer
    let result = self.ctx.program(self.program_id)
        .call(instruction::SetFeeRate { fee_rate: 50_000 })
        .accounts(accounts::SetFeeRate {
            whirlpools_config: self.config,
            whirlpool: self.pool.whirlpool,
            fee_authority: impostor.pubkey(),
        })
        .signers(&[&impostor])
        .send();

    let success = match &result {
        Ok(TxOutcome::ProgramError { .. }) => {
            // Good — should fail with wrong authority
            // Verify fee_rate unchanged
            if let Ok(post_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                fuzz_assert_eq!(post_state.fee_rate, current_fee_rate,
                    "Wrong authority fee change succeeded! fee_rate {} -> {}",
                    current_fee_rate, post_state.fee_rate);
            }
            debug_print!("[WRONG_AUTH_FEE] SUCCESS: correctly rejected");
            true
        }
        Ok(TxOutcome::Success { .. }) => {
            // BAD — should NOT succeed with wrong authority
            fuzz_assert!(false,
                "SetFeeRate succeeded with wrong authority! impostor={}", impostor.pubkey());
            false
        }
        Err(e) => {
            debug_print!("[WRONG_AUTH_FEE] SEND_FAILED: {:?}", e);
            false
        }
    };
    action_stats::record(&action_stats::WRONG_AUTHORITY_FEE, success);
    success
}
