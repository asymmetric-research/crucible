// actions/fees.rs — Fee-related action methods (included in impl WhirlpoolFixture via include!())

// --- Update & collect position fees ---

    pub fn action_update_fees_and_rewards(&mut self, #[range(0..5)] position_idx: usize) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }

        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];
        let pool = &self.pool;

        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        // Pre-snapshot for postcondition
        let pre_pos = self.ctx.read_anchor_account::<whirlpool::state::Position>(&position.position).ok();
        let (pre_fee_a, pre_fee_b, pre_rewards) = pre_pos.as_ref()
            .map(|p| (p.fee_owed_a, p.fee_owed_b, [
                p.reward_infos[0].amount_owed,
                p.reward_infos[1].amount_owed,
                p.reward_infos[2].amount_owed,
            ]))
            .unwrap_or((0, 0, [0, 0, 0]));
        let pre_checkpoint_a = pre_pos.as_ref().map(|p| p.fee_growth_checkpoint_a).unwrap_or(0);
        let pre_checkpoint_b = pre_pos.as_ref().map(|p| p.fee_growth_checkpoint_b).unwrap_or(0);

        let result = self.ctx.program(self.program_id)
            .call(instruction::UpdateFeesAndRewards {})
            .accounts(accounts::UpdateFeesAndRewards {
                whirlpool: pool.whirlpool,
                position: position.position,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])  // Fee payer
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: fee_owed and reward_amount_owed can only increase
                if let Ok(post_pos) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
                    fuzz_assert!(post_pos.fee_owed_a >= pre_fee_a,
                        "update_fees: fee_owed_a decreased {} -> {}", pre_fee_a, post_pos.fee_owed_a);
                    fuzz_assert!(post_pos.fee_owed_b >= pre_fee_b,
                        "update_fees: fee_owed_b decreased {} -> {}", pre_fee_b, post_pos.fee_owed_b);
                    // Reward amounts should also only increase during update
                    for i in 0..3 {
                        fuzz_assert!(post_pos.reward_infos[i].amount_owed >= pre_rewards[i],
                            "update_fees: reward[{}] amount_owed decreased {} -> {}",
                            i, pre_rewards[i], post_pos.reward_infos[i].amount_owed);
                    }
                    // Checkpoint postcondition: if fees accrued (fee_owed increased),
                    // checkpoint must have been updated to current fee_growth_inside.
                    // The checkpoint should not go backwards (wrapping-safe).
                    let ckpt_delta_a = post_pos.fee_growth_checkpoint_a.wrapping_sub(pre_checkpoint_a);
                    let ckpt_delta_b = post_pos.fee_growth_checkpoint_b.wrapping_sub(pre_checkpoint_b);
                    // If fee_owed increased, checkpoint must have advanced
                    if post_pos.fee_owed_a > pre_fee_a {
                        fuzz_assert!(ckpt_delta_a > 0 || post_pos.fee_growth_checkpoint_a != pre_checkpoint_a,
                            "update_fees: fee_owed_a increased but checkpoint_a unchanged ({} -> {})",
                            pre_checkpoint_a, post_pos.fee_growth_checkpoint_a);
                    }
                    if post_pos.fee_owed_b > pre_fee_b {
                        fuzz_assert!(ckpt_delta_b > 0 || post_pos.fee_growth_checkpoint_b != pre_checkpoint_b,
                            "update_fees: fee_owed_b increased but checkpoint_b unchanged ({} -> {})",
                            pre_checkpoint_b, post_pos.fee_growth_checkpoint_b);
                    }
                }
                debug_print!("[UPDATE_FEES] SUCCESS: pos={}", position_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[UPDATE_FEES] TX_FAILED: pos={}", position_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[UPDATE_FEES] SEND_FAILED: pos={}: {:?}", position_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::UPDATE_FEES, success);
        success
    }

    /// Collect fees from a position (auto-prepends update_fees_and_rewards for higher ok rate)
    pub fn action_collect_fees(&mut self, #[range(0..5)] position_idx: usize) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }

        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];
        let pool = &self.pool;

        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        // Pre-snapshot for transfer conservation postcondition
        let pre_user_a = self.ctx.token_balance(&user.token_account_a);
        let pre_user_b = self.ctx.token_balance(&user.token_account_b);
        let pre_vault_a = self.ctx.token_balance(&pool.token_vault_a);
        let pre_vault_b = self.ctx.token_balance(&pool.token_vault_b);

        // Queue update_fees_and_rewards first (ensures fees are up to date)
        let _ = self.ctx.program(self.program_id)
            .call(instruction::UpdateFeesAndRewards {})
            .accounts(accounts::UpdateFeesAndRewards {
                whirlpool: pool.whirlpool,
                position: position.position,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .add_transaction();

        // Queue collect_fees
        let _ = self.ctx.program(self.program_id)
            .call(instruction::CollectFees {})
            .accounts(accounts::CollectFees {
                whirlpool: pool.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_owner_account_a: user.token_account_a,
                token_vault_a: pool.token_vault_a,
                token_owner_account_b: user.token_account_b,
                token_vault_b: pool.token_vault_b,
            })
            .signers(&[&*user.keypair])
            .add_transaction();

        // Send both atomically
        let result = self.ctx.send_batch();

        let success = match &result {
            Ok(Some(TxOutcome::Success { .. })) => {
                debug_print!("[COLLECT_FEES] SUCCESS: pos={}", position_idx);
                self.positions[position_idx].fees_just_collected = true;
                // Verify fee_owed resets to zero after collection
                if let Ok(ps) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
                    fuzz_assert_eq!(ps.fee_owed_a, 0,
                        "CollectFees: position {} fee_owed_a not reset: {}", position_idx, ps.fee_owed_a);
                    fuzz_assert_eq!(ps.fee_owed_b, 0,
                        "CollectFees: position {} fee_owed_b not reset: {}", position_idx, ps.fee_owed_b);
                }
                // Transfer conservation: vault decrease == user increase for both tokens
                let post_user_a = self.ctx.token_balance(&self.users[self.positions[position_idx].owner_idx].token_account_a);
                let post_user_b = self.ctx.token_balance(&self.users[self.positions[position_idx].owner_idx].token_account_b);
                let post_vault_a = self.ctx.token_balance(&self.pool.token_vault_a);
                let post_vault_b = self.ctx.token_balance(&self.pool.token_vault_b);
                let vault_a_out = pre_vault_a.saturating_sub(post_vault_a);
                let user_a_in = post_user_a.saturating_sub(pre_user_a);
                let vault_b_out = pre_vault_b.saturating_sub(post_vault_b);
                let user_b_in = post_user_b.saturating_sub(pre_user_b);
                fuzz_assert_eq!(vault_a_out, user_a_in,
                    "collect_fees: token A vault_out ({}) != user_in ({})", vault_a_out, user_a_in);
                fuzz_assert_eq!(vault_b_out, user_b_in,
                    "collect_fees: token B vault_out ({}) != user_in ({})", vault_b_out, user_b_in);
                true
            }
            Ok(Some(TxOutcome::ProgramError { logs, .. })) => {
                debug_print!("[COLLECT_FEES] TX_FAILED: pos={}", position_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Ok(None) => false,
            Err(e) => {
                debug_print!("[COLLECT_FEES] SEND_FAILED: pos={}: {:?}", position_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::COLLECT_FEES, success);
        success
    }

// --- V2 collect fees ---

    pub fn action_collect_fees_v2(&mut self, #[range(0..5)] position_idx: usize) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }

        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];
        let pool = &self.pool;

        let tick_array_lower = self.get_tick_array_for_tick(position.tick_lower_index);
        let tick_array_upper = self.get_tick_array_for_tick(position.tick_upper_index);

        // Pre-snapshot for transfer conservation postcondition
        let v2_pre_user_a = self.ctx.token_balance(&user.token_account_a);
        let v2_pre_user_b = self.ctx.token_balance(&user.token_account_b);
        let v2_pre_vault_a = self.ctx.token_balance(&pool.token_vault_a);
        let v2_pre_vault_b = self.ctx.token_balance(&pool.token_vault_b);

        // Queue update_fees_and_rewards first
        let _ = self.ctx.program(self.program_id)
            .call(instruction::UpdateFeesAndRewards {})
            .accounts(accounts::UpdateFeesAndRewards {
                whirlpool: pool.whirlpool,
                position: position.position,
                tick_array_lower,
                tick_array_upper,
            })
            .signers(&[&*user.keypair])
            .add_transaction();

        // Queue collect_fees_v2
        let _ = self.ctx.program(self.program_id)
            .call(instruction::CollectFeesV2 {
                remaining_accounts_info: None,
            })
            .accounts(accounts::CollectFeesV2 {
                whirlpool: pool.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                token_mint_a: pool.token_mint_a,
                token_mint_b: pool.token_mint_b,
                token_owner_account_a: user.token_account_a,
                token_vault_a: pool.token_vault_a,
                token_owner_account_b: user.token_account_b,
                token_vault_b: pool.token_vault_b,
                token_program_a: spl_token::ID,
                token_program_b: spl_token::ID,

            })
            .signers(&[&*user.keypair])
            .add_transaction();

        let result = self.ctx.send_batch();

        let success = match &result {
            Ok(Some(TxOutcome::Success { .. })) => {
                debug_print!("[COLLECT_FEES_V2] SUCCESS: pos={}", position_idx);
                self.positions[position_idx].fees_just_collected = true;
                // Verify fee_owed resets to zero after collection
                if let Ok(ps) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
                    fuzz_assert_eq!(ps.fee_owed_a, 0,
                        "CollectFeesV2: position {} fee_owed_a not reset: {}", position_idx, ps.fee_owed_a);
                    fuzz_assert_eq!(ps.fee_owed_b, 0,
                        "CollectFeesV2: position {} fee_owed_b not reset: {}", position_idx, ps.fee_owed_b);
                }
                // Transfer conservation: vault decrease == user increase
                let v2_post_user_a = self.ctx.token_balance(&self.users[self.positions[position_idx].owner_idx].token_account_a);
                let v2_post_user_b = self.ctx.token_balance(&self.users[self.positions[position_idx].owner_idx].token_account_b);
                let v2_post_vault_a = self.ctx.token_balance(&self.pool.token_vault_a);
                let v2_post_vault_b = self.ctx.token_balance(&self.pool.token_vault_b);
                let v2_vault_a_out = v2_pre_vault_a.saturating_sub(v2_post_vault_a);
                let v2_user_a_in = v2_post_user_a.saturating_sub(v2_pre_user_a);
                let v2_vault_b_out = v2_pre_vault_b.saturating_sub(v2_post_vault_b);
                let v2_user_b_in = v2_post_user_b.saturating_sub(v2_pre_user_b);
                fuzz_assert_eq!(v2_vault_a_out, v2_user_a_in,
                    "collect_fees_v2: token A vault_out ({}) != user_in ({})", v2_vault_a_out, v2_user_a_in);
                fuzz_assert_eq!(v2_vault_b_out, v2_user_b_in,
                    "collect_fees_v2: token B vault_out ({}) != user_in ({})", v2_vault_b_out, v2_user_b_in);
                true
            }
            Ok(Some(TxOutcome::ProgramError { logs, .. })) => {
                debug_print!("[COLLECT_FEES_V2] TX_FAILED: pos={}", position_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Ok(None) => false,
            Err(e) => {
                debug_print!("[COLLECT_FEES_V2] SEND_FAILED: pos={}: {:?}", position_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::COLLECT_FEES_V2, success);
        success
    }

// --- Protocol fees: collect, set fee rate, set protocol fee rate ---

    pub fn action_collect_protocol_fees(&mut self) -> bool {
        // Pre-snapshot: protocol fees owed and balances
        let pre_owed_a = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
            .map(|s| s.protocol_fee_owed_a).unwrap_or(0);
        let pre_owed_b = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
            .map(|s| s.protocol_fee_owed_b).unwrap_or(0);
        let vault_a_pre = self.ctx.token_balance(&self.pool.token_vault_a);
        let vault_b_pre = self.ctx.token_balance(&self.pool.token_vault_b);
        let dest_a_pre = self.ctx.token_balance(&self.users[0].token_account_a);
        let dest_b_pre = self.ctx.token_balance(&self.users[0].token_account_b);

        let result = self.ctx.program(self.program_id)
            .call(instruction::CollectProtocolFees {})
            .accounts(accounts::CollectProtocolFees {
                whirlpools_config: self.config,
                whirlpool: self.pool.whirlpool,
                collect_protocol_fees_authority: self.collect_protocol_fees_authority.pubkey(),
                token_vault_a: self.pool.token_vault_a,
                token_vault_b: self.pool.token_vault_b,
                token_destination_a: self.users[0].token_account_a,
                token_destination_b: self.users[0].token_account_b,
            })
            .signers(&[&*self.collect_protocol_fees_authority])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Post-action verification: protocol_fee_owed must reset to 0
                if let Ok(post_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    fuzz_assert_eq!(post_state.protocol_fee_owed_a, 0u64,
                        "collect_protocol_fees: protocol_fee_owed_a not reset ({})", post_state.protocol_fee_owed_a);
                    fuzz_assert_eq!(post_state.protocol_fee_owed_b, 0u64,
                        "collect_protocol_fees: protocol_fee_owed_b not reset ({})", post_state.protocol_fee_owed_b);
                }

                // Vault decreased by exactly pre_owed amount
                let vault_a_post = self.ctx.token_balance(&self.pool.token_vault_a);
                let vault_b_post = self.ctx.token_balance(&self.pool.token_vault_b);
                fuzz_assert_eq!(vault_a_pre.saturating_sub(vault_a_post), pre_owed_a,
                    "collect_protocol_fees: vault_a delta {} != pre_owed_a {}",
                    vault_a_pre.saturating_sub(vault_a_post), pre_owed_a);
                fuzz_assert_eq!(vault_b_pre.saturating_sub(vault_b_post), pre_owed_b,
                    "collect_protocol_fees: vault_b delta {} != pre_owed_b {}",
                    vault_b_pre.saturating_sub(vault_b_post), pre_owed_b);

                // Destination increased by exactly pre_owed amount
                let dest_a_post = self.ctx.token_balance(&self.users[0].token_account_a);
                let dest_b_post = self.ctx.token_balance(&self.users[0].token_account_b);
                fuzz_assert_eq!(dest_a_post.saturating_sub(dest_a_pre), pre_owed_a,
                    "collect_protocol_fees: dest_a delta {} != pre_owed_a {}",
                    dest_a_post.saturating_sub(dest_a_pre), pre_owed_a);
                fuzz_assert_eq!(dest_b_post.saturating_sub(dest_b_pre), pre_owed_b,
                    "collect_protocol_fees: dest_b delta {} != pre_owed_b {}",
                    dest_b_post.saturating_sub(dest_b_pre), pre_owed_b);

                self.protocol_fees_just_collected = true;
                debug_print!("[COLLECT_PROTO_FEES] SUCCESS: collected a={} b={}", pre_owed_a, pre_owed_b);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[COLLECT_PROTO_FEES] TX_FAILED");
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[COLLECT_PROTO_FEES] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::COLLECT_PROTOCOL_FEES, success);
        success
    }

    /// Set fee rate (fee-authority-only, max 6% = 60000)
    pub fn action_set_fee_rate(&mut self, fee_rate: u16) -> bool {
        let fee_rate = fee_rate % 60_001; // 0 to 60000 (0% to 6%)

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetFeeRate { fee_rate })
            .accounts(accounts::SetFeeRate {
                whirlpools_config: self.config,
                whirlpool: self.pool.whirlpool,
                fee_authority: self.fee_authority.pubkey(),
            })
            .signers(&[&*self.fee_authority])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: on-chain fee_rate matches parameter
                if let Ok(pool_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    fuzz_assert_eq!(pool_state.fee_rate, fee_rate,
                        "set_fee_rate: on-chain fee_rate {} != param {}", pool_state.fee_rate, fee_rate);
                }
                debug_print!("[SET_FEE_RATE] SUCCESS: rate={}", fee_rate);
                self.expected_fee_rate = fee_rate;
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SET_FEE_RATE] TX_FAILED: rate={}", fee_rate);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SET_FEE_RATE] SEND_FAILED: rate={}: {:?}", fee_rate, e);
                false
            }
        };
        action_stats::record(&action_stats::SET_FEE_RATE, success);
        success
    }

    /// Set protocol fee rate (fee-authority-only, max 25% = 2500)
    pub fn action_set_protocol_fee_rate(&mut self, protocol_fee_rate: u16) -> bool {
        let protocol_fee_rate = protocol_fee_rate % 2_501; // 0 to 2500 (0% to 25%)

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetProtocolFeeRate { protocol_fee_rate })
            .accounts(accounts::SetProtocolFeeRate {
                whirlpools_config: self.config,
                whirlpool: self.pool.whirlpool,
                fee_authority: self.fee_authority.pubkey(),
            })
            .signers(&[&*self.fee_authority])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: on-chain protocol_fee_rate matches parameter
                if let Ok(pool_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    fuzz_assert_eq!(pool_state.protocol_fee_rate, protocol_fee_rate,
                        "set_protocol_fee_rate: on-chain {} != param {}", pool_state.protocol_fee_rate, protocol_fee_rate);
                }
                debug_print!("[SET_PROTO_FEE] SUCCESS: rate={}", protocol_fee_rate);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SET_PROTO_FEE] TX_FAILED: rate={}", protocol_fee_rate);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SET_PROTO_FEE] SEND_FAILED: rate={}: {:?}", protocol_fee_rate, e);
                false
            }
        };
        action_stats::record(&action_stats::SET_PROTOCOL_FEE_RATE, success);
        success
    }

// --- V2 collect protocol fees ---

    /// V2 collect protocol fees
    pub fn action_collect_protocol_fees_v2(&mut self) -> bool {
        // Disabled: binary/IDL mismatch causes access violation (binary doesn't support this V2 layout)
        // The non-V2 collect_protocol_fees action covers the same code path.
        return false;
        // Pre-snapshot
        let pre_owed_a = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
            .map(|s| s.protocol_fee_owed_a).unwrap_or(0);
        let pre_owed_b = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
            .map(|s| s.protocol_fee_owed_b).unwrap_or(0);
        let vault_a_pre = self.ctx.token_balance(&self.pool.token_vault_a);
        let vault_b_pre = self.ctx.token_balance(&self.pool.token_vault_b);
        let dest_a_pre = self.ctx.token_balance(&self.users[0].token_account_a);
        let dest_b_pre = self.ctx.token_balance(&self.users[0].token_account_b);

        let result = self.ctx.program(self.program_id)
            .call(instruction::CollectProtocolFeesV2 {
                remaining_accounts_info: None,
            })
            .accounts(accounts::CollectProtocolFeesV2 {
                whirlpools_config: self.config,
                whirlpool: self.pool.whirlpool,
                collect_protocol_fees_authority: self.collect_protocol_fees_authority.pubkey(),
                token_mint_a: self.pool.token_mint_a,
                token_mint_b: self.pool.token_mint_b,
                token_vault_a: self.pool.token_vault_a,
                token_vault_b: self.pool.token_vault_b,
                token_destination_a: self.users[0].token_account_a,
                token_destination_b: self.users[0].token_account_b,
                token_program_a: spl_token::ID,
                token_program_b: spl_token::ID,

            })
            .signers(&[&*self.collect_protocol_fees_authority])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Post-action verification
                if let Ok(post_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    fuzz_assert_eq!(post_state.protocol_fee_owed_a, 0u64,
                        "collect_protocol_fees_v2: fee_owed_a not reset ({})", post_state.protocol_fee_owed_a);
                    fuzz_assert_eq!(post_state.protocol_fee_owed_b, 0u64,
                        "collect_protocol_fees_v2: fee_owed_b not reset ({})", post_state.protocol_fee_owed_b);
                }

                let vault_a_post = self.ctx.token_balance(&self.pool.token_vault_a);
                let vault_b_post = self.ctx.token_balance(&self.pool.token_vault_b);
                fuzz_assert_eq!(vault_a_pre.saturating_sub(vault_a_post), pre_owed_a,
                    "collect_protocol_fees_v2: vault_a delta {} != pre_owed_a {}",
                    vault_a_pre.saturating_sub(vault_a_post), pre_owed_a);
                fuzz_assert_eq!(vault_b_pre.saturating_sub(vault_b_post), pre_owed_b,
                    "collect_protocol_fees_v2: vault_b delta {} != pre_owed_b {}",
                    vault_b_pre.saturating_sub(vault_b_post), pre_owed_b);

                let dest_a_post = self.ctx.token_balance(&self.users[0].token_account_a);
                let dest_b_post = self.ctx.token_balance(&self.users[0].token_account_b);
                fuzz_assert_eq!(dest_a_post.saturating_sub(dest_a_pre), pre_owed_a,
                    "collect_protocol_fees_v2: dest_a delta {} != pre_owed_a {}",
                    dest_a_post.saturating_sub(dest_a_pre), pre_owed_a);
                fuzz_assert_eq!(dest_b_post.saturating_sub(dest_b_pre), pre_owed_b,
                    "collect_protocol_fees_v2: dest_b delta {} != pre_owed_b {}",
                    dest_b_post.saturating_sub(dest_b_pre), pre_owed_b);

                self.protocol_fees_just_collected = true;
                debug_print!("[COLLECT_PROTO_FEES_V2] SUCCESS: a={} b={}", pre_owed_a, pre_owed_b);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[COLLECT_PROTO_FEES_V2] TX_FAILED");
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[COLLECT_PROTO_FEES_V2] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::COLLECT_PROTOCOL_FEES_V2, success);
        success
    }

// --- Default fee rate & default protocol fee rate ---

    pub fn action_set_default_fee_rate(&mut self, default_fee_rate: u16) -> bool {
        let default_fee_rate = default_fee_rate % 60_001; // 0 to 60000

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetDefaultFeeRate { default_fee_rate })
            .accounts(accounts::SetDefaultFeeRate {
                whirlpools_config: self.config,
                fee_tier: self.fee_tier,
                fee_authority: self.fee_authority.pubkey(),
            })
            .signers(&[&*self.fee_authority])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: verify fee_tier on-chain matches
                if let Ok(ft) = self.ctx.read_anchor_account::<whirlpool::state::FeeTier>(&self.fee_tier) {
                    fuzz_assert_eq!(ft.default_fee_rate, default_fee_rate,
                        "set_default_fee_rate: on-chain {} != param {}", ft.default_fee_rate, default_fee_rate);
                }
                debug_print!("[SET_DEFAULT_FEE] SUCCESS: rate={}", default_fee_rate);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SET_DEFAULT_FEE] TX_FAILED: rate={}", default_fee_rate);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SET_DEFAULT_FEE] SEND_FAILED: rate={}: {:?}", default_fee_rate, e);
                false
            }
        };
        action_stats::record(&action_stats::SET_DEFAULT_FEE_RATE, success);
        success
    }

    /// Set the default protocol fee rate on the config (fee-authority-only)
    pub fn action_set_default_protocol_fee_rate(&mut self, default_protocol_fee_rate: u16) -> bool {
        let default_protocol_fee_rate = default_protocol_fee_rate % 2_501; // 0 to 2500

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetDefaultProtocolFeeRate { default_protocol_fee_rate })
            .accounts(accounts::SetDefaultProtocolFeeRate {
                whirlpools_config: self.config,
                fee_authority: self.fee_authority.pubkey(),
            })
            .signers(&[&*self.fee_authority])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: verify config on-chain matches
                if let Ok(cfg) = self.ctx.read_anchor_account::<whirlpool::state::WhirlpoolsConfig>(&self.config) {
                    fuzz_assert_eq!(cfg.default_protocol_fee_rate, default_protocol_fee_rate,
                        "set_default_protocol_fee_rate: on-chain {} != param {}",
                        cfg.default_protocol_fee_rate, default_protocol_fee_rate);
                }
                debug_print!("[SET_DEFAULT_PROTO_FEE] SUCCESS: rate={}", default_protocol_fee_rate);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SET_DEFAULT_PROTO_FEE] TX_FAILED: rate={}", default_protocol_fee_rate);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SET_DEFAULT_PROTO_FEE] SEND_FAILED: rate={}: {:?}", default_protocol_fee_rate, e);
                false
            }
        };
        action_stats::record(&action_stats::SET_DEFAULT_PROTOCOL_FEE_RATE, success);
        success
    }

// --- Fee authority rotation ---

    pub fn action_set_fee_authority(&mut self) -> bool {
        let new_authority = Rc::new(Keypair::new());

        // Fund the new authority
        let _ = self.ctx.create_account()
            .pubkey(new_authority.pubkey())
            .lamports(1_000_000_000)
            .owner(system_program::ID)
            .create();

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetFeeAuthority {})
            .accounts(accounts::SetFeeAuthority {
                whirlpools_config: self.config,
                fee_authority: self.fee_authority.pubkey(),
                new_fee_authority: new_authority.pubkey(),
            })
            .signers(&[&*self.fee_authority])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: on-chain config reflects new authority
                if let Ok(cfg) = self.ctx.read_anchor_account::<whirlpool::state::WhirlpoolsConfig>(&self.config) {
                    fuzz_assert_eq!(cfg.fee_authority, new_authority.pubkey(),
                        "set_fee_authority: on-chain {} != new {}",
                        cfg.fee_authority, new_authority.pubkey());
                }
                debug_print!("[SET_FEE_AUTH] SUCCESS: {} -> {}",
                    self.fee_authority.pubkey(), new_authority.pubkey());
                self.fee_authority = new_authority;
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SET_FEE_AUTH] TX_FAILED");
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SET_FEE_AUTH] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::SET_FEE_AUTHORITY, success);
        success
    }

// --- Collect protocol fees authority rotation ---

    pub fn action_set_collect_protocol_fees_authority(&mut self) -> bool {
        let new_authority = Rc::new(Keypair::new());
        let _ = self.ctx.create_account()
            .pubkey(new_authority.pubkey())
            .lamports(1_000_000_000)
            .owner(system_program::ID)
            .create();

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetCollectProtocolFeesAuthority {})
            .accounts(accounts::SetCollectProtocolFeesAuthority {
                whirlpools_config: self.config,
                collect_protocol_fees_authority: self.collect_protocol_fees_authority.pubkey(),
                new_collect_protocol_fees_authority: new_authority.pubkey(),
            })
            .signers(&[&*self.collect_protocol_fees_authority])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: on-chain config reflects new authority
                if let Ok(cfg) = self.ctx.read_anchor_account::<whirlpool::state::WhirlpoolsConfig>(&self.config) {
                    fuzz_assert_eq!(cfg.collect_protocol_fees_authority, new_authority.pubkey(),
                        "set_cpf_authority: on-chain {} != new {}",
                        cfg.collect_protocol_fees_authority, new_authority.pubkey());
                }
                debug_print!("[SET_CPF_AUTH] SUCCESS: {} -> {}",
                    self.collect_protocol_fees_authority.pubkey(), new_authority.pubkey());
                self.collect_protocol_fees_authority = new_authority;
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SET_CPF_AUTH] TX_FAILED");
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SET_CPF_AUTH] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::SET_COLLECT_PROTO_FEES_AUTHORITY, success);
        success
    }
