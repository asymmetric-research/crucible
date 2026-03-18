// actions/rewards.rs — Reward action methods (included in impl WhirlpoolFixture via include!())

    pub fn action_collect_reward_v2(
        &mut self,
        #[range(0..5)] position_idx: usize,
        #[range(0..3)] reward_index: usize,
    ) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }
        if reward_index >= 3 || !self.pool.reward_initialized[reward_index] {
            return false;
        }

        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];

        if reward_index >= user.reward_accounts.len() {
            return false;
        }

        // Pre-snapshot for postcondition
        let pre_pos_state = self.ctx.read_anchor_account::<whirlpool::state::Position>(&position.position).ok();
        let pre_amount_owed = pre_pos_state.as_ref().map(|s| s.reward_infos[reward_index].amount_owed).unwrap_or(0);
        // Snapshot other rewards for isolation check
        let pre_other_rewards: Vec<(usize, u64)> = (0..3)
            .filter(|&i| i != reward_index)
            .map(|i| (i, pre_pos_state.as_ref().map(|s| s.reward_infos[i].amount_owed).unwrap_or(0)))
            .collect();
        let pre_vault_bal = self.ctx.token_balance(&self.pool.reward_vaults[reward_index]);
        let pre_user_bal = self.ctx.token_balance(&user.reward_accounts[reward_index]);

        let result = self.ctx.program(self.program_id)
            .call(instruction::CollectRewardV2 {
                reward_index: reward_index as u8,
                remaining_accounts_info: None,
            })
            .accounts(accounts::CollectRewardV2 {
                whirlpool: self.pool.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                reward_owner_account: user.reward_accounts[reward_index],
                reward_mint: self.pool.reward_mints[reward_index],
                reward_vault: self.pool.reward_vaults[reward_index],
                reward_token_program: spl_token::ID,

            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: amount_owed should reset, transfer conservation
                if let Ok(post_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
                    let post_amount_owed = post_state.reward_infos[reward_index].amount_owed;
                    let post_vault_bal = self.ctx.token_balance(&self.pool.reward_vaults[reward_index]);
                    let post_user_bal = self.ctx.token_balance(&self.users[self.positions[position_idx].owner_idx].reward_accounts[reward_index]);
                    let vault_decrease = pre_vault_bal.saturating_sub(post_vault_bal);
                    let user_increase = post_user_bal.saturating_sub(pre_user_bal);
                    // Transfer conservation: vault outflow == user inflow
                    fuzz_assert_eq!(vault_decrease, user_increase,
                        "collect_reward_v2: vault outflow {} != user inflow {} (pos={} reward={})",
                        vault_decrease, user_increase, position_idx, reward_index);
                    // Exact transfer: min(owed, vault_balance)
                    let expected_transfer = std::cmp::min(pre_amount_owed, pre_vault_bal);
                    fuzz_assert_eq!(vault_decrease, expected_transfer,
                        "collect_reward_v2: actual transfer {} != expected min(owed={}, vault={}) (pos={} reward={})",
                        vault_decrease, pre_amount_owed, pre_vault_bal, position_idx, reward_index);
                    // Exact post amount_owed: owed - transfer
                    let expected_post_owed = pre_amount_owed.saturating_sub(expected_transfer);
                    fuzz_assert_eq!(post_amount_owed, expected_post_owed,
                        "collect_reward_v2: post amount_owed {} != expected {} (pre_owed={} transfer={} pos={} reward={})",
                        post_amount_owed, expected_post_owed, pre_amount_owed, expected_transfer, position_idx, reward_index);
                    // Isolation: other reward indices' amount_owed should be unchanged
                    for &(other_idx, pre_other_owed) in &pre_other_rewards {
                        let post_other_owed = post_state.reward_infos[other_idx].amount_owed;
                        fuzz_assert_eq!(post_other_owed, pre_other_owed,
                            "collect_reward_v2: reward[{}].amount_owed changed {} -> {} after collecting reward[{}] (pos={})",
                            other_idx, pre_other_owed, post_other_owed, reward_index, position_idx);
                    }
                }
                debug_print!("[COLLECT_REWARD_V2] SUCCESS: pos={} reward={}", position_idx, reward_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[COLLECT_REWARD_V2] TX_FAILED: pos={} reward={}", position_idx, reward_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[COLLECT_REWARD_V2] SEND_FAILED: pos={} reward={}: {:?}", position_idx, reward_index, e);
                false
            }
        };
        action_stats::record(&action_stats::COLLECT_REWARD_V2, success);
        success
    }

    pub fn action_set_reward_emissions_v2(
        &mut self,
        #[range(0..3)] reward_index: usize,
        emissions_rate: u64,
    ) -> bool {
        if reward_index >= 3 || !self.pool.reward_initialized[reward_index] {
            return false;
        }

        let emissions_per_second_x64 = ((emissions_rate % 1_000_000) as u128 + 1) << 32;

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetRewardEmissionsV2 {
                reward_index: reward_index as u8,
                emissions_per_second_x64,
            })
            .accounts(accounts::SetRewardEmissionsV2 {
                whirlpool: self.pool.whirlpool,
                reward_authority: self.admin.pubkey(),
                reward_vault: self.pool.reward_vaults[reward_index],
            })
            .signers(&[&*self.admin])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: emissions_per_second_x64 should be updated
                if let Ok(pool_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    fuzz_assert_eq!(pool_state.reward_infos[reward_index].emissions_per_second_x64,
                        emissions_per_second_x64,
                        "set_reward_emissions_v2: expected rate {} got {} (reward={})",
                        emissions_per_second_x64,
                        pool_state.reward_infos[reward_index].emissions_per_second_x64,
                        reward_index);
                }
                debug_print!("[SET_REWARD_EMS_V2] SUCCESS: index={} rate={}", reward_index, emissions_per_second_x64);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SET_REWARD_EMS_V2] TX_FAILED: index={}", reward_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SET_REWARD_EMS_V2] SEND_FAILED: index={}: {:?}", reward_index, e);
                false
            }
        };
        action_stats::record(&action_stats::SET_REWARD_EMISSIONS_V2, success);
        success
    }

    pub fn action_initialize_reward(&mut self, #[range(0..3)] reward_index: usize) -> bool {
        if reward_index >= 3 || self.pool.reward_initialized[reward_index] {
            return false;
        }
        // Must initialize sequentially
        if reward_index > 0 && !self.pool.reward_initialized[reward_index - 1] {
            return false;
        }
        if reward_index >= self.pool.reward_mints.len() {
            return false;
        }

        let reward_vault = Keypair::new();
        let reward_mint = self.pool.reward_mints[reward_index];

        let result = self.ctx.program(self.program_id)
            .call(instruction::InitializeReward {
                reward_index: reward_index as u8,
            })
            .accounts(accounts::InitializeReward {
                reward_authority: self.admin.pubkey(),
                funder: self.admin.pubkey(),
                whirlpool: self.pool.whirlpool,
                reward_mint,
                reward_vault: reward_vault.pubkey(),
            })
            .signers(&[&*self.admin, &reward_vault])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.pool.reward_initialized[reward_index] = true;
                // Store or update the vault pubkey
                if reward_index < self.pool.reward_vaults.len() {
                    self.pool.reward_vaults[reward_index] = reward_vault.pubkey();
                } else {
                    self.pool.reward_vaults.push(reward_vault.pubkey());
                }
                // Postcondition: verify pool reward_info is correctly initialized
                if let Ok(pool_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    let ri = &pool_state.reward_infos[reward_index];
                    fuzz_assert_eq!(ri.mint, reward_mint,
                        "initialize_reward: reward_info[{}].mint {} != expected {}",
                        reward_index, ri.mint, reward_mint);
                    fuzz_assert_eq!(ri.vault, reward_vault.pubkey(),
                        "initialize_reward: reward_info[{}].vault {} != expected {}",
                        reward_index, ri.vault, reward_vault.pubkey());
                    fuzz_assert_eq!(ri.emissions_per_second_x64, 0u128,
                        "initialize_reward: reward_info[{}].emissions should be 0, got {}",
                        reward_index, ri.emissions_per_second_x64);
                }
                // Fund the vault with reward tokens
                let _ = self.ctx.mint_to(
                    &reward_mint,
                    &reward_vault.pubkey(),
                    1_000_000_000_000, // 1000 tokens with 9 decimals
                    &self.admin,
                );
                debug_print!("[INIT_REWARD] SUCCESS: index={}", reward_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[INIT_REWARD] TX_FAILED: index={}", reward_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[INIT_REWARD] SEND_FAILED: index={}: {:?}", reward_index, e);
                false
            }
        };
        action_stats::record(&action_stats::INITIALIZE_REWARD, success);
        success
    }

    /// Set reward emissions rate for an initialized reward
    pub fn action_set_reward_emissions(
        &mut self,
        #[range(0..3)] reward_index: usize,
        emissions_rate: u64,
    ) -> bool {
        if reward_index >= 3 || !self.pool.reward_initialized[reward_index] {
            return false;
        }

        // Scale to reasonable Q64.64 value: (1..1_000_000) << 32
        let emissions_per_second_x64 = ((emissions_rate % 1_000_000) as u128 + 1) << 32;

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetRewardEmissions {
                reward_index: reward_index as u8,
                emissions_per_second_x64,
            })
            .accounts(accounts::SetRewardEmissions {
                whirlpool: self.pool.whirlpool,
                reward_authority: self.admin.pubkey(),
                reward_vault: self.pool.reward_vaults[reward_index],
            })
            .signers(&[&*self.admin])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: emissions_per_second_x64 should be updated
                if let Ok(pool_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    fuzz_assert_eq!(pool_state.reward_infos[reward_index].emissions_per_second_x64,
                        emissions_per_second_x64,
                        "set_reward_emissions: expected rate {} got {} (reward={})",
                        emissions_per_second_x64,
                        pool_state.reward_infos[reward_index].emissions_per_second_x64,
                        reward_index);
                }
                debug_print!("[SET_REWARD_EMS] SUCCESS: index={} rate={}", reward_index, emissions_per_second_x64);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SET_REWARD_EMS] TX_FAILED: index={}", reward_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SET_REWARD_EMS] SEND_FAILED: index={}: {:?}", reward_index, e);
                false
            }
        };
        action_stats::record(&action_stats::SET_REWARD_EMISSIONS, success);
        success
    }

    /// Collect reward from a position
    pub fn action_collect_reward(
        &mut self,
        #[range(0..5)] position_idx: usize,
        #[range(0..3)] reward_index: usize,
    ) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }
        if reward_index >= 3 || !self.pool.reward_initialized[reward_index] {
            return false;
        }

        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];

        if reward_index >= user.reward_accounts.len() {
            return false;
        }

        // Pre-snapshot for postcondition
        let pre_pos_legacy = self.ctx.read_anchor_account::<whirlpool::state::Position>(&position.position).ok();
        let pre_amount_owed = pre_pos_legacy.as_ref().map(|s| s.reward_infos[reward_index].amount_owed).unwrap_or(0);
        let pre_other_rewards_legacy: Vec<(usize, u64)> = (0..3)
            .filter(|&i| i != reward_index)
            .map(|i| (i, pre_pos_legacy.as_ref().map(|s| s.reward_infos[i].amount_owed).unwrap_or(0)))
            .collect();
        let pre_vault_bal = self.ctx.token_balance(&self.pool.reward_vaults[reward_index]);
        let pre_user_bal = self.ctx.token_balance(&user.reward_accounts[reward_index]);

        let result = self.ctx.program(self.program_id)
            .call(instruction::CollectReward {
                reward_index: reward_index as u8,
            })
            .accounts(accounts::CollectReward {
                whirlpool: self.pool.whirlpool,
                position_authority: user.keypair.pubkey(),
                position: position.position,
                position_token_account: position.position_token_account,
                reward_owner_account: user.reward_accounts[reward_index],
                reward_vault: self.pool.reward_vaults[reward_index],
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: amount_owed should decrease or stay 0
                if let Ok(post_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
                    let post_amount_owed = post_state.reward_infos[reward_index].amount_owed;
                    let post_vault_bal = self.ctx.token_balance(&self.pool.reward_vaults[reward_index]);
                    let post_user_bal = self.ctx.token_balance(&self.users[self.positions[position_idx].owner_idx].reward_accounts[reward_index]);
                    let vault_decrease = pre_vault_bal.saturating_sub(post_vault_bal);
                    let user_increase = post_user_bal.saturating_sub(pre_user_bal);
                    // Transfer conservation: vault decrease == user increase
                    fuzz_assert_eq!(vault_decrease, user_increase,
                        "collect_reward: vault outflow {} != user inflow {} (pos={} reward={})",
                        vault_decrease, user_increase, position_idx, reward_index);
                    // Exact transfer: min(owed, vault_balance)
                    let expected_transfer = std::cmp::min(pre_amount_owed, pre_vault_bal);
                    fuzz_assert_eq!(vault_decrease, expected_transfer,
                        "collect_reward: actual transfer {} != expected min(owed={}, vault={}) (pos={} reward={})",
                        vault_decrease, pre_amount_owed, pre_vault_bal, position_idx, reward_index);
                    // Exact post amount_owed: owed - transfer
                    let expected_post_owed = pre_amount_owed.saturating_sub(expected_transfer);
                    fuzz_assert_eq!(post_amount_owed, expected_post_owed,
                        "collect_reward: post amount_owed {} != expected {} (pre_owed={} transfer={} pos={} reward={})",
                        post_amount_owed, expected_post_owed, pre_amount_owed, expected_transfer, position_idx, reward_index);
                    // Isolation: other reward indices' amount_owed should be unchanged
                    for &(other_idx, pre_owed) in &pre_other_rewards_legacy {
                        let post_other_owed = post_state.reward_infos[other_idx].amount_owed;
                        fuzz_assert_eq!(post_other_owed, pre_owed,
                            "collect_reward: reward[{}].amount_owed changed {} -> {} after collecting reward[{}] (pos={})",
                            other_idx, pre_owed, post_other_owed, reward_index, position_idx);
                    }
                }
                debug_print!("[COLLECT_REWARD] SUCCESS: pos={} reward={}", position_idx, reward_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[COLLECT_REWARD] TX_FAILED: pos={} reward={}", position_idx, reward_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[COLLECT_REWARD] SEND_FAILED: pos={} reward={}: {:?}", position_idx, reward_index, e);
                false
            }
        };
        action_stats::record(&action_stats::COLLECT_REWARD, success);
        success
    }

    pub fn action_set_reward_authority(&mut self, #[range(0..3)] reward_index: usize) -> bool {
        if reward_index >= 3 || !self.pool.reward_initialized[reward_index] {
            return false;
        }

        // Use super authority to set reward authority (simpler — doesn't require tracking per-reward authority)
        let new_authority = Rc::new(Keypair::new());
        let _ = self.ctx.create_account()
            .pubkey(new_authority.pubkey())
            .lamports(1_000_000_000)
            .owner(system_program::ID)
            .create();

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetRewardAuthorityBySuperAuthority {
                reward_index: reward_index as u8,
            })
            .accounts(accounts::SetRewardAuthorityBySuperAuthority {
                whirlpools_config: self.config,
                whirlpool: self.pool.whirlpool,
                reward_emissions_super_authority: self.reward_emissions_super_authority.pubkey(),
                new_reward_authority: new_authority.pubkey(),
            })
            .signers(&[&*self.reward_emissions_super_authority])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: verify on-chain reward authority updated.
                // update_reward_authority() always writes to reward_infos[0].extension
                // (single shared authority, regardless of reward_index).
                // Source: state/whirlpool.rs:210-216
                if let Ok(pool_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    let on_chain_auth = Pubkey::from(pool_state.reward_infos[0].extension);
                    fuzz_assert_eq!(on_chain_auth, new_authority.pubkey(),
                        "set_reward_authority: on-chain authority {} != new {}",
                        on_chain_auth, new_authority.pubkey());
                }
                debug_print!("[SET_REWARD_AUTH] SUCCESS: reward_index={}", reward_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SET_REWARD_AUTH] TX_FAILED: reward_index={}", reward_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SET_REWARD_AUTH] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::SET_REWARD_AUTHORITY, success);
        success
    }

    pub fn action_set_reward_emissions_super_authority(&mut self) -> bool {
        let new_authority = Rc::new(Keypair::new());

        // Fund the new authority
        let _ = self.ctx.create_account()
            .pubkey(new_authority.pubkey())
            .lamports(1_000_000_000)
            .owner(system_program::ID)
            .create();

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetRewardEmissionsSuperAuthority {})
            .accounts(accounts::SetRewardEmissionsSuperAuthority {
                whirlpools_config: self.config,
                reward_emissions_super_authority: self.reward_emissions_super_authority.pubkey(),
                new_reward_emissions_super_authority: new_authority.pubkey(),
            })
            .signers(&[&*self.reward_emissions_super_authority])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: verify on-chain super authority updated
                if let Ok(cfg) = self.ctx.read_anchor_account::<whirlpool::state::WhirlpoolsConfig>(&self.config) {
                    fuzz_assert_eq!(cfg.reward_emissions_super_authority, new_authority.pubkey(),
                        "set_reward_super_auth: on-chain {} != new {}",
                        cfg.reward_emissions_super_authority, new_authority.pubkey());
                }
                debug_print!("[SET_REWARD_SUPER] SUCCESS: {} -> {}",
                    self.reward_emissions_super_authority.pubkey(), new_authority.pubkey());
                self.reward_emissions_super_authority = new_authority;
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SET_REWARD_SUPER] TX_FAILED");
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SET_REWARD_SUPER] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::SET_REWARD_EMISSIONS_SUPER_AUTH, success);
        success
    }

    pub fn action_set_reward_authority_by_super_authority(
        &mut self,
        #[range(0..3)] reward_index: usize,
    ) -> bool {
        if reward_index >= 3 || !self.pool.reward_initialized[reward_index] {
            return false;
        }

        let new_authority = Rc::new(Keypair::new());
        let _ = self.ctx.create_account()
            .pubkey(new_authority.pubkey())
            .lamports(1_000_000_000)
            .owner(system_program::ID)
            .create();

        let result = self.ctx.program(self.program_id)
            .call(instruction::SetRewardAuthorityBySuperAuthority {
                reward_index: reward_index as u8,
            })
            .accounts(accounts::SetRewardAuthorityBySuperAuthority {
                whirlpools_config: self.config,
                whirlpool: self.pool.whirlpool,
                reward_emissions_super_authority: self.reward_emissions_super_authority.pubkey(),
                new_reward_authority: new_authority.pubkey(),
            })
            .signers(&[&*self.reward_emissions_super_authority])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: verify on-chain reward authority updated.
                // Same as set_reward_authority: always writes to reward_infos[0].extension.
                if let Ok(pool_state) = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool) {
                    let on_chain_auth = Pubkey::from(pool_state.reward_infos[0].extension);
                    fuzz_assert_eq!(on_chain_auth, new_authority.pubkey(),
                        "set_reward_auth_by_super: on-chain authority {} != new {}",
                        on_chain_auth, new_authority.pubkey());
                }
                debug_print!("[SET_RWD_AUTH_SUPER] SUCCESS: reward_index={}", reward_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[SET_RWD_AUTH_SUPER] TX_FAILED: reward_index={}", reward_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[SET_RWD_AUTH_SUPER] SEND_FAILED: {:?}", e);
                false
            }
        };
        action_stats::record(&action_stats::SET_REWARD_AUTH_BY_SUPER, success);
        success
    }
