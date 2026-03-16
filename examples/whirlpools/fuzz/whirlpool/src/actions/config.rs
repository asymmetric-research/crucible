// actions/config.rs — Config extension and token badge action methods (included in impl WhirlpoolFixture via include!())

pub fn action_initialize_config_extension(&mut self) -> bool {
    if self.config_extension.is_some() {
        return false; // Already initialized
    }

    let (config_extension_pda, _) = Pubkey::find_program_address(
        &[b"config_extension", self.config.as_ref()],
        &self.program_id,
    );

    let result = self.ctx.program(self.program_id)
        .call(instruction::InitializeConfigExtension {})
        .accounts(accounts::InitializeConfigExtension {
            config: self.config,
            config_extension: config_extension_pda,
            funder: self.admin.pubkey(),
            fee_authority: self.fee_authority.pubkey(),
        })
        .signers(&[&*self.admin, &*self.fee_authority])
        .send();

    let success = match &result {
        Ok(TxOutcome::Success { .. }) => {
            self.config_extension = Some(config_extension_pda);
            // InitializeConfigExtension sets both config_extension_authority AND
            // token_badge_authority to fee_authority.key()
            self.config_extension_authority = self.fee_authority.clone();
            self.token_badge_authority = self.fee_authority.clone();
            debug_print!("[INIT_CONFIG_EXT] SUCCESS: {}", config_extension_pda);
            true
        }
        Ok(TxOutcome::ProgramError { logs, .. }) => {
            debug_print!("[INIT_CONFIG_EXT] TX_FAILED");
            for log in logs { debug_print!("  {}", log); }
            false
        }
        Err(e) => {
            debug_print!("[INIT_CONFIG_EXT] SEND_FAILED: {:?}", e);
            false
        }
    };
    action_stats::record(&action_stats::INIT_CONFIG_EXTENSION, success);
    success
}

/// Set config extension authority (rotate to new keypair)
pub fn action_set_config_extension_authority(&mut self) -> bool {
    let config_extension_pda = match self.config_extension {
        Some(ce) => ce,
        None => return false,
    };

    let new_authority = Rc::new(Keypair::new());
    let _ = self.ctx.create_account()
        .pubkey(new_authority.pubkey())
        .lamports(1_000_000_000)
        .owner(system_program::ID)
        .create();

    let result = self.ctx.program(self.program_id)
        .call(instruction::SetConfigExtensionAuthority {})
        .accounts(accounts::SetConfigExtensionAuthority {
            whirlpools_config: self.config,
            whirlpools_config_extension: config_extension_pda,
            config_extension_authority: self.config_extension_authority.pubkey(),
            new_config_extension_authority: new_authority.pubkey(),
        })
        .signers(&[&*self.config_extension_authority])
        .send();

    let success = match &result {
        Ok(TxOutcome::Success { .. }) => {
            // Postcondition: on-chain authority matches new authority
            if let Ok(ext_state) = self.ctx.read_anchor_account::<whirlpool::state::WhirlpoolsConfigExtension>(&config_extension_pda) {
                fuzz_assert_eq!(ext_state.config_extension_authority, new_authority.pubkey(),
                    "set_config_ext_auth: on-chain {} != expected {}", ext_state.config_extension_authority, new_authority.pubkey());
            }
            debug_print!("[SET_CFG_EXT_AUTH] SUCCESS: {} -> {}",
                self.config_extension_authority.pubkey(), new_authority.pubkey());
            self.config_extension_authority = new_authority;
            true
        }
        Ok(TxOutcome::ProgramError { logs, .. }) => {
            debug_print!("[SET_CFG_EXT_AUTH] TX_FAILED");
            for log in logs { debug_print!("  {}", log); }
            false
        }
        Err(e) => {
            debug_print!("[SET_CFG_EXT_AUTH] SEND_FAILED: {:?}", e);
            false
        }
    };
    action_stats::record(&action_stats::SET_CONFIG_EXT_AUTH, success);
    success
}

/// Set token badge authority on config extension
pub fn action_set_token_badge_authority(&mut self) -> bool {
    let config_extension_pda = match self.config_extension {
        Some(ce) => ce,
        None => return false,
    };

    let new_authority = Rc::new(Keypair::new());
    let _ = self.ctx.create_account()
        .pubkey(new_authority.pubkey())
        .lamports(1_000_000_000)
        .owner(system_program::ID)
        .create();

    let result = self.ctx.program(self.program_id)
        .call(instruction::SetTokenBadgeAuthority {})
        .accounts(accounts::SetTokenBadgeAuthority {
            whirlpools_config: self.config,
            whirlpools_config_extension: config_extension_pda,
            config_extension_authority: self.config_extension_authority.pubkey(),
            new_token_badge_authority: new_authority.pubkey(),
        })
        .signers(&[&*self.config_extension_authority])
        .send();

    let success = match &result {
        Ok(TxOutcome::Success { .. }) => {
            // Postcondition: on-chain token_badge_authority matches new authority
            if let Ok(ext_state) = self.ctx.read_anchor_account::<whirlpool::state::WhirlpoolsConfigExtension>(&config_extension_pda) {
                fuzz_assert_eq!(ext_state.token_badge_authority, new_authority.pubkey(),
                    "set_token_badge_auth: on-chain {} != expected {}", ext_state.token_badge_authority, new_authority.pubkey());
            }
            debug_print!("[SET_BADGE_AUTH] SUCCESS: {} -> {}",
                self.token_badge_authority.pubkey(), new_authority.pubkey());
            self.token_badge_authority = new_authority;
            true
        }
        Ok(TxOutcome::ProgramError { logs, .. }) => {
            debug_print!("[SET_BADGE_AUTH] TX_FAILED");
            for log in logs { debug_print!("  {}", log); }
            false
        }
        Err(e) => {
            debug_print!("[SET_BADGE_AUTH] SEND_FAILED: {:?}", e);
            false
        }
    };
    action_stats::record(&action_stats::SET_TOKEN_BADGE_AUTH, success);
    success
}

pub fn action_set_config_feature_flag(&mut self) -> bool {
    let enable = !self.token_badge_feature_enabled;
    let result = self.ctx.program(self.program_id)
        .call(instruction::SetConfigFeatureFlag {
            feature_flag: whirlpool::types::ConfigFeatureFlag::TokenBadge(enable),
        })
        .accounts(accounts::SetConfigFeatureFlag {
            whirlpools_config: self.config,
            authority: self.admin.pubkey(),
        })
        .signers(&[&*self.admin])
        .send();
    let success = matches!(&result, Ok(TxOutcome::Success { .. }));
    if success {
        self.token_badge_feature_enabled = enable;
        debug_print!("[SET_CFG_FEATURE] SUCCESS: token_badge_enabled={}", enable);
    } else {
        debug_print!("[SET_CFG_FEATURE] FAILED");
    }
    action_stats::record(&action_stats::SET_CONFIG_FEATURE_FLAG, success);
    success
}

/// Initialize a token badge for one of our mints
pub fn action_initialize_token_badge(&mut self, mint_selector: u8) -> bool {
    if self.config_extension.is_none() || !self.token_badge_feature_enabled {
        return false;
    }
    let config_extension_pda = self.config_extension.unwrap();

    // Build a list of candidate mints
    let mut candidate_mints = vec![
        self.pool.token_mint_a,
        self.pool.token_mint_b,
        self.token_mint_c,
    ];
    for i in 0..3 {
        if i < self.pool.reward_mints.len() {
            candidate_mints.push(self.pool.reward_mints[i]);
        }
    }

    let mint_idx = (mint_selector as usize) % candidate_mints.len();
    let mint = candidate_mints[mint_idx];

    // Check if badge already exists for that mint
    if self.token_badges.iter().any(|(m, _)| *m == mint) {
        return false;
    }

    let (token_badge_pda, _) = Pubkey::find_program_address(
        &[b"token_badge", self.config.as_ref(), mint.as_ref()],
        &self.program_id,
    );

    let result = self.ctx.program(self.program_id)
        .call(instruction::InitializeTokenBadge {})
        .accounts(accounts::InitializeTokenBadge {
            whirlpools_config: self.config,
            whirlpools_config_extension: config_extension_pda,
            token_badge_authority: self.token_badge_authority.pubkey(),
            token_mint: mint,
            token_badge: token_badge_pda,
            funder: self.admin.pubkey(),
        })
        .signers(&[&*self.token_badge_authority, &*self.admin])
        .send();

    let success = match &result {
        Ok(TxOutcome::Success { .. }) => {
            self.token_badges.push((mint, token_badge_pda));
            debug_print!("[INIT_TOKEN_BADGE] SUCCESS: mint={} badge={}", mint, token_badge_pda);
            true
        }
        Ok(TxOutcome::ProgramError { logs, .. }) => {
            debug_print!("[INIT_TOKEN_BADGE] TX_FAILED");
            for log in logs { debug_print!("  {}", log); }
            false
        }
        Err(e) => {
            debug_print!("[INIT_TOKEN_BADGE] SEND_FAILED: {:?}", e);
            false
        }
    };
    action_stats::record(&action_stats::INIT_TOKEN_BADGE, success);
    success
}

/// Delete a token badge
pub fn action_delete_token_badge(&mut self, badge_selector: u8) -> bool {
    if self.token_badges.is_empty() || self.config_extension.is_none() {
        return false;
    }
    let config_extension_pda = self.config_extension.unwrap();
    let badge_idx = (badge_selector as usize) % self.token_badges.len();
    let (mint, token_badge_pda) = self.token_badges[badge_idx];

    let result = self.ctx.program(self.program_id)
        .call(instruction::DeleteTokenBadge {})
        .accounts(accounts::DeleteTokenBadge {
            whirlpools_config: self.config,
            whirlpools_config_extension: config_extension_pda,
            token_badge_authority: self.token_badge_authority.pubkey(),
            token_mint: mint,
            token_badge: token_badge_pda,
            receiver: self.admin.pubkey(),
        })
        .signers(&[&*self.token_badge_authority])
        .send();

    let success = match &result {
        Ok(TxOutcome::Success { .. }) => {
            self.token_badges.remove(badge_idx);
            debug_print!("[DELETE_TOKEN_BADGE] SUCCESS: mint={}", mint);
            true
        }
        Ok(TxOutcome::ProgramError { logs, .. }) => {
            debug_print!("[DELETE_TOKEN_BADGE] TX_FAILED");
            for log in logs { debug_print!("  {}", log); }
            false
        }
        Err(e) => {
            debug_print!("[DELETE_TOKEN_BADGE] SEND_FAILED: {:?}", e);
            false
        }
    };
    action_stats::record(&action_stats::DELETE_TOKEN_BADGE, success);
    success
}

/// Set an attribute on a token badge
pub fn action_set_token_badge_attribute(&mut self, badge_selector: u8, attr_val: bool) -> bool {
    if self.token_badges.is_empty() || self.config_extension.is_none() {
        return false;
    }
    let config_extension_pda = self.config_extension.unwrap();
    let badge_idx = (badge_selector as usize) % self.token_badges.len();
    let (mint, token_badge_pda) = self.token_badges[badge_idx];

    let result = self.ctx.program(self.program_id)
        .call(instruction::SetTokenBadgeAttribute {
            attribute: whirlpool::types::TokenBadgeAttribute::RequireNonTransferablePosition(attr_val),
        })
        .accounts(accounts::SetTokenBadgeAttribute {
            whirlpools_config: self.config,
            whirlpools_config_extension: config_extension_pda,
            token_badge_authority: self.token_badge_authority.pubkey(),
            token_mint: mint,
            token_badge: token_badge_pda,
        })
        .signers(&[&*self.token_badge_authority])
        .send();

    let success = match &result {
        Ok(TxOutcome::Success { .. }) => {
            debug_print!("[SET_BADGE_ATTR] SUCCESS: mint={} attr={}", mint, attr_val);
            true
        }
        Ok(TxOutcome::ProgramError { logs, .. }) => {
            debug_print!("[SET_BADGE_ATTR] TX_FAILED");
            for log in logs { debug_print!("  {}", log); }
            false
        }
        Err(e) => {
            debug_print!("[SET_BADGE_ATTR] SEND_FAILED: {:?}", e);
            false
        }
    };
    action_stats::record(&action_stats::SET_TOKEN_BADGE_ATTR, success);
    success
}
