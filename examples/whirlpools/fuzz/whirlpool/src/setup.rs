use super::*;

/// Load the localnet admin keypair from the whirlpool program's auth directory.
/// This keypair is in the ADMINS whitelist required by InitializeConfig.
fn load_localnet_admin() -> Keypair {
    // Hardcoded from programs/whirlpool/src/auth/localnet/localnet-admin-keypair-0.json
    // Pubkey: tstYmkF9JHjZbSugJe1H3ygUTox1bqSxpn5QjxMwVrm
    let bytes: [u8; 64] = [
        177, 132, 153, 219, 3, 29, 214, 174, 187, 166, 254, 107, 173, 113, 207, 134,
        17, 53, 203, 189, 22, 128, 45, 37, 77, 187, 57, 146, 226, 162, 184, 112, 13,
        74, 41, 78, 251, 147, 132, 170, 77, 107, 238, 244, 51, 111, 207, 234, 88, 212,
        14, 239, 228, 185, 130, 71, 111, 173, 229, 157, 218, 8, 156, 70
    ];
    Keypair::try_from(bytes.as_slice()).expect("Invalid localnet admin keypair")
}

pub fn initialize_state(ctx: &mut TestContext, program_id: &Pubkey) -> WhirlpoolFixture {
    // Use the predefined localnet admin keypair from the whirlpool ADMINS whitelist
    let admin = Rc::new(load_localnet_admin());
    ctx.create_account()
        .pubkey(admin.pubkey())
        .lamports(100_000_000_000)
        .owner(system_program::ID)
        .create()
        .unwrap();

    // Initialize WhirlpoolsConfig
    let config = init_config(ctx, &admin, program_id);

    // Initialize FeeTier
    let fee_tier = init_fee_tier(ctx, &admin, &config, program_id);

    // Create token mints (must be ordered: mint_a < mint_b by pubkey)
    let (mint_a, mint_b) = create_ordered_mints(ctx, &admin);

    // Create a third mint for pool two (TwoHopSwap intermediary is mint_b)
    let mint_c = ctx.create_mint()
        .pubkey(next_keypair().pubkey())
        .decimals(9)
        .mint_authority(admin.pubkey())
        .create()
        .unwrap();

    // Create a fourth mint for pool three (adaptive fee pool)
    let mint_d = ctx.create_mint()
        .pubkey(next_keypair().pubkey())
        .decimals(9)
        .mint_authority(admin.pubkey())
        .create()
        .unwrap();

    // Create reward mints (3 separate mints for reward indices 0, 1, 2)
    let reward_mints = create_reward_mints(ctx, &admin);

    // Initialize Whirlpool
    let pool = init_pool(ctx, &admin, &config, &fee_tier, &mint_a, &mint_b, program_id);

    // Initialize tick arrays around current price
    let tick_arrays = init_tick_arrays(ctx, &admin, &pool.whirlpool, program_id);

    // Initialize reward index 0
    let reward_vaults = init_reward(ctx, &admin, &pool.whirlpool, &reward_mints[0], 0, program_id);
    let mut reward_initialized = [false; 3];
    let reward_vaults = if let Some(vault) = reward_vaults {
        reward_initialized[0] = true;
        vec![vault, Pubkey::default(), Pubkey::default()]
    } else {
        vec![Pubkey::default(), Pubkey::default(), Pubkey::default()]
    };

    let pool = PoolData {
        tick_arrays,
        reward_mints,
        reward_vaults,
        reward_initialized,
        ..pool
    };

    // Create users with token accounts (including reward token accounts)
    let users: Vec<_> = (0..3)
        .map(|_| {
            create_user(ctx, &admin, &mint_a, &mint_b, &mint_c, &mint_d, &pool.reward_mints)
        })
        .collect();

    // Create some initial positions with liquidity
    let positions = create_initial_positions(ctx, &users, &pool, program_id);

    // Initialize second pool for TwoHopSwap: mint_b / mint_c
    // Pool two needs mint_b < mint_c for ordering; if not, swap them
    let mut pool_two_setup_position: Option<PositionData> = None;
    let pool_two = init_pool_two(ctx, &admin, &config, &fee_tier, &mint_b, &mint_c, program_id);
    let pool_two = pool_two.map(|p| {
        // Initialize tick arrays for pool two
        let tick_arrays = init_tick_arrays(ctx, &admin, &p.whirlpool, program_id);
        // Add initial liquidity to pool two (using user 0)
        let p = PoolData { tick_arrays, ..p };
        pool_two_setup_position = add_pool_two_liquidity(ctx, &users[0], &p, &mint_b, program_id);
        p
    });

    // ---- Theme 1: Pre-init config extension + token badge feature ----
    // This ensures badge/extension actions are immediately discoverable without
    // relying on fuzzer to sequence init_config_extension → set_feature_flag first.
    let (config_extension_pda, _) = Pubkey::find_program_address(
        &[b"config_extension", config.as_ref()],
        program_id,
    );
    let mut config_extension: Option<Pubkey> = None;
    let mut config_extension_authority = admin.clone();
    let mut token_badge_authority_kp = admin.clone();
    let mut token_badge_feature_enabled = false;

    let ext_result = ctx.program(*program_id)
        .call(instruction::InitializeConfigExtension {})
        .accounts(accounts::InitializeConfigExtension {
            config,
            config_extension: config_extension_pda,
            funder: admin.pubkey(),
            fee_authority: admin.pubkey(),
        })
        .signers(&[&*admin])
        .send();
    if matches!(&ext_result, Ok(TxOutcome::Success { .. })) {
        config_extension = Some(config_extension_pda);
        config_extension_authority = admin.clone();
        token_badge_authority_kp = admin.clone();

        // Enable TOKEN_BADGE feature flag
        let flag_result = ctx.program(*program_id)
            .call(instruction::SetConfigFeatureFlag {
                feature_flag: whirlpool::types::ConfigFeatureFlag::TokenBadge(true),
            })
            .accounts(accounts::SetConfigFeatureFlag {
                whirlpools_config: config,
                authority: admin.pubkey(),
            })
            .signers(&[&*admin])
            .send();
        if matches!(&flag_result, Ok(TxOutcome::Success { .. })) {
            token_badge_feature_enabled = true;
        }
    }

    // ---- Theme 3: Initialize Adaptive Fee Tier + Pool Three ----
    let mut pool_three_setup_position: Option<PositionData> = None;
    let adaptive_fee_tier_index: u16 = 128;
    let delegated_fee_authority = Rc::new(next_keypair());
    ctx.create_account()
        .pubkey(delegated_fee_authority.pubkey())
        .lamports(1_000_000_000)
        .owner(system_program::ID)
        .create()
        .unwrap();

    let (adaptive_fee_tier_pda, _) = Pubkey::find_program_address(
        &[b"fee_tier", config.as_ref(), &adaptive_fee_tier_index.to_le_bytes()],
        program_id,
    );

    let mut adaptive_fee_tier: Option<Pubkey> = None;
    let aft_result = ctx.program(*program_id)
        .call(instruction::InitializeAdaptiveFeeTier {
            fee_tier_index: adaptive_fee_tier_index,
            tick_spacing: TICK_SPACING,
            initialize_pool_authority: Pubkey::default(), // permissionless
            delegated_fee_authority: delegated_fee_authority.pubkey(),
            default_base_fee_rate: DEFAULT_FEE_RATE,
            filter_period: 10,
            decay_period: 60,
            reduction_factor: 50,
            adaptive_fee_control_factor: 100,
            max_volatility_accumulator: 1000,
            tick_group_size: 1,
            major_swap_threshold_ticks: 10,
        })
        .accounts(accounts::InitializeAdaptiveFeeTier {
            whirlpools_config: config,
            adaptive_fee_tier: adaptive_fee_tier_pda,
            funder: admin.pubkey(),
            fee_authority: admin.pubkey(),
        })
        .signers(&[&*admin])
        .send();

    let mut pool_three: Option<PoolData> = None;
    if matches!(&aft_result, Ok(TxOutcome::Success { .. })) {
        adaptive_fee_tier = Some(adaptive_fee_tier_pda);

        // Create pool three: mint_a / mint_d (ordered by pubkey)
        let (p3_mint_a, p3_mint_b) = if mint_a < mint_d {
            (mint_a, mint_d)
        } else {
            (mint_d, mint_a)
        };

        let (p3_whirlpool, _) = Pubkey::find_program_address(
            &[
                b"whirlpool",
                config.as_ref(),
                p3_mint_a.as_ref(),
                p3_mint_b.as_ref(),
                &adaptive_fee_tier_index.to_le_bytes(),
            ],
            program_id,
        );
        let p3_vault_a = next_keypair();
        let p3_vault_b = next_keypair();
        let (p3_oracle, _) = Pubkey::find_program_address(
            &[b"oracle", p3_whirlpool.as_ref()],
            program_id,
        );

        // Token badge PDAs (may be uninitialized - program accepts them)
        let (badge_a_pda, _) = Pubkey::find_program_address(
            &[b"token_badge", config.as_ref(), p3_mint_a.as_ref()],
            program_id,
        );
        let (badge_b_pda, _) = Pubkey::find_program_address(
            &[b"token_badge", config.as_ref(), p3_mint_b.as_ref()],
            program_id,
        );

        let p3_result = ctx.program(*program_id)
            .call(instruction::InitializePoolWithAdaptiveFee {
                initial_sqrt_price: INITIAL_SQRT_PRICE,
                trade_enable_timestamp: None,
            })
            .accounts(accounts::InitializePoolWithAdaptiveFee {
                whirlpools_config: config,
                token_mint_a: p3_mint_a,
                token_mint_b: p3_mint_b,
                token_badge_a: badge_a_pda,
                token_badge_b: badge_b_pda,
                funder: admin.pubkey(),
                initialize_pool_authority: admin.pubkey(),
                whirlpool: p3_whirlpool,
                oracle: p3_oracle,
                token_vault_a: p3_vault_a.pubkey(),
                token_vault_b: p3_vault_b.pubkey(),
                adaptive_fee_tier: adaptive_fee_tier_pda,
                token_program_a: spl_token::ID,
                token_program_b: spl_token::ID,
            })
            .signers(&[&*admin, &p3_vault_a, &p3_vault_b])
            .send();

        match &p3_result {
            Ok(TxOutcome::Success { .. }) => {
                // Initialize tick arrays for pool three
                let p3_tick_arrays = init_tick_arrays(ctx, &admin, &p3_whirlpool, program_id);
                let p3 = PoolData {
                    whirlpool: p3_whirlpool,
                    token_mint_a: p3_mint_a,
                    token_mint_b: p3_mint_b,
                    token_vault_a: p3_vault_a.pubkey(),
                    token_vault_b: p3_vault_b.pubkey(),
                    tick_arrays: p3_tick_arrays,
                    oracle: p3_oracle,
                    reward_mints: vec![],
                    reward_vaults: vec![],
                    reward_initialized: [false; 3],
                };
                // Add initial liquidity to pool three
                pool_three_setup_position = add_pool_three_liquidity(ctx, &users[0], &p3, &mint_a, &mint_d, program_id);
                pool_three = Some(p3);
            }
            Ok(TxOutcome::ProgramError { .. }) => {}
            Err(_) => {}
        }
    }

    // Compute initial total token balances for conservation invariant
    let mut initial_total_token_a = ctx.token_balance(&pool.token_vault_a)
        + users.iter().map(|u| ctx.token_balance(&u.token_account_a)).sum::<u64>();
    let mut initial_total_token_b = ctx.token_balance(&pool.token_vault_b)
        + users.iter().map(|u| ctx.token_balance(&u.token_account_b)).sum::<u64>();
    let mut initial_total_token_c: u64 = users.iter().map(|u| ctx.token_balance(&u.token_account_c)).sum();
    let mut initial_total_token_d: u64 = users.iter().map(|u| ctx.token_balance(&u.token_account_d)).sum();
    if let Some(ref p2) = pool_two {
        let p2_va = ctx.token_balance(&p2.token_vault_a);
        let p2_vb = ctx.token_balance(&p2.token_vault_b);
        if p2.token_mint_a == pool.token_mint_b {
            initial_total_token_b += p2_va;
            initial_total_token_c += p2_vb;
        } else {
            initial_total_token_c += p2_va;
            initial_total_token_b += p2_vb;
        }
    }
    // Include pool three vaults (pool three uses mint_a and mint_d)
    if let Some(ref p3) = pool_three {
        let p3_va = ctx.token_balance(&p3.token_vault_a);
        let p3_vb = ctx.token_balance(&p3.token_vault_b);
        // p3 mints are sorted: determine which vault is mint_a vs mint_d
        if p3.token_mint_a == pool.token_mint_a {
            // p3.mint_a == mint_a, p3.mint_b == mint_d
            initial_total_token_a += p3_va;
            initial_total_token_d += p3_vb;
        } else {
            // p3.mint_a == mint_d, p3.mint_b == mint_a
            initial_total_token_d += p3_va;
            initial_total_token_a += p3_vb;
        }
    }
    WhirlpoolFixture {
        ctx: std::mem::replace(ctx, TestContext::new()),
        program_id: *program_id,
        admin: admin.clone(),
        config,
        fee_tier,
        pool,
        pool_two,
        token_mint_c: mint_c,
        users,
        positions,
        bundles: vec![],
        fee_authority: admin.clone(),
        collect_protocol_fees_authority: admin.clone(),
        reward_emissions_super_authority: admin.clone(),
        total_liquidity_added: 0,
        total_swaps: 0,
        successful_swaps: 0,
        initial_total_token_a,
        initial_total_token_b,
        initial_total_token_c,
        prev_fee_growth_global_a: 0,
        prev_fee_growth_global_b: 0,
        prev_reward_growths: [0; 3],
        prev_tick_current: 0,
        prev_sqrt_price_val: INITIAL_SQRT_PRICE,
        prev_reward_timestamp: 0,
        prev_p2_fee_growth_a: 0,
        prev_p2_fee_growth_b: 0,
        prev_p1_zero_liquidity: false,
        prev_p2_zero_liquidity: false,
        prev_protocol_fee_owed_a: 0,
        prev_protocol_fee_owed_b: 0,
        protocol_fees_just_collected: false,
        config_extension,
        config_extension_authority,
        token_badge_authority: token_badge_authority_kp,
        token_badges: vec![],
        token_badge_feature_enabled,
        pool_two_positions: pool_two_setup_position.into_iter().collect(),
        mint_d,
        pool_three,
        pool_three_positions: pool_three_setup_position.into_iter().collect(),
        adaptive_fee_tier,
        adaptive_fee_tier_index,
        delegated_fee_authority,
        prev_p3_fee_growth_global_a: 0,
        prev_p3_fee_growth_global_b: 0,
        prev_p3_sqrt_price_val: INITIAL_SQRT_PRICE,
        prev_p3_tick_current: 0,
        prev_p3_zero_liquidity: false,
        prev_p2_reward_growths: [0u128; 3],
        prev_p2_reward_timestamp: 0,
        prev_p3_reward_growths: [0u128; 3],
        prev_p3_reward_timestamp: 0,
        dynamic_tick_arrays: vec![],
        prev_p2_tick_current: 0,
        prev_p2_sqrt_price_val: INITIAL_SQRT_PRICE,
        prev_p2_protocol_fee_owed_a: 0,
        prev_p2_protocol_fee_owed_b: 0,
        p2_protocol_fees_just_collected: false,
        initial_total_token_d,
        expected_fee_rate: DEFAULT_FEE_RATE,
        prev_p3_protocol_fee_owed_a: 0,
        prev_p3_protocol_fee_owed_b: 0,
        p3_protocol_fees_just_collected: false,
        p3_adaptive_fee_constants_snapshot: None,
        prev_p3_oracle_last_ref_update_ts: 0,
        prev_p3_oracle_last_major_swap_ts: 0,
    }
}

fn init_config(ctx: &mut TestContext, admin: &Rc<Keypair>, program_id: &Pubkey) -> Pubkey {
    let config = next_keypair();

    let result = ctx.program(*program_id)
        .call(instruction::InitializeConfig {
            fee_authority: admin.pubkey(),
            collect_protocol_fees_authority: admin.pubkey(),
            reward_emissions_super_authority: admin.pubkey(),
            default_protocol_fee_rate: 300, // 0.03%
        })
        .accounts(accounts::InitializeConfig {
            config: config.pubkey(),
            funder: admin.pubkey(),
        })
        .signers(&[&**admin, &config])
        .send();

    match result {
        Ok(TxOutcome::Success { .. }) => {}
        Ok(TxOutcome::ProgramError { .. }) => {
            panic!("Setup failed: InitializeConfig");
        }
        Err(_) => {
            panic!("Setup failed: InitializeConfig");
        }
    }

    config.pubkey()
}

fn init_fee_tier(
    ctx: &mut TestContext,
    admin: &Rc<Keypair>,
    config: &Pubkey,
    program_id: &Pubkey,
) -> Pubkey {
    let (fee_tier, _) = Pubkey::find_program_address(
        &[b"fee_tier", config.as_ref(), &TICK_SPACING.to_le_bytes()],
        program_id,
    );

    let result = ctx.program(*program_id)
        .call(instruction::InitializeFeeTier {
            tick_spacing: TICK_SPACING,
            default_fee_rate: DEFAULT_FEE_RATE,
        })
        .accounts(accounts::InitializeFeeTier {
            config: *config,
            fee_tier,
            funder: admin.pubkey(),
            fee_authority: admin.pubkey(),
        })
        .signers(&[&**admin])
        .send();

    match result {
        Ok(TxOutcome::Success { .. }) => {}
        Ok(TxOutcome::ProgramError { .. }) => {
            panic!("Setup failed: InitializeFeeTier");
        }
        Err(_) => {
            panic!("Setup failed: InitializeFeeTier");
        }
    }

    fee_tier
}

fn create_ordered_mints(ctx: &mut TestContext, admin: &Rc<Keypair>) -> (Pubkey, Pubkey) {
    // Create two mints and order them by pubkey
    let mint1 = ctx.create_mint()
        .pubkey(next_keypair().pubkey())
        .decimals(9)
        .mint_authority(admin.pubkey())
        .create()
        .unwrap();

    let mint2 = ctx.create_mint()
        .pubkey(next_keypair().pubkey())
        .decimals(9)
        .mint_authority(admin.pubkey())
        .create()
        .unwrap();

    // Whirlpool requires mint_a < mint_b
    if mint1 < mint2 {
        (mint1, mint2)
    } else {
        (mint2, mint1)
    }
}

fn create_reward_mints(ctx: &mut TestContext, admin: &Rc<Keypair>) -> Vec<Pubkey> {
    (0..3).map(|_| {
        ctx.create_mint()
            .pubkey(next_keypair().pubkey())
            .decimals(9)
            .mint_authority(admin.pubkey())
            .create()
            .unwrap()
    }).collect()
}

fn init_pool(
    ctx: &mut TestContext,
    admin: &Rc<Keypair>,
    config: &Pubkey,
    fee_tier: &Pubkey,
    mint_a: &Pubkey,
    mint_b: &Pubkey,
    program_id: &Pubkey,
) -> PoolData {
    let (whirlpool, whirlpool_bump) = Pubkey::find_program_address(
        &[
            b"whirlpool",
            config.as_ref(),
            mint_a.as_ref(),
            mint_b.as_ref(),
            &TICK_SPACING.to_le_bytes(),
        ],
        program_id,
    );

    let token_vault_a = next_keypair();
    let token_vault_b = next_keypair();

    let (oracle, _) = Pubkey::find_program_address(
        &[b"oracle", whirlpool.as_ref()],
        program_id,
    );

    let result = ctx.program(*program_id)
        .call(instruction::InitializePool {
            bumps: WhirlpoolBumps { whirlpool_bump },
            tick_spacing: TICK_SPACING,
            initial_sqrt_price: INITIAL_SQRT_PRICE,
        })
        .accounts(accounts::InitializePool {
            whirlpools_config: *config,
            token_mint_a: *mint_a,
            token_mint_b: *mint_b,
            funder: admin.pubkey(),
            whirlpool,
            token_vault_a: token_vault_a.pubkey(),
            token_vault_b: token_vault_b.pubkey(),
            fee_tier: *fee_tier,
        })
        .signers(&[&**admin, &token_vault_a, &token_vault_b])
        .send();

    match result {
        Ok(TxOutcome::Success { .. }) => {}
        Ok(TxOutcome::ProgramError { .. }) => {
            panic!("Setup failed: InitializePool");
        }
        Err(_) => {
            panic!("Setup failed: InitializePool");
        }
    }

    PoolData {
        whirlpool,
        token_mint_a: *mint_a,
        token_mint_b: *mint_b,
        token_vault_a: token_vault_a.pubkey(),
        token_vault_b: token_vault_b.pubkey(),
        tick_arrays: vec![],
        oracle,
        reward_mints: vec![],
        reward_vaults: vec![],
        reward_initialized: [false; 3],
    }
}

fn init_tick_arrays(
    ctx: &mut TestContext,
    admin: &Rc<Keypair>,
    whirlpool: &Pubkey,
    program_id: &Pubkey,
) -> Vec<(i32, Pubkey)> {
    let mut tick_arrays = Vec::new();

    // Initialize tick arrays around the current tick (0)
    // Each array covers TICK_ARRAY_SIZE * TICK_SPACING ticks = 88 * 64 = 5632
    let array_span = TICK_ARRAY_SIZE * (TICK_SPACING as i32);

    // Create more tick arrays for better coverage
    for i in -5..=5 {
        let start_tick_index = i * array_span;

        // Note: Whirlpool uses string representation of tick index in seeds
        // seeds = [b"tick_array", whirlpool, start_tick_index.to_string().as_bytes()]
        let start_tick_str = start_tick_index.to_string();
        let (tick_array, _) = Pubkey::find_program_address(
            &[
                b"tick_array",
                whirlpool.as_ref(),
                start_tick_str.as_bytes(),
            ],
            program_id,
        );

        let result = ctx.program(*program_id)
            .call(instruction::InitializeTickArray { start_tick_index })
            .accounts(accounts::InitializeTickArray {
                whirlpool: *whirlpool,
                funder: admin.pubkey(),
                tick_array,
            })
            .signers(&[&**admin])
            .send();

        match result {
            Ok(TxOutcome::Success { .. }) => {
                tick_arrays.push((start_tick_index, tick_array));
            }
            Ok(TxOutcome::ProgramError { .. }) => {
                panic!("Setup failed: InitializeTickArray at start_tick={}", start_tick_index);
            }
            Err(_) => {
                panic!("Setup failed: InitializeTickArray at start_tick={}", start_tick_index);
            }
        }
    }

    if tick_arrays.is_empty() {
        panic!("Setup failed: No tick arrays were created!");
    }

    tick_arrays
}

/// Initialize a reward for the pool during setup (non-fatal if fails)
fn init_reward(
    ctx: &mut TestContext,
    admin: &Rc<Keypair>,
    whirlpool: &Pubkey,
    reward_mint: &Pubkey,
    reward_index: u8,
    program_id: &Pubkey,
) -> Option<Pubkey> {
    let reward_vault = next_keypair();

    let result = ctx.program(*program_id)
        .call(instruction::InitializeReward {
            reward_index,
        })
        .accounts(accounts::InitializeReward {
            reward_authority: admin.pubkey(),
            funder: admin.pubkey(),
            whirlpool: *whirlpool,
            reward_mint: *reward_mint,
            reward_vault: reward_vault.pubkey(),
        })
        .signers(&[&**admin, &reward_vault])
        .send();

    match result {
        Ok(TxOutcome::Success { .. }) => {
            // Fund the reward vault
            let _ = ctx.mint_to(reward_mint, &reward_vault.pubkey(), 1_000_000_000_000, admin);
            Some(reward_vault.pubkey())
        }
        Ok(TxOutcome::ProgramError { .. }) => {
            None
        }
        Err(_) => {
            None
        }
    }
}

fn create_user(
    ctx: &mut TestContext,
    admin: &Rc<Keypair>,
    mint_a: &Pubkey,
    mint_b: &Pubkey,
    mint_c: &Pubkey,
    mint_d: &Pubkey,
    reward_mints: &[Pubkey],
) -> UserData {
    let keypair = Rc::new(next_keypair());

    ctx.create_account()
        .pubkey(keypair.pubkey())
        .lamports(10_000_000_000)
        .owner(system_program::ID)
        .create()
        .unwrap();

    // Create token accounts
    let token_account_a = ctx.create_token_account()
        .pubkey(next_keypair().pubkey())
        .mint(*mint_a)
        .token_owner(keypair.pubkey())
        .create()
        .unwrap();

    let token_account_b = ctx.create_token_account()
        .pubkey(next_keypair().pubkey())
        .mint(*mint_b)
        .token_owner(keypair.pubkey())
        .create()
        .unwrap();

    let token_account_c = ctx.create_token_account()
        .pubkey(next_keypair().pubkey())
        .mint(*mint_c)
        .token_owner(keypair.pubkey())
        .create()
        .unwrap();

    let token_account_d = ctx.create_token_account()
        .pubkey(next_keypair().pubkey())
        .mint(*mint_d)
        .token_owner(keypair.pubkey())
        .create()
        .unwrap();

    // Mint tokens to user
    let amount = 1_000_000_000_000u64; // 1000 tokens with 9 decimals
    ctx.mint_to(mint_a, &token_account_a, amount, admin).unwrap();
    ctx.mint_to(mint_b, &token_account_b, amount, admin).unwrap();
    ctx.mint_to(mint_c, &token_account_c, amount, admin).unwrap();
    ctx.mint_to(mint_d, &token_account_d, amount, admin).unwrap();

    // Create reward token accounts for each reward mint
    let reward_accounts: Vec<Pubkey> = reward_mints.iter().map(|reward_mint| {
        ctx.create_token_account()
            .pubkey(next_keypair().pubkey())
            .mint(*reward_mint)
            .token_owner(keypair.pubkey())
            .create()
            .unwrap()
    }).collect();

    UserData {
        keypair,
        token_account_a,
        token_account_b,
        token_account_c,
        token_account_d,
        reward_accounts,
    }
}

fn create_initial_positions(
    ctx: &mut TestContext,
    users: &[UserData],
    pool: &PoolData,
    program_id: &Pubkey,
) -> Vec<PositionData> {
    let mut positions = Vec::new();

    // Create positions with varying ranges around current price
    let ranges = [
        (-10, 10),   // Narrow around current price
        (-20, 20),   // Medium range
        (-5, 5),     // Very narrow
    ];

    for (user_idx, user) in users.iter().enumerate() {
        let (lower_mult, upper_mult) = ranges[user_idx % ranges.len()];
        let tick_lower_index = lower_mult * (TICK_SPACING as i32);
        let tick_upper_index = upper_mult * (TICK_SPACING as i32);

        let position_mint = next_keypair();

        let (position, position_bump) = Pubkey::find_program_address(
            &[b"position", position_mint.pubkey().as_ref()],
            program_id,
        );

        let position_token_account = associated_token::get_associated_token_address(
            &user.keypair.pubkey(),
            &position_mint.pubkey(),
        );

        let result = ctx.program(*program_id)
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
                whirlpool: pool.whirlpool,
            })
            .signers(&[&*user.keypair, &position_mint])
            .send();

        match result {
            Ok(TxOutcome::Success { .. }) => {
                positions.push(PositionData {
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
            }
            Ok(TxOutcome::ProgramError { .. }) => {
                panic!("Setup failed: OpenPosition for user {}", user_idx);
            }
            Err(_) => {
                panic!("Setup failed: OpenPosition for user {}", user_idx);
            }
        }
    }

    // Add initial liquidity to positions so swaps can work
    for (pos_idx, position) in positions.iter_mut().enumerate() {
        let user = &users[position.owner_idx];

        // Find tick arrays for this position
        let ticks_in_array = TICK_ARRAY_SIZE * (TICK_SPACING as i32);
        let lower_array_start = if position.tick_lower_index >= 0 {
            (position.tick_lower_index / ticks_in_array) * ticks_in_array
        } else {
            ((position.tick_lower_index - ticks_in_array + 1) / ticks_in_array) * ticks_in_array
        };
        let upper_array_start = if position.tick_upper_index >= 0 {
            (position.tick_upper_index / ticks_in_array) * ticks_in_array
        } else {
            ((position.tick_upper_index - ticks_in_array + 1) / ticks_in_array) * ticks_in_array
        };

        let tick_array_lower = pool.tick_arrays.iter()
            .find(|(start, _)| *start == lower_array_start)
            .map(|(_, pk)| *pk)
            .unwrap_or(pool.tick_arrays[0].1);

        let tick_array_upper = pool.tick_arrays.iter()
            .find(|(start, _)| *start == upper_array_start)
            .map(|(_, pk)| *pk)
            .unwrap_or(pool.tick_arrays[0].1);

        let result = ctx.program(*program_id)
            .call(instruction::IncreaseLiquidity {
                liquidity_amount: 1_000_000_000, // 1B liquidity units
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

        match result {
            Ok(TxOutcome::Success { .. }) => {
                position.has_liquidity = true;
            }
            Ok(TxOutcome::ProgramError { .. }) => {
                panic!("Setup failed: IncreaseLiquidity for position {}", pos_idx);
            }
            Err(_) => {
                panic!("Setup failed: IncreaseLiquidity for position {}", pos_idx);
            }
        }
    }

    if positions.is_empty() {
        panic!("Setup failed: No positions were created!");
    }

    positions
}

/// Initialize a second pool for TwoHopSwap (mint_b / mint_c)
fn init_pool_two(
    ctx: &mut TestContext,
    admin: &Rc<Keypair>,
    config: &Pubkey,
    fee_tier: &Pubkey,
    mint_b: &Pubkey,
    mint_c: &Pubkey,
    program_id: &Pubkey,
) -> Option<PoolData> {
    // Whirlpool requires mint_a < mint_b by pubkey ordering
    let (pool_mint_a, pool_mint_b) = if *mint_b < *mint_c {
        (*mint_b, *mint_c)
    } else {
        (*mint_c, *mint_b)
    };

    let (whirlpool, whirlpool_bump) = Pubkey::find_program_address(
        &[
            b"whirlpool",
            config.as_ref(),
            pool_mint_a.as_ref(),
            pool_mint_b.as_ref(),
            &TICK_SPACING.to_le_bytes(),
        ],
        program_id,
    );

    let token_vault_a = next_keypair();
    let token_vault_b = next_keypair();

    let (oracle, _) = Pubkey::find_program_address(
        &[b"oracle", whirlpool.as_ref()],
        program_id,
    );

    let result = ctx.program(*program_id)
        .call(instruction::InitializePool {
            bumps: WhirlpoolBumps { whirlpool_bump },
            tick_spacing: TICK_SPACING,
            initial_sqrt_price: INITIAL_SQRT_PRICE,
        })
        .accounts(accounts::InitializePool {
            whirlpools_config: *config,
            token_mint_a: pool_mint_a,
            token_mint_b: pool_mint_b,
            funder: admin.pubkey(),
            whirlpool,
            token_vault_a: token_vault_a.pubkey(),
            token_vault_b: token_vault_b.pubkey(),
            fee_tier: *fee_tier,
        })
        .signers(&[&**admin, &token_vault_a, &token_vault_b])
        .send();

    match result {
        Ok(TxOutcome::Success { .. }) => {
            Some(PoolData {
                whirlpool,
                token_mint_a: pool_mint_a,
                token_mint_b: pool_mint_b,
                token_vault_a: token_vault_a.pubkey(),
                token_vault_b: token_vault_b.pubkey(),
                tick_arrays: vec![],
                oracle,
                reward_mints: vec![],
                reward_vaults: vec![],
                reward_initialized: [false; 3],
            })
        }
        Ok(TxOutcome::ProgramError { .. }) => {
            None
        }
        Err(_) => {
            None
        }
    }
}

/// Add initial liquidity to pool two so TwoHopSwap can work
fn add_pool_two_liquidity(
    ctx: &mut TestContext,
    user: &UserData,
    pool: &PoolData,
    mint_b: &Pubkey,
    program_id: &Pubkey,
) -> Option<PositionData> {
    // Use a range covered by our tick arrays (-5..+5 spans)
    // Each span = 88 * 64 = 5632 ticks, so 5 spans = ±28160
    let tick_lower_index = -10 * (TICK_SPACING as i32);  // -640
    let tick_upper_index = 10 * (TICK_SPACING as i32);   //  640

    let position_mint = next_keypair();
    let (position, position_bump) = Pubkey::find_program_address(
        &[b"position", position_mint.pubkey().as_ref()],
        program_id,
    );
    let position_token_account = associated_token::get_associated_token_address(
        &user.keypair.pubkey(),
        &position_mint.pubkey(),
    );

    let result = ctx.program(*program_id)
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
            whirlpool: pool.whirlpool,
        })
        .signers(&[&*user.keypair, &position_mint])
        .send();

    match &result {
        Ok(TxOutcome::Success { .. }) => {}
        _ => {
            return None;
        }
    }

    let pos_mint_pubkey = position_mint.pubkey();

    // Map user token accounts to pool two's mint ordering
    let (user_account_a, user_account_b) = if pool.token_mint_a == *mint_b {
        // pool_two.mint_a == mint_b → user_account_b for side A, user_account_c for side B
        (user.token_account_b, user.token_account_c)
    } else {
        // pool_two.mint_a == mint_c → user_account_c for side A, user_account_b for side B
        (user.token_account_c, user.token_account_b)
    };

    let tick_array_lower = pool.tick_arrays.iter()
        .find(|(start, _)| {
            let ticks_in_array = TICK_ARRAY_SIZE * (TICK_SPACING as i32);
            let target = if tick_lower_index >= 0 {
                (tick_lower_index / ticks_in_array) * ticks_in_array
            } else {
                ((tick_lower_index - ticks_in_array + 1) / ticks_in_array) * ticks_in_array
            };
            *start == target
        })
        .map(|(_, pk)| *pk)
        .unwrap_or(pool.tick_arrays[0].1);

    let tick_array_upper = pool.tick_arrays.iter()
        .find(|(start, _)| {
            let ticks_in_array = TICK_ARRAY_SIZE * (TICK_SPACING as i32);
            let target = if tick_upper_index >= 0 {
                (tick_upper_index / ticks_in_array) * ticks_in_array
            } else {
                ((tick_upper_index - ticks_in_array + 1) / ticks_in_array) * ticks_in_array
            };
            *start == target
        })
        .map(|(_, pk)| *pk)
        .unwrap_or(pool.tick_arrays[0].1);

    let result = ctx.program(*program_id)
        .call(instruction::IncreaseLiquidity {
            liquidity_amount: 1_000_000_000, // 1B liquidity
            token_max_a: u64::MAX,
            token_max_b: u64::MAX,
        })
        .accounts(accounts::IncreaseLiquidity {
            whirlpool: pool.whirlpool,
            position_authority: user.keypair.pubkey(),
            position,
            position_token_account,
            token_owner_account_a: user_account_a,
            token_owner_account_b: user_account_b,
            token_vault_a: pool.token_vault_a,
            token_vault_b: pool.token_vault_b,
            tick_array_lower,
            tick_array_upper,
        })
        .signers(&[&*user.keypair])
        .send();

    match &result {
        Ok(TxOutcome::Success { .. }) => {
            Some(PositionData {
                position,
                position_mint: pos_mint_pubkey,
                position_token_account,
                tick_lower_index,
                tick_upper_index,
                owner_idx: 0,
                has_liquidity: true,
                bundle_info: None,
                prev_fee_owed_a: 0,
                prev_fee_owed_b: 0,
                fees_just_collected: false,
            })
        }
        _ => {
            None
        }
    }
}

/// Add initial liquidity to pool three (adaptive fee pool)
fn add_pool_three_liquidity(
    ctx: &mut TestContext,
    user: &UserData,
    pool: &PoolData,
    mint_a: &Pubkey,
    mint_d: &Pubkey,
    program_id: &Pubkey,
) -> Option<PositionData> {
    let tick_lower_index = -10 * (TICK_SPACING as i32);
    let tick_upper_index = 10 * (TICK_SPACING as i32);

    let position_mint = next_keypair();
    let (position, position_bump) = Pubkey::find_program_address(
        &[b"position", position_mint.pubkey().as_ref()],
        program_id,
    );
    let position_token_account = associated_token::get_associated_token_address(
        &user.keypair.pubkey(),
        &position_mint.pubkey(),
    );

    let result = ctx.program(*program_id)
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
            whirlpool: pool.whirlpool,
        })
        .signers(&[&*user.keypair, &position_mint])
        .send();

    match &result {
        Ok(TxOutcome::Success { .. }) => {}
        _ => {
            return None;
        }
    }

    let pos_mint_pubkey = position_mint.pubkey();

    // Map user token accounts to pool three's mint ordering
    // pool three mints are sorted: determine which is mint_a vs mint_d
    let (user_account_a, user_account_b) = if pool.token_mint_a == *mint_a {
        // p3.mint_a == mint_a → user_account_a for side A, user_account_d for side B
        (user.token_account_a, user.token_account_d)
    } else {
        // p3.mint_a == mint_d → user_account_d for side A, user_account_a for side B
        (user.token_account_d, user.token_account_a)
    };

    let tick_array_lower = pool.tick_arrays.iter()
        .find(|(start, _)| {
            let ticks_in_array = TICK_ARRAY_SIZE * (TICK_SPACING as i32);
            let target = if tick_lower_index >= 0 {
                (tick_lower_index / ticks_in_array) * ticks_in_array
            } else {
                ((tick_lower_index - ticks_in_array + 1) / ticks_in_array) * ticks_in_array
            };
            *start == target
        })
        .map(|(_, pk)| *pk)
        .unwrap_or(pool.tick_arrays[0].1);

    let tick_array_upper = pool.tick_arrays.iter()
        .find(|(start, _)| {
            let ticks_in_array = TICK_ARRAY_SIZE * (TICK_SPACING as i32);
            let target = if tick_upper_index >= 0 {
                (tick_upper_index / ticks_in_array) * ticks_in_array
            } else {
                ((tick_upper_index - ticks_in_array + 1) / ticks_in_array) * ticks_in_array
            };
            *start == target
        })
        .map(|(_, pk)| *pk)
        .unwrap_or(pool.tick_arrays[0].1);

    let result = ctx.program(*program_id)
        .call(instruction::IncreaseLiquidity {
            liquidity_amount: 1_000_000_000,
            token_max_a: u64::MAX,
            token_max_b: u64::MAX,
        })
        .accounts(accounts::IncreaseLiquidity {
            whirlpool: pool.whirlpool,
            position_authority: user.keypair.pubkey(),
            position,
            position_token_account,
            token_owner_account_a: user_account_a,
            token_owner_account_b: user_account_b,
            token_vault_a: pool.token_vault_a,
            token_vault_b: pool.token_vault_b,
            tick_array_lower,
            tick_array_upper,
        })
        .signers(&[&*user.keypair])
        .send();

    match &result {
        Ok(TxOutcome::Success { .. }) => {
            Some(PositionData {
                position,
                position_mint: pos_mint_pubkey,
                position_token_account,
                tick_lower_index,
                tick_upper_index,
                owner_idx: 0,
                has_liquidity: true,
                bundle_info: None,
                prev_fee_owed_a: 0,
                prev_fee_owed_b: 0,
                fees_just_collected: false,
            })
        }
        _ => {
            None
        }
    }
}
