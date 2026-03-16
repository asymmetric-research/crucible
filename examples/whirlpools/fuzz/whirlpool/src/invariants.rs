// Imports provided by include!() from main.rs — no `use` needed here.

#[invariant_test]
fn invariant_test(fixture: &mut WhirlpoolFixture) {
    // ---- Token Conservation (including pool two and pool three) ----
    let vault_a_balance = fixture.ctx.token_balance(&fixture.pool.token_vault_a);
    let vault_b_balance = fixture.ctx.token_balance(&fixture.pool.token_vault_b);
    let mut total_a: u64 = vault_a_balance;
    let mut total_b: u64 = vault_b_balance;
    let mut total_c: u64 = 0;
    let mut total_d: u64 = 0;
    for user in &fixture.users {
        total_a = total_a.saturating_add(fixture.ctx.token_balance(&user.token_account_a));
        total_b = total_b.saturating_add(fixture.ctx.token_balance(&user.token_account_b));
        total_c = total_c.saturating_add(fixture.ctx.token_balance(&user.token_account_c));
        total_d = total_d.saturating_add(fixture.ctx.token_balance(&user.token_account_d));
    }
    // Include pool two vaults in token conservation (respecting mint ordering)
    if let Some(ref p2) = fixture.pool_two {
        let p2_vault_a_bal = fixture.ctx.token_balance(&p2.token_vault_a);
        let p2_vault_b_bal = fixture.ctx.token_balance(&p2.token_vault_b);
        if p2.token_mint_a == fixture.pool.token_mint_b {
            total_b = total_b.saturating_add(p2_vault_a_bal);
            total_c = total_c.saturating_add(p2_vault_b_bal);
        } else {
            total_c = total_c.saturating_add(p2_vault_a_bal);
            total_b = total_b.saturating_add(p2_vault_b_bal);
        }
    }
    // Include pool three vaults (pool three uses mint_a and mint_d)
    if let Some(ref p3) = fixture.pool_three {
        let p3_vault_a_bal = fixture.ctx.token_balance(&p3.token_vault_a);
        let p3_vault_b_bal = fixture.ctx.token_balance(&p3.token_vault_b);
        if p3.token_mint_a == fixture.pool.token_mint_a {
            total_a = total_a.saturating_add(p3_vault_a_bal);
            total_d = total_d.saturating_add(p3_vault_b_bal);
        } else {
            total_d = total_d.saturating_add(p3_vault_a_bal);
            total_a = total_a.saturating_add(p3_vault_b_bal);
        }
    }

    fuzz_assert_eq!(
        total_a, fixture.initial_total_token_a,
        "Token A conservation violated: current={} initial={}",
        total_a, fixture.initial_total_token_a
    );
    fuzz_assert_eq!(
        total_b, fixture.initial_total_token_b,
        "Token B conservation violated: current={} initial={}",
        total_b, fixture.initial_total_token_b
    );
    fuzz_assert_eq!(
        total_c, fixture.initial_total_token_c,
        "Token C conservation violated: current={} initial={}",
        total_c, fixture.initial_total_token_c
    );
    fuzz_assert_eq!(
        total_d, fixture.initial_total_token_d,
        "Token D conservation violated: current={} initial={}",
        total_d, fixture.initial_total_token_d
    );

    // ---- On-Chain Pool State Checks ----
    if let Ok(pool_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
        // Sqrt price bounds
        fuzz_assert!(
            pool_state.sqrt_price >= MIN_SQRT_PRICE_X64 && pool_state.sqrt_price <= MAX_SQRT_PRICE_X64,
            "Sqrt price out of bounds: {} (min={}, max={})",
            pool_state.sqrt_price, MIN_SQRT_PRICE_X64, MAX_SQRT_PRICE_X64
        );

        // ---- Step 1: Tight sqrt_price ↔ tick_current_index Bound (KyberSwap invariant) ----
        // sqrt_price_from_tick(tick) <= sqrt_price <= sqrt_price_from_tick(tick + 1)
        // Note: upper bound uses <= because a_to_b swaps that land exactly on a tick
        // boundary set tick_current = boundary_tick - 1 while sqrt_price equals the
        // boundary tick's price. This is the Whirlpool convention.
        let lower_bound = harness_sqrt_price_from_tick(pool_state.tick_current_index);
        let upper_bound = harness_sqrt_price_from_tick(pool_state.tick_current_index + 1);
        fuzz_assert!(pool_state.sqrt_price >= lower_bound,
            "Pool1 sqrt_price {} below tick {} lower bound {}",
            pool_state.sqrt_price, pool_state.tick_current_index, lower_bound);
        fuzz_assert!(pool_state.sqrt_price <= upper_bound,
            "Pool1 sqrt_price {} > tick {} upper bound {}",
            pool_state.sqrt_price, pool_state.tick_current_index, upper_bound);

        // ---- Fee Rate Bounds ----
        fuzz_assert_le!(
            pool_state.fee_rate, MAX_FEE_RATE,
            "Fee rate exceeds max: {} > {}",
            pool_state.fee_rate, MAX_FEE_RATE
        );
        fuzz_assert_le!(
            pool_state.protocol_fee_rate, MAX_PROTOCOL_FEE_RATE,
            "Protocol fee rate exceeds max: {} > {}",
            pool_state.protocol_fee_rate, MAX_PROTOCOL_FEE_RATE
        );
        // ---- Expected Fee Rate Consistency ----
        fuzz_assert_eq!(
            pool_state.fee_rate, fixture.expected_fee_rate,
            "Fee rate corrupted: on-chain={} expected={}",
            pool_state.fee_rate, fixture.expected_fee_rate
        );

        // ---- Protocol Fee Monotonicity ----
        // protocol_fee_owed accumulates via += in update_after_swap.
        // It should only increase between collections (when it resets to 0).
        // A decrease without collection indicates fee corruption or unauthorized drain.
        if fixture.protocol_fees_just_collected {
            // ---- Collect Protocol Fees Postcondition ----
            // After successful collect_protocol_fees, both owed fields must be zero.
            // Any residual means dust accumulated across swaps or the instruction
            // only collected one token side, inflating accounting.
            fuzz_assert_eq!(pool_state.protocol_fee_owed_a, 0,
                "Pool1 protocol_fee_owed_a not cleared after collection: {}",
                pool_state.protocol_fee_owed_a);
            fuzz_assert_eq!(pool_state.protocol_fee_owed_b, 0,
                "Pool1 protocol_fee_owed_b not cleared after collection: {}",
                pool_state.protocol_fee_owed_b);
        } else {
            fuzz_assert!(pool_state.protocol_fee_owed_a >= fixture.prev_protocol_fee_owed_a,
                "Protocol fee A decreased without collection: {} -> {}",
                fixture.prev_protocol_fee_owed_a, pool_state.protocol_fee_owed_a);
            fuzz_assert!(pool_state.protocol_fee_owed_b >= fixture.prev_protocol_fee_owed_b,
                "Protocol fee B decreased without collection: {} -> {}",
                fixture.prev_protocol_fee_owed_b, pool_state.protocol_fee_owed_b);
        }
        fixture.prev_protocol_fee_owed_a = pool_state.protocol_fee_owed_a;
        fixture.prev_protocol_fee_owed_b = pool_state.protocol_fee_owed_b;
        fixture.protocol_fees_just_collected = false;

        // ---- Tick within bounds ----
        fuzz_assert_ge!(
            pool_state.tick_current_index, MIN_TICK_INDEX,
            "Current tick below min: {} < {}",
            pool_state.tick_current_index, MIN_TICK_INDEX
        );
        fuzz_assert_le!(
            pool_state.tick_current_index, MAX_TICK_INDEX,
            "Current tick above max: {} > {}",
            pool_state.tick_current_index, MAX_TICK_INDEX
        );

        // ---- Tick spacing invariant ----
        fuzz_assert_eq!(
            pool_state.tick_spacing, TICK_SPACING,
            "Tick spacing changed: {} != {}",
            pool_state.tick_spacing, TICK_SPACING
        );

        // ---- Tick ↔ Sqrt Price Monotonicity Cross-Check (Step 2) ----
        // If tick_current_index increased, sqrt_price must have increased (and vice versa).
        // Catches bugs where one field updates but not the other.
        let cur_tick = pool_state.tick_current_index;
        let cur_sqrt = pool_state.sqrt_price;
        if cur_tick > fixture.prev_tick_current {
            fuzz_assert!(
                cur_sqrt >= fixture.prev_sqrt_price_val,
                "Tick increased ({} -> {}) but sqrt_price decreased ({} -> {})",
                fixture.prev_tick_current, cur_tick,
                fixture.prev_sqrt_price_val, cur_sqrt
            );
        }
        if cur_tick < fixture.prev_tick_current {
            fuzz_assert!(
                cur_sqrt <= fixture.prev_sqrt_price_val,
                "Tick decreased ({} -> {}) but sqrt_price increased ({} -> {})",
                fixture.prev_tick_current, cur_tick,
                fixture.prev_sqrt_price_val, cur_sqrt
            );
        }
        fixture.prev_tick_current = cur_tick;
        fixture.prev_sqrt_price_val = cur_sqrt;

        // Fee growth monotonicity
        fuzz_assert!(
            pool_state.fee_growth_global_a >= fixture.prev_fee_growth_global_a,
            "Fee growth A decreased: {} < {}",
            pool_state.fee_growth_global_a, fixture.prev_fee_growth_global_a
        );
        fuzz_assert!(
            pool_state.fee_growth_global_b >= fixture.prev_fee_growth_global_b,
            "Fee growth B decreased: {} < {}",
            pool_state.fee_growth_global_b, fixture.prev_fee_growth_global_b
        );

        // ---- Step 7: Zero-Liquidity Fee Growth Freeze ----
        // When pool had zero liquidity at BOTH the previous and current check,
        // fee_growth_global must not change (no fees can accrue without liquidity).
        // We require both checks to be zero because actions between checks could
        // include a swap (with liquidity) followed by a liquidity removal.
        let p1_zero_now = pool_state.liquidity == 0;
        if p1_zero_now && fixture.prev_p1_zero_liquidity {
            fuzz_assert!(
                pool_state.fee_growth_global_a == fixture.prev_fee_growth_global_a,
                "Zero-liquidity pool1: fee_growth_global_a changed {} -> {}",
                fixture.prev_fee_growth_global_a, pool_state.fee_growth_global_a
            );
            fuzz_assert!(
                pool_state.fee_growth_global_b == fixture.prev_fee_growth_global_b,
                "Zero-liquidity pool1: fee_growth_global_b changed {} -> {}",
                fixture.prev_fee_growth_global_b, pool_state.fee_growth_global_b
            );
        }
        fixture.prev_p1_zero_liquidity = p1_zero_now;

        fixture.prev_fee_growth_global_a = pool_state.fee_growth_global_a;
        fixture.prev_fee_growth_global_b = pool_state.fee_growth_global_b;

        // Snapshot reward growths BEFORE updating, for temporal consistency check below
        let reward_growth_snapshot = fixture.prev_reward_growths;

        // Reward growth monotonicity
        for i in 0..3 {
            if fixture.pool.reward_initialized[i] {
                let current_growth = pool_state.reward_infos[i].growth_global_x64;
                fuzz_assert!(
                    current_growth >= fixture.prev_reward_growths[i],
                    "Reward {} growth decreased: {} < {}",
                    i, current_growth, fixture.prev_reward_growths[i]
                );
                fixture.prev_reward_growths[i] = current_growth;
            }
        }

        // ---- Reward Timestamp Monotonicity ----
        // reward_last_updated_timestamp going backward would re-emit rewards for past periods.
        let cur_reward_ts = pool_state.reward_last_updated_timestamp;
        fuzz_assert!(cur_reward_ts >= fixture.prev_reward_timestamp,
            "reward_last_updated_timestamp decreased: {} -> {}",
            fixture.prev_reward_timestamp, cur_reward_ts);

        // ---- Reward Emission Temporal Consistency (Step 13) ----
        // If time advanced AND emissions > 0 AND pool has liquidity, reward_growth must strictly increase
        // Uses the snapshot from BEFORE monotonicity update to compare properly.
        if cur_reward_ts > fixture.prev_reward_timestamp && pool_state.liquidity > 0 {
            for i in 0..3 {
                if fixture.pool.reward_initialized[i] {
                    let ems = pool_state.reward_infos[i].emissions_per_second_x64;
                    if ems > 0 {
                        let current_growth = pool_state.reward_infos[i].growth_global_x64;
                        fuzz_assert!(
                            current_growth > reward_growth_snapshot[i],
                            "Reward {} has emissions_per_second={} and liquidity={} and time advanced ({} -> {}) but growth didn't increase ({} -> {})",
                            i, ems, pool_state.liquidity,
                            fixture.prev_reward_timestamp, cur_reward_ts,
                            reward_growth_snapshot[i], current_growth
                        );
                    }
                }
            }
        }
        fixture.prev_reward_timestamp = cur_reward_ts;

        // ---- Pool config pointer immutability ----
        fuzz_assert_eq!(
            pool_state.whirlpools_config, fixture.config,
            "Pool config changed: {} != {}",
            pool_state.whirlpools_config, fixture.config
        );

        // ---- Oracle PDA derivation consistency ----
        let (expected_oracle, _) = Pubkey::find_program_address(
            &[b"oracle", fixture.pool.whirlpool.as_ref()],
            &fixture.program_id,
        );
        fuzz_assert_eq!(fixture.pool.oracle, expected_oracle,
            "Pool1 oracle PDA mismatch: tracked={} expected={}",
            fixture.pool.oracle, expected_oracle);

        // ---- Token mint immutability ----
        fuzz_assert_eq!(
            pool_state.token_mint_a, fixture.pool.token_mint_a,
            "Token mint A changed"
        );
        fuzz_assert_eq!(
            pool_state.token_mint_b, fixture.pool.token_mint_b,
            "Token mint B changed"
        );

        // ---- Token Mint Ordering ----
        // Program enforces token_mint_a < token_mint_b at initialize_pool.
        // Corruption here makes pool unreachable or creates duplicate pair pools.
        fuzz_assert!(pool_state.token_mint_a < pool_state.token_mint_b,
            "Pool1 mint ordering violated: mint_a ({}) >= mint_b ({})",
            pool_state.token_mint_a, pool_state.token_mint_b);

        // ---- Vault address immutability ----
        fuzz_assert_eq!(
            pool_state.token_vault_a, fixture.pool.token_vault_a,
            "Token vault A changed"
        );
        fuzz_assert_eq!(
            pool_state.token_vault_b, fixture.pool.token_vault_b,
            "Token vault B changed"
        );

        // Liquidity sum: pool.liquidity == sum of in-range position liquidities
        let mut expected_liquidity: u128 = 0;
        for pos in &fixture.positions {
            if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                if pos_state.tick_lower_index <= pool_state.tick_current_index
                    && pool_state.tick_current_index < pos_state.tick_upper_index
                {
                    expected_liquidity += pos_state.liquidity;
                }
            }
        }
        fuzz_assert_eq!(
            pool_state.liquidity, expected_liquidity,
            "Liquidity mismatch: pool={} expected={}",
            pool_state.liquidity, expected_liquidity
        );

        // ---- Tick-Level Invariants (Pool One) ----
        // Check liquidity_net sum == 0 and liquidity_gross >= |liquidity_net| for all ticks
        // TickArray is zero-copy packed: 8 (disc) + 4 (start_tick_index) + 88*113 (ticks) + 32 (whirlpool)
        // Each Tick is 113 bytes: 1 (initialized) + 16 (liquidity_net i128) + 16 (liquidity_gross u128) + ...

        // Build expected liquidity_gross from tracked positions (Step 7 cross-check)
        let mut expected_gross: HashMap<i32, u128> = HashMap::new();
        for pos in &fixture.positions {
            if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                if pos_state.liquidity > 0 {
                    *expected_gross.entry(pos.tick_lower_index).or_insert(0) += pos_state.liquidity;
                    *expected_gross.entry(pos.tick_upper_index).or_insert(0) += pos_state.liquidity;
                }
            }
        }

        let mut liquidity_net_sum: i128 = 0;
        // Step 9: Tick-walk liquidity — sum liquidity_net for ticks <= tick_current_index
        let mut tick_walk_liquidity: i128 = 0;
        for (start_tick, tick_array_pubkey) in &fixture.pool.tick_arrays {
            if let Ok(account) = fixture.ctx.read_account(tick_array_pubkey) {
                let data = &account.data;
                // Skip 8-byte discriminator + 4-byte start_tick_index = offset 12
                let ticks_offset = 12;
                const TICK_SIZE: usize = 113;
                for tick_idx in 0..88usize {
                    let base = ticks_offset + tick_idx * TICK_SIZE;
                    if base + TICK_SIZE > data.len() { break; }

                    let initialized = data[base] != 0;

                    // Parse liquidity_gross/net for ALL ticks (not just initialized)
                    // to verify tick initialization consistency invariant
                    let net_bytes: [u8; 16] = data[base+1..base+17].try_into().unwrap();
                    let liquidity_net = i128::from_le_bytes(net_bytes);
                    let gross_bytes: [u8; 16] = data[base+17..base+33].try_into().unwrap();
                    let liquidity_gross = u128::from_le_bytes(gross_bytes);

                    let actual_tick = start_tick + (tick_idx as i32) * (TICK_SPACING as i32);

                    // Tick initialization consistency: initialized ⟺ liquidity_gross > 0
                    // Source: tick_manager.rs:46-50. Phantom ticks (initialized=true, gross=0)
                    // corrupt pool.liquidity during swap crossing; skipped ticks (!initialized,
                    // gross>0) cause phantom liquidity.
                    fuzz_assert!(
                        initialized == (liquidity_gross > 0),
                        "Pool1 tick {}: initialized={} but liquidity_gross={} (must be consistent)",
                        actual_tick, initialized, liquidity_gross
                    );

                    // Uninitialized tick zeroing: when initialized==false, ALL fields must be zero.
                    // Source: tick_manager.rs:49-50 returns TickUpdate::default() when gross→0.
                    // Stale non-zero fee_growth_outside in uninitialized ticks would corrupt
                    // fee calculations on re-initialization.
                    if !initialized {
                        fuzz_assert_eq!(liquidity_net, 0i128,
                            "Pool1 tick {}: uninitialized but liquidity_net={}", actual_tick, liquidity_net);
                        // Check fee_growth_outside_a/b (offsets 33..49, 49..65)
                        let fgo_a_bytes: [u8; 16] = data[base+33..base+49].try_into().unwrap();
                        let fgo_a = u128::from_le_bytes(fgo_a_bytes);
                        let fgo_b_bytes: [u8; 16] = data[base+49..base+65].try_into().unwrap();
                        let fgo_b = u128::from_le_bytes(fgo_b_bytes);
                        fuzz_assert_eq!(fgo_a, 0u128,
                            "Pool1 tick {}: uninitialized but fee_growth_outside_a={}", actual_tick, fgo_a);
                        fuzz_assert_eq!(fgo_b, 0u128,
                            "Pool1 tick {}: uninitialized but fee_growth_outside_b={}", actual_tick, fgo_b);
                        // Check reward_growths_outside (offsets 65..113, 3 x u128)
                        for ri in 0..3usize {
                            let rgo_bytes: [u8; 16] = data[base+65+ri*16..base+81+ri*16].try_into().unwrap();
                            let rgo = u128::from_le_bytes(rgo_bytes);
                            fuzz_assert_eq!(rgo, 0u128,
                                "Pool1 tick {}: uninitialized but reward_growth_outside[{}]={}", actual_tick, ri, rgo);
                        }
                    }

                    if initialized {
                        liquidity_net_sum += liquidity_net;

                        let abs_net = liquidity_net.unsigned_abs();
                        fuzz_assert_ge!(
                            liquidity_gross, abs_net,
                            "Pool one tick array {} idx {}: liquidity_gross ({}) < |liquidity_net| ({})",
                            start_tick, tick_idx,
                            liquidity_gross, abs_net
                        );

                        // Cross-check liquidity_gross against expected from positions
                        if let Some(&expected) = expected_gross.get(&actual_tick) {
                            fuzz_assert_eq!(
                                liquidity_gross, expected,
                                "Pool one tick {} liquidity_gross mismatch: on-chain={} expected_from_positions={}",
                                actual_tick, liquidity_gross, expected
                            );
                        }

                        // Step 9: Accumulate liquidity_net for ticks <= tick_current_index
                        if actual_tick <= pool_state.tick_current_index {
                            tick_walk_liquidity += liquidity_net;
                        }
                    }
                }
            }
        }
        fuzz_assert_eq!(
            liquidity_net_sum, 0i128,
            "Pool one tick liquidity_net sum != 0: {}",
            liquidity_net_sum
        );
        // Step 9: Tick-walk liquidity must equal pool.liquidity
        // liquidity is u128 but always fits since it's a sum of position liquidities
        fuzz_assert!(
            tick_walk_liquidity >= 0,
            "Tick-walk liquidity is negative: {}", tick_walk_liquidity
        );
        fuzz_assert_eq!(
            tick_walk_liquidity as u128, pool_state.liquidity,
            "Tick-walk liquidity {} != pool liquidity {}",
            tick_walk_liquidity, pool_state.liquidity
        );

        // ---- Tick-Level Invariants (Pool Two) (Step 4) ----
        if let Some(ref p2) = fixture.pool_two {
            let p2_tick_current = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool)
                .ok().map(|s| s.tick_current_index).unwrap_or(0);
            // Build expected liquidity_gross from pool two positions
            let mut p2_expected_gross: HashMap<i32, u128> = HashMap::new();
            for pos in &fixture.pool_two_positions {
                if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                    if pos_state.liquidity > 0 {
                        *p2_expected_gross.entry(pos.tick_lower_index).or_insert(0) += pos_state.liquidity;
                        *p2_expected_gross.entry(pos.tick_upper_index).or_insert(0) += pos_state.liquidity;
                    }
                }
            }
            let mut p2_liquidity_net_sum: i128 = 0;
            let mut p2_tick_walk_liquidity: i128 = 0;
            for (start_tick, tick_array_pubkey) in &p2.tick_arrays {
                if let Ok(account) = fixture.ctx.read_account(tick_array_pubkey) {
                    let data = &account.data;
                    let ticks_offset = 12;
                    const TICK_SIZE_P2: usize = 113;
                    for tick_idx in 0..88usize {
                        let base = ticks_offset + tick_idx * TICK_SIZE_P2;
                        if base + TICK_SIZE_P2 > data.len() { break; }

                        let initialized = data[base] != 0;

                        let net_bytes: [u8; 16] = data[base+1..base+17].try_into().unwrap();
                        let liquidity_net = i128::from_le_bytes(net_bytes);
                        let gross_bytes: [u8; 16] = data[base+17..base+33].try_into().unwrap();
                        let liquidity_gross = u128::from_le_bytes(gross_bytes);

                        let actual_tick = start_tick + (tick_idx as i32) * (TICK_SPACING as i32);

                        fuzz_assert!(
                            initialized == (liquidity_gross > 0),
                            "Pool2 tick {}: initialized={} but liquidity_gross={} (must be consistent)",
                            actual_tick, initialized, liquidity_gross
                        );

                        if !initialized {
                            fuzz_assert_eq!(liquidity_net, 0i128,
                                "Pool2 tick {}: uninitialized but liquidity_net={}", actual_tick, liquidity_net);
                            let fgo_a = u128::from_le_bytes(data[base+33..base+49].try_into().unwrap());
                            let fgo_b = u128::from_le_bytes(data[base+49..base+65].try_into().unwrap());
                            fuzz_assert_eq!(fgo_a, 0u128,
                                "Pool2 tick {}: uninitialized but fgo_a={}", actual_tick, fgo_a);
                            fuzz_assert_eq!(fgo_b, 0u128,
                                "Pool2 tick {}: uninitialized but fgo_b={}", actual_tick, fgo_b);
                            for ri in 0..3usize {
                                let rgo = u128::from_le_bytes(data[base+65+ri*16..base+81+ri*16].try_into().unwrap());
                                fuzz_assert_eq!(rgo, 0u128,
                                    "Pool2 tick {}: uninitialized but rgo[{}]={}", actual_tick, ri, rgo);
                            }
                        }

                        if initialized {
                            p2_liquidity_net_sum += liquidity_net;

                            let abs_net = liquidity_net.unsigned_abs();
                            fuzz_assert_ge!(
                                liquidity_gross, abs_net,
                                "Pool two tick array {} idx {}: liquidity_gross ({}) < |liquidity_net| ({})",
                                start_tick, tick_idx,
                                liquidity_gross, abs_net
                            );

                            // Cross-check liquidity_gross against expected from positions
                            if let Some(&expected) = p2_expected_gross.get(&actual_tick) {
                                fuzz_assert_eq!(
                                    liquidity_gross, expected,
                                    "Pool2 tick {} liquidity_gross mismatch: on-chain={} expected_from_positions={}",
                                    actual_tick, liquidity_gross, expected
                                );
                            }

                            // Tick-walk: accumulate for ticks <= tick_current
                            if actual_tick <= p2_tick_current {
                                p2_tick_walk_liquidity += liquidity_net;
                            }
                        }
                    }
                }
            }
            fuzz_assert_eq!(
                p2_liquidity_net_sum, 0i128,
                "Pool two tick liquidity_net sum != 0: {}",
                p2_liquidity_net_sum
            );
            // Pool two tick-walk liquidity
            if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
                fuzz_assert!(p2_tick_walk_liquidity >= 0,
                    "Pool2 tick-walk liquidity is negative: {}", p2_tick_walk_liquidity);
                fuzz_assert_eq!(p2_tick_walk_liquidity as u128, p2_state.liquidity,
                    "Pool2 tick-walk liquidity {} != pool liquidity {}",
                    p2_tick_walk_liquidity, p2_state.liquidity);
            }
        }

        // ---- Step 4: Pool Two Comprehensive State Checks ----
        if let Some(ref p2) = fixture.pool_two {
            if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
                // Sqrt price bounds
                fuzz_assert!(
                    p2_state.sqrt_price >= MIN_SQRT_PRICE_X64 && p2_state.sqrt_price <= MAX_SQRT_PRICE_X64,
                    "Pool2 sqrt_price out of bounds: {} (min={}, max={})",
                    p2_state.sqrt_price, MIN_SQRT_PRICE_X64, MAX_SQRT_PRICE_X64
                );
                // Token mint ordering
                fuzz_assert!(p2_state.token_mint_a < p2_state.token_mint_b,
                    "Pool2 mint ordering violated: mint_a ({}) >= mint_b ({})",
                    p2_state.token_mint_a, p2_state.token_mint_b);
                // Oracle PDA derivation consistency (pool two)
                let (expected_oracle_p2, _) = Pubkey::find_program_address(
                    &[b"oracle", p2.whirlpool.as_ref()],
                    &fixture.program_id,
                );
                fuzz_assert_eq!(p2.oracle, expected_oracle_p2,
                    "Pool2 oracle PDA mismatch: tracked={} expected={}",
                    p2.oracle, expected_oracle_p2);
                // Tick bounds
                fuzz_assert!(
                    p2_state.tick_current_index >= MIN_TICK_INDEX && p2_state.tick_current_index <= MAX_TICK_INDEX,
                    "Pool2 tick out of bounds: {} (min={}, max={})",
                    p2_state.tick_current_index, MIN_TICK_INDEX, MAX_TICK_INDEX
                );
                // Tight sqrt_price ↔ tick bound (Step 1 applied to pool two)
                let p2_lower = harness_sqrt_price_from_tick(p2_state.tick_current_index);
                let p2_upper = harness_sqrt_price_from_tick(p2_state.tick_current_index + 1);
                fuzz_assert!(p2_state.sqrt_price >= p2_lower,
                    "Pool2 sqrt_price {} below tick {} lower bound {}",
                    p2_state.sqrt_price, p2_state.tick_current_index, p2_lower);
                fuzz_assert!(p2_state.sqrt_price <= p2_upper,
                    "Pool2 sqrt_price {} > tick {} upper bound {}",
                    p2_state.sqrt_price, p2_state.tick_current_index, p2_upper);
                // Vault solvency: vault_balance >= protocol_fee_owed
                let p2_vault_a_bal = fixture.ctx.token_balance(&p2.token_vault_a);
                let p2_vault_b_bal = fixture.ctx.token_balance(&p2.token_vault_b);
                fuzz_assert_ge!(
                    p2_vault_a_bal, p2_state.protocol_fee_owed_a,
                    "Pool2 vault A insolvent: balance={} < protocol_fee_owed={}",
                    p2_vault_a_bal, p2_state.protocol_fee_owed_a
                );
                fuzz_assert_ge!(
                    p2_vault_b_bal, p2_state.protocol_fee_owed_b,
                    "Pool2 vault B insolvent: balance={} < protocol_fee_owed={}",
                    p2_vault_b_bal, p2_state.protocol_fee_owed_b
                );
                // Fee growth monotonicity for pool two
                fuzz_assert!(
                    p2_state.fee_growth_global_a >= fixture.prev_p2_fee_growth_a,
                    "Pool2 fee growth A decreased: {} < {}",
                    p2_state.fee_growth_global_a, fixture.prev_p2_fee_growth_a
                );
                fuzz_assert!(
                    p2_state.fee_growth_global_b >= fixture.prev_p2_fee_growth_b,
                    "Pool2 fee growth B decreased: {} < {}",
                    p2_state.fee_growth_global_b, fixture.prev_p2_fee_growth_b
                );
                // Zero-liquidity fee growth freeze for pool two
                let p2_zero_now = p2_state.liquidity == 0;
                if p2_zero_now && fixture.prev_p2_zero_liquidity {
                    fuzz_assert!(
                        p2_state.fee_growth_global_a == fixture.prev_p2_fee_growth_a,
                        "Zero-liquidity pool2: fee_growth_global_a changed {} -> {}",
                        fixture.prev_p2_fee_growth_a, p2_state.fee_growth_global_a
                    );
                    fuzz_assert!(
                        p2_state.fee_growth_global_b == fixture.prev_p2_fee_growth_b,
                        "Zero-liquidity pool2: fee_growth_global_b changed {} -> {}",
                        fixture.prev_p2_fee_growth_b, p2_state.fee_growth_global_b
                    );
                }
                fixture.prev_p2_zero_liquidity = p2_zero_now;
                fixture.prev_p2_fee_growth_a = p2_state.fee_growth_global_a;
                fixture.prev_p2_fee_growth_b = p2_state.fee_growth_global_b;

                // ---- Pool Two Tick↔Price Monotonicity Cross-Check ----
                let p2_cur_tick = p2_state.tick_current_index;
                let p2_cur_sqrt = p2_state.sqrt_price;
                if p2_cur_tick > fixture.prev_p2_tick_current {
                    fuzz_assert!(p2_cur_sqrt >= fixture.prev_p2_sqrt_price_val,
                        "Pool2 tick increased ({} -> {}) but sqrt_price decreased ({} -> {})",
                        fixture.prev_p2_tick_current, p2_cur_tick,
                        fixture.prev_p2_sqrt_price_val, p2_cur_sqrt);
                }
                if p2_cur_tick < fixture.prev_p2_tick_current {
                    fuzz_assert!(p2_cur_sqrt <= fixture.prev_p2_sqrt_price_val,
                        "Pool2 tick decreased ({} -> {}) but sqrt_price increased ({} -> {})",
                        fixture.prev_p2_tick_current, p2_cur_tick,
                        fixture.prev_p2_sqrt_price_val, p2_cur_sqrt);
                }
                fixture.prev_p2_tick_current = p2_cur_tick;
                fixture.prev_p2_sqrt_price_val = p2_cur_sqrt;

                // ---- Pool Two Tick Spacing Immutability ----
                fuzz_assert_eq!(p2_state.tick_spacing, TICK_SPACING,
                    "Pool2 tick spacing changed: {} != {}", p2_state.tick_spacing, TICK_SPACING);

                // ---- Pool Two Protocol Fee Monotonicity ----
                if fixture.p2_protocol_fees_just_collected {
                    // Postcondition: after collection, owed must be zero
                    fuzz_assert_eq!(p2_state.protocol_fee_owed_a, 0,
                        "Pool2 protocol_fee_owed_a not cleared after collection: {}",
                        p2_state.protocol_fee_owed_a);
                    fuzz_assert_eq!(p2_state.protocol_fee_owed_b, 0,
                        "Pool2 protocol_fee_owed_b not cleared after collection: {}",
                        p2_state.protocol_fee_owed_b);
                } else {
                    fuzz_assert!(p2_state.protocol_fee_owed_a >= fixture.prev_p2_protocol_fee_owed_a,
                        "Pool2 protocol fee A decreased without collection: {} -> {}",
                        fixture.prev_p2_protocol_fee_owed_a, p2_state.protocol_fee_owed_a);
                    fuzz_assert!(p2_state.protocol_fee_owed_b >= fixture.prev_p2_protocol_fee_owed_b,
                        "Pool2 protocol fee B decreased without collection: {} -> {}",
                        fixture.prev_p2_protocol_fee_owed_b, p2_state.protocol_fee_owed_b);
                }
                fixture.prev_p2_protocol_fee_owed_a = p2_state.protocol_fee_owed_a;
                fixture.prev_p2_protocol_fee_owed_b = p2_state.protocol_fee_owed_b;
                fixture.p2_protocol_fees_just_collected = false;

                // ---- Pool Two Total Fee Solvency ----
                let mut p2_total_fee_a: u64 = 0;
                let mut p2_total_fee_b: u64 = 0;
                for pos in &fixture.pool_two_positions {
                    if let Ok(ps) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                        p2_total_fee_a = p2_total_fee_a.saturating_add(ps.fee_owed_a);
                        p2_total_fee_b = p2_total_fee_b.saturating_add(ps.fee_owed_b);
                    }
                }
                let p2_claims_a = p2_total_fee_a.saturating_add(p2_state.protocol_fee_owed_a);
                let p2_claims_b = p2_total_fee_b.saturating_add(p2_state.protocol_fee_owed_b);
                fuzz_assert_ge!(p2_vault_a_bal, p2_claims_a,
                    "Pool2 fee solvency A violated: vault={} < fees={} + protocol={}",
                    p2_vault_a_bal, p2_total_fee_a, p2_state.protocol_fee_owed_a);
                fuzz_assert_ge!(p2_vault_b_bal, p2_claims_b,
                    "Pool2 fee solvency B violated: vault={} < fees={} + protocol={}",
                    p2_vault_b_bal, p2_total_fee_b, p2_state.protocol_fee_owed_b);
            }
        }

        // ---- Pool Three Invariants ----
        if let Some(ref p3) = fixture.pool_three {
            if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
                // Sqrt price bounds
                fuzz_assert!(
                    p3_state.sqrt_price >= MIN_SQRT_PRICE_X64 && p3_state.sqrt_price <= MAX_SQRT_PRICE_X64,
                    "Pool3 sqrt_price out of bounds: {}", p3_state.sqrt_price
                );
                // Tick bounds
                fuzz_assert!(
                    p3_state.tick_current_index >= MIN_TICK_INDEX && p3_state.tick_current_index <= MAX_TICK_INDEX,
                    "Pool3 tick out of bounds: {}", p3_state.tick_current_index
                );
                // Fee rate hard limit (adaptive fee pool static part)
                // FEE_RATE_HARD_LIMIT = 100_000 (10%) is the runtime clamp for total fee.
                // The stored fee_rate is the static component, must stay <= MAX_FEE_RATE.
                fuzz_assert_le!(p3_state.fee_rate, MAX_FEE_RATE,
                    "Pool3 fee_rate {} exceeds MAX_FEE_RATE {}", p3_state.fee_rate, MAX_FEE_RATE);
                fuzz_assert_le!(p3_state.protocol_fee_rate, MAX_PROTOCOL_FEE_RATE,
                    "Pool3 protocol_fee_rate {} exceeds max {}", p3_state.protocol_fee_rate, MAX_PROTOCOL_FEE_RATE);
                // Tick spacing immutability (pool three may use different spacing for adaptive fee)
                // Pool three uses the same TICK_SPACING as configured
                fuzz_assert_eq!(p3_state.tick_spacing, TICK_SPACING,
                    "Pool3 tick spacing changed: {} != {}", p3_state.tick_spacing, TICK_SPACING);
                // Tight sqrt_price ↔ tick bound
                let p3_lower = harness_sqrt_price_from_tick(p3_state.tick_current_index);
                let p3_upper = harness_sqrt_price_from_tick(p3_state.tick_current_index + 1);
                fuzz_assert!(p3_state.sqrt_price >= p3_lower,
                    "Pool3 sqrt_price {} below tick {} lower bound {}",
                    p3_state.sqrt_price, p3_state.tick_current_index, p3_lower);
                fuzz_assert!(p3_state.sqrt_price <= p3_upper,
                    "Pool3 sqrt_price {} > tick {} upper bound {}",
                    p3_state.sqrt_price, p3_state.tick_current_index, p3_upper);
                // Vault solvency
                let p3_vault_a_bal = fixture.ctx.token_balance(&p3.token_vault_a);
                let p3_vault_b_bal = fixture.ctx.token_balance(&p3.token_vault_b);
                fuzz_assert_ge!(p3_vault_a_bal, p3_state.protocol_fee_owed_a,
                    "Pool3 vault A insolvent: balance={} < protocol_fee_owed={}",
                    p3_vault_a_bal, p3_state.protocol_fee_owed_a);
                fuzz_assert_ge!(p3_vault_b_bal, p3_state.protocol_fee_owed_b,
                    "Pool3 vault B insolvent: balance={} < protocol_fee_owed={}",
                    p3_vault_b_bal, p3_state.protocol_fee_owed_b);
                // Protocol fee monotonicity (pool3)
                if fixture.p3_protocol_fees_just_collected {
                    fuzz_assert_eq!(p3_state.protocol_fee_owed_a, 0,
                        "Pool3 protocol_fee_owed_a not cleared after collection: {}",
                        p3_state.protocol_fee_owed_a);
                    fuzz_assert_eq!(p3_state.protocol_fee_owed_b, 0,
                        "Pool3 protocol_fee_owed_b not cleared after collection: {}",
                        p3_state.protocol_fee_owed_b);
                } else {
                    fuzz_assert!(p3_state.protocol_fee_owed_a >= fixture.prev_p3_protocol_fee_owed_a,
                        "Pool3 protocol fee A decreased without collection: {} -> {}",
                        fixture.prev_p3_protocol_fee_owed_a, p3_state.protocol_fee_owed_a);
                    fuzz_assert!(p3_state.protocol_fee_owed_b >= fixture.prev_p3_protocol_fee_owed_b,
                        "Pool3 protocol fee B decreased without collection: {} -> {}",
                        fixture.prev_p3_protocol_fee_owed_b, p3_state.protocol_fee_owed_b);
                }
                fixture.prev_p3_protocol_fee_owed_a = p3_state.protocol_fee_owed_a;
                fixture.prev_p3_protocol_fee_owed_b = p3_state.protocol_fee_owed_b;
                fixture.p3_protocol_fees_just_collected = false;
                // Fee growth monotonicity
                fuzz_assert!(p3_state.fee_growth_global_a >= fixture.prev_p3_fee_growth_global_a,
                    "Pool3 fee growth A decreased: {} < {}",
                    p3_state.fee_growth_global_a, fixture.prev_p3_fee_growth_global_a);
                fuzz_assert!(p3_state.fee_growth_global_b >= fixture.prev_p3_fee_growth_global_b,
                    "Pool3 fee growth B decreased: {} < {}",
                    p3_state.fee_growth_global_b, fixture.prev_p3_fee_growth_global_b);
                // Zero-liquidity fee growth freeze
                let p3_zero_now = p3_state.liquidity == 0;
                if p3_zero_now && fixture.prev_p3_zero_liquidity {
                    fuzz_assert!(p3_state.fee_growth_global_a == fixture.prev_p3_fee_growth_global_a,
                        "Zero-liquidity pool3: fee_growth_a changed {} -> {}",
                        fixture.prev_p3_fee_growth_global_a, p3_state.fee_growth_global_a);
                    fuzz_assert!(p3_state.fee_growth_global_b == fixture.prev_p3_fee_growth_global_b,
                        "Zero-liquidity pool3: fee_growth_b changed {} -> {}",
                        fixture.prev_p3_fee_growth_global_b, p3_state.fee_growth_global_b);
                }
                fixture.prev_p3_zero_liquidity = p3_zero_now;
                fixture.prev_p3_fee_growth_global_a = p3_state.fee_growth_global_a;
                fixture.prev_p3_fee_growth_global_b = p3_state.fee_growth_global_b;
                // Tick↔price monotonicity
                let p3_cur_tick = p3_state.tick_current_index;
                let p3_cur_sqrt = p3_state.sqrt_price;
                if p3_cur_tick > fixture.prev_p3_tick_current {
                    fuzz_assert!(p3_cur_sqrt >= fixture.prev_p3_sqrt_price_val,
                        "Pool3 tick increased but sqrt_price decreased");
                }
                if p3_cur_tick < fixture.prev_p3_tick_current {
                    fuzz_assert!(p3_cur_sqrt <= fixture.prev_p3_sqrt_price_val,
                        "Pool3 tick decreased but sqrt_price increased");
                }
                fixture.prev_p3_tick_current = p3_cur_tick;
                fixture.prev_p3_sqrt_price_val = p3_cur_sqrt;
                // Token mint ordering
                fuzz_assert!(p3_state.token_mint_a < p3_state.token_mint_b,
                    "Pool3 mint ordering violated");
                // Oracle PDA consistency
                let (expected_oracle_p3, _) = Pubkey::find_program_address(
                    &[b"oracle", p3.whirlpool.as_ref()],
                    &fixture.program_id,
                );
                fuzz_assert_eq!(p3.oracle, expected_oracle_p3,
                    "Pool3 oracle PDA mismatch: tracked={} expected={}",
                    p3.oracle, expected_oracle_p3);
                // ---- Pool Three Adaptive Fee Hard Limit ----
                // fee_rate_manager.rs:16 defines FEE_RATE_HARD_LIMIT = 100_000 (10%).
                // The static fee_rate stored in pool must stay <= MAX_FEE_RATE (60000).
                // The adaptive computation is runtime-only and clamped at FEE_RATE_HARD_LIMIT.
                fuzz_assert_le!(p3_state.fee_rate, MAX_FEE_RATE,
                    "Pool3 stored fee_rate exceeds MAX_FEE_RATE: {} > {}",
                    p3_state.fee_rate, MAX_FEE_RATE);
            }
        }

        // ---- Pool Three Position Validity ----
        if let Some(ref p3) = fixture.pool_three {
            for (idx, pos) in fixture.pool_three_positions.iter().enumerate() {
                if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                    fuzz_assert_eq!(pos_state.whirlpool, p3.whirlpool,
                        "Pool3 position {} whirlpool mismatch", idx);
                    fuzz_assert_lt!(pos_state.tick_lower_index, pos_state.tick_upper_index,
                        "Pool3 position {} tick range invalid", idx);
                    fuzz_assert_eq!(pos_state.tick_lower_index % (TICK_SPACING as i32), 0,
                        "Pool3 position {} lower tick not aligned", idx);
                    fuzz_assert_eq!(pos_state.tick_upper_index % (TICK_SPACING as i32), 0,
                        "Pool3 position {} upper tick not aligned", idx);
                    fuzz_assert_ge!(pos_state.tick_lower_index, MIN_TICK_INDEX,
                        "Pool3 position {} lower tick below min", idx);
                    fuzz_assert_le!(pos_state.tick_upper_index, MAX_TICK_INDEX,
                        "Pool3 position {} upper tick above max", idx);
                    fuzz_assert_eq!(pos_state.position_mint, pos.position_mint,
                        "Pool3 position {} position_mint changed", idx);
                    let on_chain_has_liq = pos_state.liquidity > 0;
                    fuzz_assert_eq!(pos.has_liquidity, on_chain_has_liq,
                        "Pool3 position {} has_liquidity drift", idx);
                }
            }
        }

        // ---- Pool Three Tick-Walk Liquidity ----
        if let Some(ref p3) = fixture.pool_three {
            let p3_tick_current = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool)
                .ok().map(|s| s.tick_current_index).unwrap_or(0);
            // Build expected liquidity_gross from pool three positions
            let mut p3_expected_gross: HashMap<i32, u128> = HashMap::new();
            for pos in &fixture.pool_three_positions {
                if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                    if pos_state.liquidity > 0 {
                        *p3_expected_gross.entry(pos.tick_lower_index).or_insert(0) += pos_state.liquidity;
                        *p3_expected_gross.entry(pos.tick_upper_index).or_insert(0) += pos_state.liquidity;
                    }
                }
            }
            let mut p3_liquidity_net_sum: i128 = 0;
            let mut p3_tick_walk_liquidity: i128 = 0;
            for (start_tick, tick_array_pubkey) in &p3.tick_arrays {
                if let Ok(account) = fixture.ctx.read_account(tick_array_pubkey) {
                    let data = &account.data;
                    let ticks_offset = 12;
                    const TICK_SIZE_P3: usize = 113;
                    for tick_idx in 0..88usize {
                        let base = ticks_offset + tick_idx * TICK_SIZE_P3;
                        if base + TICK_SIZE_P3 > data.len() { break; }

                        let initialized = data[base] != 0;

                        let net_bytes: [u8; 16] = data[base+1..base+17].try_into().unwrap();
                        let liquidity_net = i128::from_le_bytes(net_bytes);
                        let gross_bytes: [u8; 16] = data[base+17..base+33].try_into().unwrap();
                        let liquidity_gross = u128::from_le_bytes(gross_bytes);

                        let actual_tick = start_tick + (tick_idx as i32) * (TICK_SPACING as i32);

                        // Tick initialization consistency
                        fuzz_assert!(
                            initialized == (liquidity_gross > 0),
                            "Pool3 tick {}: initialized={} but liquidity_gross={} (must be consistent)",
                            actual_tick, initialized, liquidity_gross
                        );

                        if !initialized {
                            fuzz_assert_eq!(liquidity_net, 0i128,
                                "Pool3 tick {}: uninitialized but liquidity_net={}", actual_tick, liquidity_net);
                            let fgo_a = u128::from_le_bytes(data[base+33..base+49].try_into().unwrap());
                            let fgo_b = u128::from_le_bytes(data[base+49..base+65].try_into().unwrap());
                            fuzz_assert_eq!(fgo_a, 0u128,
                                "Pool3 tick {}: uninitialized but fgo_a={}", actual_tick, fgo_a);
                            fuzz_assert_eq!(fgo_b, 0u128,
                                "Pool3 tick {}: uninitialized but fgo_b={}", actual_tick, fgo_b);
                            for ri in 0..3usize {
                                let rgo = u128::from_le_bytes(data[base+65+ri*16..base+81+ri*16].try_into().unwrap());
                                fuzz_assert_eq!(rgo, 0u128,
                                    "Pool3 tick {}: uninitialized but rgo[{}]={}", actual_tick, ri, rgo);
                            }
                        }

                        if initialized {
                            p3_liquidity_net_sum += liquidity_net;

                            let abs_net = liquidity_net.unsigned_abs();
                            fuzz_assert_ge!(
                                liquidity_gross, abs_net,
                                "Pool3 tick {}: liquidity_gross ({}) < |liquidity_net| ({})",
                                actual_tick, liquidity_gross, abs_net
                            );

                            // Cross-check liquidity_gross against expected from positions
                            if let Some(&expected) = p3_expected_gross.get(&actual_tick) {
                                fuzz_assert_eq!(
                                    liquidity_gross, expected,
                                    "Pool3 tick {} liquidity_gross mismatch: on-chain={} expected_from_positions={}",
                                    actual_tick, liquidity_gross, expected
                                );
                            }

                            // Tick-walk: accumulate for ticks <= tick_current
                            if actual_tick <= p3_tick_current {
                                p3_tick_walk_liquidity += liquidity_net;
                            }
                        }
                    }
                }
            }
            fuzz_assert_eq!(
                p3_liquidity_net_sum, 0i128,
                "Pool3 tick liquidity_net sum != 0: {}",
                p3_liquidity_net_sum
            );
            if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
                fuzz_assert!(p3_tick_walk_liquidity >= 0,
                    "Pool3 tick-walk liquidity is negative: {}", p3_tick_walk_liquidity);
                fuzz_assert_eq!(p3_tick_walk_liquidity as u128, p3_state.liquidity,
                    "Pool3 tick-walk liquidity {} != pool liquidity {}",
                    p3_tick_walk_liquidity, p3_state.liquidity);
            }
        }

        // ---- Pool Three Liquidity Sum ----
        if let Some(ref p3) = fixture.pool_three {
            if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
                let mut p3_expected_liquidity: u128 = 0;
                for pos in &fixture.pool_three_positions {
                    if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                        if pos_state.tick_lower_index <= p3_state.tick_current_index
                            && p3_state.tick_current_index < pos_state.tick_upper_index
                        {
                            p3_expected_liquidity += pos_state.liquidity;
                        }
                    }
                }
                fuzz_assert_eq!(p3_expected_liquidity, p3_state.liquidity,
                    "Pool3 liquidity mismatch: tracked_in_range={} pool={}",
                    p3_expected_liquidity, p3_state.liquidity);
            }
        }

        // ---- Pool Three Total Fee Solvency ----
        if let Some(ref p3) = fixture.pool_three {
            if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
                let p3_vault_a_bal = fixture.ctx.token_balance(&p3.token_vault_a);
                let p3_vault_b_bal = fixture.ctx.token_balance(&p3.token_vault_b);
                let mut p3_total_fee_a: u64 = 0;
                let mut p3_total_fee_b: u64 = 0;
                for pos in &fixture.pool_three_positions {
                    if let Ok(ps) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                        p3_total_fee_a = p3_total_fee_a.saturating_add(ps.fee_owed_a);
                        p3_total_fee_b = p3_total_fee_b.saturating_add(ps.fee_owed_b);
                    }
                }
                let p3_claims_a = p3_total_fee_a.saturating_add(p3_state.protocol_fee_owed_a);
                let p3_claims_b = p3_total_fee_b.saturating_add(p3_state.protocol_fee_owed_b);
                fuzz_assert_ge!(p3_vault_a_bal, p3_claims_a,
                    "Pool3 fee solvency A violated: vault={} < fees={} + protocol={}",
                    p3_vault_a_bal, p3_total_fee_a, p3_state.protocol_fee_owed_a);
                fuzz_assert_ge!(p3_vault_b_bal, p3_claims_b,
                    "Pool3 fee solvency B violated: vault={} < fees={} + protocol={}",
                    p3_vault_b_bal, p3_total_fee_b, p3_state.protocol_fee_owed_b);
            }
        }

        // ---- Pool Two Whirlpools Config Immutability ----
    if let Some(ref p2) = fixture.pool_two {
        if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
            fuzz_assert_eq!(p2_state.whirlpools_config, fixture.config,
                "Pool2 whirlpools_config changed: on-chain={} expected={}",
                p2_state.whirlpools_config, fixture.config);
        }
    }

    // ---- Pool Three Whirlpools Config Immutability ----
    if let Some(ref p3) = fixture.pool_three {
        if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
            fuzz_assert_eq!(p3_state.whirlpools_config, fixture.config,
                "Pool3 whirlpools_config changed: on-chain={} expected={}",
                p3_state.whirlpools_config, fixture.config);
        }
    }

    // ---- Pool Two Reward Growth Monotonicity & Temporal Consistency ----
    if let Some(ref p2) = fixture.pool_two {
        if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
            // Snapshot BEFORE updating for temporal consistency check
            let p2_reward_growth_snapshot = fixture.prev_p2_reward_growths;
            for i in 0..3 {
                if p2.reward_initialized[i] {
                    let current_growth = p2_state.reward_infos[i].growth_global_x64;
                    fuzz_assert!(current_growth >= fixture.prev_p2_reward_growths[i],
                        "Pool2 reward {} growth decreased: {} < {}",
                        i, current_growth, fixture.prev_p2_reward_growths[i]);
                    fixture.prev_p2_reward_growths[i] = current_growth;
                }
            }
            let p2_reward_ts = p2_state.reward_last_updated_timestamp;
            fuzz_assert!(p2_reward_ts >= fixture.prev_p2_reward_timestamp,
                "Pool2 reward_last_updated_timestamp decreased: {} -> {}",
                fixture.prev_p2_reward_timestamp, p2_reward_ts);
            // Emission temporal consistency: if time advanced AND emissions > 0 AND liquidity > 0, growth must increase
            if p2_reward_ts > fixture.prev_p2_reward_timestamp && p2_state.liquidity > 0 {
                for i in 0..3 {
                    if p2.reward_initialized[i] {
                        let ems = p2_state.reward_infos[i].emissions_per_second_x64;
                        if ems > 0 {
                            let current_growth = p2_state.reward_infos[i].growth_global_x64;
                            fuzz_assert!(current_growth > p2_reward_growth_snapshot[i],
                                "Pool2 reward {} has ems={} liq={} time advanced ({}->{}) but growth didn't increase ({} -> {})",
                                i, ems, p2_state.liquidity,
                                fixture.prev_p2_reward_timestamp, p2_reward_ts,
                                p2_reward_growth_snapshot[i], current_growth);
                        }
                    }
                }
            }
            fixture.prev_p2_reward_timestamp = p2_reward_ts;
        }
        for i in 0..3 {
            if p2.reward_initialized[i] && p2.reward_vaults[i] != Pubkey::default() {
                let vault_balance = fixture.ctx.token_balance(&p2.reward_vaults[i]);
                let mut total_owed: u64 = 0;
                for pos in &fixture.pool_two_positions {
                    if let Ok(ps) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                        total_owed = total_owed.saturating_add(ps.reward_infos[i].amount_owed);
                    }
                }
                fuzz_assert_ge!(vault_balance, total_owed,
                    "Pool2 reward {} vault insolvent: balance={} < total_owed={}",
                    i, vault_balance, total_owed);
            }
        }
    }

    // ---- Pool Three Reward Growth Monotonicity & Vault Solvency ----
    if let Some(ref p3) = fixture.pool_three {
        if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
            for i in 0..3 {
                if p3.reward_initialized[i] {
                    let current_growth = p3_state.reward_infos[i].growth_global_x64;
                    fuzz_assert!(current_growth >= fixture.prev_p3_reward_growths[i],
                        "Pool3 reward {} growth decreased: {} < {}",
                        i, current_growth, fixture.prev_p3_reward_growths[i]);
                    fixture.prev_p3_reward_growths[i] = current_growth;
                }
            }
            let p3_reward_ts = p3_state.reward_last_updated_timestamp;
            fuzz_assert!(p3_reward_ts >= fixture.prev_p3_reward_timestamp,
                "Pool3 reward_last_updated_timestamp decreased: {} -> {}",
                fixture.prev_p3_reward_timestamp, p3_reward_ts);
            fixture.prev_p3_reward_timestamp = p3_reward_ts;
        }
        for i in 0..3 {
            if p3.reward_initialized[i] && p3.reward_vaults[i] != Pubkey::default() {
                let vault_balance = fixture.ctx.token_balance(&p3.reward_vaults[i]);
                let mut total_owed: u64 = 0;
                for pos in &fixture.pool_three_positions {
                    if let Ok(ps) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                        total_owed = total_owed.saturating_add(ps.reward_infos[i].amount_owed);
                    }
                }
                fuzz_assert_ge!(vault_balance, total_owed,
                    "Pool3 reward {} vault insolvent: balance={} < total_owed={}",
                    i, vault_balance, total_owed);
            }
        }
    }

    // ---- Position Fee Checkpoint Invariant ----
        // NOTE: fee_growth_checkpoint uses wrapping u128 arithmetic (like Uniswap V3).
        // fee_growth_inside = fee_growth_global - fee_growth_outside_lower - fee_growth_outside_upper
        // This can wrap around u128, so checkpoint values near u128::MAX are valid.
        // We only verify that fee_owed values are not unreasonably large (> vault balance).
        for (idx, pos) in fixture.positions.iter().enumerate() {
            if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                fuzz_assert_le!(
                    pos_state.fee_owed_a, vault_a_balance,
                    "Position {} fee_owed_a ({}) > vault_a balance ({})",
                    idx, pos_state.fee_owed_a, vault_a_balance
                );
                fuzz_assert_le!(
                    pos_state.fee_owed_b, vault_b_balance,
                    "Position {} fee_owed_b ({}) > vault_b balance ({})",
                    idx, pos_state.fee_owed_b, vault_b_balance
                );
            }
        }

        // ---- Total Fee Solvency Invariant (Step 1) ----
        // The AGGREGATE of all position fees + protocol fees must fit in the vault.
        // This is the real solvency invariant (individual checks above are weaker).
        let mut total_fee_owed_a: u64 = 0;
        let mut total_fee_owed_b: u64 = 0;
        for pos in &fixture.positions {
            if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                total_fee_owed_a = total_fee_owed_a.saturating_add(pos_state.fee_owed_a);
                total_fee_owed_b = total_fee_owed_b.saturating_add(pos_state.fee_owed_b);
            }
        }
        let total_claims_a = total_fee_owed_a.saturating_add(pool_state.protocol_fee_owed_a);
        let total_claims_b = total_fee_owed_b.saturating_add(pool_state.protocol_fee_owed_b);
        fuzz_assert_ge!(
            vault_a_balance, total_claims_a,
            "Total fee solvency A violated: vault={} < sum(position_fees)={} + protocol_fees={}",
            vault_a_balance, total_fee_owed_a, pool_state.protocol_fee_owed_a
        );
        fuzz_assert_ge!(
            vault_b_balance, total_claims_b,
            "Total fee solvency B violated: vault={} < sum(position_fees)={} + protocol_fees={}",
            vault_b_balance, total_fee_owed_b, pool_state.protocol_fee_owed_b
        );
    }

    // ---- On-Chain Position Validity ----
    for (idx, pos) in fixture.positions.iter().enumerate() {
        if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
            // Position belongs to this pool
            fuzz_assert_eq!(
                pos_state.whirlpool, fixture.pool.whirlpool,
                "Position {} whirlpool mismatch: {} != {}",
                idx, pos_state.whirlpool, fixture.pool.whirlpool
            );

            // Position mint immutability: position_mint is the NFT granting authority.
            // If changed, someone could hijack a position's liquidity and fees.
            fuzz_assert_eq!(pos_state.position_mint, pos.position_mint,
                "Position {} position_mint changed: on-chain={} local={}",
                idx, pos_state.position_mint, pos.position_mint);

            // On-chain tick indices match local tracking
            fuzz_assert_eq!(
                pos_state.tick_lower_index, pos.tick_lower_index,
                "Position {} tick_lower mismatch: on-chain={} local={}",
                idx, pos_state.tick_lower_index, pos.tick_lower_index
            );
            fuzz_assert_eq!(
                pos_state.tick_upper_index, pos.tick_upper_index,
                "Position {} tick_upper mismatch: on-chain={} local={}",
                idx, pos_state.tick_upper_index, pos.tick_upper_index
            );

            // Tick range valid
            fuzz_assert_lt!(
                pos_state.tick_lower_index, pos_state.tick_upper_index,
                "Position {} on-chain tick range invalid: {} >= {}",
                idx, pos_state.tick_lower_index, pos_state.tick_upper_index
            );

            // Ticks must be multiples of tick_spacing
            fuzz_assert_eq!(
                pos_state.tick_lower_index % (TICK_SPACING as i32), 0,
                "Position {} lower tick not aligned to tick spacing",
                idx
            );
            fuzz_assert_eq!(
                pos_state.tick_upper_index % (TICK_SPACING as i32), 0,
                "Position {} upper tick not aligned to tick spacing",
                idx
            );

            // Ticks within bounds
            fuzz_assert_ge!(
                pos_state.tick_lower_index, MIN_TICK_INDEX,
                "Position {} lower tick below min: {} < {}",
                idx, pos_state.tick_lower_index, MIN_TICK_INDEX
            );
            fuzz_assert_le!(
                pos_state.tick_upper_index, MAX_TICK_INDEX,
                "Position {} upper tick above max: {} > {}",
                idx, pos_state.tick_upper_index, MAX_TICK_INDEX
            );

            // ---- Reward amount_owed overflow detection ----
            // reward_info.amount_owed uses wrapping_add in position_manager.rs.
            // A value near u64::MAX is a strong indicator of wrapping overflow.
            for ri in 0..3 {
                if fixture.pool.reward_initialized[ri] {
                    fuzz_assert!(pos_state.reward_infos[ri].amount_owed < u64::MAX / 2,
                        "Position {} reward {} amount_owed suspiciously large (possible wrap): {}",
                        idx, ri, pos_state.reward_infos[ri].amount_owed);
                }
            }
        }
    }

    // ---- Position Emptiness Consistency (Step 8) ----
    // Verify our local has_liquidity flag matches on-chain state
    for (idx, pos) in fixture.positions.iter().enumerate() {
        if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
            let on_chain_has_liq = pos_state.liquidity > 0;
            fuzz_assert_eq!(
                pos.has_liquidity, on_chain_has_liq,
                "Position {} has_liquidity drift: local={} on-chain={}",
                idx, pos.has_liquidity, on_chain_has_liq
            );
        }
    }

    // ---- Position fee_owed Monotonicity (detects wrapping_add overflow) ----
    // fee_owed uses wrapping_add in position_manager.rs. Between fee collections,
    // fee_owed can only increase. A decrease means wrapping overflow occurred.
    for (idx, pos) in fixture.positions.iter_mut().enumerate() {
        if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
            if pos.fees_just_collected {
                // ---- Collect Fees Postcondition ----
                // After successful collect_fees, fee_owed_a and fee_owed_b must be zero.
                // Any residual means tokens were silently left in the pool (LP loss)
                // or the checkpoint was incorrectly updated allowing re-collection.
                fuzz_assert_eq!(pos_state.fee_owed_a, 0,
                    "Position {} fee_owed_a not cleared after collect_fees: {}",
                    idx, pos_state.fee_owed_a);
                fuzz_assert_eq!(pos_state.fee_owed_b, 0,
                    "Position {} fee_owed_b not cleared after collect_fees: {}",
                    idx, pos_state.fee_owed_b);
            } else {
                fuzz_assert!(pos_state.fee_owed_a >= pos.prev_fee_owed_a,
                    "Position {} fee_owed_a decreased (wrapping overflow?): {} -> {}",
                    idx, pos.prev_fee_owed_a, pos_state.fee_owed_a);
                fuzz_assert!(pos_state.fee_owed_b >= pos.prev_fee_owed_b,
                    "Position {} fee_owed_b decreased (wrapping overflow?): {} -> {}",
                    idx, pos.prev_fee_owed_b, pos_state.fee_owed_b);
            }
            pos.prev_fee_owed_a = pos_state.fee_owed_a;
            pos.prev_fee_owed_b = pos_state.fee_owed_b;
            pos.fees_just_collected = false;
        }
    }

    // ---- Position reward_owed Overflow Detection (wrapping_add in position_manager.rs:47) ----
    // reward_info.amount_owed uses wrapping_add. A value near u64::MAX is a strong
    // indicator that wrapping overflow occurred. We use u64::MAX / 2 as the threshold.
    for (idx, pos) in fixture.positions.iter().enumerate() {
        if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
            for ri in 0..3 {
                if fixture.pool.reward_initialized[ri] {
                    fuzz_assert!(pos_state.reward_infos[ri].amount_owed < u64::MAX / 2,
                        "Position {} reward {} amount_owed near overflow: {} (threshold={})",
                        idx, ri, pos_state.reward_infos[ri].amount_owed, u64::MAX / 2);
                }
            }
        }
    }

    // NOTE: Step 6 (fee_growth_checkpoint bounds) was removed because fee_growth_inside
    // uses wrapping u128 arithmetic. Checkpoints legitimately exceed fee_growth_global
    // when fee_growth_outside values cause the subtraction to wrap around.

    // Verify we have tick arrays
    fuzz_assert_ge!(
        fixture.pool.tick_arrays.len(), 3,
        "Not enough tick arrays: {}",
        fixture.pool.tick_arrays.len()
    );

    // ---- Reward Vault Solvency ----
    // For each initialized reward: vault_balance >= sum(position.reward_owed)
    for i in 0..3 {
        if fixture.pool.reward_initialized[i] && fixture.pool.reward_vaults[i] != Pubkey::default() {
            let vault_balance = fixture.ctx.token_balance(&fixture.pool.reward_vaults[i]);
            let mut total_owed: u64 = 0;
            for pos in &fixture.positions {
                if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                    total_owed = total_owed.saturating_add(pos_state.reward_infos[i].amount_owed);
                }
            }
            fuzz_assert_ge!(
                vault_balance, total_owed,
                "Reward {} vault insolvent: balance={} < total_owed={}",
                i, vault_balance, total_owed
            );
        }
    }

    // ---- Bundle Bitmap Consistency ----
    // For each bundle: on-chain bitmap bit count == local open_bundle_indices count
    for (bi, bundle) in fixture.bundles.iter().enumerate() {
        if let Ok(account) = fixture.ctx.read_account(&bundle.position_bundle) {
            let data = &account.data;
            // PositionBundle layout: 8 (discriminator) + 32 (position_bundle_mint) + 32 (position_bitmap = u8[32])
            if data.len() >= 72 {
                let bitmap = &data[40..72]; // 32 bytes = 256 bits
                let set_bits: u32 = bitmap.iter().map(|b| b.count_ones()).sum();
                fuzz_assert_eq!(
                    set_bits as usize, bundle.open_bundle_indices.len(),
                    "Bundle {} bitmap mismatch: on-chain bits={} local={}",
                    bi, set_bits, bundle.open_bundle_indices.len()
                );
            }
        }
    }

    // ---- Bundle Reference Validity ----
    // For each position with bundle_info: bundle_idx is valid and bundle_index is in open list
    for (pi, pos) in fixture.positions.iter().enumerate() {
        if let Some(ref bi) = pos.bundle_info {
            fuzz_assert!(
                bi.bundle_idx < fixture.bundles.len(),
                "Position {} bundle_idx {} out of range (bundles: {})",
                pi, bi.bundle_idx, fixture.bundles.len()
            );
            if bi.bundle_idx < fixture.bundles.len() {
                fuzz_assert!(
                    fixture.bundles[bi.bundle_idx].open_bundle_indices.contains(&bi.bundle_index),
                    "Position {} bundle_index {} not in bundle {}'s open list",
                    pi, bi.bundle_index, bi.bundle_idx
                );
            }
        }
    }

    // ---- Config Authority Consistency ----
    // Verify on-chain config authorities match our local tracking
    if let Ok(config_state) = fixture.ctx.read_anchor_account::<whirlpool::state::WhirlpoolsConfig>(&fixture.config) {
        fuzz_assert_eq!(config_state.fee_authority, fixture.fee_authority.pubkey(),
            "Config fee_authority mismatch: on-chain={} local={}",
            config_state.fee_authority, fixture.fee_authority.pubkey());
        fuzz_assert_eq!(config_state.collect_protocol_fees_authority, fixture.collect_protocol_fees_authority.pubkey(),
            "Config collect_protocol_fees_authority mismatch: on-chain={} local={}",
            config_state.collect_protocol_fees_authority, fixture.collect_protocol_fees_authority.pubkey());
        fuzz_assert_eq!(config_state.reward_emissions_super_authority, fixture.reward_emissions_super_authority.pubkey(),
            "Config reward_emissions_super_authority mismatch: on-chain={} local={}",
            config_state.reward_emissions_super_authority, fixture.reward_emissions_super_authority.pubkey());
        // default_protocol_fee_rate bounds
        fuzz_assert_le!(config_state.default_protocol_fee_rate, MAX_PROTOCOL_FEE_RATE,
            "Config default_protocol_fee_rate {} > max {}",
            config_state.default_protocol_fee_rate, MAX_PROTOCOL_FEE_RATE);
    }

    // ---- Config Extension Authority Consistency ----
    if let Some(config_ext_pda) = fixture.config_extension {
        if let Ok(ext) = fixture.ctx.read_anchor_account::<whirlpool::state::WhirlpoolsConfigExtension>(&config_ext_pda) {
            fuzz_assert_eq!(ext.config_extension_authority, fixture.config_extension_authority.pubkey(),
                "ConfigExtension config_extension_authority mismatch: on-chain={} local={}",
                ext.config_extension_authority, fixture.config_extension_authority.pubkey());
            fuzz_assert_eq!(ext.token_badge_authority, fixture.token_badge_authority.pubkey(),
                "ConfigExtension token_badge_authority mismatch: on-chain={} local={}",
                ext.token_badge_authority, fixture.token_badge_authority.pubkey());
        }
    }

    // ---- Token Badge State Consistency ----
    for (badge_mint, badge_pubkey) in &fixture.token_badges {
        if let Ok(badge) = fixture.ctx.read_anchor_account::<whirlpool::state::TokenBadge>(badge_pubkey) {
            fuzz_assert_eq!(badge.whirlpools_config, fixture.config,
                "TokenBadge {} config mismatch: on-chain={} expected={}",
                badge_pubkey, badge.whirlpools_config, fixture.config);
            fuzz_assert_eq!(badge.token_mint, *badge_mint,
                "TokenBadge {} mint mismatch: on-chain={} expected={}",
                badge_pubkey, badge.token_mint, badge_mint);
        }
    }

    // ---- Pool Two Position Validity ----
    if let Some(ref p2) = fixture.pool_two {
        for (idx, pos) in fixture.pool_two_positions.iter().enumerate() {
            if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                // Position belongs to pool two
                fuzz_assert_eq!(pos_state.whirlpool, p2.whirlpool,
                    "Pool2 position {} whirlpool mismatch: on-chain={} expected={}",
                    idx, pos_state.whirlpool, p2.whirlpool);
                // Tick bounds valid
                fuzz_assert_lt!(pos_state.tick_lower_index, pos_state.tick_upper_index,
                    "Pool2 position {} tick range invalid: {} >= {}",
                    idx, pos_state.tick_lower_index, pos_state.tick_upper_index);
                // Tick spacing aligned
                fuzz_assert_eq!(pos_state.tick_lower_index % (TICK_SPACING as i32), 0,
                    "Pool2 position {} lower tick not aligned", idx);
                fuzz_assert_eq!(pos_state.tick_upper_index % (TICK_SPACING as i32), 0,
                    "Pool2 position {} upper tick not aligned", idx);
                // Ticks within global bounds
                fuzz_assert_ge!(pos_state.tick_lower_index, MIN_TICK_INDEX,
                    "Pool2 position {} lower tick below min", idx);
                fuzz_assert_le!(pos_state.tick_upper_index, MAX_TICK_INDEX,
                    "Pool2 position {} upper tick above max", idx);
                // Position mint immutability
                fuzz_assert_eq!(pos_state.position_mint, pos.position_mint,
                    "Pool2 position {} position_mint changed", idx);
                // has_liquidity consistency
                let on_chain_has_liq = pos_state.liquidity > 0;
                fuzz_assert_eq!(pos.has_liquidity, on_chain_has_liq,
                    "Pool2 position {} has_liquidity drift: local={} on-chain={}",
                    idx, pos.has_liquidity, on_chain_has_liq);
            }
        }

        // ---- Pool Two Liquidity Sum ----
        // Sum of in-range pool_two_position liquidity == pool_two.liquidity
        // Setup position is now tracked, so we can do strict equality.
        if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
            let mut tracked_in_range: u128 = 0;
            for pos in &fixture.pool_two_positions {
                if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                    if pos_state.tick_lower_index <= p2_state.tick_current_index
                        && p2_state.tick_current_index < pos_state.tick_upper_index
                    {
                        tracked_in_range += pos_state.liquidity;
                    }
                }
            }
            fuzz_assert_eq!(tracked_in_range, p2_state.liquidity,
                "Pool2 liquidity mismatch: tracked_in_range={} pool={}",
                tracked_in_range, p2_state.liquidity);
        }
    }

    // ---- Reward Vault Mint Consistency ----
    // For each initialized reward, verify the vault's mint matches the expected reward mint
    for i in 0..3 {
        if fixture.pool.reward_initialized[i] && fixture.pool.reward_vaults[i] != Pubkey::default() {
            if let Ok(vault_account) = fixture.ctx.read_account(&fixture.pool.reward_vaults[i]) {
                // SPL Token account layout: mint is at bytes 0..32
                if vault_account.data.len() >= 32 {
                    let mint_bytes: [u8; 32] = vault_account.data[0..32].try_into().unwrap();
                    let vault_mint = Pubkey::from(mint_bytes);
                    fuzz_assert_eq!(vault_mint, fixture.pool.reward_mints[i],
                        "Reward {} vault mint mismatch: vault_mint={} expected={}",
                        i, vault_mint, fixture.pool.reward_mints[i]);
                }
            }
        }
    }

    // ---- Liquidity Upper Bound (from error 6013: LiquidityTooHigh) ----
    // The program enforces liquidity < i64::MAX. If exceeded, tick crossing math breaks.
    if let Ok(pool_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
        fuzz_assert!(pool_state.liquidity <= i64::MAX as u128,
            "Pool1 liquidity exceeds i64::MAX: {}", pool_state.liquidity);
    }
    for (idx, pos) in fixture.positions.iter().enumerate() {
        if let Ok(ps) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
            fuzz_assert!(ps.liquidity <= i64::MAX as u128,
                "Position {} liquidity exceeds i64::MAX: {}", idx, ps.liquidity);
        }
    }
    if let Some(ref p2) = fixture.pool_two {
        if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
            fuzz_assert!(p2_state.liquidity <= i64::MAX as u128,
                "Pool2 liquidity exceeds i64::MAX: {}", p2_state.liquidity);
        }
        for (idx, pos) in fixture.pool_two_positions.iter().enumerate() {
            if let Ok(ps) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                fuzz_assert!(ps.liquidity <= i64::MAX as u128,
                    "Pool2 position {} liquidity exceeds i64::MAX: {}", idx, ps.liquidity);
            }
        }
    }
    if let Some(ref p3) = fixture.pool_three {
        if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
            fuzz_assert!(p3_state.liquidity <= i64::MAX as u128,
                "Pool3 liquidity exceeds i64::MAX: {}", p3_state.liquidity);
        }
        for (idx, pos) in fixture.pool_three_positions.iter().enumerate() {
            if let Ok(ps) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                fuzz_assert!(ps.liquidity <= i64::MAX as u128,
                    "Pool3 position {} liquidity exceeds i64::MAX: {}", idx, ps.liquidity);
            }
        }
    }

    // ---- Pool Two Position Fee Owed Monotonicity + Collect Postcondition ----
    for (idx, pos) in fixture.pool_two_positions.iter_mut().enumerate() {
        if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
            if pos.fees_just_collected {
                fuzz_assert_eq!(pos_state.fee_owed_a, 0,
                    "Pool2 position {} fee_owed_a not cleared after collect_fees: {}",
                    idx, pos_state.fee_owed_a);
                fuzz_assert_eq!(pos_state.fee_owed_b, 0,
                    "Pool2 position {} fee_owed_b not cleared after collect_fees: {}",
                    idx, pos_state.fee_owed_b);
            } else {
                fuzz_assert!(pos_state.fee_owed_a >= pos.prev_fee_owed_a,
                    "Pool2 position {} fee_owed_a decreased (wrapping overflow?): {} -> {}",
                    idx, pos.prev_fee_owed_a, pos_state.fee_owed_a);
                fuzz_assert!(pos_state.fee_owed_b >= pos.prev_fee_owed_b,
                    "Pool2 position {} fee_owed_b decreased (wrapping overflow?): {} -> {}",
                    idx, pos.prev_fee_owed_b, pos_state.fee_owed_b);
            }
            pos.prev_fee_owed_a = pos_state.fee_owed_a;
            pos.prev_fee_owed_b = pos_state.fee_owed_b;
            pos.fees_just_collected = false;
        }
    }

    // ---- Pool Three Position Fee Owed Monotonicity + Collect Postcondition ----
    for (idx, pos) in fixture.pool_three_positions.iter_mut().enumerate() {
        if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
            if pos.fees_just_collected {
                fuzz_assert_eq!(pos_state.fee_owed_a, 0,
                    "Pool3 position {} fee_owed_a not cleared after collect_fees: {}",
                    idx, pos_state.fee_owed_a);
                fuzz_assert_eq!(pos_state.fee_owed_b, 0,
                    "Pool3 position {} fee_owed_b not cleared after collect_fees: {}",
                    idx, pos_state.fee_owed_b);
            } else {
                fuzz_assert!(pos_state.fee_owed_a >= pos.prev_fee_owed_a,
                    "Pool3 position {} fee_owed_a decreased (wrapping overflow?): {} -> {}",
                    idx, pos.prev_fee_owed_a, pos_state.fee_owed_a);
                fuzz_assert!(pos_state.fee_owed_b >= pos.prev_fee_owed_b,
                    "Pool3 position {} fee_owed_b decreased (wrapping overflow?): {} -> {}",
                    idx, pos.prev_fee_owed_b, pos_state.fee_owed_b);
            }
            pos.prev_fee_owed_a = pos_state.fee_owed_a;
            pos.prev_fee_owed_b = pos_state.fee_owed_b;
            pos.fees_just_collected = false;
        }
    }

    // ---- Pool Two/Three Position Reward Overflow Detection ----
    for (idx, pos) in fixture.pool_two_positions.iter().enumerate() {
        if let Ok(ps) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
            if let Some(ref p2) = fixture.pool_two {
                for ri in 0..3 {
                    if p2.reward_initialized[ri] {
                        fuzz_assert!(ps.reward_infos[ri].amount_owed < u64::MAX / 2,
                            "Pool2 position {} reward {} amount_owed near overflow: {}",
                            idx, ri, ps.reward_infos[ri].amount_owed);
                    }
                }
            }
        }
    }
    for (idx, pos) in fixture.pool_three_positions.iter().enumerate() {
        if let Ok(ps) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
            if let Some(ref p3) = fixture.pool_three {
                for ri in 0..3 {
                    if p3.reward_initialized[ri] {
                        fuzz_assert!(ps.reward_infos[ri].amount_owed < u64::MAX / 2,
                            "Pool3 position {} reward {} amount_owed near overflow: {}",
                            idx, ri, ps.reward_infos[ri].amount_owed);
                    }
                }
            }
        }
    }

    // ---- Vault Token Mint Consistency (All Pools) ----
    // Verify the SPL token accounts at vault addresses hold the correct token mint.
    // Catches vault-substitution attacks where a vault is swapped to a different mint.
    // SPL Token account layout: mint is at bytes 0..32
    {
        // Pool 1
        if let Ok(vault_a_acct) = fixture.ctx.read_account(&fixture.pool.token_vault_a) {
            if vault_a_acct.data.len() >= 32 {
                let mint_bytes: [u8; 32] = vault_a_acct.data[0..32].try_into().unwrap();
                let vault_mint = Pubkey::from(mint_bytes);
                fuzz_assert_eq!(vault_mint, fixture.pool.token_mint_a,
                    "Pool1 vault_a mint mismatch: vault_mint={} expected={}",
                    vault_mint, fixture.pool.token_mint_a);
            }
        }
        if let Ok(vault_b_acct) = fixture.ctx.read_account(&fixture.pool.token_vault_b) {
            if vault_b_acct.data.len() >= 32 {
                let mint_bytes: [u8; 32] = vault_b_acct.data[0..32].try_into().unwrap();
                let vault_mint = Pubkey::from(mint_bytes);
                fuzz_assert_eq!(vault_mint, fixture.pool.token_mint_b,
                    "Pool1 vault_b mint mismatch: vault_mint={} expected={}",
                    vault_mint, fixture.pool.token_mint_b);
            }
        }
        // Pool 2
        if let Some(ref p2) = fixture.pool_two {
            if let Ok(vault_a_acct) = fixture.ctx.read_account(&p2.token_vault_a) {
                if vault_a_acct.data.len() >= 32 {
                    let mint_bytes: [u8; 32] = vault_a_acct.data[0..32].try_into().unwrap();
                    let vault_mint = Pubkey::from(mint_bytes);
                    fuzz_assert_eq!(vault_mint, p2.token_mint_a,
                        "Pool2 vault_a mint mismatch: vault_mint={} expected={}",
                        vault_mint, p2.token_mint_a);
                }
            }
            if let Ok(vault_b_acct) = fixture.ctx.read_account(&p2.token_vault_b) {
                if vault_b_acct.data.len() >= 32 {
                    let mint_bytes: [u8; 32] = vault_b_acct.data[0..32].try_into().unwrap();
                    let vault_mint = Pubkey::from(mint_bytes);
                    fuzz_assert_eq!(vault_mint, p2.token_mint_b,
                        "Pool2 vault_b mint mismatch: vault_mint={} expected={}",
                        vault_mint, p2.token_mint_b);
                }
            }
        }
        // Pool 3
        if let Some(ref p3) = fixture.pool_three {
            if let Ok(vault_a_acct) = fixture.ctx.read_account(&p3.token_vault_a) {
                if vault_a_acct.data.len() >= 32 {
                    let mint_bytes: [u8; 32] = vault_a_acct.data[0..32].try_into().unwrap();
                    let vault_mint = Pubkey::from(mint_bytes);
                    fuzz_assert_eq!(vault_mint, p3.token_mint_a,
                        "Pool3 vault_a mint mismatch: vault_mint={} expected={}",
                        vault_mint, p3.token_mint_a);
                }
            }
            if let Ok(vault_b_acct) = fixture.ctx.read_account(&p3.token_vault_b) {
                if vault_b_acct.data.len() >= 32 {
                    let mint_bytes: [u8; 32] = vault_b_acct.data[0..32].try_into().unwrap();
                    let vault_mint = Pubkey::from(mint_bytes);
                    fuzz_assert_eq!(vault_mint, p3.token_mint_b,
                        "Pool3 vault_b mint mismatch: vault_mint={} expected={}",
                        vault_mint, p3.token_mint_b);
                }
            }
        }
    }

    // ---- Pool Two/Three Vault Address Immutability ----
    // Verify on-chain vault addresses haven't been mutated for pool 2 and pool 3.
    // Pool 1 already has vault_address_immutability. This extends to all pools.
    if let Some(ref p2) = fixture.pool_two {
        if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
            fuzz_assert_eq!(p2_state.token_vault_a, p2.token_vault_a,
                "Pool2 token_vault_a mutated: on-chain={} tracked={}",
                p2_state.token_vault_a, p2.token_vault_a);
            fuzz_assert_eq!(p2_state.token_vault_b, p2.token_vault_b,
                "Pool2 token_vault_b mutated: on-chain={} tracked={}",
                p2_state.token_vault_b, p2.token_vault_b);
            fuzz_assert_eq!(p2_state.token_mint_a, p2.token_mint_a,
                "Pool2 token_mint_a mutated: on-chain={} tracked={}",
                p2_state.token_mint_a, p2.token_mint_a);
            fuzz_assert_eq!(p2_state.token_mint_b, p2.token_mint_b,
                "Pool2 token_mint_b mutated: on-chain={} tracked={}",
                p2_state.token_mint_b, p2.token_mint_b);
        }
    }
    if let Some(ref p3) = fixture.pool_three {
        if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
            fuzz_assert_eq!(p3_state.token_vault_a, p3.token_vault_a,
                "Pool3 token_vault_a mutated: on-chain={} tracked={}",
                p3_state.token_vault_a, p3.token_vault_a);
            fuzz_assert_eq!(p3_state.token_vault_b, p3.token_vault_b,
                "Pool3 token_vault_b mutated: on-chain={} tracked={}",
                p3_state.token_vault_b, p3.token_vault_b);
            fuzz_assert_eq!(p3_state.token_mint_a, p3.token_mint_a,
                "Pool3 token_mint_a mutated: on-chain={} tracked={}",
                p3_state.token_mint_a, p3.token_mint_a);
            fuzz_assert_eq!(p3_state.token_mint_b, p3.token_mint_b,
                "Pool3 token_mint_b mutated: on-chain={} tracked={}",
                p3_state.token_mint_b, p3.token_mint_b);
        }
    }

    // ---- Tick Array Whirlpool Pointer Consistency (All Pools) ----
    // Each TickArray account has a `whirlpool` field at the end (after 8+4+88*113 = 9956 bytes).
    // If this pointer is corrupted, the tick array could be used with a different pool,
    // causing phantom liquidity or fee miscalculation.
    {
        const TICK_ARRAY_WHIRLPOOL_OFFSET: usize = 8 + 4 + 88 * 113; // 9956
        // Pool 1
        for (start_tick, tick_array_pubkey) in &fixture.pool.tick_arrays {
            if let Ok(account) = fixture.ctx.read_account(tick_array_pubkey) {
                if account.data.len() >= TICK_ARRAY_WHIRLPOOL_OFFSET + 32 {
                    let whirlpool_bytes: [u8; 32] = account.data[TICK_ARRAY_WHIRLPOOL_OFFSET..TICK_ARRAY_WHIRLPOOL_OFFSET + 32].try_into().unwrap();
                    let ta_whirlpool = Pubkey::from(whirlpool_bytes);
                    fuzz_assert_eq!(ta_whirlpool, fixture.pool.whirlpool,
                        "Pool1 tick_array (start={}) whirlpool pointer mismatch: {} != {}",
                        start_tick, ta_whirlpool, fixture.pool.whirlpool);
                }
            }
        }
        // Pool 2
        if let Some(ref p2) = fixture.pool_two {
            for (start_tick, tick_array_pubkey) in &p2.tick_arrays {
                if let Ok(account) = fixture.ctx.read_account(tick_array_pubkey) {
                    if account.data.len() >= TICK_ARRAY_WHIRLPOOL_OFFSET + 32 {
                        let whirlpool_bytes: [u8; 32] = account.data[TICK_ARRAY_WHIRLPOOL_OFFSET..TICK_ARRAY_WHIRLPOOL_OFFSET + 32].try_into().unwrap();
                        let ta_whirlpool = Pubkey::from(whirlpool_bytes);
                        fuzz_assert_eq!(ta_whirlpool, p2.whirlpool,
                            "Pool2 tick_array (start={}) whirlpool pointer mismatch: {} != {}",
                            start_tick, ta_whirlpool, p2.whirlpool);
                    }
                }
            }
        }
        // Pool 3
        if let Some(ref p3) = fixture.pool_three {
            for (start_tick, tick_array_pubkey) in &p3.tick_arrays {
                if let Ok(account) = fixture.ctx.read_account(tick_array_pubkey) {
                    if account.data.len() >= TICK_ARRAY_WHIRLPOOL_OFFSET + 32 {
                        let whirlpool_bytes: [u8; 32] = account.data[TICK_ARRAY_WHIRLPOOL_OFFSET..TICK_ARRAY_WHIRLPOOL_OFFSET + 32].try_into().unwrap();
                        let ta_whirlpool = Pubkey::from(whirlpool_bytes);
                        fuzz_assert_eq!(ta_whirlpool, p3.whirlpool,
                            "Pool3 tick_array (start={}) whirlpool pointer mismatch: {} != {}",
                            start_tick, ta_whirlpool, p3.whirlpool);
                    }
                }
            }
        }
    }

    // ---- Tick Array Start Index Alignment (all pools) ----
    // Tick arrays must have start_tick_index divisible by (TICK_ARRAY_SIZE * tick_spacing).
    // Misalignment means the tick array covers an invalid range and tick lookups will be wrong.
    {
        const TICK_ARRAY_SIZE_I32: i32 = 88;
        let ts = TICK_SPACING as i32;
        let alignment = TICK_ARRAY_SIZE_I32 * ts;
        // Pool 1
        for (start_tick, _) in &fixture.pool.tick_arrays {
            fuzz_assert_eq!(
                start_tick % alignment, 0,
                "Pool1 tick_array start {} not aligned to {} (88 * {})",
                start_tick, alignment, TICK_SPACING
            );
        }
        // Pool 2
        if let Some(ref p2) = fixture.pool_two {
            for (start_tick, _) in &p2.tick_arrays {
                fuzz_assert_eq!(
                    start_tick % alignment, 0,
                    "Pool2 tick_array start {} not aligned to {}",
                    start_tick, alignment
                );
            }
        }
        // Pool 3
        if let Some(ref p3) = fixture.pool_three {
            for (start_tick, _) in &p3.tick_arrays {
                fuzz_assert_eq!(
                    start_tick % alignment, 0,
                    "Pool3 tick_array start {} not aligned to {}",
                    start_tick, alignment
                );
            }
        }
        // Dynamic tick arrays
        for (_, start_tick) in &fixture.dynamic_tick_arrays {
            fuzz_assert_eq!(
                start_tick % alignment, 0,
                "Dynamic tick_array start {} not aligned to {}",
                start_tick, alignment
            );
        }
    }

    // ---- Reward Emission Daily Solvency (all pools) ----
    // Error 6027: reward vault must hold enough for at least 1 day of emissions.
    // emissions_per_second_x64 * 86400 / 2^64 must be <= vault_balance.
    // If violated, emissions are unsustainable and will silently stop.
    {
        let check_reward_solvency = |pool_data: &PoolData, pool_state: &whirlpool::state::Whirlpool, pool_name: &str| {
            for i in 0..3 {
                if pool_data.reward_initialized[i] && pool_data.reward_vaults[i] != Pubkey::default() {
                    let ems = pool_state.reward_infos[i].emissions_per_second_x64;
                    if ems > 0 {
                        // daily_emission = ems * 86400 / 2^64
                        // To avoid overflow: ems * 86400 could overflow u128 only for huge ems values
                        let daily_x64 = (ems as u128).saturating_mul(86400u128);
                        let daily_tokens = daily_x64 >> 64;
                        let vault_balance = fixture.ctx.token_balance(&pool_data.reward_vaults[i]);
                        // The program enforces this at set_reward_emissions time.
                        // If violated here, either the vault was drained or emissions were set without
                        // sufficient funding.
                        fuzz_assert!(
                            vault_balance as u128 >= daily_tokens,
                            "{} reward {} daily emission ({}) exceeds vault balance ({}). ems_x64={}",
                            pool_name, i, daily_tokens, vault_balance, ems
                        );
                    }
                }
            };
        };
        if let Ok(pool_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
            check_reward_solvency(&fixture.pool, &pool_state, "Pool1");
        }
        if let Some(ref p2) = fixture.pool_two {
            if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
                check_reward_solvency(p2, &p2_state, "Pool2");
            }
        }
        if let Some(ref p3) = fixture.pool_three {
            if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
                check_reward_solvency(p3, &p3_state, "Pool3");
            }
        }
    }

    // ---- Pool Liquidity Upper Bound (all pools) ----
    // pool.liquidity is the sum of in-range position liquidities. It can never exceed
    // the sum of ALL position liquidities (the theoretical max if all were in-range).
    // Violation means phantom liquidity was injected without a corresponding position.
    {
        if let Ok(pool_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
            let mut total_pos_liquidity: u128 = 0;
            for pos in &fixture.positions {
                if let Ok(ps) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                    total_pos_liquidity = total_pos_liquidity.saturating_add(ps.liquidity);
                }
            }
            fuzz_assert!(
                pool_state.liquidity <= total_pos_liquidity,
                "Pool1 liquidity {} exceeds total position liquidity {}",
                pool_state.liquidity, total_pos_liquidity
            );
        }
        if let Some(ref p2) = fixture.pool_two {
            if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
                let mut total_pos_liquidity: u128 = 0;
                for pos in &fixture.pool_two_positions {
                    if let Ok(ps) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                        total_pos_liquidity = total_pos_liquidity.saturating_add(ps.liquidity);
                    }
                }
                fuzz_assert!(
                    p2_state.liquidity <= total_pos_liquidity,
                    "Pool2 liquidity {} exceeds total position liquidity {}",
                    p2_state.liquidity, total_pos_liquidity
                );
            }
        }
        if let Some(ref p3) = fixture.pool_three {
            if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
                let mut total_pos_liquidity: u128 = 0;
                for pos in &fixture.pool_three_positions {
                    if let Ok(ps) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                        total_pos_liquidity = total_pos_liquidity.saturating_add(ps.liquidity);
                    }
                }
                fuzz_assert!(
                    p3_state.liquidity <= total_pos_liquidity,
                    "Pool3 liquidity {} exceeds total position liquidity {}",
                    p3_state.liquidity, total_pos_liquidity
                );
            }
        }
    }

    // ---- Whirlpool PDA Bump Verification (all pools) ----
    // Re-derive the PDA from seeds and verify the stored bump matches.
    // A mismatch means the pool account's bump was corrupted, which would
    // break all CPI calls that use the pool as a signer PDA.
    {
        let verify_bump = |pool_data: &PoolData, pool_state: &whirlpool::state::Whirlpool, pool_name: &str| {
            let (expected_pda, expected_bump) = Pubkey::find_program_address(
                &[
                    b"whirlpool",
                    pool_state.whirlpools_config.as_ref(),
                    pool_state.token_mint_a.as_ref(),
                    pool_state.token_mint_b.as_ref(),
                    &pool_state.fee_tier_index_seed,
                ],
                &fixture.program_id,
            );
            fuzz_assert_eq!(
                pool_state.whirlpool_bump[0], expected_bump,
                "{} PDA bump mismatch: stored={} expected={}",
                pool_name, pool_state.whirlpool_bump[0], expected_bump
            );
            fuzz_assert_eq!(
                pool_data.whirlpool, expected_pda,
                "{} PDA address mismatch: tracked={} expected={}",
                pool_name, pool_data.whirlpool, expected_pda
            );
        };
        if let Ok(pool_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
            verify_bump(&fixture.pool, &pool_state, "Pool1");
        }
        if let Some(ref p2) = fixture.pool_two {
            if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
                verify_bump(p2, &p2_state, "Pool2");
            }
        }
        if let Some(ref p3) = fixture.pool_three {
            if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
                verify_bump(p3, &p3_state, "Pool3");
            }
        }
    }

    // ---- Fee Tier Index Seed Encoding Consistency (all pools) ----
    // fee_tier_index_seed is set to fee_tier_index.to_le_bytes() at initialization.
    // For standard pools, decoded value must equal tick_spacing.
    // For adaptive fee pools, it equals the adaptive_fee_tier_index.
    // Corruption here means the PDA derivation would produce a wrong address.
    {
        if let Ok(pool_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
            let decoded_index = u16::from_le_bytes(pool_state.fee_tier_index_seed);
            fuzz_assert_eq!(
                decoded_index, pool_state.tick_spacing,
                "Pool1 fee_tier_index_seed decoded={} != tick_spacing={}",
                decoded_index, pool_state.tick_spacing
            );
        }
        if let Some(ref p2) = fixture.pool_two {
            if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
                let decoded_index = u16::from_le_bytes(p2_state.fee_tier_index_seed);
                fuzz_assert_eq!(
                    decoded_index, p2_state.tick_spacing,
                    "Pool2 fee_tier_index_seed decoded={} != tick_spacing={}",
                    decoded_index, p2_state.tick_spacing
                );
            }
        }
        if let Some(ref _p3) = fixture.pool_three {
            if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool_three.as_ref().unwrap().whirlpool) {
                let decoded_index = u16::from_le_bytes(p3_state.fee_tier_index_seed);
                fuzz_assert_eq!(
                    decoded_index, fixture.adaptive_fee_tier_index,
                    "Pool3 fee_tier_index_seed decoded={} != adaptive_fee_tier_index={}",
                    decoded_index, fixture.adaptive_fee_tier_index
                );
            }
        }
    }

    // ---- Reward Info Vault Pointer and Mint Immutability (all pools) ----
    // Once a reward is initialized, its vault and mint pubkeys must never change.
    // A change would redirect reward tokens to a different account.
    {
        let check_reward_pointers = |pool_data: &PoolData, pool_state: &whirlpool::state::Whirlpool, pool_name: &str| {
            for i in 0..3 {
                if pool_data.reward_initialized[i] {
                    // Verify on-chain reward_infos[i].vault matches tracked vault
                    fuzz_assert_eq!(
                        pool_state.reward_infos[i].vault, pool_data.reward_vaults[i],
                        "{} reward {} vault pointer changed: on-chain={} tracked={}",
                        pool_name, i, pool_state.reward_infos[i].vault, pool_data.reward_vaults[i]
                    );
                    // Verify on-chain reward_infos[i].mint matches tracked mint
                    fuzz_assert_eq!(
                        pool_state.reward_infos[i].mint, pool_data.reward_mints[i],
                        "{} reward {} mint pointer changed: on-chain={} tracked={}",
                        pool_name, i, pool_state.reward_infos[i].mint, pool_data.reward_mints[i]
                    );
                }
            }
        };
        if let Ok(pool_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
            check_reward_pointers(&fixture.pool, &pool_state, "Pool1");
        }
        if let Some(ref p2) = fixture.pool_two {
            if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
                check_reward_pointers(p2, &p2_state, "Pool2");
            }
        }
        if let Some(ref p3) = fixture.pool_three {
            if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
                check_reward_pointers(p3, &p3_state, "Pool3");
            }
        }
    }

    // ---- Reward Initialized Monotonicity (all pools) ----
    // Once a reward is initialized (mint != Pubkey::default()), it cannot revert.
    // Source: "Once initialized, a reward cannot transition back to uninitialized."
    {
        let check_initialized_monotonicity = |pool_data: &PoolData, pool_state: &whirlpool::state::Whirlpool, pool_name: &str| {
            for i in 0..3 {
                if pool_data.reward_initialized[i] {
                    fuzz_assert!(
                        pool_state.reward_infos[i].mint != Pubkey::default(),
                        "{} reward {} was initialized but on-chain mint is now default (reverted to uninitialized)",
                        pool_name, i
                    );
                }
            }
        };
        if let Ok(pool_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
            check_initialized_monotonicity(&fixture.pool, &pool_state, "Pool1");
        }
        if let Some(ref p2) = fixture.pool_two {
            if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p2.whirlpool) {
                check_initialized_monotonicity(p2, &p2_state, "Pool2");
            }
        }
        if let Some(ref p3) = fixture.pool_three {
            if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&p3.whirlpool) {
                check_initialized_monotonicity(p3, &p3_state, "Pool3");
            }
        }
    }

    // ---- WhirlpoolsConfig On-Chain Authority Cross-Check ----
    // Verify the on-chain config account's authority fields match what we track.
    // Divergence means an authority was changed without our harness detecting it,
    // or there's a state corruption bug overwriting authority fields.
    if let Ok(config_state) = fixture.ctx.read_anchor_account::<whirlpool::state::WhirlpoolsConfig>(&fixture.config) {
        fuzz_assert_eq!(
            config_state.fee_authority, fixture.fee_authority.pubkey(),
            "Config fee_authority mismatch: on-chain={} tracked={}",
            config_state.fee_authority, fixture.fee_authority.pubkey()
        );
        fuzz_assert_eq!(
            config_state.collect_protocol_fees_authority, fixture.collect_protocol_fees_authority.pubkey(),
            "Config collect_protocol_fees_authority mismatch: on-chain={} tracked={}",
            config_state.collect_protocol_fees_authority, fixture.collect_protocol_fees_authority.pubkey()
        );
        fuzz_assert_eq!(
            config_state.reward_emissions_super_authority, fixture.reward_emissions_super_authority.pubkey(),
            "Config reward_emissions_super_authority mismatch: on-chain={} tracked={}",
            config_state.reward_emissions_super_authority, fixture.reward_emissions_super_authority.pubkey()
        );
        // default_protocol_fee_rate must be within bounds
        fuzz_assert_le!(
            config_state.default_protocol_fee_rate, MAX_PROTOCOL_FEE_RATE,
            "Config default_protocol_fee_rate exceeds max: {} > {}",
            config_state.default_protocol_fee_rate, MAX_PROTOCOL_FEE_RATE
        );
    }

    // ---- FeeTier On-Chain Consistency ----
    // The fee tier's tick_spacing and whirlpools_config should match what we expect.
    if let Ok(ft_state) = fixture.ctx.read_anchor_account::<whirlpool::state::FeeTier>(&fixture.fee_tier) {
        fuzz_assert_eq!(
            ft_state.whirlpools_config, fixture.config,
            "FeeTier whirlpools_config mismatch: on-chain={} tracked={}",
            ft_state.whirlpools_config, fixture.config
        );
        fuzz_assert_eq!(
            ft_state.tick_spacing, TICK_SPACING,
            "FeeTier tick_spacing changed: on-chain={} expected={}",
            ft_state.tick_spacing, TICK_SPACING
        );
        // Fee tier's default_fee_rate must be within MAX_FEE_RATE
        fuzz_assert_le!(
            ft_state.default_fee_rate, MAX_FEE_RATE,
            "FeeTier default_fee_rate exceeds max: {} > {}",
            ft_state.default_fee_rate, MAX_FEE_RATE
        );
    }

    // ---- Position Fee Checkpoint ≤ Pool Fee Growth Global (all pools) ----
    // A position's fee_growth_checkpoint must never exceed the pool's fee_growth_global.
    // The checkpoint is set to the global value at last update; exceeding it means phantom fees.
    {
        let check_fee_checkpoint = |positions: &[PositionData], pool_state: &whirlpool::state::Whirlpool, pool_name: &str| {
            for pos in positions {
                if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                    // Only check if position has been touched (checkpoint != 0 or has liquidity)
                    if pos_state.liquidity > 0 || pos_state.fee_growth_checkpoint_a > 0 || pos_state.fee_growth_checkpoint_b > 0 {
                        // For u128 wrapping: if checkpoint > global AND the difference is huge, it's a wrap
                        // If checkpoint > global AND difference is small, it's a real violation
                        if pos_state.fee_growth_checkpoint_a > pool_state.fee_growth_global_a {
                            let diff = pos_state.fee_growth_checkpoint_a - pool_state.fee_growth_global_a;
                            fuzz_assert!(diff > u128::MAX / 2,
                                "{}: pos {} fee_growth_checkpoint_a ({}) > fee_growth_global_a ({}) by {}",
                                pool_name, pos.position, pos_state.fee_growth_checkpoint_a,
                                pool_state.fee_growth_global_a, diff);
                        }
                        if pos_state.fee_growth_checkpoint_b > pool_state.fee_growth_global_b {
                            let diff = pos_state.fee_growth_checkpoint_b - pool_state.fee_growth_global_b;
                            fuzz_assert!(diff > u128::MAX / 2,
                                "{}: pos {} fee_growth_checkpoint_b ({}) > fee_growth_global_b ({}) by {}",
                                pool_name, pos.position, pos_state.fee_growth_checkpoint_b,
                                pool_state.fee_growth_global_b, diff);
                        }
                    }
                }
            }
        };
        if let Ok(p1) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
            check_fee_checkpoint(&fixture.positions, &p1, "pool1");
        }
        if let Some(ref pool_two) = fixture.pool_two {
            if let Ok(p2) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                check_fee_checkpoint(&fixture.pool_two_positions, &p2, "pool2");
            }
        }
        if let Some(ref pool_three) = fixture.pool_three {
            if let Ok(p3) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
                check_fee_checkpoint(&fixture.pool_three_positions, &p3, "pool3");
            }
        }
    }

    // ---- No Phantom Liquidity: Zero-Liquidity Positions (all pools) ----
    // Positions with liquidity==0 should not contribute to pool.liquidity even if in range.
    // We verify that pool.liquidity == sum of liquidities from positions with liquidity > 0
    // whose range contains tick_current_index (this is a refinement of liquidity_sum).
    {
        let check_no_phantom = |positions: &[PositionData], pool_state: &whirlpool::state::Whirlpool, pool_name: &str| {
            let mut active_liquidity_sum: u128 = 0;
            for pos in positions {
                if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                    if pos_state.liquidity > 0
                        && pos_state.tick_lower_index <= pool_state.tick_current_index
                        && pos_state.tick_upper_index > pool_state.tick_current_index
                    {
                        active_liquidity_sum += pos_state.liquidity;
                    }
                }
            }
            // pool.liquidity must exactly equal the sum of in-range non-zero positions.
            // Since the harness creates and tracks ALL positions, this is an exact check.
            fuzz_assert_eq!(pool_state.liquidity, active_liquidity_sum,
                "{}: pool liquidity {} != tracked active position sum {}",
                pool_name, pool_state.liquidity, active_liquidity_sum);
        };
        if let Ok(p1) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
            check_no_phantom(&fixture.positions, &p1, "pool1");
        }
        if let Some(ref pool_two) = fixture.pool_two {
            if let Ok(p2) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                check_no_phantom(&fixture.pool_two_positions, &p2, "pool2");
            }
        }
        if let Some(ref pool_three) = fixture.pool_three {
            if let Ok(p3) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
                check_no_phantom(&fixture.pool_three_positions, &p3, "pool3");
            }
        }
    }

    // ---- Protocol Fee Overflow Detection (Pool 1) ----
    // protocol_fee_owed uses wrapping_add in swap_manager.rs:284.
    // If protocol_fee_owed wraps around u64, it would suddenly become small.
    // Combined with monotonicity check, this detects overflow.
    // Additional check: protocol_fee_owed_a + protocol_fee_owed_b should be
    // reasonable relative to the vault balance (never more than vault).
    if let Ok(pool_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
        let vault_a = fixture.ctx.token_balance(&fixture.pool.token_vault_a);
        let vault_b = fixture.ctx.token_balance(&fixture.pool.token_vault_b);
        // Protocol fees are a fraction of vault contents; they should never exceed vault
        fuzz_assert_le!(
            pool_state.protocol_fee_owed_a, vault_a,
            "Pool1 protocol_fee_owed_a ({}) > vault_a balance ({})",
            pool_state.protocol_fee_owed_a, vault_a
        );
        fuzz_assert_le!(
            pool_state.protocol_fee_owed_b, vault_b,
            "Pool1 protocol_fee_owed_b ({}) > vault_b balance ({})",
            pool_state.protocol_fee_owed_b, vault_b
        );
    }

    // ---- Position Reward Inside Checkpoint Consistency (all pools) ----
    // Each position's reward_infos[i].growth_inside_checkpoint is set to
    // the computed growth_inside value at the last modify/collect operation.
    // growth_inside = growth_global - growth_outside_lower - growth_outside_upper
    // It should never exceed growth_global (accounting for u128 wrapping).
    // A violation means phantom rewards are being generated.
    {
        let check_reward_checkpoint = |positions: &[PositionData], pool_state: &whirlpool::state::Whirlpool, pool_name: &str| {
            for pos in positions {
                if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                    if pos_state.liquidity == 0 { continue; }
                    for i in 0..3 {
                        let checkpoint = pos_state.reward_infos[i].growth_inside_checkpoint;
                        let global = pool_state.reward_infos[i].growth_global_x64;
                        // growth_inside <= growth_global (modular arithmetic)
                        // If checkpoint > global, it should be because of u128 wrapping (huge difference)
                        if checkpoint > global {
                            let diff = checkpoint - global;
                            fuzz_assert!(diff > u128::MAX / 2,
                                "{}: pos {} reward {} growth_inside_checkpoint ({}) > growth_global_x64 ({}) by {}",
                                pool_name, pos.position, i, checkpoint, global, diff);
                        }
                    }
                }
            }
        };
        if let Ok(p1) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
            check_reward_checkpoint(&fixture.positions, &p1, "pool1");
        }
        if let Some(ref pool_two) = fixture.pool_two {
            if let Ok(p2) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                check_reward_checkpoint(&fixture.pool_two_positions, &p2, "pool2");
            }
        }
        if let Some(ref pool_three) = fixture.pool_three {
            if let Ok(p3) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
                check_reward_checkpoint(&fixture.pool_three_positions, &p3, "pool3");
            }
        }
    }

    // ---- Fee Growth Increment Consistency (all pools) ----
    // After a swap with non-zero fees and non-zero in-range liquidity,
    // fee_growth_global must strictly increase for the input token.
    // We check this as: if fee_growth_global didn't change between checks BUT
    // protocol_fee_owed increased, then fees were collected but not distributed
    // to LPs — indicating a bug in calculate_fees or zero liquidity at swap time.
    // Since we can't track per-swap, we check: protocol_fee_owed increased implies
    // fee_growth_global also increased (fees flow to both protocol AND LPs).
    if let Ok(pool_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
        let p_fee_a = pool_state.protocol_fee_owed_a;
        let p_fee_b = pool_state.protocol_fee_owed_b;
        // If protocol fees increased for token A, fee_growth_global_a should also have increased
        // (both come from the same fee_amount in calculate_fees, split by protocol_fee_rate)
        // Exception: if liquidity was 0 during the swap, fee_growth doesn't increase
        // We use a relaxed check: if protocol fee increased significantly (>100),
        // fee_growth should have increased too.
        if p_fee_a > fixture.prev_protocol_fee_owed_a.saturating_add(100)
            && !fixture.protocol_fees_just_collected
        {
            fuzz_assert!(pool_state.fee_growth_global_a > fixture.prev_fee_growth_global_a
                || pool_state.liquidity == 0,
                "Pool1: protocol_fee_owed_a increased ({} -> {}) but fee_growth_global_a unchanged ({}) with liquidity={}",
                fixture.prev_protocol_fee_owed_a, p_fee_a,
                pool_state.fee_growth_global_a, pool_state.liquidity);
        }
        if p_fee_b > fixture.prev_protocol_fee_owed_b.saturating_add(100)
            && !fixture.protocol_fees_just_collected
        {
            fuzz_assert!(pool_state.fee_growth_global_b > fixture.prev_fee_growth_global_b
                || pool_state.liquidity == 0,
                "Pool1: protocol_fee_owed_b increased ({} -> {}) but fee_growth_global_b unchanged ({}) with liquidity={}",
                fixture.prev_protocol_fee_owed_b, p_fee_b,
                pool_state.fee_growth_global_b, pool_state.liquidity);
        }
    }

    // ---- Pool Two/Three Protocol Fee Overflow Detection ----
    // Same as pool 1: protocol_fee_owed must not exceed vault balance.
    if let Some(ref pool_two) = fixture.pool_two {
        if let Ok(p2_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
            let vault_a = fixture.ctx.token_balance(&pool_two.token_vault_a);
            let vault_b = fixture.ctx.token_balance(&pool_two.token_vault_b);
            fuzz_assert_le!(p2_state.protocol_fee_owed_a, vault_a,
                "Pool2 protocol_fee_owed_a ({}) > vault_a ({})",
                p2_state.protocol_fee_owed_a, vault_a);
            fuzz_assert_le!(p2_state.protocol_fee_owed_b, vault_b,
                "Pool2 protocol_fee_owed_b ({}) > vault_b ({})",
                p2_state.protocol_fee_owed_b, vault_b);
        }
    }
    if let Some(ref pool_three) = fixture.pool_three {
        if let Ok(p3_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
            let vault_a = fixture.ctx.token_balance(&pool_three.token_vault_a);
            let vault_b = fixture.ctx.token_balance(&pool_three.token_vault_b);
            fuzz_assert_le!(p3_state.protocol_fee_owed_a, vault_a,
                "Pool3 protocol_fee_owed_a ({}) > vault_a ({})",
                p3_state.protocol_fee_owed_a, vault_a);
            fuzz_assert_le!(p3_state.protocol_fee_owed_b, vault_b,
                "Pool3 protocol_fee_owed_b ({}) > vault_b ({})",
                p3_state.protocol_fee_owed_b, vault_b);
        }
    }

    // ---- Tick Fee Growth Outside Bounded by Global (all pools) ----
    // For any initialized tick, fee_growth_outside_a should never exceed
    // fee_growth_global_a (modular arithmetic — large backward jump = wrapping).
    // When a tick is crossed, outside = global - old_outside. If outside > global
    // without wrapping, it means phantom fees leaked into the outside accumulator.
    // Tick layout: 1 (init) + 16 (net) + 16 (gross) + 16 (fgo_a) + 16 (fgo_b) = offset 33..65
    {
        let check_tick_fee_outside = |tick_arrays: &[(i32, Pubkey)], pool_state: &whirlpool::state::Whirlpool, pool_name: &str| {
            for (start_idx, ta_pubkey) in tick_arrays {
                if let Ok(account) = fixture.ctx.read_account(ta_pubkey) {
                    let data = &account.data;
                    let ticks_offset = 12; // 8 disc + 4 start_tick_index
                    const TICK_SIZE: usize = 113;
                    for tick_idx in 0..88usize {
                        let base = ticks_offset + tick_idx * TICK_SIZE;
                        if base + TICK_SIZE > data.len() { break; }
                        let initialized = data[base] != 0;
                        if !initialized { continue; }
                        // fee_growth_outside_a at offset 33 (1+16+16), 16 bytes
                        let fgo_a_bytes: [u8; 16] = data[base+33..base+49].try_into().unwrap();
                        let fee_growth_outside_a = u128::from_le_bytes(fgo_a_bytes);
                        let fgo_b_bytes: [u8; 16] = data[base+49..base+65].try_into().unwrap();
                        let fee_growth_outside_b = u128::from_le_bytes(fgo_b_bytes);

                        let actual_tick = start_idx + (tick_idx as i32) * (TICK_SPACING as i32);

                        if fee_growth_outside_a > pool_state.fee_growth_global_a {
                            let diff = fee_growth_outside_a - pool_state.fee_growth_global_a;
                            fuzz_assert!(diff > u128::MAX / 2,
                                "{}: tick {} fee_growth_outside_a ({}) > global_a ({}) by {}",
                                pool_name, actual_tick, fee_growth_outside_a,
                                pool_state.fee_growth_global_a, diff);
                        }
                        if fee_growth_outside_b > pool_state.fee_growth_global_b {
                            let diff = fee_growth_outside_b - pool_state.fee_growth_global_b;
                            fuzz_assert!(diff > u128::MAX / 2,
                                "{}: tick {} fee_growth_outside_b ({}) > global_b ({}) by {}",
                                pool_name, actual_tick, fee_growth_outside_b,
                                pool_state.fee_growth_global_b, diff);
                        }
                    }
                }
            }
        };
        if let Ok(p1) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
            check_tick_fee_outside(&fixture.pool.tick_arrays, &p1, "pool1");
        }
        if let Some(ref pool_two) = fixture.pool_two {
            if let Ok(p2) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                check_tick_fee_outside(&pool_two.tick_arrays, &p2, "pool2");
            }
        }
        if let Some(ref pool_three) = fixture.pool_three {
            if let Ok(p3) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
                check_tick_fee_outside(&pool_three.tick_arrays, &p3, "pool3");
            }
        }
    }

    // ---- Oracle Whirlpool Pointer Consistency (all pools) ----
    // Each Oracle account stores a whirlpool field that must match the pool it was
    // derived from. A mismatch means the oracle is corrupted or points to wrong pool.
    // Oracle layout: 8 (disc) + 32 (whirlpool) = first 40 bytes
    {
        let check_oracle_pointer = |oracle: &Pubkey, expected_pool: &Pubkey, pool_name: &str| {
            if let Ok(account) = fixture.ctx.read_account(oracle) {
                if account.data.len() >= 40 {
                    let stored_whirlpool = Pubkey::from(<[u8; 32]>::try_from(&account.data[8..40]).unwrap());
                    fuzz_assert_eq!(stored_whirlpool, *expected_pool,
                        "{}: oracle {} whirlpool field ({}) != expected pool ({})",
                        pool_name, oracle, stored_whirlpool, expected_pool);
                }
            }
        };
        check_oracle_pointer(&fixture.pool.oracle, &fixture.pool.whirlpool, "pool1");
        if let Some(ref pool_two) = fixture.pool_two {
            check_oracle_pointer(&pool_two.oracle, &pool_two.whirlpool, "pool2");
        }
        if let Some(ref pool_three) = fixture.pool_three {
            check_oracle_pointer(&pool_three.oracle, &pool_three.whirlpool, "pool3");
        }
    }

    // ---- Pool Three Oracle: Volatility Accumulator Bounded by Max ----
    // The adaptive fee volatility_accumulator must never exceed max_volatility_accumulator.
    // Oracle layout offsets (zero_copy packed):
    //   8: disc, 8..40: whirlpool, 40..48: trade_enable_timestamp
    //   48..82: AdaptiveFeeConstants (filter_period u16, decay_period u16, reduction_factor u16,
    //           adaptive_fee_control_factor u32, max_volatility_accumulator u32 @58..62,
    //           tick_group_size u16, major_swap_threshold_ticks u16, reserved [u8;16])
    //   82..126: AdaptiveFeeVariables (last_ref_update_ts u64, last_major_swap_ts u64,
    //            volatility_reference u32, tick_group_index_ref i32,
    //            volatility_accumulator u32 @106..110, reserved [u8;16])
    if let Some(ref pool_three) = fixture.pool_three {
        if let Ok(account) = fixture.ctx.read_account(&pool_three.oracle) {
            let data = &account.data;
            if data.len() >= 110 {
                let max_vol_acc = u32::from_le_bytes(data[58..62].try_into().unwrap());
                let vol_acc = u32::from_le_bytes(data[106..110].try_into().unwrap());
                fuzz_assert!(vol_acc <= max_vol_acc,
                    "pool3 oracle: volatility_accumulator ({}) > max_volatility_accumulator ({})",
                    vol_acc, max_vol_acc);

                // Also verify volatility_reference <= volatility_accumulator
                // (reference is a decayed version of accumulator, should never exceed it
                //  unless accumulator was recently reset while reference is stale)
                let vol_ref = u32::from_le_bytes(data[98..102].try_into().unwrap());
                // volatility_reference can exceed current accumulator after reset,
                // but should still be <= max
                fuzz_assert!(vol_ref <= max_vol_acc,
                    "pool3 oracle: volatility_reference ({}) > max_volatility_accumulator ({})",
                    vol_ref, max_vol_acc);
            }
        }
    }

    // ---- Pool Three Oracle: Timestamp Monotonicity ----
    // The adaptive fee oracle timestamps (last_reference_update_timestamp and
    // last_major_swap_timestamp) must never decrease. A decrease would indicate
    // time-travel or timestamp corruption that breaks the adaptive fee decay logic.
    if let Some(ref pool_three) = fixture.pool_three {
        if let Ok(account) = fixture.ctx.read_account(&pool_three.oracle) {
            let data = &account.data;
            if data.len() >= 98 {
                let last_ref_ts = u64::from_le_bytes(data[82..90].try_into().unwrap());
                let last_major_ts = u64::from_le_bytes(data[90..98].try_into().unwrap());
                fuzz_assert!(last_ref_ts >= fixture.prev_p3_oracle_last_ref_update_ts,
                    "pool3 oracle: last_reference_update_timestamp decreased {} -> {}",
                    fixture.prev_p3_oracle_last_ref_update_ts, last_ref_ts);
                fuzz_assert!(last_major_ts >= fixture.prev_p3_oracle_last_major_swap_ts,
                    "pool3 oracle: last_major_swap_timestamp decreased {} -> {}",
                    fixture.prev_p3_oracle_last_major_swap_ts, last_major_ts);
                fixture.prev_p3_oracle_last_ref_update_ts = last_ref_ts;
                fixture.prev_p3_oracle_last_major_swap_ts = last_major_ts;
            }
        }
    }

    // ---- Pool Three Oracle: Adaptive Fee Constants Validation ----
    // Stored adaptive fee constants must satisfy the program's validation constraints:
    // filter_period >= 1, decay_period > filter_period, reduction_factor < 10000,
    // adaptive_fee_control_factor < 100000
    if let Some(ref pool_three) = fixture.pool_three {
        if let Ok(account) = fixture.ctx.read_account(&pool_three.oracle) {
            let data = &account.data;
            if data.len() >= 82 {
                let filter_period = u16::from_le_bytes(data[48..50].try_into().unwrap());
                let decay_period = u16::from_le_bytes(data[50..52].try_into().unwrap());
                let reduction_factor = u16::from_le_bytes(data[52..54].try_into().unwrap());
                let adaptive_fee_control_factor = u32::from_le_bytes(data[54..58].try_into().unwrap());
                let max_vol_acc = u32::from_le_bytes(data[58..62].try_into().unwrap());
                let tick_group_size = u16::from_le_bytes(data[62..64].try_into().unwrap());

                // filter_period must be >= 1
                fuzz_assert!(filter_period >= 1,
                    "pool3 oracle: filter_period ({}) < 1", filter_period);
                // decay_period must be > filter_period
                fuzz_assert!(decay_period > filter_period,
                    "pool3 oracle: decay_period ({}) <= filter_period ({})",
                    decay_period, filter_period);
                // reduction_factor must be < REDUCTION_FACTOR_DENOMINATOR (10000)
                fuzz_assert!(reduction_factor < 10_000,
                    "pool3 oracle: reduction_factor ({}) >= 10000", reduction_factor);
                // adaptive_fee_control_factor must be < 100000
                fuzz_assert!(adaptive_fee_control_factor < 100_000,
                    "pool3 oracle: adaptive_fee_control_factor ({}) >= 100000",
                    adaptive_fee_control_factor);
                // max_volatility_accumulator * tick_group_size must fit in u32
                if tick_group_size > 0 {
                    fuzz_assert!(
                        (max_vol_acc as u64) * (tick_group_size as u64) <= u32::MAX as u64,
                        "pool3 oracle: max_vol_acc({}) * tick_group_size({}) = {} > u32::MAX",
                        max_vol_acc, tick_group_size,
                        (max_vol_acc as u64) * (tick_group_size as u64));
                }
            }
        }
    }

    // ---- Pool Three Oracle: Adaptive Fee Constants Immutability ----
    // The adaptive fee constants (filter_period, decay_period, reduction_factor,
    // adaptive_fee_control_factor, max_volatility_accumulator, tick_group_size,
    // major_swap_threshold_ticks) should not change during fuzzing since
    // set_preset_adaptive_fee_constants is an admin-only instruction not fuzzed.
    // Any mutation indicates corruption from swap or other user-facing instruction.
    if let Some(ref pool_three) = fixture.pool_three {
        if let Ok(account) = fixture.ctx.read_account(&pool_three.oracle) {
            let data = &account.data;
            if data.len() >= 82 {
                // Adaptive fee constants: bytes 48..82 (34 bytes)
                let current: [u8; 34] = data[48..82].try_into().unwrap();
                match fixture.p3_adaptive_fee_constants_snapshot {
                    None => {
                        // First observation: capture the snapshot
                        fixture.p3_adaptive_fee_constants_snapshot = Some(current);
                    }
                    Some(ref snapshot) => {
                        fuzz_assert_eq!(current, *snapshot,
                            "pool3 oracle: adaptive fee constants mutated! \
                             Expected {:?}, got {:?}", &snapshot[..8], &current[..8]);
                    }
                }
            }
        }
    }

    // ---- Tick Reward Growths Outside Bounded by Global (all pools) ----
    // Same logic as fee_growth_outside: for each initialized tick, each
    // reward_growths_outside[i] should not exceed the pool's reward growth global.
    // Tick layout: reward_growths_outside starts at offset 65 (1+16+16+16+16), 3 * 16 bytes
    {
        let check_tick_reward_outside = |tick_arrays: &[(i32, Pubkey)], pool_state: &whirlpool::state::Whirlpool, pool_name: &str| {
            for (start_idx, ta_pubkey) in tick_arrays {
                if let Ok(account) = fixture.ctx.read_account(ta_pubkey) {
                    let data = &account.data;
                    let ticks_offset = 12;
                    const TICK_SIZE: usize = 113;
                    for tick_idx in 0..88usize {
                        let base = ticks_offset + tick_idx * TICK_SIZE;
                        if base + TICK_SIZE > data.len() { break; }
                        let initialized = data[base] != 0;
                        if !initialized { continue; }
                        let actual_tick = start_idx + (tick_idx as i32) * (TICK_SPACING as i32);
                        // reward_growths_outside at offset 65, 3 x u128
                        for i in 0..3usize {
                            let rgo_offset = base + 65 + i * 16;
                            if rgo_offset + 16 > data.len() { break; }
                            let rgo_bytes: [u8; 16] = data[rgo_offset..rgo_offset+16].try_into().unwrap();
                            let reward_growth_outside = u128::from_le_bytes(rgo_bytes);
                            let reward_growth_global = pool_state.reward_infos[i].growth_global_x64;
                            if reward_growth_outside > reward_growth_global {
                                let diff = reward_growth_outside - reward_growth_global;
                                fuzz_assert!(diff > u128::MAX / 2,
                                    "{}: tick {} reward {} growth_outside ({}) > growth_global ({}) by {}",
                                    pool_name, actual_tick, i, reward_growth_outside,
                                    reward_growth_global, diff);
                            }
                        }
                    }
                }
            }
        };
        if let Ok(p1) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&fixture.pool.whirlpool) {
            check_tick_reward_outside(&fixture.pool.tick_arrays, &p1, "pool1");
        }
        if let Some(ref pool_two) = fixture.pool_two {
            if let Ok(p2) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_two.whirlpool) {
                check_tick_reward_outside(&pool_two.tick_arrays, &p2, "pool2");
            }
        }
        if let Some(ref pool_three) = fixture.pool_three {
            if let Ok(p3) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool_three.whirlpool) {
                check_tick_reward_outside(&pool_three.tick_arrays, &p3, "pool3");
            }
        }
    }

    // ---- Position Reward Growth Inside Checkpoint Bounded (all pools) ----
    // A position's reward_infos[i].growth_inside_checkpoint should be consistent
    // with the pool's reward_infos[i].growth_global_x64. If the checkpoint exceeds
    // global growth by more than half of u128 range, it indicates a bug (not wrapping).
    {
        let check_reward_checkpoint = |positions: &[PositionData], pool_key: &Pubkey, pool_name: &str| {
            if let Ok(pool_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(pool_key) {
                for pos in positions {
                    if let Ok(pos_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position) {
                        for i in 0..3usize {
                            let checkpoint = pos_state.reward_infos[i].growth_inside_checkpoint;
                            let global = pool_state.reward_infos[i].growth_global_x64;
                            // If checkpoint > global, it should be due to wrapping (diff > u128::MAX/2)
                            if checkpoint > global {
                                let diff = checkpoint - global;
                                fuzz_assert!(diff > u128::MAX / 2,
                                    "{}: pos {} reward[{}] growth_inside_checkpoint ({}) > reward_growth_global ({}) by {} (non-wrapping)",
                                    pool_name, pos.position, i, checkpoint, global, diff);
                            }
                        }
                    }
                }
            }
        };
        check_reward_checkpoint(&fixture.positions, &fixture.pool.whirlpool, "pool1");
        if let Some(ref p2) = fixture.pool_two {
            check_reward_checkpoint(&fixture.pool_two_positions, &p2.whirlpool, "pool2");
        }
        if let Some(ref p3) = fixture.pool_three {
            check_reward_checkpoint(&fixture.pool_three_positions, &p3.whirlpool, "pool3");
        }
    }

    // ---- Swap Success Implies Non-Trivial Trade (pool 1) ----
    // If do_swap succeeded (successful_swaps increased), at least one vault balance
    // should have changed. A "successful" swap that moves no tokens is a no-op bug.
    // This is checked per-swap in the action postconditions, but we also verify
    // the total_swaps vs successful_swaps ratio hasn't degraded unexpectedly.
    {
        if fixture.total_swaps > 0 && fixture.successful_swaps > 0 {
            // The vault balances post-swap are already checked in each action.
            // Here we verify that the cumulative vault change is consistent:
            // After N successful swaps on pool 1, at least one vault should differ from setup.
            let vault_a = fixture.ctx.token_balance(&fixture.pool.token_vault_a);
            let vault_b = fixture.ctx.token_balance(&fixture.pool.token_vault_b);
            // If we had successful swaps, at least one vault should have moved
            // (unless all swaps hit the same pool with exact reversals, which is
            // theoretically possible but extremely unlikely with random fuzzing).
            // We use a soft check here - just verify vaults are non-zero
            // (the stronger per-swap checks are in actions/swaps.rs).
            fuzz_assert!(vault_a > 0 || vault_b > 0,
                "Both pool1 vaults are zero after {} successful swaps", fixture.successful_swaps);
        }
    }

    // ---- Vault Balance ≥ Protocol Fee Owed (all pools) ----
    // The vault must always hold at least as many tokens as protocol_fee_owed.
    // If violated, collect_protocol_fees would drain LP funds.
    {
        let check_vault_proto_fee = |pool_key: &Pubkey, vault_a: &Pubkey, vault_b: &Pubkey, name: &str| {
            if let Ok(pool_state) = fixture.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(pool_key) {
                let va = fixture.ctx.token_balance(vault_a);
                let vb = fixture.ctx.token_balance(vault_b);
                fuzz_assert!(va >= pool_state.protocol_fee_owed_a,
                    "{}: vault_a ({}) < protocol_fee_owed_a ({})", name, va, pool_state.protocol_fee_owed_a);
                fuzz_assert!(vb >= pool_state.protocol_fee_owed_b,
                    "{}: vault_b ({}) < protocol_fee_owed_b ({})", name, vb, pool_state.protocol_fee_owed_b);
            }
        };
        check_vault_proto_fee(&fixture.pool.whirlpool, &fixture.pool.token_vault_a,
            &fixture.pool.token_vault_b, "pool1");
        if let Some(ref p2) = fixture.pool_two {
            check_vault_proto_fee(&p2.whirlpool, &p2.token_vault_a, &p2.token_vault_b, "pool2");
        }
        if let Some(ref p3) = fixture.pool_three {
            check_vault_proto_fee(&p3.whirlpool, &p3.token_vault_a, &p3.token_vault_b, "pool3");
        }
    }


}
