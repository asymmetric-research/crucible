// actions/positions.rs — Position lifecycle action methods (included in impl WhirlpoolFixture via include!())

    pub fn action_open_position(
        &mut self,
        #[range(0..3)] user_idx: usize,
        tick_lower_offset: i64,
        tick_upper_offset: i64,
    ) -> bool {
        // Limit to 10 positions to avoid memory issues
        if self.positions.len() >= 20 {
            return false;
        }

        // Calculate tick indices biased toward existing tick arrays for better success rate
        let tick_lower_offset = tick_lower_offset as i32;
        let tick_upper_offset = tick_upper_offset as i32;

        // Pick a tick array to base the position on (bias toward covered ranges)
        let chosen_array_idx = (tick_lower_offset.unsigned_abs() as usize) % self.pool.tick_arrays.len();
        let base_start = self.pool.tick_arrays[chosen_array_idx].0;

        // Place lower tick within the chosen array's range
        let inner_offset = ((tick_lower_offset.abs() % (TICK_ARRAY_SIZE as i32)).max(0)) * (TICK_SPACING as i32);
        let tick_lower_raw = base_start + inner_offset;
        let span = ((tick_upper_offset.abs() % 20) + 1) * (TICK_SPACING as i32);
        let tick_upper_raw = tick_lower_raw + span;

        let tick_lower_index = tick_lower_raw.max(MIN_TICK_INDEX).min(MAX_TICK_INDEX - TICK_SPACING as i32);
        let tick_upper_index = tick_upper_raw.max(tick_lower_index + TICK_SPACING as i32).min(MAX_TICK_INDEX);

        let user = &self.users[user_idx];
        let pool = &self.pool;

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
                whirlpool: pool.whirlpool,
            })
            .signers(&[&*user.keypair, &position_mint])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: verify on-chain position state
                if let Ok(pos_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&position) {
                    fuzz_assert_eq!(pos_state.tick_lower_index, tick_lower_index,
                        "open_pos: tick_lower {} != expected {}", pos_state.tick_lower_index, tick_lower_index);
                    fuzz_assert_eq!(pos_state.tick_upper_index, tick_upper_index,
                        "open_pos: tick_upper {} != expected {}", pos_state.tick_upper_index, tick_upper_index);
                    fuzz_assert_eq!(pos_state.liquidity, 0,
                        "open_pos: new position has non-zero liquidity {}", pos_state.liquidity);
                    fuzz_assert_eq!(pos_state.whirlpool, pool.whirlpool,
                        "open_pos: whirlpool mismatch");
                    fuzz_assert_eq!(pos_state.position_mint, position_mint.pubkey(),
                        "open_pos: mint mismatch");
                }
                self.positions.push(PositionData {
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
                debug_print!("[OPEN_POS] SUCCESS: user={} ticks=[{},{}]", user_idx, tick_lower_index, tick_upper_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[OPEN_POS] TX_FAILED: user={} ticks=[{},{}]",
                    user_idx, tick_lower_index, tick_upper_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[OPEN_POS] SEND_FAILED: user={} ticks=[{},{}]: {:?}",
                    user_idx, tick_lower_index, tick_upper_index, e);
                false
            }
        };
        action_stats::record(&action_stats::OPEN_POSITION, success);
        success
    }

    /// Close an empty position (no liquidity, no uncollected fees/rewards)
    pub fn action_close_position(&mut self, #[range(0..5)] position_idx: usize) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }

        // Only close positions without liquidity
        if self.positions[position_idx].has_liquidity {
            debug_print!("[CLOSE_POS] SKIP: pos={} has liquidity", position_idx);
            return false;
        }
        // Skip bundled positions (use close_bundled_position instead)
        if self.positions[position_idx].bundle_info.is_some() {
            return false;
        }

        // Read on-chain state to verify full emptiness (liquidity + fees + rewards all zero)
        if let Ok(pos_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
            if pos_state.liquidity > 0 || pos_state.fee_owed_a > 0 || pos_state.fee_owed_b > 0 {
                debug_print!("[CLOSE_POS] SKIP: pos={} not empty on-chain (liq={}, fee_a={}, fee_b={})",
                    position_idx, pos_state.liquidity, pos_state.fee_owed_a, pos_state.fee_owed_b);
                return false;
            }
            // Check all rewards are zero
            for ri in &pos_state.reward_infos {
                if ri.amount_owed > 0 {
                    debug_print!("[CLOSE_POS] SKIP: pos={} has uncollected reward", position_idx);
                    return false;
                }
            }
        }

        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];

        let result = self.ctx.program(self.program_id)
            .call(instruction::ClosePosition {})
            .accounts(accounts::ClosePosition {
                position_authority: user.keypair.pubkey(),
                receiver: user.keypair.pubkey(),
                position: position.position,
                position_mint: position.position_mint,
                position_token_account: position.position_token_account,
            })
            .signers(&[&*user.keypair])
            .send();

        let closed_pos_pubkey = position.position;
        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: position account should be closed (no lamports)
                if let Ok(account) = self.ctx.read_account(&closed_pos_pubkey) {
                    fuzz_assert_eq!(account.lamports, 0,
                        "close_position: pos {} account still has {} lamports after close",
                        position_idx, account.lamports);
                }
                debug_print!("[CLOSE_POS] SUCCESS: pos={}", position_idx);
                self.positions.remove(position_idx);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[CLOSE_POS] TX_FAILED: pos={}", position_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[CLOSE_POS] SEND_FAILED: pos={}: {:?}", position_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::CLOSE_POSITION, success);
        success
    }

    /// Try to close a position that has non-zero state (liquidity/fees/rewards).
    /// The program MUST reject this. If it succeeds, funds were destroyed.
    pub fn action_force_close_nonempty_position(&mut self, #[range(0..5)] position_idx: usize) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }
        // Only attempt if position has liquidity (interesting attack scenario)
        if !self.positions[position_idx].has_liquidity {
            return false;
        }
        // Skip bundled positions
        if self.positions[position_idx].bundle_info.is_some() {
            return false;
        }

        let position = &self.positions[position_idx];
        let user = &self.users[position.owner_idx];

        // Snapshot pre-close state
        let pre_liq = self.ctx.read_anchor_account::<whirlpool::state::Position>(&position.position)
            .ok().map(|s| s.liquidity).unwrap_or(0);

        let result = self.ctx.program(self.program_id)
            .call(instruction::ClosePosition {})
            .accounts(accounts::ClosePosition {
                position_authority: user.keypair.pubkey(),
                receiver: user.keypair.pubkey(),
                position: position.position,
                position_mint: position.position_mint,
                position_token_account: position.position_token_account,
            })
            .signers(&[&*user.keypair])
            .send();

        match &result {
            Ok(TxOutcome::Success { .. }) => {
                // This should NEVER happen — program should reject closing non-empty position
                fuzz_assert!(pre_liq == 0,
                    "CRITICAL: close_position succeeded with liquidity={}! Funds destroyed!", pre_liq);
                // If somehow it passed with 0 liquidity (race), clean up
                self.positions.remove(position_idx);
                true
            }
            Ok(TxOutcome::ProgramError { .. }) => {
                // Expected: program correctly rejected the close
                debug_print!("[FORCE_CLOSE] Correctly rejected: pos={} liq={}", position_idx, pre_liq);
                false
            }
            Err(_) => false,
        }
    }

    /// Open a full-range position (maximum tick range)
    pub fn action_open_full_range_position(&mut self, #[range(0..3)] user_idx: usize) -> bool {
        if self.positions.len() >= 20 {
            return false;
        }

        let user = &self.users[user_idx];
        let pool = &self.pool;

        // Full range ticks (aligned to tick spacing)
        let tick_lower_index = (MIN_TICK_INDEX / (TICK_SPACING as i32)) * (TICK_SPACING as i32);
        let tick_upper_index = (MAX_TICK_INDEX / (TICK_SPACING as i32)) * (TICK_SPACING as i32);

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
                whirlpool: pool.whirlpool,
            })
            .signers(&[&*user.keypair, &position_mint])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.positions.push(PositionData {
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
                debug_print!("[OPEN_FULL_RANGE] SUCCESS: user={} ticks=[{},{}]", user_idx, tick_lower_index, tick_upper_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[OPEN_FULL_RANGE] TX_FAILED: user={}", user_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[OPEN_FULL_RANGE] SEND_FAILED: user={}: {:?}", user_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::OPEN_POSITION, success);
        success
    }

    /// Open a position at extreme tick boundaries (boundary testing)
    pub fn action_open_position_extreme_ticks(
        &mut self,
        #[range(0..3)] user_idx: usize,
        variant: u8,
    ) -> bool {
        if self.positions.len() >= 20 {
            return false;
        }

        let ts = TICK_SPACING as i32;
        let min_aligned = (MIN_TICK_INDEX / ts) * ts;
        let max_aligned = (MAX_TICK_INDEX / ts) * ts;

        // Pick from extreme configurations
        let (tick_lower_index, tick_upper_index) = match variant % 5 {
            // Single-tick-spacing-width position at current tick
            0 => {
                let current = self.read_pool_tick();
                let aligned = (current / ts) * ts;
                let lower = aligned.max(min_aligned);
                let upper = (lower + ts).min(max_aligned);
                if lower >= upper { return false; }
                (lower, upper)
            }
            // Position at MIN_TICK boundary
            1 => (min_aligned, min_aligned + ts * 2),
            // Position at MAX_TICK boundary
            2 => (max_aligned - ts * 2, max_aligned),
            // Tick array boundary: position straddling array boundary
            3 => {
                // Position crossing the 0-th array boundary
                (-ts, ts)
            }
            // Very wide position near extremes
            _ => (min_aligned, max_aligned),
        };

        let user = &self.users[user_idx];
        let pool = &self.pool;

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
                whirlpool: pool.whirlpool,
            })
            .signers(&[&*user.keypair, &position_mint])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.positions.push(PositionData {
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
                debug_print!("[OPEN_EXTREME_POS] SUCCESS: user={} ticks=[{},{}]",
                    user_idx, tick_lower_index, tick_upper_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[OPEN_EXTREME_POS] TX_FAILED: user={} ticks=[{},{}]",
                    user_idx, tick_lower_index, tick_upper_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[OPEN_EXTREME_POS] SEND_FAILED: user={}: {:?}", user_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::OPEN_EXTREME_POSITION, success);
        success
    }

    /// Open a position at the same tick range as an existing position (tests tick reference counting).
    /// Multiple positions on identical tick ranges stress liquidity_gross accumulation.
    /// If the program sets instead of adding to liquidity_gross, closing one position
    /// would zero it out, corrupting swap logic for the remaining position.
    pub fn action_open_duplicate_range_position(
        &mut self,
        #[range(0..5)] source_position_idx: usize,
        #[range(0..3)] user_idx: usize,
    ) -> bool {
        if self.positions.len() >= 20 {
            return false;
        }
        if source_position_idx >= self.positions.len() {
            return false;
        }

        let tick_lower_index = self.positions[source_position_idx].tick_lower_index;
        let tick_upper_index = self.positions[source_position_idx].tick_upper_index;

        let user = &self.users[user_idx];
        let pool = &self.pool;

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
                whirlpool: pool.whirlpool,
            })
            .signers(&[&*user.keypair, &position_mint])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.positions.push(PositionData {
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
                debug_print!("[OPEN_DUP_RANGE] SUCCESS: user={} source_pos={} ticks=[{},{}]",
                    user_idx, source_position_idx, tick_lower_index, tick_upper_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[OPEN_DUP_RANGE] TX_FAILED: user={} source_pos={}",
                    user_idx, source_position_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[OPEN_DUP_RANGE] SEND_FAILED: user={}: {:?}", user_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::OPEN_DUPLICATE_RANGE, success);
        success
    }

    pub fn action_advance_time(&mut self, seconds: u64) -> bool {
        let seconds = (seconds % 3600) + 1; // 1 second to 1 hour
        self.ctx.advance_slots(seconds);
        action_stats::record(&action_stats::ADVANCE_TIME, true);
        true
    }

    /// Reset an empty position's tick range (reuse the position NFT with new bounds)
    pub fn action_reset_position_range(
        &mut self,
        #[range(0..5)] position_idx: usize,
        tick_lower_offset: i64,
        tick_upper_offset: i64,
    ) -> bool {
        if position_idx >= self.positions.len() {
            return false;
        }

        // Can only reset empty positions (no liquidity)
        if self.positions[position_idx].has_liquidity {
            return false;
        }

        let tick_lower_offset = tick_lower_offset as i32;
        let tick_upper_offset = tick_upper_offset as i32;
        let new_tick_lower = ((tick_lower_offset % 50) - 25) * (TICK_SPACING as i32);
        let new_tick_upper = new_tick_lower + ((tick_upper_offset.abs() % 20 + 1) * (TICK_SPACING as i32));

        let new_tick_lower = new_tick_lower.max(MIN_TICK_INDEX).min(MAX_TICK_INDEX - TICK_SPACING as i32);
        let new_tick_upper = new_tick_upper.max(new_tick_lower + TICK_SPACING as i32).min(MAX_TICK_INDEX);

        // Must be different from current range
        let pos = &self.positions[position_idx];
        if new_tick_lower == pos.tick_lower_index && new_tick_upper == pos.tick_upper_index {
            return false;
        }

        let user = &self.users[pos.owner_idx];

        // Pre-snapshot for immutability checks
        let pre_whirlpool = self.ctx.read_anchor_account::<whirlpool::state::Position>(&pos.position)
            .map(|p| (p.whirlpool, p.position_mint))
            .ok();

        let result = self.ctx.program(self.program_id)
            .call(instruction::ResetPositionRange {
                new_tick_lower_index: new_tick_lower,
                new_tick_upper_index: new_tick_upper,
            })
            .accounts(accounts::ResetPositionRange {
                funder: user.keypair.pubkey(),
                position_authority: user.keypair.pubkey(),
                whirlpool: self.pool.whirlpool,
                position: pos.position,
                position_token_account: pos.position_token_account,
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: verify on-chain ticks match requested values
                if let Ok(pos_state) = self.ctx.read_anchor_account::<whirlpool::state::Position>(&self.positions[position_idx].position) {
                    fuzz_assert_eq!(pos_state.tick_lower_index, new_tick_lower,
                        "reset_pos_range: on-chain tick_lower {} != expected {}", pos_state.tick_lower_index, new_tick_lower);
                    fuzz_assert_eq!(pos_state.tick_upper_index, new_tick_upper,
                        "reset_pos_range: on-chain tick_upper {} != expected {}", pos_state.tick_upper_index, new_tick_upper);
                    // Liquidity must remain zero after range reset
                    fuzz_assert_eq!(pos_state.liquidity, 0u128,
                        "reset_pos_range: liquidity non-zero {} after range reset", pos_state.liquidity);
                    // Fee checkpoints should be reset (no stale fees from old range)
                    fuzz_assert_eq!(pos_state.fee_owed_a, 0u64,
                        "reset_pos_range: fee_owed_a non-zero {} after range reset", pos_state.fee_owed_a);
                    fuzz_assert_eq!(pos_state.fee_owed_b, 0u64,
                        "reset_pos_range: fee_owed_b non-zero {} after range reset", pos_state.fee_owed_b);
                    // fee_growth_checkpoint must be zeroed to prevent stale fee accrual in new range
                    fuzz_assert_eq!(pos_state.fee_growth_checkpoint_a, 0u128,
                        "reset_pos_range: fee_growth_checkpoint_a non-zero {} after reset",
                        pos_state.fee_growth_checkpoint_a);
                    fuzz_assert_eq!(pos_state.fee_growth_checkpoint_b, 0u128,
                        "reset_pos_range: fee_growth_checkpoint_b non-zero {} after reset",
                        pos_state.fee_growth_checkpoint_b);
                    // reward growth checkpoints must also be zeroed
                    for i in 0..3 {
                        fuzz_assert_eq!(pos_state.reward_infos[i].growth_inside_checkpoint, 0u128,
                            "reset_pos_range: reward[{}] growth_inside_checkpoint non-zero {} after reset",
                            i, pos_state.reward_infos[i].growth_inside_checkpoint);
                        fuzz_assert_eq!(pos_state.reward_infos[i].amount_owed, 0u64,
                            "reset_pos_range: reward[{}] amount_owed non-zero {} after reset",
                            i, pos_state.reward_infos[i].amount_owed);
                    }
                    // Structural fields must be immutable across reset
                    if let Some((pre_wp, pre_mint)) = pre_whirlpool {
                        fuzz_assert_eq!(pos_state.whirlpool, pre_wp,
                            "reset_pos_range: whirlpool pointer changed after reset");
                        fuzz_assert_eq!(pos_state.position_mint, pre_mint,
                            "reset_pos_range: position_mint changed after reset");
                    }
                }
                self.positions[position_idx].tick_lower_index = new_tick_lower;
                self.positions[position_idx].tick_upper_index = new_tick_upper;
                debug_print!("[RESET_POS_RANGE] SUCCESS: pos={} ticks=[{},{}]",
                    position_idx, new_tick_lower, new_tick_upper);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[RESET_POS_RANGE] TX_FAILED: pos={}", position_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[RESET_POS_RANGE] SEND_FAILED: pos={}: {:?}", position_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::RESET_POSITION_RANGE, success);
        success
    }

    /// Initialize a new tick array at a fuzzer-chosen offset, extending reachable tick range
    pub fn action_initialize_tick_array(&mut self, array_offset: i32) -> bool {
        // Limit total tick arrays to avoid excessive memory usage
        if self.pool.tick_arrays.len() >= 30 {
            return false;
        }

        let array_span = TICK_ARRAY_SIZE * (TICK_SPACING as i32);
        // Pick an array index in range [-15, 15] that we don't already have
        let array_index = (array_offset % 31) - 15;
        let start_tick_index = array_index * array_span;

        // Check bounds
        if start_tick_index < MIN_TICK_INDEX - array_span || start_tick_index > MAX_TICK_INDEX {
            return false;
        }

        // Skip if already initialized
        if self.pool.tick_arrays.iter().any(|(s, _)| *s == start_tick_index) {
            return false;
        }

        let start_tick_str = start_tick_index.to_string();
        let (tick_array, _) = Pubkey::find_program_address(
            &[
                b"tick_array",
                self.pool.whirlpool.as_ref(),
                start_tick_str.as_bytes(),
            ],
            &self.program_id,
        );

        let result = self.ctx.program(self.program_id)
            .call(instruction::InitializeTickArray { start_tick_index })
            .accounts(accounts::InitializeTickArray {
                whirlpool: self.pool.whirlpool,
                funder: self.admin.pubkey(),
                tick_array,
            })
            .signers(&[&*self.admin])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Postcondition: verify tick array on-chain points to correct whirlpool
                // TickArray is zero-copy, can't use read_anchor_account. Parse raw bytes.
                // Layout: 8 (disc) + 4 (start_tick_index) + 88*113 (ticks) + 32 (whirlpool)
                if let Ok(account) = self.ctx.read_account(&tick_array) {
                    let data = &account.data;
                    const WHIRLPOOL_OFFSET: usize = 8 + 4 + 88 * 113; // 9956
                    if data.len() >= WHIRLPOOL_OFFSET + 32 {
                        let stored_whirlpool = Pubkey::from(<[u8; 32]>::try_from(&data[WHIRLPOOL_OFFSET..WHIRLPOOL_OFFSET + 32]).unwrap());
                        fuzz_assert_eq!(stored_whirlpool, self.pool.whirlpool,
                            "init_tick_array: whirlpool mismatch {} != {}", stored_whirlpool, self.pool.whirlpool);
                    }
                    if data.len() >= 12 {
                        let stored_start = i32::from_le_bytes(data[8..12].try_into().unwrap());
                        fuzz_assert_eq!(stored_start, start_tick_index,
                            "init_tick_array: start_tick {} != expected {}", stored_start, start_tick_index);
                    }
                }
                self.pool.tick_arrays.push((start_tick_index, tick_array));
                debug_print!("[INIT_TICK_ARRAY] SUCCESS: start_tick={}", start_tick_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[INIT_TICK_ARRAY] TX_FAILED: start_tick={}", start_tick_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[INIT_TICK_ARRAY] SEND_FAILED: start_tick={}: {:?}", start_tick_index, e);
                false
            }
        };
        action_stats::record(&action_stats::INIT_TICK_ARRAY, success);
        success
    }

    /// Initialize a new position bundle (max 3 bundles)
    pub fn action_initialize_position_bundle(&mut self, #[range(0..3)] user_idx: usize) -> bool {
        if self.bundles.len() >= 3 {
            return false;
        }

        let user = &self.users[user_idx];
        let position_bundle_mint = Keypair::new();

        let (position_bundle, _) = Pubkey::find_program_address(
            &[b"position_bundle", position_bundle_mint.pubkey().as_ref()],
            &self.program_id,
        );

        let position_bundle_token_account = associated_token::get_associated_token_address(
            &user.keypair.pubkey(),
            &position_bundle_mint.pubkey(),
        );

        let result = self.ctx.program(self.program_id)
            .call(instruction::InitializePositionBundle {})
            .accounts(accounts::InitializePositionBundle {
                position_bundle,
                position_bundle_mint: position_bundle_mint.pubkey(),
                position_bundle_token_account,
                position_bundle_owner: user.keypair.pubkey(),
                funder: user.keypair.pubkey(),
            })
            .signers(&[&*user.keypair, &position_bundle_mint])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                self.bundles.push(BundleData {
                    position_bundle,
                    position_bundle_mint: position_bundle_mint.pubkey(),
                    position_bundle_token_account,
                    owner_idx: user_idx,
                    open_bundle_indices: vec![],
                });
                debug_print!("[INIT_POS_BUNDLE] SUCCESS: user={} bundle={}", user_idx, position_bundle);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[INIT_POS_BUNDLE] TX_FAILED: user={}", user_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[INIT_POS_BUNDLE] SEND_FAILED: user={}: {:?}", user_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::INIT_POSITION_BUNDLE, success);
        success
    }

    /// Open a bundled position in an existing bundle
    pub fn action_open_bundled_position(
        &mut self,
        #[range(0..3)] bundle_idx: usize,
        bundle_index_raw: u16,
        tick_lower_offset: i64,
        tick_upper_offset: i64,
    ) -> bool {
        if bundle_idx >= self.bundles.len() {
            return false;
        }
        // Max 10 total positions
        if self.positions.len() >= 20 {
            return false;
        }

        let bundle_index = bundle_index_raw % 256;

        // Check slot not already occupied
        if self.bundles[bundle_idx].open_bundle_indices.contains(&bundle_index) {
            return false;
        }

        let bundle = &self.bundles[bundle_idx];
        let user = &self.users[bundle.owner_idx];

        // Calculate tick indices
        let tick_lower_offset = tick_lower_offset as i32;
        let tick_upper_offset = tick_upper_offset as i32;
        let tick_lower_raw = ((tick_lower_offset % 50) - 25) * (TICK_SPACING as i32);
        let tick_upper_raw = tick_lower_raw + ((tick_upper_offset.abs() % 20 + 1) * (TICK_SPACING as i32));
        let tick_lower_index = tick_lower_raw.max(MIN_TICK_INDEX).min(MAX_TICK_INDEX - TICK_SPACING as i32);
        let tick_upper_index = tick_upper_raw.max(tick_lower_index + TICK_SPACING as i32).min(MAX_TICK_INDEX);

        let bundle_index_str = bundle_index.to_string();
        let (bundled_position, _) = Pubkey::find_program_address(
            &[
                b"bundled_position",
                bundle.position_bundle_mint.as_ref(),
                bundle_index_str.as_bytes(),
            ],
            &self.program_id,
        );

        let result = self.ctx.program(self.program_id)
            .call(instruction::OpenBundledPosition {
                bundle_index,
                tick_lower_index,
                tick_upper_index,
            })
            .accounts(accounts::OpenBundledPosition {
                bundled_position,
                position_bundle: bundle.position_bundle,
                position_bundle_token_account: bundle.position_bundle_token_account,
                position_bundle_authority: user.keypair.pubkey(),
                whirlpool: self.pool.whirlpool,
                funder: user.keypair.pubkey(),
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                let bi = bundle_idx;
                self.bundles[bi].open_bundle_indices.push(bundle_index);
                self.positions.push(PositionData {
                    position: bundled_position,
                    position_mint: self.bundles[bi].position_bundle_mint,
                    position_token_account: self.bundles[bi].position_bundle_token_account,
                    tick_lower_index,
                    tick_upper_index,
                    owner_idx: self.bundles[bi].owner_idx,
                    has_liquidity: false,
                    bundle_info: Some(BundlePositionInfo {
                        bundle_idx: bi,
                        bundle_index,
                    }),
                    prev_fee_owed_a: 0,
                    prev_fee_owed_b: 0,
                    fees_just_collected: false,
                });
                debug_print!("[OPEN_BUNDLED_POS] SUCCESS: bundle={} slot={} ticks=[{},{}]",
                    bundle_idx, bundle_index, tick_lower_index, tick_upper_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[OPEN_BUNDLED_POS] TX_FAILED: bundle={} slot={}", bundle_idx, bundle_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[OPEN_BUNDLED_POS] SEND_FAILED: bundle={} slot={}: {:?}", bundle_idx, bundle_index, e);
                false
            }
        };
        action_stats::record(&action_stats::OPEN_BUNDLED_POSITION, success);
        success
    }

    /// Close a bundled position (must have no liquidity)
    pub fn action_close_bundled_position(
        &mut self,
        #[range(0..3)] bundle_idx: usize,
        slot_raw: u16,
    ) -> bool {
        if bundle_idx >= self.bundles.len() {
            return false;
        }
        if self.bundles[bundle_idx].open_bundle_indices.is_empty() {
            return false;
        }

        // Pick from open slots
        let slot_idx = (slot_raw as usize) % self.bundles[bundle_idx].open_bundle_indices.len();
        let bundle_index = self.bundles[bundle_idx].open_bundle_indices[slot_idx];

        // Find position in self.positions
        let pos_idx = self.positions.iter().position(|p| {
            p.bundle_info.as_ref().map_or(false, |bi| bi.bundle_idx == bundle_idx && bi.bundle_index == bundle_index)
        });
        let pos_idx = match pos_idx {
            Some(i) => i,
            None => return false,
        };

        // Check position has no liquidity
        if self.positions[pos_idx].has_liquidity {
            return false;
        }

        let bundle = &self.bundles[bundle_idx];
        let user = &self.users[bundle.owner_idx];

        let bundle_index_str = bundle_index.to_string();
        let (bundled_position, _) = Pubkey::find_program_address(
            &[
                b"bundled_position",
                bundle.position_bundle_mint.as_ref(),
                bundle_index_str.as_bytes(),
            ],
            &self.program_id,
        );

        let result = self.ctx.program(self.program_id)
            .call(instruction::CloseBundledPosition {
                bundle_index,
            })
            .accounts(accounts::CloseBundledPosition {
                bundled_position,
                position_bundle: bundle.position_bundle,
                position_bundle_token_account: bundle.position_bundle_token_account,
                position_bundle_authority: user.keypair.pubkey(),
                receiver: user.keypair.pubkey(),
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                // Remove from open_bundle_indices
                self.bundles[bundle_idx].open_bundle_indices.retain(|&i| i != bundle_index);
                // Remove from positions
                self.positions.remove(pos_idx);
                // Fix bundle_info.bundle_idx references for remaining positions that reference
                // the same bundle (indices may shift if a position was removed before them)
                debug_print!("[CLOSE_BUNDLED_POS] SUCCESS: bundle={} slot={}", bundle_idx, bundle_index);
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[CLOSE_BUNDLED_POS] TX_FAILED: bundle={} slot={}", bundle_idx, bundle_index);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[CLOSE_BUNDLED_POS] SEND_FAILED: bundle={} slot={}: {:?}", bundle_idx, bundle_index, e);
                false
            }
        };
        action_stats::record(&action_stats::CLOSE_BUNDLED_POSITION, success);
        success
    }

    /// Delete a position bundle (all slots must be closed)
    pub fn action_delete_position_bundle(&mut self, #[range(0..3)] bundle_idx: usize) -> bool {
        if bundle_idx >= self.bundles.len() {
            return false;
        }
        // All slots must be closed
        if !self.bundles[bundle_idx].open_bundle_indices.is_empty() {
            return false;
        }

        let bundle = &self.bundles[bundle_idx];
        let user = &self.users[bundle.owner_idx];

        let result = self.ctx.program(self.program_id)
            .call(instruction::DeletePositionBundle {})
            .accounts(accounts::DeletePositionBundle {
                position_bundle: bundle.position_bundle,
                position_bundle_mint: bundle.position_bundle_mint,
                position_bundle_token_account: bundle.position_bundle_token_account,
                position_bundle_owner: user.keypair.pubkey(),
                receiver: user.keypair.pubkey(),
            })
            .signers(&[&*user.keypair])
            .send();

        let success = match &result {
            Ok(TxOutcome::Success { .. }) => {
                debug_print!("[DEL_POS_BUNDLE] SUCCESS: bundle={}", bundle_idx);
                self.bundles.remove(bundle_idx);
                // Fix bundle_info.bundle_idx references in remaining positions
                for pos in &mut self.positions {
                    if let Some(ref mut bi) = pos.bundle_info {
                        if bi.bundle_idx > bundle_idx {
                            bi.bundle_idx -= 1;
                        }
                    }
                }
                true
            }
            Ok(TxOutcome::ProgramError { logs, .. }) => {
                debug_print!("[DEL_POS_BUNDLE] TX_FAILED: bundle={}", bundle_idx);
                for log in logs { debug_print!("  {}", log); }
                false
            }
            Err(e) => {
                debug_print!("[DEL_POS_BUNDLE] SEND_FAILED: bundle={}: {:?}", bundle_idx, e);
                false
            }
        };
        action_stats::record(&action_stats::DELETE_POSITION_BUNDLE, success);
        success
    }
