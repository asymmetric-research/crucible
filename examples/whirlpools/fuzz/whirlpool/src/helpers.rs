use crate::types::*;
use crate::constants::*;
use crate::whirlpool;
use solana_pubkey::Pubkey;

impl WhirlpoolFixture {
    /// Read current pool sqrt_price from on-chain state
    pub(crate) fn read_pool_sqrt_price(&self) -> Option<u128> {
        self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
            .ok()
            .map(|s| s.sqrt_price)
    }

    /// Read current pool tick_current_index from on-chain state
    pub(crate) fn read_pool_tick(&self) -> i32 {
        self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&self.pool.whirlpool)
            .ok()
            .map(|s| s.tick_current_index)
            .unwrap_or(0)
    }

    pub(crate) fn get_tick_array_for_tick(&self, tick_index: i32) -> Pubkey {
        let target_start = self.get_start_tick_index(tick_index);

        // Prefer dynamic tick arrays when available (exercises DynamicTickArrayLoader)
        for (pubkey, start) in &self.dynamic_tick_arrays {
            if *start == target_start {
                return *pubkey;
            }
        }

        // Find the fixed tick array that covers this tick
        for (start, pubkey) in &self.pool.tick_arrays {
            if *start == target_start {
                return *pubkey;
            }
        }

        // Fallback: find the closest tick array (fixed or dynamic)
        let mut closest = self.pool.tick_arrays[0];
        let mut closest_dist = i32::MAX;
        for (start, pubkey) in &self.pool.tick_arrays {
            let dist = (start - target_start).abs();
            if dist < closest_dist {
                closest_dist = dist;
                closest = (*start, *pubkey);
            }
        }

        closest.1
    }

    /// Get tick array for a specific pool (for pool two positions)
    pub(crate) fn get_tick_array_for_tick_pool(&self, pool: &PoolData, tick_index: i32) -> Pubkey {
        let target_start = self.get_start_tick_index(tick_index);

        for (start, pubkey) in &pool.tick_arrays {
            if *start == target_start {
                return *pubkey;
            }
        }

        // Fallback: find the closest tick array in this pool
        pool.tick_arrays.iter()
            .min_by_key(|(start, _)| (start - target_start).abs())
            .map(|(_, pk)| *pk)
            .unwrap_or(pool.tick_arrays[0].1)
    }

    pub(crate) fn get_start_tick_index(&self, tick_index: i32) -> i32 {
        let ticks_in_array = TICK_ARRAY_SIZE * (TICK_SPACING as i32);
        // Floor division for negative numbers
        let array_index = if tick_index >= 0 {
            tick_index / ticks_in_array
        } else {
            (tick_index - ticks_in_array + 1) / ticks_in_array
        };
        array_index * ticks_in_array
    }

    /// Get the 3 tick arrays needed for a swap, matching the program's
    /// `get_start_tick_indexes` logic exactly.
    pub(crate) fn get_tick_arrays_for_swap(&self, a_to_b: bool) -> (Pubkey, Pubkey, Pubkey) {
        let current_tick = self.read_pool_tick();
        self.compute_swap_tick_arrays(&self.pool, current_tick, a_to_b)
    }

    /// Compute the 3 tick array pubkeys needed for a swap on a given pool.
    /// Mirrors the program's SparseSwapTickSequenceBuilder.get_start_tick_indexes.
    pub(crate) fn compute_swap_tick_arrays(&self, pool: &PoolData, current_tick: i32, a_to_b: bool) -> (Pubkey, Pubkey, Pubkey) {
        let ticks_in_array = TICK_ARRAY_SIZE * (TICK_SPACING as i32);

        // floor_division matching the program
        let base = if current_tick >= 0 {
            (current_tick / ticks_in_array) * ticks_in_array
        } else {
            ((current_tick - ticks_in_array + 1) / ticks_in_array) * ticks_in_array
        };

        let offsets = if a_to_b {
            [0, -1, -2]
        } else {
            // Check if tick + tick_spacing crosses into next array
            let shifted = current_tick + (TICK_SPACING as i32) >= base + ticks_in_array;
            if shifted { [1, 2, 3] } else { [0, 1, 2] }
        };

        let needed: Vec<i32> = offsets.iter()
            .map(|&o| base + o * ticks_in_array)
            .collect();

        // Find matching tick arrays, preferring dynamic tick arrays
        let dyn_arrays = &self.dynamic_tick_arrays;
        let find_or_fallback = |target: i32| -> Pubkey {
            // Prefer dynamic tick arrays (exercises DynamicTickArrayLoader code paths)
            if let Some((pk, _)) = dyn_arrays.iter().find(|(_, start)| *start == target) {
                return *pk;
            }
            pool.tick_arrays.iter()
                .find(|(start, _)| *start == target)
                .map(|(_, pk)| *pk)
                .unwrap_or_else(|| {
                    pool.tick_arrays.iter()
                        .min_by_key(|(start, _)| (start - target).abs())
                        .map(|(_, pk)| *pk)
                        .unwrap_or(pool.tick_arrays[0].1)
                })
        };

        (find_or_fallback(needed[0]), find_or_fallback(needed[1]), find_or_fallback(needed[2]))
    }

    /// Get tick arrays for swap on a specific pool (for pool two in TwoHopSwap)
    pub(crate) fn get_tick_arrays_for_swap_pool(&self, pool: &PoolData, a_to_b: bool) -> (Pubkey, Pubkey, Pubkey) {
        let current_tick = self.ctx.read_anchor_account::<whirlpool::state::Whirlpool>(&pool.whirlpool)
            .ok()
            .map(|s| s.tick_current_index)
            .unwrap_or(0);
        self.compute_swap_tick_arrays(pool, current_tick, a_to_b)
    }
}
