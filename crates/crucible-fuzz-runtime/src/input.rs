use core::fmt::Debug;

use crate::action::FuzzAction;

/// Structured fuzz input: a sequence of typed actions.
///
/// This is an internal type used for decode/encode between `BytesInput`
/// (which LibAFL uses for corpus storage) and structured action sequences.
/// The custom mutators decode BytesInput → FuzzInput, mutate, then re-encode.
///
/// Serialization format (custom binary):
/// - 4 bytes: action count (u32 LE)
/// - For each action:
///   - 2 bytes: variant index (u16 LE)
///   - N*8 bytes: fields (each field as u64 LE, per FuzzAction::serialize_fields)
#[derive(Clone, Debug)]
pub struct FuzzInput<A: FuzzAction> {
    pub actions: Vec<A>,
}

impl<A: FuzzAction> FuzzInput<A> {
    pub fn new(actions: Vec<A>) -> Self {
        Self { actions }
    }

    /// Serialize to bytes using custom binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.actions.len() * 18);
        self.to_bytes_into(&mut buf);
        buf
    }

    /// Serialize into a reusable buffer (clears buf first, avoids allocation).
    pub fn to_bytes_into(&self, buf: &mut Vec<u8>) {
        buf.clear();
        buf.reserve(4 + self.actions.len() * 18);
        buf.extend_from_slice(&(self.actions.len() as u32).to_le_bytes());
        for action in &self.actions {
            buf.extend_from_slice(&(action.variant_index() as u16).to_le_bytes());
            action.serialize_fields(buf);
        }
    }

    /// Deserialize from bytes. Returns a default single-action input if parsing fails.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::try_from_bytes(bytes).unwrap_or_else(|| {
            // Fallback: empty input (mutators will add actions)
            FuzzInput::new(Vec::new())
        })
    }

    /// Try to deserialize from bytes. Returns None on failure.
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        let count = u32::from_le_bytes(bytes[0..4].try_into().ok()?) as usize;
        // Cap count to prevent OOM from malformed inputs
        let count = count.min(256);
        let mut cursor = 4;
        let mut actions = Vec::with_capacity(count);

        for _ in 0..count {
            if cursor + 2 > bytes.len() {
                break;
            }
            let variant = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().ok()?) as usize;
            cursor += 2;

            if variant >= A::variant_count() {
                break;
            }

            if let Some(action) = A::deserialize_fields(variant, bytes, &mut cursor) {
                actions.push(action);
            } else {
                break;
            }
        }

        if actions.is_empty() {
            return None;
        }

        Some(FuzzInput::new(actions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::TestAction;
    use libafl_bolts::rands::{Rand, RomuDuoJrRand};

    fn make_rng(seed: u64) -> RomuDuoJrRand {
        RomuDuoJrRand::with_seed(seed)
    }

    #[test]
    fn test_roundtrip_empty() {
        let input = FuzzInput::<TestAction>::new(Vec::new());
        let bytes = input.to_bytes();
        assert_eq!(bytes.len(), 4); // just the count header
        let decoded = FuzzInput::<TestAction>::try_from_bytes(&bytes);
        // Empty input returns None from try_from_bytes
        assert!(decoded.is_none());
        // from_bytes falls back to empty
        let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
        assert!(decoded.actions.is_empty());
    }

    #[test]
    fn test_roundtrip_each_variant() {
        let actions = vec![
            TestAction::NoFields,
            TestAction::OneField { amount: 42 },
            TestAction::TwoFields {
                user_idx: 2,
                flag: true,
            },
            TestAction::FourFields {
                a: 999,
                b: 7,
                c: u64::MAX,
                d: false,
            },
            TestAction::SixFields {
                a: 1,
                b: u64::MAX / 2,
                c: 4,
                d: 0,
                e: 500_000,
                f: true,
            },
        ];

        let input = FuzzInput::new(actions.clone());
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
        assert_eq!(decoded.actions.len(), actions.len());
        for (orig, dec) in actions.iter().zip(decoded.actions.iter()) {
            assert_eq!(orig, dec);
        }
    }

    #[test]
    fn test_roundtrip_max_actions() {
        let mut rng = make_rng(12345);
        let actions: Vec<TestAction> = (0..8)
            .map(|i| TestAction::random_variant(i % 5, &mut rng))
            .collect();

        let input = FuzzInput::new(actions.clone());
        let bytes = input.to_bytes();
        let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
        assert_eq!(decoded.actions.len(), 8);
        for (orig, dec) in actions.iter().zip(decoded.actions.iter()) {
            assert_eq!(orig, dec);
        }
    }

    #[test]
    fn test_roundtrip_random_1000() {
        let mut rng = make_rng(99999);
        for _ in 0..1000 {
            let count = 1 + (rng.next() as usize % 8);
            let actions: Vec<TestAction> = (0..count).map(|_| TestAction::random(&mut rng)).collect();
            let input = FuzzInput::new(actions);
            let bytes = input.to_bytes();
            let decoded = FuzzInput::<TestAction>::from_bytes(&bytes);
            let re_encoded = FuzzInput::new(decoded.actions.clone()).to_bytes();
            assert_eq!(
                bytes, re_encoded,
                "encode → decode → re-encode mismatch"
            );
        }
    }

    #[test]
    fn test_from_bytes_malformed() {
        // Empty bytes
        let decoded = FuzzInput::<TestAction>::from_bytes(&[]);
        assert!(decoded.actions.is_empty());

        // Too short (only 2 bytes, need 4 for header)
        let decoded = FuzzInput::<TestAction>::from_bytes(&[1, 0]);
        assert!(decoded.actions.is_empty());

        // Header says 1 action but no variant data
        let decoded = FuzzInput::<TestAction>::from_bytes(&[1, 0, 0, 0]);
        assert!(decoded.actions.is_empty());

        // Header says 1 action, variant index present but truncated fields
        // Variant 1 (OneField) needs 8 bytes of fields
        let decoded = FuzzInput::<TestAction>::from_bytes(&[1, 0, 0, 0, 1, 0, 42, 0]);
        assert!(decoded.actions.is_empty());

        // Invalid variant index (255 >= variant_count=5)
        let decoded = FuzzInput::<TestAction>::from_bytes(&[1, 0, 0, 0, 255, 0]);
        assert!(decoded.actions.is_empty());

        // Garbage bytes — should parse what it can or return empty
        let garbage: Vec<u8> = (0..100).map(|i| (i * 37) as u8).collect();
        let decoded = FuzzInput::<TestAction>::from_bytes(&garbage);
        // Should not panic, may have 0+ actions depending on garbage
        let _re_encoded = FuzzInput::new(decoded.actions).to_bytes();

        // Header says 3 actions but only enough data for 1 (NoFields variant=0)
        let mut data = vec![3, 0, 0, 0]; // count=3
        data.extend_from_slice(&[0, 0]); // variant 0 (NoFields, 0 field bytes)
        // No more data — should parse 1 action then stop
        let decoded = FuzzInput::<TestAction>::from_bytes(&data);
        assert_eq!(decoded.actions.len(), 1);
        assert_eq!(decoded.actions[0], TestAction::NoFields);
    }
}
