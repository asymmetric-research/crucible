use core::fmt::Debug;
use libafl_bolts::rands::Rand;

/// Trait for structured fuzz actions.
///
/// Each action variant knows how to generate random valid instances,
/// mutate its parameters within declared ranges, and serialize/deserialize
/// for corpus storage.
///
/// Implemented by the `#[fuzz_fixture]` macro for auto-discovered action enums.
pub trait FuzzAction: Clone + Debug + Send + 'static {
    /// Number of variants in the action enum.
    fn variant_count() -> usize;

    /// Generate a random instance of a specific variant.
    fn random_variant<R: Rand>(variant_idx: usize, rng: &mut R) -> Self;

    /// Generate a random instance of any variant.
    fn random<R: Rand>(rng: &mut R) -> Self {
        let idx = crate::rand_below(rng, Self::variant_count());
        Self::random_variant(idx, rng)
    }

    /// Mutate the parameters of this action in-place.
    fn mutate<R: Rand>(&mut self, rng: &mut R);

    /// Get the action name for debugging/display.
    fn action_name(&self) -> &'static str;

    /// Get the variant index (0-based) for serialization.
    fn variant_index(&self) -> usize;

    /// Serialize all fields to bytes (each field as 8 bytes, little-endian u64).
    fn serialize_fields(&self, buf: &mut Vec<u8>);

    /// Deserialize fields from bytes at the given cursor position.
    /// Advances cursor past the consumed bytes. Returns None if insufficient data.
    fn deserialize_fields(variant_idx: usize, bytes: &[u8], cursor: &mut usize) -> Option<Self>;

    /// Return the number of field bytes for a given variant index.
    /// Each field is encoded as 8 bytes (u64 LE), so this is `num_fields * 8`.
    fn field_byte_count(variant_idx: usize) -> usize;

    /// Reconstruct an action from its name and JSON params (from .meta.json).
    /// Used as fallback when binary crash file can't be deserialized (e.g., after
    /// action enum changes). Returns None if name is unknown or params are invalid.
    fn from_name_and_params(name: &str, params: &serde_json::Value) -> Option<Self>;
}
