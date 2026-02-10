use anchor_lang_idl::types::Idl;
use quote::quote;

/// Generate a function to register all instruction discriminators for coverage tracking.
///
/// This generates a function that can be called at harness initialization to
/// automatically register all instruction discriminators from the IDL.
pub fn generate(idl: &Idl) -> proc_macro2::TokenStream {
    // Generate discriminator registration entries for each instruction
    let entries = idl.instructions.iter().map(|ix| {
        let name = &ix.name;
        let disc = &ix.discriminator;

        // The discriminator in IDL is always 8 bytes
        quote! {
            (#name, [#(#disc),*])
        }
    });

    quote! {
        /// Register all instruction discriminators for per-instruction coverage tracking.
        /// Call this once at harness initialization.
        pub fn register_discriminators() {
            crucible_test_context::register_instruction_discriminators(&[
                #(#entries),*
            ]);
        }
    }
}
