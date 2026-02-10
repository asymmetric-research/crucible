use anchor_lang_idl::types::Idl;
use heck::ToUpperCamelCase;
use quote::{format_ident, quote};

use super::idl_type_to_tokens;

/// Generate instruction argument structs
pub fn generate(idl: &Idl) -> proc_macro2::TokenStream {
    let instructions = idl.instructions.iter().map(|ix| {
        let name = format_ident!("{}", ix.name.to_upper_camel_case());

        // Generate fields
        let fields = ix.args.iter().map(|arg| {
            let field_name = format_ident!("{}", arg.name);
            let field_type = idl_type_to_tokens(&arg.ty);
            quote! { pub #field_name: #field_type }
        });

        // Generate discriminator
        let discriminator = &ix.discriminator;

        // Struct with derives
        if ix.args.is_empty() {
            quote! {
                #[derive(Clone, AnchorSerialize, AnchorDeserialize)]
                pub struct #name;

                impl anchor_lang::Discriminator for #name {
                    const DISCRIMINATOR: &'static [u8] = &[#(#discriminator),*];
                }

                impl anchor_lang::InstructionData for #name {}
            }
        } else {
            quote! {
                #[derive(Clone, AnchorSerialize, AnchorDeserialize)]
                pub struct #name {
                    #(#fields),*
                }

                impl anchor_lang::Discriminator for #name {
                    const DISCRIMINATOR: &'static [u8] = &[#(#discriminator),*];
                }

                impl anchor_lang::InstructionData for #name {}
            }
        }
    });

    quote! {
        /// Instruction argument structs
        pub mod instruction {
            use super::*;
            use super::types::*;

            #(#instructions)*
        }
    }
}
