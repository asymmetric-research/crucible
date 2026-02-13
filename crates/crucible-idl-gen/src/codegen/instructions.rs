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

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang_idl::types::{IdlField, IdlInstruction, IdlMetadata, IdlType};

    fn make_idl(instructions: Vec<IdlInstruction>) -> Idl {
        Idl {
            address: "11111111111111111111111111111111".to_string(),
            metadata: IdlMetadata {
                name: "test".to_string(),
                version: "0.1.0".to_string(),
                spec: "0.1.0".to_string(),
                description: None,
                repository: None,
                dependencies: vec![],
                contact: None,
                deployments: None,
            },
            docs: vec![],
            instructions,
            accounts: vec![],
            events: vec![],
            errors: vec![],
            types: vec![],
            constants: vec![],
        }
    }

    #[test]
    fn test_4_byte_discriminator() {
        let idl = make_idl(vec![IdlInstruction {
            name: "initialize".to_string(),
            docs: vec![],
            discriminator: vec![0, 0, 0, 0],
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl).to_string();
        assert!(output.contains("DISCRIMINATOR"), "should have DISCRIMINATOR const");
        assert!(output.contains("0u8 , 0u8 , 0u8 , 0u8"), "should emit 4 bytes");
    }

    #[test]
    fn test_8_byte_discriminator() {
        let idl = make_idl(vec![IdlInstruction {
            name: "initialize".to_string(),
            docs: vec![],
            discriminator: vec![231, 205, 66, 242, 220, 87, 145, 38],
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl).to_string();
        assert!(output.contains("231u8"), "should emit first byte");
        assert!(output.contains("38u8"), "should emit last byte");
    }

    #[test]
    fn test_empty_args_unit_struct() {
        let idl = make_idl(vec![IdlInstruction {
            name: "doNothing".to_string(),
            docs: vec![],
            discriminator: vec![1, 0, 0, 0],
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl).to_string();
        // Should generate a unit struct (no braces with fields)
        assert!(output.contains("pub struct DoNothing ;"), "empty args should produce unit struct");
    }

    #[test]
    fn test_instruction_with_args() {
        let idl = make_idl(vec![IdlInstruction {
            name: "transfer".to_string(),
            docs: vec![],
            discriminator: vec![2, 0, 0, 0],
            accounts: vec![],
            args: vec![
                IdlField {
                    name: "amount".to_string(),
                    docs: vec![],
                    ty: IdlType::U64,
                },
                IdlField {
                    name: "memo".to_string(),
                    docs: vec![],
                    ty: IdlType::String,
                },
            ],
            returns: None,
        }]);
        let output = generate(&idl).to_string();
        assert!(output.contains("pub amount : u64"), "should have amount field");
        assert!(output.contains("pub memo : String"), "should have memo field");
    }

    #[test]
    fn test_instruction_name_upper_camel_case() {
        let idl = make_idl(vec![IdlInstruction {
            name: "delegateStake".to_string(),
            docs: vec![],
            discriminator: vec![2, 0, 0, 0],
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl).to_string();
        assert!(output.contains("DelegateStake"), "should convert to UpperCamelCase");
    }

    #[test]
    fn test_instruction_data_trait() {
        let idl = make_idl(vec![IdlInstruction {
            name: "init".to_string(),
            docs: vec![],
            discriminator: vec![0, 0, 0, 0],
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl).to_string();
        assert!(output.contains("InstructionData"), "should impl InstructionData");
        assert!(output.contains("Discriminator"), "should impl Discriminator");
    }
}
