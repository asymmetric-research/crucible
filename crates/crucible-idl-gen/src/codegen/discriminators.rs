use anchor_lang_idl::types::Idl;
use quote::quote;

/// Generate a function to register all instruction discriminators for coverage tracking.
///
/// This generates a function that can be called at harness initialization to
/// automatically register all instruction discriminators from the IDL.
/// Supports both 8-byte (Anchor/borsh) and 4-byte (native/bincode) discriminators.
pub fn generate(idl: &Idl) -> proc_macro2::TokenStream {
    // Generate discriminator registration entries for each instruction
    let entries = idl.instructions.iter().map(|ix| {
        let name = &ix.name;
        let disc = &ix.discriminator;

        quote! {
            (#name, vec![#(#disc),*])
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

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang_idl::types::{IdlInstruction, IdlMetadata};

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
    fn test_4_byte_discriminator_registration() {
        let idl = make_idl(vec![
            IdlInstruction {
                name: "initialize".to_string(),
                docs: vec![],
                discriminator: vec![0, 0, 0, 0],
                accounts: vec![],
                args: vec![],
                returns: None,
            },
            IdlInstruction {
                name: "transfer".to_string(),
                docs: vec![],
                discriminator: vec![2, 0, 0, 0],
                accounts: vec![],
                args: vec![],
                returns: None,
            },
        ]);
        let output = generate(&idl).to_string();
        assert!(
            output.contains("\"initialize\""),
            "should have instruction name"
        );
        assert!(
            output.contains("\"transfer\""),
            "should have instruction name"
        );
        assert!(
            output.contains("register_instruction_discriminators"),
            "should register"
        );
    }

    #[test]
    fn test_8_byte_discriminator_registration() {
        let idl = make_idl(vec![IdlInstruction {
            name: "doSomething".to_string(),
            docs: vec![],
            discriminator: vec![231, 205, 66, 242, 220, 87, 145, 38],
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl).to_string();
        assert!(output.contains("\"doSomething\""));
        assert!(output.contains("231u8"));
        assert!(output.contains("38u8"));
    }

    #[test]
    fn test_empty_instructions() {
        let idl = make_idl(vec![]);
        let output = generate(&idl).to_string();
        assert!(
            output.contains("register_discriminators"),
            "should still generate function"
        );
    }

    #[test]
    fn test_all_8_bytes_present_in_order() {
        // Verify that all discriminator bytes appear in the output and in the
        // correct order (not just spot-checking first and last).
        let disc = vec![0xAB, 0xCD, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let idl = make_idl(vec![IdlInstruction {
            name: "complexOp".to_string(),
            docs: vec![],
            discriminator: disc.clone(),
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl).to_string();

        // Every byte must appear as `Xu8` in the output
        for byte in &disc {
            let byte_str = format!("{}u8", byte);
            assert!(
                output.contains(&byte_str),
                "discriminator byte {} missing from output: {}",
                byte_str,
                output
            );
        }

        // Verify they appear in order by finding positions
        let mut last_pos = 0;
        for byte in &disc {
            let byte_str = format!("{}u8", byte);
            let pos = output[last_pos..].find(&byte_str).unwrap_or_else(|| {
                panic!("byte {} not found after position {}", byte_str, last_pos)
            });
            last_pos += pos + byte_str.len();
        }
    }

    #[test]
    fn test_4_byte_discriminator_all_bytes_present() {
        let disc = vec![0x01, 0x02, 0x03, 0x04];
        let idl = make_idl(vec![IdlInstruction {
            name: "shortDisc".to_string(),
            docs: vec![],
            discriminator: disc.clone(),
            accounts: vec![],
            args: vec![],
            returns: None,
        }]);
        let output = generate(&idl).to_string();

        for byte in &disc {
            let byte_str = format!("{}u8", byte);
            assert!(
                output.contains(&byte_str),
                "4-byte discriminator byte {} missing from output",
                byte_str
            );
        }
    }

    #[test]
    fn test_multiple_instructions_all_registered() {
        let idl = make_idl(vec![
            IdlInstruction {
                name: "initialize".to_string(),
                docs: vec![],
                discriminator: vec![0, 0, 0, 0],
                accounts: vec![],
                args: vec![],
                returns: None,
            },
            IdlInstruction {
                name: "deposit".to_string(),
                docs: vec![],
                discriminator: vec![1, 0, 0, 0],
                accounts: vec![],
                args: vec![],
                returns: None,
            },
            IdlInstruction {
                name: "withdraw".to_string(),
                docs: vec![],
                discriminator: vec![2, 0, 0, 0],
                accounts: vec![],
                args: vec![],
                returns: None,
            },
        ]);
        let output = generate(&idl).to_string();

        // All instruction names should appear as string literals in the registration array
        assert!(
            output.contains("\"initialize\""),
            "should have initialize entry"
        );
        assert!(output.contains("\"deposit\""), "should have deposit entry");
        assert!(
            output.contains("\"withdraw\""),
            "should have withdraw entry"
        );

        // Count tuples in the registration array — each instruction produces a (name, vec![...]) entry
        // The pattern `("name"` appears once per instruction
        let entry_count = output.matches("(\"").count();
        assert_eq!(
            entry_count, 3,
            "should have 3 registration entries, got {}",
            entry_count
        );
    }
}
