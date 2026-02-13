//! Convert Codama IDL (`RootNode`) → Anchor IDL (`Idl`).
//!
//! The `codama-nodes` crate provides serde-deserializable Rust types for the
//! entire Codama IDL format. We parse with `serde_json::from_value::<RootNode>()`
//! then convert to `anchor_lang_idl::types::Idl` so the existing codegen pipeline
//! handles everything.

use std::collections::HashSet;

use anchor_lang_idl::types::{
    Idl, IdlArrayLen, IdlDefinedFields, IdlEnumVariant, IdlField, IdlInstruction,
    IdlInstructionAccount, IdlInstructionAccountItem, IdlMetadata, IdlType, IdlTypeDef,
    IdlTypeDefTy,
};
use codama_nodes::{
    DefaultValueStrategy, DefinedTypeNode, EnumTypeNode, EnumVariantTypeNode,
    InstructionAccountNode, InstructionArgumentNode, InstructionInputValueNode, InstructionNode,
    IsAccountSigner, NestedTypeNodeTrait, Number, NumberFormat, NumberValueNode, OptionTypeNode,
    PublicKeyValueNode, RootNode, StructFieldTypeNode, StructTypeNode, TypeNode,
};
use heck::ToUpperCamelCase;

/// Convert a Codama `RootNode` into an Anchor-format `Idl`.
pub fn convert(root: &RootNode) -> anyhow::Result<Idl> {
    let program = &root.program;

    let address = program.public_key.clone();
    let name = program.name.to_string();
    let version = if program.version.is_empty() {
        "0.0.0".to_string()
    } else {
        program.version.clone()
    };

    let instructions = program
        .instructions
        .iter()
        .map(convert_instruction)
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut types = program
        .defined_types
        .iter()
        .filter_map(|dt| convert_defined_type(dt).ok())
        .collect::<Vec<_>>();

    // Post-process: find unresolved type references in instruction args and add
    // type aliases. Codama IDLs sometimes reference types by a different name
    // than they're defined under (e.g. `lockupArgs` → `lockupParams`).
    let defined_names: HashSet<String> = types.iter().map(|t| t.name.clone()).collect();
    let mut referenced_names: HashSet<String> = HashSet::new();
    for ix in &instructions {
        for arg in &ix.args {
            collect_defined_refs(&arg.ty, &mut referenced_names);
        }
    }
    for name in &referenced_names {
        if !defined_names.contains(name) {
            // Try to find a matching type by stripping common suffixes
            let stripped = name
                .trim_end_matches("Args")
                .trim_end_matches("Params");
            if let Some(target) = types.iter().find(|t| {
                let t_stripped = t.name
                    .trim_end_matches("Args")
                    .trim_end_matches("Params");
                t_stripped == stripped
            }) {
                let target_name = target.name.clone();
                types.push(IdlTypeDef {
                    name: name.clone(),
                    docs: vec![],
                    serialization: anchor_lang_idl::types::IdlSerialization::default(),
                    repr: None,
                    generics: vec![],
                    ty: IdlTypeDefTy::Type {
                        alias: IdlType::Defined {
                            name: target_name,
                            generics: vec![],
                        },
                    },
                });
            }
        }
    }

    Ok(Idl {
        address,
        metadata: IdlMetadata {
            name,
            version,
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
        types,
        constants: vec![],
    })
}

// ---------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------

fn convert_instruction(ix: &InstructionNode) -> anyhow::Result<IdlInstruction> {
    // Extract the discriminator value from the "omitted" argument.
    // Codama IDLs represent the discriminator as an argument with
    // `default_value_strategy: Some(Omitted)` and a NumberValueNode default.
    let mut discriminator_value: Option<u64> = None;
    let mut discriminator_format: Option<NumberFormat> = None;

    for arg in &ix.arguments {
        if arg.default_value_strategy == Some(DefaultValueStrategy::Omitted) {
            if let Some(InstructionInputValueNode::Number(NumberValueNode { number })) =
                &arg.default_value
            {
                discriminator_value = Some(number_to_u64(number));
            }
            // Capture the format of the discriminator type for byte-width
            if let TypeNode::Number(nt) = &arg.r#type {
                discriminator_format = Some(nt.format);
            }
            break;
        }
    }

    // Build discriminator bytes. Native programs typically use a single u8/u32
    // value. Pad to 8 bytes (Anchor convention); `truncate_bincode_discriminators`
    // in lib.rs will detect and shrink back to 4 if all are padded.
    let discriminator = match (discriminator_value, discriminator_format) {
        (Some(val), Some(fmt)) => {
            let byte_width = number_format_byte_width(&fmt);
            let le_bytes = val.to_le_bytes();
            let mut disc = le_bytes[..byte_width].to_vec();
            // Pad to 8 bytes for Anchor compatibility
            disc.resize(8, 0);
            disc
        }
        (Some(val), None) => {
            // Default to 4-byte (u32 LE) padded to 8
            let mut disc = (val as u32).to_le_bytes().to_vec();
            disc.resize(8, 0);
            disc
        }
        _ => vec![],
    };

    // Convert non-discriminator arguments to IDL fields
    let args = ix
        .arguments
        .iter()
        .filter(|arg| arg.default_value_strategy != Some(DefaultValueStrategy::Omitted))
        .map(convert_argument)
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Convert accounts
    let accounts = ix
        .accounts
        .iter()
        .map(convert_account)
        .collect::<Vec<_>>();

    Ok(IdlInstruction {
        name: ix.name.to_string(),
        docs: vec![],
        discriminator,
        accounts,
        args,
        returns: None,
    })
}

fn convert_argument(arg: &InstructionArgumentNode) -> anyhow::Result<IdlField> {
    Ok(IdlField {
        name: arg.name.to_string(),
        docs: vec![],
        ty: convert_type_node(&arg.r#type)?,
    })
}

fn convert_account(acc: &InstructionAccountNode) -> IdlInstructionAccountItem {
    let is_signer = matches!(acc.is_signer, IsAccountSigner::True | IsAccountSigner::Either);

    // Extract fixed address from default value (e.g. sysvar addresses)
    let address = match &acc.default_value {
        Some(InstructionInputValueNode::PublicKey(PublicKeyValueNode {
            public_key,
            ..
        })) => Some(public_key.clone()),
        _ => None,
    };

    IdlInstructionAccountItem::Single(IdlInstructionAccount {
        name: acc.name.to_string(),
        docs: vec![],
        writable: acc.is_writable,
        signer: is_signer,
        optional: acc.is_optional,
        address,
        pda: None,
        relations: vec![],
    })
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

fn convert_defined_type(dt: &DefinedTypeNode) -> anyhow::Result<IdlTypeDef> {
    let ty = convert_type_def_ty(&dt.r#type)?;

    Ok(IdlTypeDef {
        name: dt.name.to_upper_camel_case(),
        docs: vec![],
        serialization: anchor_lang_idl::types::IdlSerialization::default(),
        repr: None,
        generics: vec![],
        ty,
    })
}

fn convert_type_def_ty(node: &TypeNode) -> anyhow::Result<IdlTypeDefTy> {
    match node {
        TypeNode::Struct(st) => convert_struct_type(st),
        TypeNode::Enum(en) => convert_enum_type(en),
        _ => {
            // Wrap as a type alias
            let alias = convert_type_node(node)?;
            Ok(IdlTypeDefTy::Type { alias })
        }
    }
}

fn convert_struct_type(st: &StructTypeNode) -> anyhow::Result<IdlTypeDefTy> {
    let fields = st
        .fields
        .iter()
        .map(convert_struct_field)
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(IdlTypeDefTy::Struct {
        fields: if fields.is_empty() {
            None
        } else {
            Some(IdlDefinedFields::Named(fields))
        },
    })
}

fn convert_struct_field(field: &StructFieldTypeNode) -> anyhow::Result<IdlField> {
    Ok(IdlField {
        name: field.name.to_string(),
        docs: vec![],
        ty: convert_type_node(&field.r#type)?,
    })
}

fn convert_enum_type(en: &EnumTypeNode) -> anyhow::Result<IdlTypeDefTy> {
    let variants = en
        .variants
        .iter()
        .map(convert_enum_variant)
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(IdlTypeDefTy::Enum { variants })
}

fn convert_enum_variant(variant: &EnumVariantTypeNode) -> anyhow::Result<IdlEnumVariant> {
    match variant {
        EnumVariantTypeNode::Empty(v) => Ok(IdlEnumVariant {
            name: v.name.to_upper_camel_case(),
            fields: None,
        }),
        EnumVariantTypeNode::Struct(v) => {
            let inner_struct = v.r#struct.get_nested_type_node();
            let fields = inner_struct
                .fields
                .iter()
                .map(convert_struct_field)
                .collect::<anyhow::Result<Vec<_>>>()?;

            Ok(IdlEnumVariant {
                name: v.name.to_upper_camel_case(),
                fields: if fields.is_empty() {
                    None
                } else {
                    Some(IdlDefinedFields::Named(fields))
                },
            })
        }
        EnumVariantTypeNode::Tuple(v) => {
            let inner_tuple = v.tuple.get_nested_type_node();
            let types = inner_tuple
                .items
                .iter()
                .map(convert_type_node)
                .collect::<anyhow::Result<Vec<_>>>()?;

            Ok(IdlEnumVariant {
                name: v.name.to_upper_camel_case(),
                fields: if types.is_empty() {
                    None
                } else {
                    Some(IdlDefinedFields::Tuple(types))
                },
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Type node → IdlType mapping
// ---------------------------------------------------------------------------

/// Map a Codama `TypeNode` to an Anchor `IdlType`.
fn convert_type_node(node: &TypeNode) -> anyhow::Result<IdlType> {
    match node {
        TypeNode::Number(nt) => Ok(number_format_to_idl_type(&nt.format)),

        TypeNode::PublicKey(_) => Ok(IdlType::Pubkey),

        TypeNode::Boolean(_) => Ok(IdlType::Bool),

        TypeNode::String(_) => Ok(IdlType::String),

        TypeNode::Bytes(_) => Ok(IdlType::Bytes),

        TypeNode::Option(OptionTypeNode { item, .. }) => {
            let inner = convert_type_node(item)?;
            Ok(IdlType::Option(Box::new(inner)))
        }

        // SizePrefixTypeNode wrapping a StringTypeNode → String
        TypeNode::SizePrefix(sp) => {
            if matches!(*sp.r#type, TypeNode::String(_)) {
                Ok(IdlType::String)
            } else {
                convert_type_node(&sp.r#type)
            }
        }

        // DefinedTypeLinkNode → resolve built-in aliases or Defined reference
        TypeNode::Link(link) => {
            let name = link.name.to_string();
            // Built-in Codama type aliases used by native programs
            match name.as_str() {
                "epoch" => Ok(IdlType::U64),
                "unixTimestamp" | "unix_timestamp" => Ok(IdlType::I64),
                "slot" => Ok(IdlType::U64),
                "lamports" => Ok(IdlType::U64),
                _ => Ok(IdlType::Defined {
                    name: name.to_upper_camel_case(),
                    generics: vec![],
                }),
            }
        }

        TypeNode::Array(arr) => {
            let inner = convert_type_node(&arr.item)?;
            // Try to get fixed count
            match &arr.count {
                codama_nodes::CountNode::Fixed(fixed) => Ok(IdlType::Array(
                    Box::new(inner),
                    IdlArrayLen::Value(fixed.value),
                )),
                _ => Ok(IdlType::Vec(Box::new(inner))),
            }
        }

        TypeNode::Tuple(t) => {
            // Anchor IDL doesn't have a native tuple type.
            // Use Defined for non-trivial tuples, or inline the first element
            // if single-element.
            if t.items.len() == 1 {
                convert_type_node(&t.items[0])
            } else {
                // Fallback: treat as bytes
                Ok(IdlType::Bytes)
            }
        }

        TypeNode::Struct(st) => {
            // Inline struct in a type position → Defined (shouldn't normally happen)
            // Just return bytes as a fallback
            let _ = st;
            Ok(IdlType::Bytes)
        }

        TypeNode::Enum(en) => {
            let _ = en;
            Ok(IdlType::Bytes)
        }

        // FixedSize wrapping another type → Array of that type
        TypeNode::FixedSize(fs) => {
            let inner = convert_type_node(&fs.r#type)?;
            Ok(IdlType::Array(
                Box::new(inner),
                IdlArrayLen::Value(fs.size),
            ))
        }

        // Amount and SolAmount are wrappers around numbers
        TypeNode::Amount(a) => {
            Ok(number_format_to_idl_type(&a.number.get_nested_type_node().format))
        }
        TypeNode::SolAmount(_) => Ok(IdlType::U64),
        TypeNode::DateTime(_) => Ok(IdlType::I64),

        // Map → Vec of bytes (not commonly used in stake IDL)
        TypeNode::Map(_) => Ok(IdlType::Bytes),
        TypeNode::Set(_) => Ok(IdlType::Bytes),

        // RemainderOption → Option wrapping inner type
        TypeNode::RemainderOption(ro) => {
            let inner = convert_type_node(&ro.item)?;
            Ok(IdlType::Option(Box::new(inner)))
        }

        // ZeroableOption → Option wrapping inner type
        TypeNode::ZeroableOption(zo) => {
            let inner = convert_type_node(&zo.item)?;
            Ok(IdlType::Option(Box::new(inner)))
        }

        // Layout wrappers - unwrap to inner type
        TypeNode::HiddenPrefix(hp) => convert_type_node(&hp.r#type),
        TypeNode::HiddenSuffix(hs) => convert_type_node(&hs.r#type),
        TypeNode::PostOffset(po) => convert_type_node(&po.r#type),
        TypeNode::PreOffset(po) => convert_type_node(&po.r#type),
        TypeNode::Sentinel(s) => convert_type_node(&s.r#type),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn number_format_to_idl_type(fmt: &NumberFormat) -> IdlType {
    match fmt {
        NumberFormat::U8 => IdlType::U8,
        NumberFormat::U16 | NumberFormat::ShortU16 => IdlType::U16,
        NumberFormat::U32 => IdlType::U32,
        NumberFormat::U64 => IdlType::U64,
        NumberFormat::U128 => IdlType::U128,
        NumberFormat::I8 => IdlType::I8,
        NumberFormat::I16 => IdlType::I16,
        NumberFormat::I32 => IdlType::I32,
        NumberFormat::I64 => IdlType::I64,
        NumberFormat::I128 => IdlType::I128,
        NumberFormat::F32 => IdlType::F32,
        NumberFormat::F64 => IdlType::F64,
    }
}

fn number_format_byte_width(fmt: &NumberFormat) -> usize {
    match fmt {
        NumberFormat::U8 | NumberFormat::I8 => 1,
        NumberFormat::U16 | NumberFormat::I16 | NumberFormat::ShortU16 => 2,
        NumberFormat::U32 | NumberFormat::I32 | NumberFormat::F32 => 4,
        NumberFormat::U64 | NumberFormat::I64 | NumberFormat::F64 => 8,
        NumberFormat::U128 | NumberFormat::I128 => 16,
    }
}

fn number_to_u64(n: &Number) -> u64 {
    match n {
        Number::UnsignedInteger(v) => *v,
        Number::SignedInteger(v) => *v as u64,
        Number::Float(v) => *v as u64,
    }
}

/// Recursively collect all `Defined` type names referenced in an IDL type.
fn collect_defined_refs(ty: &IdlType, out: &mut HashSet<String>) {
    match ty {
        IdlType::Defined { name, .. } => {
            out.insert(name.clone());
        }
        IdlType::Option(inner) | IdlType::Vec(inner) | IdlType::Array(inner, _) => {
            collect_defined_refs(inner, out);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn load_stake_idl() -> RootNode {
        let json = include_str!("../test-data/codama_stake.json");
        serde_json::from_str(json).expect("Failed to parse codama_stake.json as Codama RootNode")
    }

    #[test]
    fn test_parse_stake_codama_idl() {
        let root = load_stake_idl();
        assert_eq!(root.program.name.as_ref(), "solanaStakeInterface");
        assert_eq!(
            root.program.public_key,
            "Stake11111111111111111111111111111111111111"
        );
    }

    #[test]
    fn test_convert_stake_idl() {
        let root = load_stake_idl();
        let idl = convert(&root).expect("Conversion failed");

        // Metadata
        assert_eq!(idl.metadata.name, "solanaStakeInterface");
        assert_eq!(
            idl.address,
            "Stake11111111111111111111111111111111111111"
        );

        // Should have 18 instructions
        assert_eq!(idl.instructions.len(), 18, "Expected 18 instructions");

        // Check first instruction: initialize
        let init = &idl.instructions[0];
        assert_eq!(init.name, "initialize");
        // Discriminator should be [0, 0, 0, 0, 0, 0, 0, 0] (value 0, u8 padded to 8)
        assert_eq!(init.discriminator.len(), 8);
        assert_eq!(init.discriminator[0], 0);

        // Should have 2 args (authorized, lockup) — discriminator filtered out
        assert_eq!(init.args.len(), 2, "initialize should have 2 args");

        // Should have 2 accounts (stake, rentSysvar)
        assert_eq!(init.accounts.len(), 2);

        // rentSysvar should have a fixed address
        if let IdlInstructionAccountItem::Single(rent) = &init.accounts[1] {
            assert_eq!(rent.name, "rentSysvar");
            assert!(rent.address.is_some(), "rentSysvar should have fixed address");
            assert_eq!(
                rent.address.as_deref().unwrap(),
                "SysvarRent111111111111111111111111111111111"
            );
        } else {
            panic!("Expected single account");
        }
    }

    #[test]
    fn test_convert_stake_types() {
        let root = load_stake_idl();
        let idl = convert(&root).expect("Conversion failed");

        // Should have defined types
        assert!(!idl.types.is_empty(), "Should have defined types");

        // Find the StakeAuthorize enum
        let stake_auth = idl
            .types
            .iter()
            .find(|t| t.name == "StakeAuthorize")
            .expect("Should have StakeAuthorize type");

        if let IdlTypeDefTy::Enum { variants } = &stake_auth.ty {
            assert_eq!(variants.len(), 2);
            assert_eq!(variants[0].name, "Staker");
            assert_eq!(variants[1].name, "Withdrawer");
        } else {
            panic!("stakeAuthorize should be an enum");
        }

        // Find the Lockup struct
        let lockup = idl
            .types
            .iter()
            .find(|t| t.name == "Lockup")
            .expect("Should have Lockup type");

        if let IdlTypeDefTy::Struct {
            fields: Some(IdlDefinedFields::Named(fields)),
        } = &lockup.ty
        {
            assert_eq!(fields.len(), 3);
            assert_eq!(fields[0].name, "unixTimestamp");
            assert_eq!(fields[2].name, "custodian");
            assert_eq!(fields[2].ty, IdlType::Pubkey);
        } else {
            panic!("lockup should be a struct with named fields");
        }
    }

    #[test]
    fn test_convert_enum_with_tuple_variants() {
        let root = load_stake_idl();
        let idl = convert(&root).expect("Conversion failed");

        // StakeState has both empty and tuple variants
        let stake_state = idl
            .types
            .iter()
            .find(|t| t.name == "StakeState")
            .expect("Should have StakeState type");

        if let IdlTypeDefTy::Enum { variants } = &stake_state.ty {
            assert_eq!(variants.len(), 4);
            assert_eq!(variants[0].name, "Uninitialized");
            assert!(variants[0].fields.is_none(), "Uninitialized has no fields");

            assert_eq!(variants[1].name, "Initialized");
            assert!(
                variants[1].fields.is_some(),
                "Initialized should have tuple fields"
            );

            assert_eq!(variants[2].name, "Stake");
            if let Some(IdlDefinedFields::Tuple(types)) = &variants[2].fields {
                assert_eq!(types.len(), 2, "stake variant has (meta, stake)");
            } else {
                panic!("stake variant should have tuple fields");
            }
        } else {
            panic!("stakeState should be an enum");
        }
    }

    #[test]
    fn test_discriminator_values() {
        let root = load_stake_idl();
        let idl = convert(&root).expect("Conversion failed");

        // Check that discriminator values increment correctly
        // initialize=0, authorize=1, delegateStake=2, split=3, withdraw=4, ...
        for (i, ix) in idl.instructions.iter().enumerate() {
            assert_eq!(
                ix.discriminator[0], i as u8,
                "Instruction {} ({}) should have discriminator {}",
                i, ix.name, i
            );
        }
    }

    #[test]
    fn test_built_in_type_aliases() {
        let root = load_stake_idl();
        let idl = convert(&root).expect("Conversion failed");

        // The Lockup type has unixTimestamp (→ i64) and epoch (→ u64) link types
        let lockup = idl
            .types
            .iter()
            .find(|t| t.name == "Lockup")
            .expect("Should have Lockup type");

        if let IdlTypeDefTy::Struct {
            fields: Some(IdlDefinedFields::Named(fields)),
        } = &lockup.ty
        {
            // unixTimestamp should resolve to i64
            assert_eq!(fields[0].ty, IdlType::I64, "unixTimestamp should be i64");
            // epoch should resolve to u64
            assert_eq!(fields[1].ty, IdlType::U64, "epoch should be u64");
        }
    }

    // -----------------------------------------------------------------------
    // System program Codama tests
    // -----------------------------------------------------------------------

    fn load_system_idl() -> RootNode {
        let json = include_str!("../test-data/codama_system.json");
        serde_json::from_str(json).expect("Failed to parse codama_system.json")
    }

    #[test]
    fn test_convert_system_idl() {
        let root = load_system_idl();
        let idl = convert(&root).expect("System conversion failed");

        assert!(!idl.metadata.name.is_empty());
        assert!(!idl.address.is_empty());
        assert!(
            idl.instructions.len() >= 10,
            "system should have >= 10 instructions, got {}",
            idl.instructions.len()
        );

        // Verify discriminators are sequential u32 LE (padded to 8)
        for (i, ix) in idl.instructions.iter().enumerate() {
            assert_eq!(ix.discriminator.len(), 8, "disc len for {}", ix.name);
            assert_eq!(
                ix.discriminator[0], i as u8,
                "instruction {} ({}) should have discriminator {}",
                i, ix.name, i
            );
        }

        // -- Deep: createAccount instruction args and accounts --
        let create = idl.instructions.iter().find(|ix| ix.name == "createAccount")
            .expect("should have createAccount instruction");
        // Args: lamports, space, programAddress (discriminator filtered out)
        assert_eq!(create.args.len(), 3, "createAccount should have 3 args, got {:?}",
            create.args.iter().map(|a| &a.name).collect::<Vec<_>>());
        assert_eq!(create.args[0].name, "lamports");
        assert_eq!(create.args[0].ty, IdlType::U64);
        assert_eq!(create.args[1].name, "space");
        assert_eq!(create.args[1].ty, IdlType::U64);
        assert_eq!(create.args[2].name, "programAddress");
        assert_eq!(create.args[2].ty, IdlType::Pubkey);

        // Accounts: payer (writable+signer), newAccount (writable+signer)
        let accs: Vec<_> = create.accounts.iter().filter_map(|a| match a {
            IdlInstructionAccountItem::Single(s) => Some(s),
            _ => None,
        }).collect();
        assert_eq!(accs[0].name, "payer");
        assert!(accs[0].writable, "payer should be writable");
        assert!(accs[0].signer, "payer should be signer");
        assert_eq!(accs[1].name, "newAccount");
        assert!(accs[1].writable, "newAccount should be writable");
        assert!(accs[1].signer, "newAccount should be signer");
    }

    #[test]
    fn test_system_has_nonce_types() {
        let root = load_system_idl();
        let idl = convert(&root).expect("Conversion failed");

        // System program defines nonce-related types
        let type_names: Vec<&str> = idl.types.iter().map(|t| t.name.as_str()).collect();
        // Look for nonce-related types (exact names may vary with CamelCase conversion)
        let has_nonce = type_names.iter().any(|n| n.contains("Nonce"));
        assert!(has_nonce, "system should have nonce types, found: {:?}", type_names);
    }

    // -----------------------------------------------------------------------
    // Token program Codama tests
    // -----------------------------------------------------------------------

    fn load_token_idl() -> RootNode {
        let json = include_str!("../test-data/codama_token.json");
        serde_json::from_str(json).expect("Failed to parse codama_token.json")
    }

    #[test]
    fn test_convert_token_idl() {
        let root = load_token_idl();
        let idl = convert(&root).expect("Token conversion failed");

        assert!(!idl.metadata.name.is_empty());
        assert!(
            idl.instructions.len() >= 20,
            "token should have >= 20 instructions, got {}",
            idl.instructions.len()
        );
    }

    #[test]
    fn test_token_has_authority_type_enum() {
        let root = load_token_idl();
        let idl = convert(&root).expect("Conversion failed");

        let auth_type = idl.types.iter().find(|t| t.name == "AuthorityType");
        assert!(auth_type.is_some(), "token should have AuthorityType enum, found types: {:?}",
            idl.types.iter().map(|t| &t.name).collect::<Vec<_>>());

        if let Some(td) = auth_type {
            if let IdlTypeDefTy::Enum { variants } = &td.ty {
                assert!(variants.len() >= 3, "AuthorityType should have multiple variants");
                // -- Deep: verify specific variant names --
                let names: Vec<&str> = variants.iter().map(|v| v.name.as_str()).collect();
                assert!(names.contains(&"MintTokens"),
                    "AuthorityType should have MintTokens variant, got {:?}", names);
                assert!(names.contains(&"FreezeAccount"),
                    "AuthorityType should have FreezeAccount variant, got {:?}", names);
                assert!(names.contains(&"AccountOwner"),
                    "AuthorityType should have AccountOwner variant, got {:?}", names);
                assert!(names.contains(&"CloseAccount"),
                    "AuthorityType should have CloseAccount variant, got {:?}", names);
            } else {
                panic!("AuthorityType should be an enum");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Compute Budget program Codama tests
    // -----------------------------------------------------------------------

    fn load_compute_budget_idl() -> RootNode {
        let json = include_str!("../test-data/codama_compute_budget.json");
        serde_json::from_str(json).expect("Failed to parse codama_compute_budget.json")
    }

    #[test]
    fn test_convert_compute_budget_idl() {
        let root = load_compute_budget_idl();
        let idl = convert(&root).expect("Compute budget conversion failed");

        assert!(!idl.metadata.name.is_empty());
        assert!(idl.instructions.len() >= 3,
            "compute_budget should have >= 3 instructions, got {}", idl.instructions.len());
        // Minimal program — should have few or no types
        // (just verify it doesn't crash)
    }

    #[test]
    fn test_compute_budget_no_types() {
        let root = load_compute_budget_idl();
        let idl = convert(&root).expect("Conversion failed");
        // Compute budget is a minimal program, may have zero defined types
        // This is fine — we just want to make sure the pipeline handles it
        assert!(idl.types.len() <= 5,
            "compute_budget should have few types, got {}", idl.types.len());
    }

    // -----------------------------------------------------------------------
    // Memo program Codama tests
    // -----------------------------------------------------------------------

    fn load_memo_idl() -> RootNode {
        let json = include_str!("../test-data/codama_memo.json");
        serde_json::from_str(json).expect("Failed to parse codama_memo.json")
    }

    #[test]
    fn test_convert_memo_idl() {
        let root = load_memo_idl();
        let idl = convert(&root).expect("Memo conversion failed");

        assert!(!idl.metadata.name.is_empty());
        // Memo is minimal: typically 1 instruction
        assert!(!idl.instructions.is_empty(), "memo should have at least 1 instruction");
    }

    // -----------------------------------------------------------------------
    // Type alias resolution tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_type_alias_resolution() {
        // Verify post-processing creates aliases for unresolved type references.
        // The stake IDL has instructions referencing types that may be defined under
        // slightly different names (e.g. "LockupArgs" → "LockupCheckedArgs" matching).
        let root = load_stake_idl();
        let idl = convert(&root).expect("Conversion failed");

        let type_names: Vec<&str> = idl.types.iter().map(|t| t.name.as_str()).collect();

        // Collect all Defined type references from instruction args
        let mut referenced: HashSet<String> = HashSet::new();
        for ix in &idl.instructions {
            for arg in &ix.args {
                collect_defined_refs(&arg.ty, &mut referenced);
            }
        }

        // Every referenced type should either be defined directly or have an alias
        for ref_name in &referenced {
            assert!(type_names.contains(&ref_name.as_str()),
                "Referenced type '{}' should exist in types list (directly or as alias), \
                 available types: {:?}", ref_name, type_names);
        }
    }

    #[test]
    fn test_type_alias_is_type_variant() {
        // If aliases are created, they should use IdlTypeDefTy::Type (alias)
        let root = load_stake_idl();
        let idl = convert(&root).expect("Conversion failed");

        // Find any type aliases (Type variant, not Struct/Enum)
        let aliases: Vec<&IdlTypeDef> = idl.types.iter().filter(|t| {
            matches!(&t.ty, IdlTypeDefTy::Type { .. })
        }).collect();

        // Each alias should point to a real type
        let type_names: HashSet<&str> = idl.types.iter().map(|t| t.name.as_str()).collect();
        for alias in &aliases {
            if let IdlTypeDefTy::Type { alias: IdlType::Defined { name, .. } } = &alias.ty {
                assert!(type_names.contains(name.as_str()),
                    "Alias '{}' points to '{}' which should exist in types", alias.name, name);
            }
        }
    }

    #[test]
    fn test_memo_instruction_has_bytes_arg() {
        let root = load_memo_idl();
        let idl = convert(&root).expect("Conversion failed");

        // Memo instruction takes a bytes/string argument
        let first_ix = &idl.instructions[0];
        assert!(
            !first_ix.args.is_empty() || first_ix.accounts.len() >= 1,
            "memo instruction should have args or accounts"
        );
    }
}
