//! Routing a classified artifact to the parser that can read it.
//!
//! One place decides which parser sees which bytes, so the answer to "was this file
//! opened, and by what?" is a single readable table rather than a chain of
//! conditionals spread through the scanner.
//!
//! Two properties of that table matter more than its contents:
//!
//! * Every type answering `false` to [`crate::detect::is_parseable`] routes to
//!   nothing. A `.pt` file has no branch here at all — not a branch that declines,
//!   but no branch — so there is no edit that could accidentally open one.
//! * A parser failure is returned, never swallowed. The scanner turns it into a
//!   coverage note naming the file, because "we could not read this" is a fact the
//!   report must carry.

use crate::{detect, ParseOutput, ReadNeed};
use tt_core::error::TtResult;
use tt_core::limits::Limits;
use tt_facts::ArtifactType;

/// What the scanner needs to hand [`parse`] for a given artifact type.
pub fn read_need(t: ArtifactType, limits: &Limits) -> ReadNeed {
    detect::read_need(t, limits)
}

/// Parse an artifact of known type.
///
/// `bytes` is whatever [`read_need`] asked for. `file_size` is the full size on
/// disk, which SafeTensors uses to check that declared tensor offsets fall inside
/// the file — a check that cannot be made from a prefix alone.
///
/// Returns `None` when the type has no parser, which is the correct outcome for
/// opaque and unrecognised artifacts.
pub fn parse(
    t: ArtifactType,
    bytes: &[u8],
    limits: &Limits,
    file_size: Option<u64>,
) -> Option<TtResult<ParseOutput>> {
    // Opaque formats execute code when loaded. They are hashed and counted by the
    // inventory and never reach a parser.
    if !detect::is_parseable(t) {
        return None;
    }
    Some(match t {
        ArtifactType::SafeTensors => crate::safetensors::parse_header(bytes, limits, file_size),
        ArtifactType::Gguf => crate::gguf::parse_metadata(bytes, limits),
        ArtifactType::TrainingLog => crate::logs::parse_tail(bytes, limits, true),
        ArtifactType::RetrievalTrace => crate::logs::parse_tail(bytes, limits, true),

        ArtifactType::TransformersConfig
        | ArtifactType::GenerationConfig
        | ArtifactType::PeftAdapterConfig
        | ArtifactType::ShardIndex
        | ArtifactType::TokenizerConfig
        | ArtifactType::TrainerState
        | ArtifactType::TrainingArgs
        | ArtifactType::ModelCard => match crate::hf::parse_for(t, bytes, limits) {
            Some(r) => r,
            None => return None,
        },

        // Recognised as structured text but with no specific reader yet. Parsing it
        // as generic data still lets the scanner record that the file was readable
        // and well-formed, which is part of coverage.
        ArtifactType::GenericJson | ArtifactType::DeepSpeedConfig | ArtifactType::AccelerateConfig => {
            tt_core::json::parse(bytes, limits).map(|_| {
                ParseOutput::new(t, "bounded_json", crate::hf::PARSER_VERSION)
            })
        }
        ArtifactType::GenericYaml => crate::yamlish::parse(bytes, limits)
            .map(|_| ParseOutput::new(t, "bounded_yaml", crate::hf::PARSER_VERSION)),

        // No reader yet. Saying so is better than pretending the file was examined.
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> Limits {
        Limits::default()
    }

    #[test]
    fn opaque_formats_have_no_parser_at_all() {
        for t in [ArtifactType::OpaqueSerialization, ArtifactType::Unrecognised, ArtifactType::PlainText]
        {
            assert!(
                parse(t, b"anything", &lim(), None).is_none(),
                "{t} must never reach a parser"
            );
        }
    }

    #[test]
    fn a_pickle_file_is_not_opened_even_with_valid_looking_content() {
        // The bytes below are a real pickle opcode sequence. Nothing may read them.
        let pickle = b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00}\x94.";
        assert!(parse(ArtifactType::OpaqueSerialization, pickle, &lim(), None).is_none());
    }

    #[test]
    fn known_types_route_to_a_parser() {
        let adapter = br#"{"peft_type":"LORA","r":8}"#;
        assert!(parse(ArtifactType::PeftAdapterConfig, adapter, &lim(), None).unwrap().is_ok());

        let cfg = br#"{"model_type":"llama"}"#;
        assert!(parse(ArtifactType::TransformersConfig, cfg, &lim(), None).unwrap().is_ok());

        let mut st = 16u64.to_le_bytes().to_vec();
        st.extend_from_slice(br#"{"__metadata__":{}}"#);
        assert!(parse(ArtifactType::SafeTensors, &st, &lim(), Some(st.len() as u64)).is_some());
    }

    #[test]
    fn a_parser_failure_is_returned_not_swallowed() {
        let r = parse(ArtifactType::PeftAdapterConfig, b"{not json", &lim(), None);
        assert!(matches!(r, Some(Err(_))), "a malformed config must surface as an error");
    }

    #[test]
    fn read_need_for_a_log_is_a_tail() {
        assert!(matches!(
            read_need(ArtifactType::TrainingLog, &lim()),
            ReadNeed::Suffix(_)
        ));
    }

    #[test]
    fn every_parseable_type_either_routes_or_is_declared_unread() {
        // Not every parseable type has a reader yet, and that is allowed - but the
        // set that does must be stable, so a future edit cannot silently stop
        // parsing adapter configs.
        for t in [
            ArtifactType::SafeTensors,
            ArtifactType::Gguf,
            ArtifactType::PeftAdapterConfig,
            ArtifactType::TransformersConfig,
            ArtifactType::ShardIndex,
            ArtifactType::TrainerState,
            ArtifactType::TrainingArgs,
            ArtifactType::TokenizerConfig,
            ArtifactType::ModelCard,
            ArtifactType::TrainingLog,
        ] {
            assert!(
                parse(t, b"{}", &lim(), None).is_some(),
                "{t} lost its parser"
            );
        }
    }
}
