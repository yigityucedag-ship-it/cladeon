//! Scoring, caps, mandatory abstention and the method-label emission gate.
//!
//! This is the part of TrainTrace that decides how confident to be, so it is written
//! to be *reluctant*. Four independent brakes stand between evidence and a named
//! method, and any one of them alone will stop a label:
//!
//! 1. **Rubric ceiling.** A claim can only reach the anchors its rubric defines. For
//!    merged adapters, two anchors worth 55 points require Stage-2 tensor analysis,
//!    so Stage 1 mathematically cannot name a merged adapter. That is by design and
//!    is asserted as a test rather than left to discipline.
//! 2. **Caps.** Evidence of a weak kind imposes a hard maximum regardless of how
//!    much of it there is. Thirty mutable config files still cap at 250.
//! 3. **Mandatory abstention.** Some conditions force an abstention outright.
//! 4. **Emission gate.** Even a high score names no method unless a method-specific
//!    anchor exists, the best evidence is a structural artifact, nothing contradicts
//!    it, and the nearest mutually exclusive rival is a clear distance behind.
//!
//! Two asymmetries are deliberate and are the tool's whole stance:
//!
//! * **A missing anchor never subtracts.** Absent evidence caps a score; it never
//!   pushes one down. Missing evidence is not contradiction, and a screen that
//!   punishes silence turns "we did not send you that file" into an accusation.
//! * **A contradiction zeroes the claim it contradicts**, but a contradiction is
//!   only ever a conflict between an exact claim and an observed artifact - never an
//!   inference about intent.

use crate::model::{AnchorScore, CapApplied, ClaimScore, Conclusion, RuleOutcome, RuleReport};
use std::collections::BTreeMap;
use tt_core::vocab::{
    AbstentionId, CapId, Claim, EvidenceTier, Facet, OutcomeKind, SupportBand,
    EMISSION_MIN_SEPARATION_TENTHS, EMISSION_MIN_TENTHS, EMISSION_MIN_TIER,
};

/// Rules that constitute a *method-specific anchor* for the emission gate.
///
/// Note what is absent: `TT-LORA-001` (an adapter config declaring a PEFT method) is
/// not here, and neither is `TT-BASE-001`. A config file is a text record that
/// anyone can write. Naming a method requires having observed the structure the
/// method leaves behind, not having read a claim that it was used.
const METHOD_ANCHORS: &[(Claim, &str)] = &[
    (Claim::UnmergedLora, "TT-LORA-002"),
    (Claim::UnmergedLora, "TT-LORA-003"),
    (Claim::UnmergedLora, "TT-LORA-004"),
    (Claim::MergedAdapter, "TT-MERGE-003"),
    (Claim::DenseFinetune, "TT-DENSE-001"),
    (Claim::DenseFinetune, "TT-DENSE-003"),
    (Claim::DenseFinetune, "TT-DENSE-004"),
    (Claim::ContinuedPretraining, "TT-CPT-002"),
    (Claim::ContinuedPretraining, "TT-CPT-004"),
    (Claim::Distillation, "TT-DIST-003"),
    (Claim::Distillation, "TT-DIST-004"),
    (Claim::Scratch, "TT-SCRATCH-001"),
    (Claim::Scratch, "TT-SCRATCH-002"),
    (Claim::Rag, "TT-RAG-001"),
    (Claim::ExternalApi, "TT-API-001"),
    (Claim::ExternalApi, "TT-API-003"),
];

pub fn is_method_anchor(claim: Claim, rule_id: &str) -> bool {
    METHOD_ANCHORS.iter().any(|(c, r)| *c == claim && *r == rule_id)
}

/// A cap a rule family asked the engine to apply to one claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapRequest {
    pub claim: Claim,
    pub cap_id: CapId,
    pub triggered_by: &'static str,
}

/// An abstention a rule family asked the engine to apply to one facet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstentionRequest {
    pub facet: Facet,
    pub id: AbstentionId,
}

/// Everything the rule families produced, before the engine judges it.
#[derive(Debug, Default)]
pub struct Emissions {
    pub outcomes: Vec<RuleOutcome>,
    pub caps: Vec<CapRequest>,
    pub abstentions: Vec<AbstentionRequest>,
    /// Facets for which no artifact was in scope at all.
    pub out_of_scope: Vec<Facet>,
}

/// Convert `sum(weight * achievement)` into tenths of a percent, with the divisor
/// the rubric declares. Integer arithmetic with round-half-up; no float ever
/// participates in a number that reaches a report.
pub fn tenths_from(weighted_sum: u64, divisor: u32) -> i64 {
    if divisor == 0 {
        return 0;
    }
    let denom = (divisor as u64) * 100;
    // Both operations saturate. `saturating_mul` followed by a plain `+` overflows
    // the moment the multiply has already saturated, which is the exact class of bug
    // this codebase forbids elsewhere.
    let scaled = weighted_sum.saturating_mul(1000);
    ((scaled.saturating_add(denom / 2) / denom) as i64).clamp(0, 1000)
}

/// Score one claim from the outcomes that mention it.
fn score_claim(claim: Claim, emissions: &Emissions) -> ClaimScore {
    let rubric = claim.rubric();
    let divisor = claim.rubric_divisor();

    // Per anchor, keep the single best achievement and remember what witnessed it.
    // Taking the maximum - rather than a sum - is what stops five copies of the same
    // observation from looking like five confirmations.
    let mut best: BTreeMap<&'static str, (u32, &'static str, String, Option<EvidenceTier>)> =
        BTreeMap::new();

    for o in &emissions.outcomes {
        if o.kind != OutcomeKind::SupportingEvidence || o.claim != Some(claim) {
            continue;
        }
        let Some(anchor) = o.anchor else { continue };
        if !rubric.iter().any(|a| a.name == anchor) {
            // A rule feeding an anchor this claim does not have is a catalogue bug.
            // The invariant test catches it; at runtime we ignore it rather than
            // inventing weight for it.
            continue;
        }
        let entry = best.entry(anchor).or_insert((0, o.rule_id, o.source_group.clone(), o.tier));
        if o.achievement > entry.0 {
            *entry = (o.achievement, o.rule_id, o.source_group.clone(), o.tier);
        }
    }

    let mut anchors = Vec::with_capacity(rubric.len());
    let mut weighted_sum: u64 = 0;
    let mut best_tier: Option<EvidenceTier> = None;
    let mut groups: Vec<String> = Vec::new();

    for spec in rubric {
        let (achievement, rule, group, tier) = match best.get(spec.name) {
            Some((a, r, g, t)) => (*a, Some(*r), Some(g.clone()), *t),
            None => (0, None, None, None),
        };
        weighted_sum += (spec.weight as u64) * (achievement as u64);
        if achievement > 0 {
            if let Some(t) = tier {
                best_tier = Some(match best_tier {
                    Some(b) if b.rank() >= t.rank() => b,
                    _ => t,
                });
            }
            if let Some(g) = &group {
                if !g.is_empty() && !groups.contains(g) {
                    groups.push(g.clone());
                }
            }
        }
        anchors.push(AnchorScore {
            anchor: spec.name,
            weight: spec.weight,
            achievement,
            witness_rule: rule,
            witness_group: group,
            witness_tier: tier,
        });
    }
    groups.sort();

    let raw_tenths = tenths_from(weighted_sum, divisor);
    let mut score_tenths = raw_tenths;

    // Caps, lowest wins. Every applied cap is reported with the rule that triggered it.
    let mut caps: Vec<CapApplied> = Vec::new();
    let mut by_id: BTreeMap<CapId, Vec<&'static str>> = BTreeMap::new();
    for c in emissions.caps.iter().filter(|c| c.claim == claim) {
        by_id.entry(c.cap_id).or_default().push(c.triggered_by);
    }
    // Corroboration requires independent sources. Applied only when it would
    // actually bind, so reports are not littered with inert caps.
    if groups.len() <= 1 && raw_tenths > CapId::SingleSource.max_tenths() {
        by_id.entry(CapId::SingleSource).or_default().push("TT-XSOURCE-001");
    }
    for (cap_id, triggers) in by_id {
        caps.push(CapApplied { cap_id, max_tenths: cap_id.max_tenths(), triggered_by: triggers });
        score_tenths = score_tenths.min(cap_id.max_tenths());
    }
    caps.sort_by_key(|c| c.max_tenths);

    let contradicted_by: Vec<&'static str> = emissions
        .outcomes
        .iter()
        .filter(|o| o.kind == OutcomeKind::Contradiction && o.claim == Some(claim))
        .map(|o| o.rule_id)
        .collect();
    if !contradicted_by.is_empty() {
        score_tenths = 0;
    }

    ClaimScore {
        claim,
        raw_tenths,
        score_tenths,
        rubric_divisor: divisor,
        anchors,
        caps,
        best_tier,
        source_groups: groups,
        contradicted_by,
    }
}

/// Decide one facet from its competing claims.
fn conclude_facet(facet: Facet, scores: &[ClaimScore], emissions: &Emissions) -> Conclusion {
    let mut candidates: Vec<&ClaimScore> =
        scores.iter().filter(|s| s.claim.facet() == facet).collect();
    // Deterministic ordering: score first, then claim name, so a tie never depends
    // on evaluation order.
    candidates.sort_by(|a, b| {
        b.score_tenths.cmp(&a.score_tenths).then(a.claim.as_str().cmp(b.claim.as_str()))
    });

    let mut abstentions: Vec<AbstentionId> =
        emissions.abstentions.iter().filter(|a| a.facet == facet).map(|a| a.id).collect();

    let facet_contradictions: Vec<&RuleOutcome> = emissions
        .outcomes
        .iter()
        .filter(|o| o.kind == OutcomeKind::Contradiction && o.facet == Some(facet))
        .collect();

    let rule_ids: Vec<&'static str> = emissions
        .outcomes
        .iter()
        .filter(|o| o.facet == Some(facet))
        .map(|o| o.rule_id)
        .collect();

    let alternatives: Vec<(Claim, i64)> =
        candidates.iter().skip(1).map(|c| (c.claim, c.score_tenths)).collect();

    let Some(best) = candidates.first().copied() else {
        // No claim competes for this facet at all.
        return Conclusion {
            facet,
            claim: None,
            band: SupportBand::InsufficientEvidence,
            score_tenths: 0,
            rubric_divisor: 0,
            anchors: Vec::new(),
            caps: Vec::new(),
            abstentions,
            best_tier: None,
            method_label_emitted: false,
            alternatives,
            rule_ids: dedup(rule_ids),
        };
    };

    // Separation from the nearest mutually exclusive rival.
    let rival = candidates
        .iter()
        .skip(1)
        .filter(|c| best.claim.mutually_exclusive_with().contains(&c.claim))
        .map(|c| c.score_tenths)
        .max()
        .unwrap_or(0);
    let separation = best.score_tenths - rival;

    // Engine-derived abstentions.
    if best.score_tenths > 0
        && separation < EMISSION_MIN_SEPARATION_TENTHS
        && !best.claim.mutually_exclusive_with().is_empty()
        && rival > 0
    {
        abstentions.push(AbstentionId::HybridTooClose);
    }
    if best.score_tenths >= EMISSION_MIN_TENTHS
        && best.best_tier.map(|t| t.rank()).unwrap_or(0) < EMISSION_MIN_TIER.rank()
    {
        abstentions.push(AbstentionId::EvidenceMutable);
    }
    abstentions.sort_by_key(|a| a.as_str());
    abstentions.dedup();

    let has_method_anchor = emissions.outcomes.iter().any(|o| {
        o.claim == Some(best.claim)
            && o.kind == OutcomeKind::SupportingEvidence
            && is_method_anchor(best.claim, o.rule_id)
    });

    let tier_ok = best.best_tier.map(|t| t.rank() >= EMISSION_MIN_TIER.rank()).unwrap_or(false);

    let gate_passes = best.score_tenths >= EMISSION_MIN_TENTHS
        && has_method_anchor
        && tier_ok
        && !best.is_contradicted()
        && facet_contradictions.is_empty()
        && separation >= EMISSION_MIN_SEPARATION_TENTHS;

    let band = if emissions.out_of_scope.contains(&facet) {
        SupportBand::NotSupplied
    } else if !facet_contradictions.is_empty() || best.is_contradicted() {
        SupportBand::Contradicted
    } else if !abstentions.is_empty() {
        SupportBand::InsufficientEvidence
    } else {
        let by_score = SupportBand::from_tenths(best.score_tenths);
        match by_score {
            // High score, but the gate refused to name the method. That is a real
            // state of knowledge and it gets its own word rather than being rounded
            // up into a claim or down into silence.
            SupportBand::StronglyConsistent | SupportBand::Corroborated if !gate_passes => {
                SupportBand::PartiallySupported
            }
            other => other,
        }
    };

    Conclusion {
        facet,
        claim: Some(best.claim),
        band,
        score_tenths: best.score_tenths,
        rubric_divisor: best.rubric_divisor,
        anchors: best.anchors.clone(),
        caps: best.caps.clone(),
        abstentions,
        best_tier: best.best_tier,
        method_label_emitted: gate_passes && band != SupportBand::NotSupplied,
        alternatives,
        rule_ids: dedup(rule_ids),
    }
}

fn dedup(mut v: Vec<&'static str>) -> Vec<&'static str> {
    v.sort_unstable();
    v.dedup();
    v
}

/// Turn rule-family emissions into scored claims and facet conclusions.
pub fn judge(emissions: Emissions) -> RuleReport {
    let mut claim_scores: Vec<ClaimScore> =
        Claim::ALL.iter().map(|c| score_claim(*c, &emissions)).collect();
    claim_scores.sort_by_key(|c| c.claim.as_str());

    let conclusions: Vec<Conclusion> =
        Facet::ALL.iter().map(|f| conclude_facet(*f, &claim_scores, &emissions)).collect();

    RuleReport { outcomes: emissions.outcomes, claim_scores, conclusions }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RuleOutcome;

    fn support(
        rule: &'static str,
        claim: Claim,
        anchor: &'static str,
        ach: u32,
        tier: EvidenceTier,
        group: &str,
    ) -> RuleOutcome {
        RuleOutcome::support(rule, claim, anchor, ach, tier, "t").group(group)
    }

    #[test]
    fn tenths_arithmetic_is_exact_at_the_ends() {
        assert_eq!(tenths_from(0, 100), 0);
        assert_eq!(tenths_from(100 * 100, 100), 1000);
        assert_eq!(tenths_from(50 * 100, 100), 500);
        assert_eq!(tenths_from(0, 0), 0);
    }

    #[test]
    fn tenths_rounds_half_up_and_never_exceeds_bounds() {
        // 30*100 + 20*100 + 20*100 = 7000 over divisor 100 -> 700
        assert_eq!(tenths_from(7000, 100), 700);
        // Saturation guard
        assert_eq!(tenths_from(u64::MAX, 100), 1000);
    }

    #[test]
    fn duplicate_observations_do_not_stack() {
        let mut e = Emissions::default();
        for i in 0..5 {
            let _ = i;
            e.outcomes.push(support(
                "TT-LORA-003",
                Claim::UnmergedLora,
                "structure",
                100,
                EvidenceTier::E2,
                "artifact::A-0001",
            ));
        }
        let s = score_claim(Claim::UnmergedLora, &e);
        // structure is worth 30 of 100, so five copies still give 300 tenths.
        assert_eq!(s.raw_tenths, 300);
    }

    #[test]
    fn missing_anchors_never_subtract() {
        let mut e = Emissions::default();
        e.outcomes.push(support(
            "TT-LORA-003",
            Claim::UnmergedLora,
            "structure",
            100,
            EvidenceTier::E2,
            "artifact::A-0001",
        ));
        let with_support = score_claim(Claim::UnmergedLora, &e).raw_tenths;
        e.outcomes.push(RuleOutcome::missing("TT-BASE-003", Claim::UnmergedLora, "base", "t"));
        e.outcomes.push(RuleOutcome::missing(
            "TT-LORA-014",
            Claim::UnmergedLora,
            "load_or_remerge_record",
            "t",
        ));
        assert_eq!(score_claim(Claim::UnmergedLora, &e).raw_tenths, with_support);
    }

    #[test]
    fn single_source_cannot_reach_corroborated() {
        let mut e = Emissions::default();
        for (rule, anchor) in [
            ("TT-LORA-003", "structure"),
            ("TT-BASE-001", "base"),
            ("TT-BASE-009", "base_consistency"),
            ("TT-LORA-013", "load_or_remerge_record"),
            ("TT-BIND-001", "deployment_binding"),
        ] {
            e.outcomes.push(support(
                rule,
                Claim::UnmergedLora,
                anchor,
                100,
                EvidenceTier::E2,
                "dir::ROOT1",
            ));
        }
        let s = score_claim(Claim::UnmergedLora, &e);
        assert_eq!(s.raw_tenths, 1000);
        assert_eq!(s.score_tenths, 849, "one source must not corroborate itself");
        assert!(s.caps.iter().any(|c| c.cap_id == CapId::SingleSource));
    }

    #[test]
    fn two_independent_sources_can_reach_corroborated() {
        let mut e = Emissions::default();
        for (rule, anchor, group) in [
            ("TT-LORA-003", "structure", "artifact::A-0001"),
            ("TT-BASE-001", "base", "dir::ROOT1"),
            ("TT-BASE-009", "base_consistency", "artifact::A-0002"),
            ("TT-LORA-013", "load_or_remerge_record", "dir::ROOT2"),
            ("TT-BIND-001", "deployment_binding", "dir::ROOT2"),
        ] {
            e.outcomes.push(support(
                rule,
                Claim::UnmergedLora,
                anchor,
                100,
                EvidenceTier::E2,
                group,
            ));
        }
        let s = score_claim(Claim::UnmergedLora, &e);
        assert_eq!(s.score_tenths, 1000);
        assert!(!s.caps.iter().any(|c| c.cap_id == CapId::SingleSource));
    }

    #[test]
    fn lowest_cap_wins() {
        let mut e = Emissions::default();
        for (rule, anchor, g) in [
            ("TT-LORA-003", "structure", "a"),
            ("TT-BASE-001", "base", "b"),
            ("TT-BASE-009", "base_consistency", "c"),
        ] {
            e.outcomes.push(support(rule, Claim::UnmergedLora, anchor, 100, EvidenceTier::E2, g));
        }
        e.caps.push(CapRequest {
            claim: Claim::UnmergedLora,
            cap_id: CapId::NoBase,
            triggered_by: "TT-BASE-003",
        });
        e.caps.push(CapRequest {
            claim: Claim::UnmergedLora,
            cap_id: CapId::Questionnaire,
            triggered_by: "TT-FMT-009",
        });
        let s = score_claim(Claim::UnmergedLora, &e);
        assert_eq!(s.score_tenths, 250, "the lowest cap binds");
        assert_eq!(s.caps.len(), 2, "both caps are still reported");
    }

    #[test]
    fn contradiction_zeroes_the_claim_and_sets_the_band() {
        let mut e = Emissions::default();
        e.outcomes.push(support(
            "TT-LORA-003",
            Claim::UnmergedLora,
            "structure",
            100,
            EvidenceTier::E2,
            "a",
        ));
        e.outcomes.push(
            RuleOutcome::contradiction("TT-LORA-006", Facet::ParameterUpdate, "t")
                .on_claim(Claim::UnmergedLora)
                .artifact_digest("a".repeat(64)),
        );
        let r = judge(e);
        let s = r.claim_scores.iter().find(|s| s.claim == Claim::UnmergedLora).unwrap();
        assert_eq!(s.score_tenths, 0);
        let c = r.conclusion(Facet::ParameterUpdate).unwrap();
        assert_eq!(c.band, SupportBand::Contradicted);
        assert!(!c.method_label_emitted);
    }

    #[test]
    fn e1_only_evidence_cannot_name_a_method() {
        let mut e = Emissions::default();
        for (rule, anchor, g) in [
            ("TT-LORA-001", "structure", "dir::a"),
            ("TT-BASE-001", "base", "dir::b"),
            ("TT-BASE-005", "base_consistency", "dir::c"),
            ("TT-LORA-013", "load_or_remerge_record", "dir::d"),
            ("TT-BIND-001", "deployment_binding", "dir::e"),
        ] {
            e.outcomes.push(support(rule, Claim::UnmergedLora, anchor, 100, EvidenceTier::E1, g));
        }
        let r = judge(e);
        let c = r.conclusion(Facet::ParameterUpdate).unwrap();
        assert_eq!(c.score_tenths, 1000);
        assert!(c.abstentions.contains(&AbstentionId::EvidenceMutable));
        assert_eq!(c.band, SupportBand::InsufficientEvidence);
        assert!(!c.method_label_emitted);
    }

    #[test]
    fn a_high_score_without_a_method_anchor_is_partially_supported_not_a_label() {
        let mut e = Emissions::default();
        // Strong structural evidence, but via rules that are not method anchors.
        for (rule, anchor, g) in [
            ("TT-LORA-005", "structure", "artifact::a"),
            ("TT-BASE-009", "base", "artifact::b"),
            ("TT-BASE-009", "base_consistency", "artifact::c"),
            ("TT-LORA-013", "load_or_remerge_record", "dir::d"),
            ("TT-BIND-001", "deployment_binding", "dir::e"),
        ] {
            e.outcomes.push(support(rule, Claim::UnmergedLora, anchor, 100, EvidenceTier::E2, g));
        }
        let r = judge(e);
        let c = r.conclusion(Facet::ParameterUpdate).unwrap();
        assert_eq!(c.score_tenths, 1000);
        assert!(!c.method_label_emitted, "no method anchor fired");
        assert_eq!(c.band, SupportBand::PartiallySupported);
    }

    #[test]
    fn close_rivals_force_abstention() {
        let mut e = Emissions::default();
        e.outcomes.push(support(
            "TT-LORA-003",
            Claim::UnmergedLora,
            "structure",
            100,
            EvidenceTier::E2,
            "a",
        ));
        e.outcomes.push(support(
            "TT-DENSE-001",
            Claim::DenseFinetune,
            "pre_post",
            100,
            EvidenceTier::E2,
            "b",
        ));
        // 300 vs 150 tenths: within the 150 separation floor is false here, so make
        // them genuinely close.
        e.outcomes.push(support(
            "TT-DENSE-003",
            Claim::DenseFinetune,
            "optimizer_trainability",
            75,
            EvidenceTier::E2,
            "c",
        ));
        let r = judge(e);
        let c = r.conclusion(Facet::ParameterUpdate).unwrap();
        assert!(
            c.abstentions.contains(&AbstentionId::HybridTooClose),
            "scores {:?}",
            r.claim_scores
                .iter()
                .map(|s| (s.claim, s.score_tenths))
                .collect::<Vec<_>>()
        );
        assert_eq!(c.band, SupportBand::InsufficientEvidence);
    }

    #[test]
    fn merged_adapter_is_unreachable_in_stage_one_even_with_perfect_evidence() {
        let mut e = Emissions::default();
        // Give every anchor Stage 1 can actually reach its full value.
        for (anchor, g) in
            [("exact_base", "a"), ("pre_merge_adapter", "b"), ("binding", "c")]
        {
            e.outcomes.push(support(
                "TT-MERGE-003",
                Claim::MergedAdapter,
                anchor,
                100,
                EvidenceTier::E2,
                g,
            ));
        }
        let s = score_claim(Claim::MergedAdapter, &e);
        assert_eq!(s.raw_tenths, 450);
        assert!(s.raw_tenths < EMISSION_MIN_TENTHS);
    }

    #[test]
    fn out_of_scope_facet_reports_not_supplied() {
        let mut e = Emissions::default();
        e.out_of_scope.push(Facet::WeightOrigin);
        let r = judge(e);
        assert_eq!(r.conclusion(Facet::WeightOrigin).unwrap().band, SupportBand::NotSupplied);
    }

    #[test]
    fn every_facet_always_gets_a_conclusion() {
        let r = judge(Emissions::default());
        assert_eq!(r.conclusions.len(), Facet::ALL.len());
        for f in Facet::ALL {
            assert!(r.conclusion(*f).is_some());
        }
    }

    #[test]
    fn judging_is_order_independent() {
        let mk = || {
            let mut e = Emissions::default();
            e.outcomes.push(support(
                "TT-LORA-003",
                Claim::UnmergedLora,
                "structure",
                100,
                EvidenceTier::E2,
                "a",
            ));
            e.outcomes.push(support(
                "TT-BASE-001",
                Claim::UnmergedLora,
                "base",
                60,
                EvidenceTier::E1,
                "b",
            ));
            e
        };
        let a = mk();
        let mut b = mk();
        b.outcomes.reverse();
        assert_eq!(judge(a).conclusions_canon(), judge(b).conclusions_canon());
    }
}
