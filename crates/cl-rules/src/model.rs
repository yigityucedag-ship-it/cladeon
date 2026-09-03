//! Output types of the rules engine.
//!
//! Everything here is *judgement*, and nothing here parses. The split from
//! `cl-facts` is the point: a parser can be wrong about what a file says, and a rule
//! can be wrong about what that means, and keeping the two apart lets each be
//! argued about on its own.

use cl_core::canon::{CanonValue, Obj};
use cl_core::vocab::{
    AbstentionId, CapId, Claim, EvidenceTier, Facet, OutcomeKind, SupportBand,
};

/// One rule firing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleOutcome {
    /// A `CL-*` id from `docs/01-RULE-CATALOGUE.md`.
    pub rule_id: &'static str,
    pub kind: OutcomeKind,
    pub facet: Option<Facet>,
    /// The hypothesis this outcome speaks to, when it speaks to one.
    pub claim: Option<Claim>,
    /// The rubric anchor this outcome feeds, when it feeds one.
    pub anchor: Option<&'static str>,
    /// Achievement of that anchor, `0..=100`.
    pub achievement: u32,
    pub tier: Option<EvidenceTier>,
    /// Correlated-evidence marker. Outcomes sharing a group are one source.
    pub source_group: String,
    pub fact_ids: Vec<String>,
    /// Hex digests of the artifacts this outcome rests on.
    ///
    /// A contradiction with no artifact behind it is not a contradiction, and the
    /// engine asserts that invariant.
    pub artifact_sha256: Vec<String>,
    pub text: String,
}

impl RuleOutcome {
    pub fn new(rule_id: &'static str, kind: OutcomeKind, text: impl Into<String>) -> Self {
        RuleOutcome {
            rule_id,
            kind,
            facet: None,
            claim: None,
            anchor: None,
            achievement: 0,
            tier: None,
            source_group: String::new(),
            fact_ids: Vec::new(),
            artifact_sha256: Vec::new(),
            text: text.into(),
        }
    }

    #[must_use]
    pub fn support(
        rule_id: &'static str,
        claim: Claim,
        anchor: &'static str,
        achievement: u32,
        tier: EvidenceTier,
        text: impl Into<String>,
    ) -> Self {
        let mut o = RuleOutcome::new(rule_id, OutcomeKind::SupportingEvidence, text);
        o.facet = Some(claim.facet());
        o.claim = Some(claim);
        o.anchor = Some(anchor);
        o.achievement = achievement.min(100);
        o.tier = Some(tier);
        o
    }

    #[must_use]
    pub fn missing(
        rule_id: &'static str,
        claim: Claim,
        anchor: &'static str,
        text: impl Into<String>,
    ) -> Self {
        let mut o = RuleOutcome::new(rule_id, OutcomeKind::MissingAnchor, text);
        o.facet = Some(claim.facet());
        o.claim = Some(claim);
        o.anchor = Some(anchor);
        o
    }

    #[must_use]
    pub fn contradiction(rule_id: &'static str, facet: Facet, text: impl Into<String>) -> Self {
        let mut o = RuleOutcome::new(rule_id, OutcomeKind::Contradiction, text);
        o.facet = Some(facet);
        o
    }

    #[must_use]
    pub fn ambiguity(rule_id: &'static str, text: impl Into<String>) -> Self {
        RuleOutcome::new(rule_id, OutcomeKind::Ambiguity, text)
    }

    #[must_use]
    pub fn limitation(rule_id: &'static str, text: impl Into<String>) -> Self {
        RuleOutcome::new(rule_id, OutcomeKind::CoverageLimitation, text)
    }

    #[must_use]
    pub fn next_evidence(rule_id: &'static str, text: impl Into<String>) -> Self {
        RuleOutcome::new(rule_id, OutcomeKind::NextEvidenceRequest, text)
    }

    #[must_use]
    pub fn on_facet(mut self, f: Facet) -> Self {
        self.facet = Some(f);
        self
    }
    #[must_use]
    pub fn on_claim(mut self, c: Claim) -> Self {
        self.claim = Some(c);
        self.facet = Some(c.facet());
        self
    }
    #[must_use]
    pub fn group(mut self, g: impl Into<String>) -> Self {
        self.source_group = g.into();
        self
    }
    #[must_use]
    pub fn facts(mut self, ids: impl IntoIterator<Item = String>) -> Self {
        self.fact_ids.extend(ids);
        self
    }
    #[must_use]
    pub fn fact(mut self, id: impl Into<String>) -> Self {
        self.fact_ids.push(id.into());
        self
    }
    #[must_use]
    pub fn artifact_digest(mut self, d: impl Into<String>) -> Self {
        self.artifact_sha256.push(d.into());
        self
    }

    pub fn to_canon(&self) -> CanonValue {
        let mut o = Obj::new()
            .with("rule_id", self.rule_id)
            .with("ruleset_version", cl_core::RULESET_VERSION)
            .with("kind", self.kind)
            .with("text", self.text.as_str());
        if let Some(f) = self.facet {
            o.set("facet", f);
        }
        if let Some(c) = self.claim {
            o.set("claim", c);
        }
        if let Some(a) = self.anchor {
            o.set("anchor", a);
            o.set("achievement", self.achievement);
        }
        if let Some(t) = self.tier {
            o.set("evidence_tier", t);
        }
        if !self.source_group.is_empty() {
            o.set("source_group", self.source_group.as_str());
        }
        if !self.fact_ids.is_empty() {
            let mut ids = self.fact_ids.clone();
            ids.sort();
            o.set("fact_ids", ids);
        }
        if !self.artifact_sha256.is_empty() {
            let mut ds = self.artifact_sha256.clone();
            ds.sort();
            ds.dedup();
            o.set("artifact_sha256", ds);
        }
        CanonValue::Obj(o)
    }
}

/// How much of one rubric anchor was achieved, and by what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorScore {
    pub anchor: &'static str,
    pub weight: u32,
    pub achievement: u32,
    pub witness_rule: Option<&'static str>,
    pub witness_group: Option<String>,
    pub witness_tier: Option<EvidenceTier>,
}

impl AnchorScore {
    pub fn to_canon(&self) -> CanonValue {
        let mut o = Obj::new()
            .with("anchor", self.anchor)
            .with("weight", self.weight)
            .with("achievement", self.achievement);
        if let Some(r) = self.witness_rule {
            o.set("witness_rule", r);
        }
        if let Some(g) = &self.witness_group {
            o.set("witness_group", g.as_str());
        }
        if let Some(t) = self.witness_tier {
            o.set("witness_tier", t);
        }
        CanonValue::Obj(o)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapApplied {
    pub cap_id: CapId,
    pub max_tenths: i64,
    pub triggered_by: Vec<&'static str>,
}

impl CapApplied {
    pub fn to_canon(&self) -> CanonValue {
        let mut t = self.triggered_by.clone();
        t.sort_unstable();
        t.dedup();
        CanonValue::Obj(
            Obj::new()
                .with("cap_id", self.cap_id)
                .with("max_tenths", self.max_tenths)
                .with("reason", self.cap_id.render())
                .with("triggered_by", t.into_iter().map(|s| s.to_string()).collect::<Vec<_>>()),
        )
    }
}

/// The scored result for one hypothesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimScore {
    pub claim: Claim,
    /// Before caps.
    pub raw_tenths: i64,
    /// After caps and contradictions. This is the reported number.
    pub score_tenths: i64,
    pub rubric_divisor: u32,
    pub anchors: Vec<AnchorScore>,
    pub caps: Vec<CapApplied>,
    pub best_tier: Option<EvidenceTier>,
    /// Distinct correlated-evidence groups behind the achieved anchors.
    pub source_groups: Vec<String>,
    pub contradicted_by: Vec<&'static str>,
}

impl ClaimScore {
    pub fn is_contradicted(&self) -> bool {
        !self.contradicted_by.is_empty()
    }

    pub fn to_canon(&self) -> CanonValue {
        let mut o = Obj::new()
            .with("claim", self.claim)
            .with("raw_tenths", self.raw_tenths)
            .with("score_tenths", self.score_tenths)
            .with("rubric_divisor", self.rubric_divisor)
            .with("independent_source_count", self.source_groups.len())
            .with(
                "anchor_scores",
                CanonValue::Arr(self.anchors.iter().map(|a| a.to_canon()).collect()),
            )
            .with("caps_applied", CanonValue::Arr(self.caps.iter().map(|c| c.to_canon()).collect()));
        if let Some(t) = self.best_tier {
            o.set("best_evidence_tier", t);
        }
        if !self.contradicted_by.is_empty() {
            let mut c = self.contradicted_by.clone();
            c.sort_unstable();
            o.set("contradicted_by", c.into_iter().map(|s| s.to_string()).collect::<Vec<_>>());
        }
        CanonValue::Obj(o)
    }
}

/// The reported answer for one facet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conclusion {
    pub facet: Facet,
    /// The best-supported hypothesis, present even when the band abstains, so the
    /// reader can see what was considered and rejected.
    pub claim: Option<Claim>,
    pub band: SupportBand,
    pub score_tenths: i64,
    pub rubric_divisor: u32,
    pub anchors: Vec<AnchorScore>,
    pub caps: Vec<CapApplied>,
    pub abstentions: Vec<AbstentionId>,
    pub best_tier: Option<EvidenceTier>,
    /// True only when every clause of the emission gate held.
    pub method_label_emitted: bool,
    pub alternatives: Vec<(Claim, i64)>,
    pub rule_ids: Vec<&'static str>,
}

impl Conclusion {
    pub fn to_canon(&self) -> CanonValue {
        let mut rules = self.rule_ids.clone();
        rules.sort_unstable();
        rules.dedup();
        let mut o = Obj::new()
            .with("facet", self.facet)
            .with("band", self.band)
            .with("band_text", self.band.render())
            .with("score_tenths", self.score_tenths)
            .with("rubric_divisor", self.rubric_divisor)
            .with("method_label_emitted", self.method_label_emitted)
            .with(
                "anchor_scores",
                CanonValue::Arr(self.anchors.iter().map(|a| a.to_canon()).collect()),
            )
            .with("caps_applied", CanonValue::Arr(self.caps.iter().map(|c| c.to_canon()).collect()))
            .with(
                "abstentions",
                CanonValue::Arr(
                    self.abstentions
                        .iter()
                        .map(|a| {
                            CanonValue::Obj(
                                Obj::new().with("id", *a).with("reason", a.render()),
                            )
                        })
                        .collect(),
                ),
            )
            .with(
                "alternatives",
                CanonValue::Arr(
                    self.alternatives
                        .iter()
                        .map(|(c, s)| {
                            CanonValue::Obj(Obj::new().with("claim", *c).with("score_tenths", *s))
                        })
                        .collect(),
                ),
            )
            .with("rule_ids", rules.into_iter().map(|s| s.to_string()).collect::<Vec<_>>());
        if let Some(c) = self.claim {
            o.set("claim", c);
            o.set("claim_text", c.render());
        }
        if let Some(t) = self.best_tier {
            o.set("best_evidence_tier", t);
        }
        CanonValue::Obj(o)
    }
}

/// Everything the engine concluded.
#[derive(Debug, Clone, Default)]
pub struct RuleReport {
    pub outcomes: Vec<RuleOutcome>,
    pub claim_scores: Vec<ClaimScore>,
    pub conclusions: Vec<Conclusion>,
}

impl RuleReport {
    pub fn outcomes_of(&self, kind: OutcomeKind) -> impl Iterator<Item = &RuleOutcome> {
        self.outcomes.iter().filter(move |o| o.kind == kind)
    }

    pub fn contradictions(&self) -> Vec<&'static str> {
        self.ids_of(OutcomeKind::Contradiction)
    }
    pub fn limitations(&self) -> Vec<&'static str> {
        self.ids_of(OutcomeKind::CoverageLimitation)
    }
    pub fn ambiguities(&self) -> Vec<&'static str> {
        self.ids_of(OutcomeKind::Ambiguity)
    }
    pub fn next_evidence_requests(&self) -> Vec<&'static str> {
        self.ids_of(OutcomeKind::NextEvidenceRequest)
    }

    fn ids_of(&self, kind: OutcomeKind) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.outcomes_of(kind).map(|o| o.rule_id).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    pub fn conclusion(&self, facet: Facet) -> Option<&Conclusion> {
        self.conclusions.iter().find(|c| c.facet == facet)
    }

    pub fn fired(&self, rule_id: &str) -> bool {
        self.outcomes.iter().any(|o| o.rule_id == rule_id)
    }

    pub fn outcomes_canon(&self) -> CanonValue {
        let mut sorted: Vec<&RuleOutcome> = self.outcomes.iter().collect();
        sorted.sort_by(|a, b| {
            a.rule_id
                .cmp(b.rule_id)
                .then(a.source_group.cmp(&b.source_group))
                .then(a.text.cmp(&b.text))
        });
        CanonValue::Arr(sorted.iter().map(|o| o.to_canon()).collect())
    }

    pub fn conclusions_canon(&self) -> CanonValue {
        let mut sorted: Vec<&Conclusion> = self.conclusions.iter().collect();
        sorted.sort_by_key(|c| c.facet.as_str());
        CanonValue::Arr(sorted.iter().map(|c| c.to_canon()).collect())
    }

    pub fn claim_scores_canon(&self) -> CanonValue {
        let mut sorted: Vec<&ClaimScore> = self.claim_scores.iter().collect();
        sorted.sort_by_key(|c| c.claim.as_str());
        CanonValue::Arr(sorted.iter().map(|c| c.to_canon()).collect())
    }

    /// Every piece of rendered text, for the forbidden-language guard.
    pub fn all_text(&self) -> String {
        let mut s = String::new();
        for o in &self.outcomes {
            s.push_str(&o.text);
            s.push('\n');
        }
        for c in &self.conclusions {
            s.push_str(c.band.render());
            s.push('\n');
            if let Some(cl) = c.claim {
                s.push_str(cl.render());
                s.push('\n');
            }
            for a in &c.abstentions {
                s.push_str(a.render());
                s.push('\n');
            }
            for cap in &c.caps {
                s.push_str(cap.cap_id.render());
                s.push('\n');
            }
        }
        s
    }
}
