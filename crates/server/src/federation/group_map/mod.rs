//! Group mappings of an identity provider: an upstream claim value puts
//! the signed-in user into a local group. A membership a provider's
//! mappings created carries its `idp_id`; a sign-in through that provider
//! adds and removes only such rows, so manual memberships (and those of
//! other providers) are never touched. A row both manual and mapped loses
//! only the mapping mark when the claim value goes.

mod db;

use std::collections::{BTreeMap, BTreeSet};

use entity::idp_group_mappings;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

pub use db::{Changes, apply, count, drop_owned, list, pairs, sync};

use super::profile;

/// Entries of one claim; Entra caps its `groups` claim at 200. A longer
/// array is truncated by the upstream's rules, not ours, so it is not read.
pub const MAX_CLAIM_VALUES: usize = 256;
/// Mappings per identity provider.
pub const MAX_MAPPINGS: u64 = 100;

/// `(claim, value)` pairs a provider's mappings name.
pub type Pair = (String, String);

/// What a verified token said for a provider's mappings: the pairs that
/// were decided (`read`) and, of those, the ones the token carried. Kept
/// with a parked identity until stage `link` completes the sign-in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mapped {
    pub read: BTreeSet<Pair>,
    pub present: BTreeSet<Pair>,
}

/// Decides the `asked` pairs against a verified token's `claims`. A claim
/// is a string or an array of strings, each 1–256 bytes without control
/// characters (others are skipped); a missing claim carries none of its
/// values. A claim the token can't state in full — an array over
/// [`MAX_CLAIM_VALUES`], or one the upstream moved out of the token
/// (`_claim_names`, Entra's group overage) — decides nothing.
pub fn extract(claims: &Map<String, Value>, asked: &[Pair]) -> Mapped {
    let moved = claims.get("_claim_names").and_then(Value::as_object);
    // Each claim's valid values, built once however many pairs ask it.
    let mut stated: BTreeMap<&str, Option<BTreeSet<&str>>> = BTreeMap::new();
    let mut out = Mapped::default();
    for (claim, value) in asked {
        let values = stated.entry(claim.as_str()).or_insert_with(|| {
            if moved.is_some_and(|m| m.contains_key(claim)) {
                return None;
            }
            match claims.get(claim) {
                Some(Value::String(v)) => Some(valid([v.as_str()])),
                Some(Value::Array(list)) if list.len() > MAX_CLAIM_VALUES => None,
                Some(Value::Array(list)) => Some(valid(list.iter().filter_map(Value::as_str))),
                _ => Some(BTreeSet::new()),
            }
        });
        let Some(values) = values else { continue };
        let pair = (claim.clone(), value.clone());
        if values.contains(value.as_str()) {
            out.present.insert(pair.clone());
        }
        out.read.insert(pair);
    }
    out
}

fn valid<'a>(values: impl IntoIterator<Item = &'a str>) -> BTreeSet<&'a str> {
    values
        .into_iter()
        .filter(|v| profile::is_clean_token(v))
        .collect()
}

/// The groups `mappings` grant for `mapped` and, apart, those a mapping
/// whose pair wasn't decided could grant (mappings changed after the token
/// was checked, or a claim not stated in full): their memberships are left
/// for the next sign-in.
pub fn wanted(
    mappings: &[idp_group_mappings::Model],
    mapped: &Mapped,
) -> (BTreeSet<Uuid>, BTreeSet<Uuid>) {
    let mut wanted = BTreeSet::new();
    let mut undecided = BTreeSet::new();
    for m in mappings {
        let pair = (m.claim.clone(), m.value.clone());
        if !mapped.read.contains(&pair) {
            undecided.insert(m.group_id);
        } else if mapped.present.contains(&pair) {
            wanted.insert(m.group_id);
        }
    }
    (wanted, undecided)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn mapping(claim: &str, value: &str, group_id: Uuid) -> idp_group_mappings::Model {
        idp_group_mappings::Model {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            idp_id: Uuid::nil(),
            claim: claim.into(),
            value: value.into(),
            group_id,
            created_at: chrono::Utc::now().fixed_offset(),
        }
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<Pair> {
        list.iter()
            .map(|(c, v)| ((*c).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn pair(c: &str, v: &str) -> Pair {
        (c.to_owned(), v.to_owned())
    }

    #[test]
    fn extract_reads_only_mapped_values() {
        let claims = json!({
            "groups": ["a", "b", "a", 7, "", "x\u{0}", "y".repeat(257), "other"],
            "roles": "admin",
            "obj": {"a": 1},
            "unasked": ["z"],
        });
        let asked = pairs(&[
            ("groups", "a"),
            ("groups", "x\u{0}"),
            ("groups", "c"),
            ("roles", "admin"),
            ("obj", "a"),
            ("missing", "m"),
        ]);
        let got = extract(claims.as_object().unwrap(), &asked);
        assert_eq!(got.read, asked.iter().cloned().collect());
        assert_eq!(
            got.present,
            BTreeSet::from([pair("groups", "a"), pair("roles", "admin")])
        );
    }

    #[test]
    fn claims_not_stated_in_full_decide_nothing() {
        let many: Vec<String> = (0..300).map(|i| format!("g{i}")).collect();
        let claims = json!({
            "big": many,
            "groups": ["eng"],
            "_claim_names": { "groups": "src1" },
            "_claim_sources": { "src1": { "endpoint": "https://graph.example" } },
            "roles": many[..MAX_CLAIM_VALUES].to_vec(),
        });
        let asked = pairs(&[
            ("big", "g1"),
            ("big", "g299"),
            ("groups", "eng"),
            ("roles", "g255"),
        ]);
        let got = extract(claims.as_object().unwrap(), &asked);
        assert_eq!(got.read, BTreeSet::from([pair("roles", "g255")]));
        assert_eq!(got.present, got.read);
        let (g1, g2) = (Uuid::now_v7(), Uuid::now_v7());
        let mappings = [mapping("big", "g299", g1), mapping("groups", "eng", g2)];
        assert_eq!(
            wanted(&mappings, &got),
            (BTreeSet::new(), BTreeSet::from([g1, g2]))
        );
    }

    #[test]
    fn wanted_matches_claim_and_value_exactly() {
        let (g1, g2, g3) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let mappings = [
            mapping("groups", "eng", g1),
            mapping("roles", "eng", g2),
            mapping("groups", "Ops", g3),
            mapping("groups", "dev", g1),
        ];
        let asked: Vec<Pair> = mappings
            .iter()
            .map(|m| (m.claim.clone(), m.value.clone()))
            .collect();
        let claims = json!({ "groups": ["eng", "dev", "ops"] });
        let values = extract(claims.as_object().unwrap(), &asked);
        assert_eq!(
            wanted(&mappings, &values),
            (BTreeSet::from([g1]), BTreeSet::new())
        );
        let none = extract(&Map::new(), &asked);
        assert_eq!(wanted(&mappings, &none), (BTreeSet::new(), BTreeSet::new()));
    }

    #[test]
    fn mappings_on_pairs_not_read_leave_their_groups_undecided() {
        let (g1, g2, g3) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let mappings = [
            mapping("groups", "eng", g1),
            mapping("roles", "ops", g2),
            mapping("groups", "new", g3),
        ];
        let claims = json!({ "groups": ["eng", "new"], "roles": ["ops"] });
        let values = extract(claims.as_object().unwrap(), &pairs(&[("groups", "eng")]));
        assert_eq!(
            wanted(&mappings, &values),
            (BTreeSet::from([g1]), BTreeSet::from([g2, g3]))
        );
        // A parked identity from before group mappings read nothing.
        assert_eq!(
            wanted(&mappings, &Mapped::default()),
            (BTreeSet::new(), BTreeSet::from([g1, g2, g3]))
        );
    }
}
