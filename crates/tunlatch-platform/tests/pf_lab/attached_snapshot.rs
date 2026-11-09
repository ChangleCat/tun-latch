//! Disabled-PF snapshot for an isolated root-call experiment. This is not atomic and
//! does not establish exclusivity, rule ownership, or protection. Admission is
//! deliberately limited to empty root and foreign table views.
use std::collections::BTreeSet;
use std::io;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::root_hook_readback::{self, Observation};
use super::sync_observe::{self, Slot};

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Snapshot {
    pub(crate) root_rules: Vec<u8>,
    pub(crate) leaf: Slot,
    pub(crate) foreign: [u8; 32],
    pub(crate) states_and_sources_empty: bool,
    pub(crate) enable_baseline_clear: bool,
}

fn refused(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn valid_boot(boot: &str) -> bool {
    boot.len() == 36
        && boot.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn valid_anchor(anchor: &str) -> bool {
    anchor.strip_prefix("tunlatch-lab-").is_some_and(|suffix| {
        suffix.len() == 32
            && !suffix.bytes().all(|b| b == b'0')
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn contains(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|w| w == needle)
}
fn checked_rules(data: &[u8], own: &str, context: Option<&str>, nat: bool) -> io::Result<()> {
    let text = std::str::from_utf8(data).map_err(|_| refused("invalid rules text"))?;
    if !text.is_ascii()
        || (!text.is_empty() && !text.ends_with('\n'))
        || text
            .bytes()
            .any(|b| b.is_ascii_control() && b != b'\n' && b != b'\t')
        || contains(data, own.as_bytes())
    {
        return Err(refused("invalid rules or own reference"));
    }
    for line in text.lines() {
        let mut words = line.split_ascii_whitespace();
        let class = words.next().ok_or_else(|| refused("empty rule"))?;
        let allowed = if nat {
            matches!(
                class,
                "nat" | "rdr" | "binat" | "no" | "nat-anchor" | "rdr-anchor" | "binat-anchor"
            )
        } else {
            matches!(class, "pass" | "block" | "anchor" | "scrub-anchor")
        };
        let second = words.next();
        if !allowed
            || second.is_none()
            || (class == "no" && !matches!(second, Some("nat" | "rdr" | "binat")))
        {
            return Err(refused("unsupported rule class"));
        }
    }
    sync_observe::root_calls(data, own, context)
}

// Existing calls may dispatch to empty leaf slots, including the system wildcard
// tree. Require every target to have been inventoried before calling it inert.
fn inert_calls(data: &[u8], context: Option<&str>, inventory: &BTreeSet<String>) -> bool {
    std::str::from_utf8(data).is_ok_and(|text| {
        text.lines().all(|line| {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            let target = match fields.as_slice() {
                [
                    "anchor" | "nat-anchor" | "rdr-anchor" | "binat-anchor",
                    target,
                    "all",
                ]
                | ["scrub-anchor", target, "all", "fragment", "reassemble"] => target,
                _ => return false,
            };
            let Some(target) = target.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
                return false;
            };
            let literal = target.strip_suffix("/*").unwrap_or(target);
            match context {
                Some(parent) => inventory.contains(&format!("{parent}/{literal}")),
                None => inventory.contains(literal),
            }
        })
    })
}

fn zero_state_count(info: &[u8]) -> bool {
    let Ok(info) = std::str::from_utf8(info) else {
        return false;
    };
    let mut entries = info
        .lines()
        .filter_map(|line| line.trim_ascii().strip_prefix("current entries"));
    entries
        .next()
        .is_some_and(|count| count.trim_ascii() == "0")
        && entries.next().is_none()
}

fn no_interface_skips(bytes: &[u8]) -> bool {
    let Ok(interfaces) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut lines = interfaces.lines();
    bytes.ends_with(b"\n")
        && lines.next() == Some("ALL")
        && lines.clone().next().is_some()
        && lines.all(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        })
}
fn hash_item(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
fn remove_own_inventory(raw: &[u8], own: &str) -> Vec<u8> {
    raw.split_inclusive(|b| *b == b'\n')
        .filter(|line| std::str::from_utf8(line).is_ok_and(|s| s.trim() != own))
        .flatten()
        .copied()
        .collect()
}

/// The callbacks must query the literal arguments and current boot. This function is
/// deliberately injectable for offline tests; reads are sequential, not atomic.
pub(crate) fn collect<B, Q>(
    anchor: &str,
    expected_boot: &str,
    mut boot: B,
    mut query: Q,
) -> io::Result<Snapshot>
where
    B: FnMut() -> io::Result<String>,
    Q: FnMut(&[&str]) -> io::Result<Vec<u8>>,
{
    if !valid_anchor(anchor)
        || !valid_boot(expected_boot)
        || !boot()?.eq_ignore_ascii_case(expected_boot)
    {
        return Err(refused("invalid identity or boot changed"));
    }
    let mut total = 0_usize;
    let mut query = |args: &[&str]| -> io::Result<Vec<u8>> {
        let out = query(args)?;
        total = total
            .checked_add(out.len())
            .ok_or_else(|| refused("snapshot size overflow"))?;
        if out.len() > 65_536
            || total > 128 * 1024
            || out.split(|b| *b == b'\n').any(|l| l.starts_with(b"pfctl:"))
        {
            return Err(refused("excessive output or PF error"));
        }
        Ok(out)
    };
    let status = |info: &[u8], refs: &[u8]| {
        info.starts_with(b"Status: Disabled ")
            && info.ends_with(b"\n")
            && info.is_ascii()
            && !info
                .iter()
                .any(|b| b.is_ascii_control() && !matches!(b, b'\n' | b'\t'))
            && refs == b"No pf starter references held\n"
    };
    let info_before = query(&["-s", "info"])?;
    if !status(&info_before, &query(&["-s", "References"])?) {
        return Err(refused("PF enabled or references held"));
    }
    let states_before = query(&["-s", "states"])?;
    let sources_before = query(&["-s", "Sources"])?;
    let interfaces_before = query(&["-v", "-s", "Interfaces"])?;
    let root = query(&["-s", "rules"])?;
    let call = format!("anchor \"{anchor}\" all\n");
    let mut without = Vec::new();
    let mut calls = 0;
    for line in root.split_inclusive(|b| *b == b'\n') {
        if line == call.as_bytes() {
            calls += 1;
        } else {
            without.extend_from_slice(line);
        }
    }
    if calls > 1 {
        return Err(refused("multiple own calls"));
    }
    root_hook_readback::validate_index(
        Observation {
            bytes: &without,
            complete: true,
        },
        anchor,
        0,
    )
    .map_err(refused)?;
    checked_rules(&without, anchor, None, false)?;
    let nat = query(&["-s", "nat"])?;
    checked_rules(&nat, anchor, None, true)?;
    if !query(&["-s", "Tables"])?.is_empty() {
        return Err(refused("root tables are not empty"));
    }
    let inventory_raw = query(&["-v", "-s", "Anchors"])?;
    let top_raw = query(&["-s", "Anchors"])?;
    let names = sync_observe::inventory(&inventory_raw)?;
    let top = sync_observe::inventory(&top_raw)?;
    if top != names.iter().filter(|n| !n.contains('/')).cloned().collect()
        || names
            .iter()
            .any(|name| name != anchor && name.split('/').any(|p| p == anchor))
        || names.iter().filter(|name| name.as_str() != anchor).count() > 16
    {
        return Err(refused("inconsistent or unsafe inventory"));
    }
    let mut hash = Sha256::new();
    hash.update(b"tunlatch-attached-foreign-v1\0");
    let foreign_names: BTreeSet<_> = names
        .iter()
        .filter(|n| n.as_str() != anchor)
        .cloned()
        .collect();
    let mut foreign_inert =
        inert_calls(&without, None, &foreign_names) && inert_calls(&nat, None, &foreign_names);
    for bytes in [
        &without[..],
        &nat,
        &remove_own_inventory(&inventory_raw, anchor),
        &remove_own_inventory(&top_raw, anchor),
    ] {
        hash_item(&mut hash, bytes);
    }
    for name in names.iter().filter(|name| name.as_str() != anchor) {
        let rules = query(&["-a", name, "-s", "rules"])?;
        let nat = query(&["-a", name, "-s", "nat"])?;
        if !query(&["-a", name, "-s", "Tables"])?.is_empty() {
            return Err(refused("foreign tables are not empty"));
        }
        checked_rules(&rules, anchor, Some(name), false)?;
        checked_rules(&nat, anchor, Some(name), true)?;
        foreign_inert &= inert_calls(&rules, Some(name), &foreign_names)
            && inert_calls(&nat, Some(name), &foreign_names);
        for bytes in [name.as_bytes(), &rules, &nat] {
            hash_item(&mut hash, bytes);
        }
    }
    let leaf = if top.contains(anchor) {
        for kind in ["nat", "Tables", "Anchors"] {
            if !query(&["-a", anchor, "-s", kind])?.is_empty() {
                return Err(refused("own slot is not a leaf"));
            }
        }
        let rules = query(&["-a", anchor, "-s", "rules"])?;
        checked_rules(&rules, anchor, Some(anchor), false)?;
        if rules.is_empty() {
            Slot::Empty
        } else {
            Slot::Active(rules)
        }
    } else {
        Slot::Absent
    };
    let states_after = query(&["-s", "states"])?;
    let sources_after = query(&["-s", "Sources"])?;
    let interfaces_after = query(&["-v", "-s", "Interfaces"])?;
    let info_after = query(&["-s", "info"])?;
    if root != query(&["-s", "rules"])?
        || nat != query(&["-s", "nat"])?
        || inventory_raw != query(&["-v", "-s", "Anchors"])?
        || top_raw != query(&["-s", "Anchors"])?
        || !status(&info_after, &query(&["-s", "References"])?)
        || !boot()?.eq_ignore_ascii_case(expected_boot)
    {
        return Err(refused("PF state or boot changed"));
    }
    let states_and_sources_empty = zero_state_count(&info_before)
        && zero_state_count(&info_after)
        && states_before.is_empty()
        && states_after.is_empty()
        && sources_before.is_empty()
        && sources_after.is_empty();
    Ok(Snapshot {
        root_rules: root,
        leaf,
        foreign: hash.finalize().into(),
        states_and_sources_empty,
        enable_baseline_clear: foreign_inert
            && states_and_sources_empty
            && no_interface_skips(&interfaces_before)
            && interfaces_before == interfaces_after,
    })
}

/// Reads fixed PF views only; callers must separately establish exclusive coordination.
pub(crate) fn read(anchor: &str, expected_boot: &str) -> io::Result<Snapshot> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut captured = 0_usize;
    let result = collect(
        anchor,
        expected_boot,
        || sync_observe::boot_until(deadline),
        |args| {
            let (out, size) = sync_observe::execute_program("/sbin/pfctl", args, deadline)?;
            captured = captured
                .checked_add(size)
                .ok_or_else(|| refused("snapshot size overflow"))?;
            if captured > 128 * 1024 {
                return Err(refused("snapshot exceeds aggregate limit"));
            }
            Ok(out)
        },
    )?;
    if Instant::now() >= deadline {
        return Err(refused("observation deadline exceeded"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    const OWN: &str = "tunlatch-lab-0123456789abcdef0123456789abcdef";
    const BOOT: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const ROOT: &str =
        "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n";
    const DISABLED: &str = "Status: Disabled now\nState Table\n  current entries 0  \n";
    const INTERFACES: &[u8] = b"ALL\nen0\n";

    fn fixture(
        present: bool,
        root: &str,
        foreign: &str,
        info: &str,
        reference: &str,
    ) -> io::Result<Snapshot> {
        collect(
            OWN,
            BOOT,
            || Ok(BOOT.into()),
            |args| {
                Ok(match args {
                    ["-s", "info"] => info.as_bytes().to_vec(),
                    ["-s", "References"] => reference.as_bytes().to_vec(),
                    ["-s", "states" | "Sources"] => Vec::new(),
                    ["-v", "-s", "Interfaces"] => INTERFACES.to_vec(),
                    ["-s", "rules"] => root.as_bytes().to_vec(),
                    ["-s", "nat"] => b"nat-anchor \"com.apple/*\" all\n".to_vec(),
                    ["-s", "Tables"] => Vec::new(),
                    ["-v", "-s", "Anchors"] | ["-s", "Anchors"] => {
                        if present {
                            format!("  com.apple\n  {OWN}\n").into_bytes()
                        } else {
                            b"  com.apple\n".to_vec()
                        }
                    }
                    ["-a", "com.apple", "-s", "rules"] => foreign.as_bytes().to_vec(),
                    ["-a", _, "-s", "rules" | "nat" | "Tables" | "Anchors"] => Vec::new(),
                    _ => return Err(refused("unexpected fixture query")),
                })
            },
        )
    }
    fn take(present: bool, root: &str, foreign: &str) -> io::Result<Snapshot> {
        fixture(
            present,
            root,
            foreign,
            DISABLED,
            "No pf starter references held\n",
        )
    }
    #[test]
    fn captures_raw_and_stable_foreign_across_exact_attachment() -> io::Result<()> {
        let before = take(false, ROOT, "")?;
        let attached_root = format!("{ROOT}anchor \"{OWN}\" all\n");
        let after = take(true, &attached_root, "")?;
        assert_eq!(before.leaf, Slot::Absent);
        assert_eq!(after.leaf, Slot::Empty);
        assert_eq!(after.root_rules, attached_root.as_bytes());
        assert_eq!(before.foreign, after.foreign);
        assert!(before.enable_baseline_clear && after.enable_baseline_clear);
        let foreign_rule = take(true, &attached_root, "block drop all\n")?;
        assert_ne!(after.foreign, foreign_rule.foreign);
        assert!(!foreign_rule.enable_baseline_clear);
        assert!(!take(true, &attached_root, "anchor \"unlisted/*\" all\n")?.enable_baseline_clear);
        assert!(
            take(
                true,
                &attached_root.replace("fragment reassemble", "fragment crop"),
                ""
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn rejects_tables_at_root_or_foreign_and_accepts_owned_label() {
        for table_scope in ["root", "foreign", "none"] {
            let label =
                b"pass out quick all label \"tunlatch-lab:0123456789abcdef0123456789abcdef\"\n";
            let result = collect(
                OWN,
                BOOT,
                || Ok(BOOT.into()),
                |args| {
                    Ok(match args {
                        ["-s", "info"] => DISABLED.as_bytes().to_vec(),
                        ["-s", "References"] => b"No pf starter references held\n".to_vec(),
                        ["-s", "states" | "Sources"] => Vec::new(),
                        ["-v", "-s", "Interfaces"] => INTERFACES.to_vec(),
                        ["-s", "rules"] => format!("{ROOT}anchor \"{OWN}\" all\n").into_bytes(),
                        ["-s", "nat"] => Vec::new(),
                        ["-s", "Tables"] => {
                            if table_scope == "root" {
                                b"example\n".to_vec()
                            } else {
                                Vec::new()
                            }
                        }
                        ["-s", "Anchors"] | ["-v", "-s", "Anchors"] => {
                            format!("com.apple\n{OWN}\n").into_bytes()
                        }
                        ["-a", "com.apple", "-s", "Tables"] => {
                            if table_scope == "foreign" {
                                b"example\n".to_vec()
                            } else {
                                Vec::new()
                            }
                        }
                        ["-a", name, "-s", "rules"] if *name == OWN => label.to_vec(),
                        ["-a", _, "-s", "rules" | "nat" | "Tables" | "Anchors"] => Vec::new(),
                        _ => return Err(refused("unexpected query")),
                    })
                },
            );
            if table_scope == "none" {
                assert_eq!(
                    result.map(|snapshot| snapshot.leaf).ok(),
                    Some(Slot::Active(label.to_vec()))
                );
            } else {
                assert!(result.is_err(), "{table_scope}");
            }
        }
    }

    #[test]
    fn enable_baseline_requires_two_clear_state_and_interface_views() -> io::Result<()> {
        for failure in [
            "none",
            "state",
            "source",
            "count",
            "skip",
            "interfaces",
            "root",
        ] {
            let mut interface_reads = 0;
            let mut root_reads = 0;
            let result = collect(
                OWN,
                BOOT,
                || Ok(BOOT.into()),
                |args| {
                    Ok(match args {
                        ["-s", "info"] if failure == "count" => {
                            DISABLED.replace("entries 0", "entries 1").into_bytes()
                        }
                        ["-s", "info"] => DISABLED.as_bytes().to_vec(),
                        ["-s", "References"] => b"No pf starter references held\n".to_vec(),
                        ["-s", "states"] if failure == "state" => b"one state\n".to_vec(),
                        ["-s", "Sources"] if failure == "source" => b"one source\n".to_vec(),
                        ["-v", "-s", "Interfaces"] => {
                            interface_reads += 1;
                            match failure {
                                "skip" => b"ALL\nen0 (skip)\n".to_vec(),
                                "interfaces" if interface_reads > 1 => b"ALL\nen1\n".to_vec(),
                                _ => INTERFACES.to_vec(),
                            }
                        }
                        ["-s", "rules"] => {
                            root_reads += 1;
                            if failure == "root" && root_reads > 1 {
                                ROOT.as_bytes().to_vec()
                            } else {
                                Vec::new()
                            }
                        }
                        ["-s", "states" | "Sources" | "nat" | "Tables" | "Anchors"]
                        | ["-v", "-s", "Anchors"] => Vec::new(),
                        _ => return Err(refused("unexpected fixture query")),
                    })
                },
            );
            if failure == "root" {
                assert!(result.is_err());
            } else {
                assert_eq!(
                    result?.enable_baseline_clear,
                    failure == "none",
                    "{failure}"
                );
            }
        }
        Ok(())
    }
    #[test]
    fn refuses_bad_calls_state_and_references() {
        for bad in [
            format!("{ROOT}anchor \"{OWN}\" quick all\n"),
            format!("{ROOT}anchor \"{OWN}\" all\nanchor \"{OWN}\" all\n"),
            format!("{ROOT}nat-anchor \"{OWN}\" all\n"),
            format!("{ROOT}unknown all\n"),
        ] {
            assert!(take(true, &bad, "").is_err());
        }
        assert!(take(true, ROOT, &format!("anchor \"{OWN}\" all\n")).is_err());
        assert!(checked_rules(b"no nonsense\n", OWN, None, true).is_err());
        assert!(checked_rules(b"block drop all\n", OWN, None, true).is_err());
        let mut boots = 0;
        assert!(
            collect(
                OWN,
                BOOT,
                || {
                    boots += 1;
                    Ok(if boots == 1 {
                        BOOT
                    } else {
                        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
                    }
                    .into())
                },
                |args| Ok(match args {
                    ["-s", "info"] => b"Status: Disabled now\n".to_vec(),
                    ["-s", "References"] => b"No pf starter references held\n".to_vec(),
                    ["-s", "rules" | "nat" | "Tables"]
                    | ["-v", "-s", "Anchors"]
                    | ["-s", "Anchors"] => Vec::new(),
                    _ => return Err(refused("unexpected query")),
                })
            )
            .is_err()
        );
        assert!(
            fixture(
                false,
                ROOT,
                "",
                "Status: Enabled now\n",
                "No pf starter references held\n"
            )
            .is_err()
        );
        assert!(fixture(false, ROOT, "", "Status: Disabled now\n", "held\n").is_err());
        assert!(
            collect(
                OWN,
                BOOT,
                || Ok("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into()),
                |_| Ok(Vec::new())
            )
            .is_err()
        );
        assert!(
            collect(
                "tunlatch-lab-00000000",
                BOOT,
                || Ok(BOOT.into()),
                |_| Ok(Vec::new())
            )
            .is_err()
        );
    }
}
