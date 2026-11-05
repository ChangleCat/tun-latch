//! Source-derived/synthetic pfctl display subset; these are NOT target-host captures.
#[path = "pf_lab/preflight.rs"]
mod preflight;
use preflight::{Anchor, Error, Output, Query, ReadBoundary};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Fake<'a> {
    calls: Vec<Query>,
    root: &'a str,
    inventory: &'a str,
    child: &'a str,
    interfaces: &'a str,
    references: &'a str,
    fault: Option<(usize, &'static str)>,
}
impl Default for Fake<'_> {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            root: "anchor \"project/*\" all\n",
            inventory: "project\n",
            child: "",
            interfaces: "lo0 (skip)\nen0\n",
            references: "No pf_enabled references\n",
            fault: None,
        }
    }
}
impl ReadBoundary for Fake<'_> {
    fn query(&mut self, query: Query) -> preflight::Result<Output> {
        assert_eq!(query.executable(), "/sbin/pfctl");
        assert!(
            query
                .argv()
                .iter()
                .all(|a| !matches!(*a, "-f" | "-F" | "-d" | "-E" | "-X"))
        );
        let text = match &query {
            Query::Anchors => self.inventory,
            Query::Rules(None) => self.root,
            Query::Rules(Some(_)) => self.child,
            Query::Tables(_) => "",
            Query::Interfaces => self.interfaces,
            Query::References => self.references,
        };
        self.calls.push(query);
        let i = self.calls.len();
        let mut output = Output {
            bytes: text.as_bytes().to_vec(),
            stderr: Vec::new(),
            success: true,
            truncated: false,
            started_ms: 100 + i as u64,
            ended_ms: 100 + i as u64,
            sequence: i as u64,
            boot: [1; 32],
        };
        if let Some((at, fault)) = self.fault
            && at == i
        {
            match fault {
                "status" => output.success = false,
                "truncated" => output.truncated = true,
                "stderr" => output.stderr = b"warning".to_vec(),
                "late" => output.ended_ms = 3000,
                "stale" => output.started_ms = 0,
                "replay" => output.sequence = 1,
                "boot" => output.boot = [2; 32],
                "binary" => output.bytes = vec![0xff],
                "oversize" => output.bytes = vec![b'x'; 65537],
                "unterminated" => output.bytes = b"project".to_vec(),
                "control" => output.bytes = b"project\0\n".to_vec(),
                "changed" => output.bytes = b"lo0 (skip)\nen1\n".to_vec(),
                _ => return Err(Error::Rejected("fake boundary I/O failure")),
            }
        }
        Ok(output)
    }
}
fn own() -> preflight::Result<Anchor> {
    Anchor::new("project/session")
}

#[test]
fn two_complete_sweeps_qualify_only_a_recognized_reachable_empty_namespace() -> Result {
    let mut fake = Fake::default();
    let checked = preflight::inspect(&mut fake, own()?, [1; 32], 100)?;
    assert_eq!(checked.own().name(), "project/session");
    assert!(checked.empty_owned_leaf());
    assert_eq!(checked.existing_references(), 0);
    assert_eq!(checked.boot, [1; 32]);
    assert_eq!(checked.observed_ms, 114);
    assert_ne!(checked.fingerprint(), [0; 32]);
    assert_eq!(fake.calls.len(), 14);
    assert_eq!(&fake.calls[..7], &fake.calls[7..]);
    Ok(())
}

#[test]
fn empty_leaf_without_root_path_is_refused() -> Result {
    for root in ["", "block drop out all\n", "anchor \"other\" all\n"] {
        assert!(
            preflight::inspect(
                &mut Fake {
                    root,
                    ..Fake::default()
                },
                own()?,
                [1; 32],
                100
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn unknown_quick_pass_and_ambiguous_rules_never_become_authority() -> Result {
    for root in [
        "pass out quick all\nanchor \"project/*\" all\n",
        "anchor \"project/*\" all\npass out all\n",
        "anchor \"project/*\" out quick all\n",
        "block drop out quick all\nanchor \"project/*\" all\n",
        "anchor \"project/*\" all # text\n",
        "anchor \"project/../foreign\" all\n",
        "future syntax\n",
        "\n",
    ] {
        assert!(
            preflight::inspect(
                &mut Fake {
                    root,
                    ..Fake::default()
                },
                own()?,
                [1; 32],
                100
            )
            .is_err(),
            "{root}"
        );
    }
    Ok(())
}

#[test]
fn foreign_namespace_children_and_incomplete_recursive_inventory_are_refused() -> Result {
    for inventory in [
        "project\nproject/session\n",
        "project\nproject/session/foreign\n",
        "project/child\n",
        "project\nproject\n",
        "../foreign\n",
        "project*\n",
    ] {
        assert!(
            preflight::inspect(
                &mut Fake {
                    inventory,
                    ..Fake::default()
                },
                own()?,
                [1; 32],
                100
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn nested_calls_are_traversed_and_unrecognized_nested_rule_is_not_hidden() -> Result {
    let mut direct = Fake {
        root: "anchor \"project/session\" all\n",
        inventory: "",
        ..Fake::default()
    };
    assert!(preflight::inspect(&mut direct, own()?, [1; 32], 100).is_err());
    let mut nested = Fake {
        root: "anchor \"project\" all\n",
        child: "anchor \"project/*\" all\n",
        ..Fake::default()
    };
    assert!(preflight::inspect(&mut nested, own()?, [1; 32], 100).is_ok());
    nested.child = "pass out quick all\n";
    nested.calls.clear();
    assert!(preflight::inspect(&mut nested, own()?, [1; 32], 100).is_err());
    Ok(())
}

#[test]
fn skips_unknown_interfaces_and_unqualified_reference_formats_refuse_entry() -> Result {
    for interfaces in [
        "",
        "lo0 (skip)\nen0 (skip)\n",
        "en0 unknown\n",
        "en0\nen0\n",
    ] {
        assert!(
            preflight::inspect(
                &mut Fake {
                    interfaces,
                    ..Fake::default()
                },
                own()?,
                [1; 32],
                100
            )
            .is_err()
        );
    }
    for references in ["", "garbage\n", "Token : 42\n"] {
        assert!(
            preflight::inspect(
                &mut Fake {
                    references,
                    ..Fake::default()
                },
                own()?,
                [1; 32],
                100
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn query_failures_integrity_time_boot_and_output_limits_refuse_before_mutation() -> Result {
    for fault in [
        "status",
        "truncated",
        "stderr",
        "late",
        "stale",
        "replay",
        "boot",
        "binary",
        "oversize",
        "unterminated",
        "control",
        "io",
    ] {
        let mut fake = Fake {
            fault: Some((2, fault)),
            ..Fake::default()
        };
        assert!(
            preflight::inspect(&mut fake, own()?, [1; 32], 100).is_err(),
            "{fault}"
        );
        assert_eq!(fake.calls.len(), 2);
    }
    assert!(preflight::inspect(&mut Fake::default(), own()?, [0; 32], 100).is_err());
    Ok(())
}

#[test]
fn a_changed_second_sweep_does_not_establish_exclusivity() -> Result {
    let mut fake = Fake {
        fault: Some((13, "changed")),
        ..Fake::default()
    };
    assert!(preflight::inspect(&mut fake, own()?, [1; 32], 100).is_err());
    assert_eq!(fake.calls.len(), 14);
    Ok(())
}

#[test]
fn anchor_operands_are_literal_bounded_and_cannot_inject_arguments() {
    for text in [
        "",
        "/absolute",
        "a/../b",
        "a//b",
        "a/*",
        "-f /tmp/input",
        "a\nb",
        "a\"b",
        "é",
    ] {
        assert!(Anchor::new(text).is_err());
    }
    assert!(Anchor::new(&"x".repeat(129)).is_err());
    assert!(Anchor::new("a/b/c/d/e/f/g/h/i").is_err());
}

#[test]
fn reference_rows_preserve_identity_and_reject_duplicate_tokens_and_partial_headers() -> Result {
    let header = "PID Process Name TOKEN TIMESTAMP\n";
    let text = format!("{header}12 example tool 4294967297 0 days 01:02:03\n");
    let mut fake = Fake {
        references: &text,
        ..Fake::default()
    };
    let checked = preflight::inspect(&mut fake, own()?, [1; 32], 100)?;
    assert_eq!(checked.existing_references(), 1);
    for row in [
        "",
        "12 tool 1 0 days 99:02:03\n",
        "0 tool 1 0 days 01:02:03\n",
        "12 tool 0 0 days 01:02:03\n",
        "12 tool 1 0 days 01:02\n",
        "12 tool 1 0 days 01:02:03\n13 other 1 0 days 01:02:03\n",
    ] {
        let text = format!("{header}{row}");
        let mut fake = Fake {
            references: &text,
            ..Fake::default()
        };
        assert!(preflight::inspect(&mut fake, own()?, [1; 32], 100).is_err());
    }
    Ok(())
}

#[test]
fn cycles_excessive_inventory_rules_and_total_output_are_bounded() -> Result {
    let mut cycle = Fake {
        root: "anchor \"project\" all\n",
        child: "anchor \"project\" all\n",
        ..Fake::default()
    };
    assert!(preflight::inspect(&mut cycle, own()?, [1; 32], 100).is_err());
    {
        let text = (0..17).map(|i| format!("a{i}\n")).collect::<String>();
        let mut fake = Fake {
            inventory: &text,
            ..Fake::default()
        };
        assert!(preflight::inspect(&mut fake, own()?, [1; 32], 100).is_err());
        assert_eq!(fake.calls.len(), 1);
    }
    let root = "block drop out all\n".repeat(257);
    let mut fake = Fake {
        root: &root,
        ..Fake::default()
    };
    assert!(preflight::inspect(&mut fake, own()?, [1; 32], 100).is_err());
    let inventory = format!(
        "project\n{}",
        (0..15).map(|i| format!("other{i}\n")).collect::<String>()
    );
    let child = "block drop out all\n".repeat(256);
    let mut fake = Fake {
        inventory: &inventory,
        child: &child,
        ..Fake::default()
    };
    assert!(preflight::inspect(&mut fake, own()?, [1; 32], 100).is_err());
    assert!(fake.calls.len() < 80);
    Ok(())
}
