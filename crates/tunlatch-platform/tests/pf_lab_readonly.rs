//! Ordinary-user injected collection tests. No sudo/PF command is executed.
#[allow(dead_code)]
#[path = "pf_lab/process.rs"]
mod process;
#[allow(dead_code)]
#[path = "pf_lab/readonly.rs"]
mod readonly;

use process::{Completion, ReadQuery, Reason};
use std::fs;
use std::os::unix::fs::PermissionsExt;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Fake {
    calls: usize,
    fail_at: Option<usize>,
    truncated: bool,
}
impl readonly::Reader for Fake {
    fn read(&mut self, query: ReadQuery) -> readonly::Result<Completion> {
        self.calls += 1;
        if self.fail_at == Some(self.calls) {
            return Err(readonly::Error::Refused("injected unknown"));
        }
        Ok(Completion {
            reason: Reason::Success,
            stdout: if query == ReadQuery::Anchors {
                b"  com.apple\n  com.apple/200.AirDrop\n".to_vec()
            } else {
                b"private address and token fixture".to_vec()
            },
            stderr: Vec::new(),
            input_written: 0,
            truncated: self.truncated,
            capture_failed: false,
            kill_failed: false,
            child_started: true,
            parent_reaped: true,
            pipes_closed: true,
            descendants_known_leaf: true,
        })
    }
}
fn directory() -> Result<tempfile::TempDir> {
    let dir = tempfile::tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

#[test]
fn zero_exit_with_kernel_error_on_stderr_is_incomplete() -> Result {
    struct KernelError;
    impl readonly::Reader for KernelError {
        fn read(&mut self, query: ReadQuery) -> readonly::Result<Completion> {
            let mut fake = Fake {
                calls: 0,
                fail_at: None,
                truncated: false,
            };
            let mut result = fake.read(query)?;
            result.stderr = b"No ALTQ support in kernel\nALTQ related functions disabled\npfctl: DIOCGETRULES: Invalid argument\n".to_vec();
            Ok(result)
        }
    }
    let dir = directory()?;
    let summary = readonly::collect(dir.path(), &mut KernelError)?;
    assert_eq!(summary["result"], "incomplete");
    assert_eq!(summary["queries"].as_array().map(Vec::len), Some(3));
    assert!(dir.path().join("query-01.json").is_file());
    assert!(!dir.path().join("query-04.json").exists());
    Ok(())
}

#[test]
fn captured_summary_omits_private_output_and_never_claims_pf_readiness() -> Result {
    let dir = directory()?;
    let mut fake = Fake {
        calls: 0,
        fail_at: None,
        truncated: false,
    };
    let summary = readonly::collect(dir.path(), &mut fake)?;
    assert_eq!(fake.calls, 16);
    assert_eq!(summary["result"], "captured_requires_review");
    assert_eq!(summary["pf_write_operations"], 0);
    assert_eq!(summary["PF_feasibility_passed"], false);
    assert_eq!(summary["recovery_qualified"], false);
    assert!(
        !summary
            .to_string()
            .contains("private address and token fixture")
    );
    let raw = fs::read_to_string(dir.path().join("query-01.json"))?;
    assert!(raw.contains("private address and token fixture"));
    assert_eq!(
        fs::metadata(dir.path().join("summary.json"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(readonly::collect(dir.path(), &mut fake).is_err());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    let uid = nix::unistd::geteuid().as_raw().to_string();
    exacl::setfacl(
        &[dir.path()],
        &[exacl::AclEntry::allow_user(&uid, exacl::Perm::READ, None)],
        None,
    )?;
    assert!(readonly::collect(dir.path(), &mut fake).is_err());
    exacl::setfacl(&[dir.path()], &[], None)?;
    assert_eq!(fake.calls, 16);
    Ok(())
}

#[test]
fn literal_inventory_rejects_injection_duplicates_missing_parents_and_overflow() -> Result {
    for bytes in [
        b"com.apple/*\n".as_slice(),
        b"com.apple\ncom.apple\n",
        b"com.apple/child\n",
        b"a;sh\n",
        b"a",
        b"../escape\n",
        b"\n",
    ] {
        assert!(readonly::anchor_inventory(bytes).is_err());
    }
    let excessive = (0..17).map(|n| format!("a{n}\n")).collect::<String>();
    assert!(readonly::anchor_inventory(excessive.as_bytes()).is_err());
    assert!(readonly::anchor_inventory(b"")?.is_empty());
    assert_eq!(
        readonly::anchor_inventory(b" com.apple\n com.apple/200.AirDrop\n")?.len(),
        2
    );
    Ok(())
}

#[test]
fn observed_altq_notice_is_preserved_but_other_stderr_and_inventory_changes_refuse() -> Result {
    struct NoticeReader {
        base: Fake,
        change: bool,
    }
    impl readonly::Reader for NoticeReader {
        fn read(&mut self, query: ReadQuery) -> readonly::Result<Completion> {
            let mut result = self.base.read(query)?;
            result.stderr =
                b"No ALTQ support in kernel\nALTQ related functions disabled\n".to_vec();
            if self.change && query == ReadQuery::Anchors && self.base.calls > 3 {
                result.stdout = b"com.apple\n".to_vec();
            }
            Ok(result)
        }
    }
    for change in [false, true] {
        let dir = directory()?;
        let mut reader = NoticeReader {
            base: Fake {
                calls: 0,
                fail_at: None,
                truncated: false,
            },
            change,
        };
        let summary = readonly::collect(dir.path(), &mut reader)?;
        assert_eq!(reader.base.calls, 16);
        assert_eq!(
            summary["result"],
            if change {
                "incomplete"
            } else {
                "captured_requires_review"
            }
        );
        assert_eq!(summary["stderr_requires_review"], true);
        assert_eq!(summary["queries"][0]["recognized_altq_notice"], true);
        assert_eq!(summary["literal_anchor_count"], 2);
        if change {
            assert_eq!(
                summary["queries"][15]["diagnostic"],
                "anchor_inventory_changed"
            );
        }
    }
    Ok(())
}

#[test]
fn literal_ruleset_error_does_not_hide_other_reads_or_become_an_empty_success() -> Result {
    struct DetailError(Fake);
    impl readonly::Reader for DetailError {
        fn read(&mut self, query: ReadQuery) -> readonly::Result<Completion> {
            let mut result = self.0.read(query)?;
            if matches!(query, ReadQuery::AnchorRules(_)) {
                result.stdout.clear();
                result.stderr = b"pfctl: DIOCGETRULES: Invalid argument\n".to_vec();
                result.reason = Reason::ExitFailure;
            }
            Ok(result)
        }
    }
    let dir = directory()?;
    let mut reader = DetailError(Fake {
        calls: 0,
        fail_at: None,
        truncated: false,
    });
    let summary = readonly::collect(dir.path(), &mut reader)?;
    assert_eq!(reader.0.calls, 16);
    assert_eq!(summary["result"], "incomplete");
    assert_eq!(summary["queries"][3]["status"], "incomplete");
    assert_eq!(summary["queries"][3]["diagnostic"], "command_failed");
    assert!(dir.path().join("query-16.json").is_file());
    assert_eq!(summary["PF_feasibility_passed"], false);
    Ok(())
}

#[test]
fn unknown_or_truncated_query_stops_the_batch_without_cleanup() -> Result {
    for truncated in [false, true] {
        let dir = directory()?;
        let mut fake = Fake {
            calls: 0,
            fail_at: if truncated { None } else { Some(2) },
            truncated,
        };
        let summary = readonly::collect(dir.path(), &mut fake)?;
        assert_eq!(summary["result"], "incomplete");
        assert_eq!(fake.calls, if truncated { 1 } else { 2 });
        assert!(dir.path().join("collection-intent.json").is_file());
        assert!(!dir.path().join("query-03.json").exists());
    }
    Ok(())
}

#[test]
fn public_or_symlinked_output_is_rejected_before_privileged_reader() -> Result {
    let dir = directory()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755))?;
    let mut fake = Fake {
        calls: 0,
        fail_at: None,
        truncated: false,
    };
    assert!(readonly::collect(dir.path(), &mut fake).is_err());
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(dir.path(), &alias)?;
    assert!(readonly::collect(&alias, &mut fake).is_err());
    assert_eq!(fake.calls, 0);
    Ok(())
}
