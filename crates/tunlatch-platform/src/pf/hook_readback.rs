//! Comparison of root-filter readbacks before and after a potential anchor change.
//!
//! This does not perform PF operations or prove resource ownership or packet filtering.

const MAX_BYTES: usize = 65_536;
const MAX_RULES: usize = 256;
const SYSTEM_SCRUB: &[u8] = b"scrub-anchor \"com.apple/*\" all fragment reassemble\n";

/// Bytes from one root filter query. `complete` must reflect successful, untruncated capture.
pub struct Observation<'a> {
    /// The bounded bytes returned by the independent root filter reader.
    pub bytes: &'a [u8],
    /// Whether the read completed successfully without truncation.
    pub complete: bool,
}

fn lines(observation: Observation<'_>) -> Result<Vec<&[u8]>, &'static str> {
    let bytes = observation.bytes;
    if !observation.complete || bytes.len() > MAX_BYTES {
        return Err("incomplete or excessive root filter readback");
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err("incomplete root rule framing");
    }
    std::str::from_utf8(bytes).map_err(|_| "non-UTF8 root filter readback")?;
    if bytes
        .iter()
        .any(|b| (*b < b' ' && *b != b'\n' && *b != b'\t') || *b == 127)
    {
        return Err("invalid root rule control character");
    }
    let rules: Vec<_> = bytes.split_inclusive(|b| *b == b'\n').collect();
    if rules.len() > MAX_RULES
        || rules
            .iter()
            .any(|line| line.iter().all(u8::is_ascii_whitespace))
    {
        return Err("empty or excessive root rules");
    }
    // pfctl displays the system scrub hook before the PF_PASS filter ruleset.
    // Only the previously observed canonical line is supported; unknown classes or
    // scrub spellings cannot safely be mapped to native filter indices.
    let mut saw_filter = false;
    let mut saw_scrub = false;
    for line in &rules {
        if *line == SYSTEM_SCRUB && !saw_filter && !saw_scrub {
            saw_scrub = true;
            continue;
        }
        let text = std::str::from_utf8(line).map_err(|_| "invalid root rule")?;
        let mut words = text.split_ascii_whitespace();
        match words.next() {
            Some("pass" | "block") if words.next().is_some() => {}
            Some("anchor") => {
                let name = words.next().ok_or("invalid root call")?;
                if name
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .is_none_or(str::is_empty)
                    || words.next().is_none()
                {
                    return Err("invalid root call");
                }
            }
            _ => return Err("unsupported root rule class"),
        }
        saw_filter = true;
    }
    Ok(rules)
}

/// Require exactly one canonical call at the zero-based native readback rule index.
/// All other rules must match the complete baseline byte-for-byte and in order. This
/// comparison alone does not establish exclusivity, freshness, or kernel ownership.
pub fn verify(
    baseline: Observation<'_>,
    current: Observation<'_>,
    anchor: &str,
    native_index: usize,
) -> Result<(), &'static str> {
    let baseline = baseline_without_call(baseline, anchor)?;
    let current = lines(current)?;
    let display_index = display_index(&baseline, native_index)?;
    let call = format!("anchor \"{anchor}\" all\n");
    if current.len() != baseline.len() + 1 || current.get(display_index) != Some(&call.as_bytes()) {
        return Err("root call missing, malformed, or at wrong index");
    }
    if current[..display_index] != baseline[..display_index]
        || current[display_index + 1..] != baseline[display_index..]
    {
        return Err("foreign root rules changed");
    }
    Ok(())
}

/// Derive the exact foreign-rule baseline from a current, complete root observation.
///
/// This only compares bytes and the expected position; it does not establish ownership or make
/// the subsequent deletion atomic against other PF writers.
pub(super) fn baseline_for_removal(
    current: Observation<'_>,
    anchor: &str,
    native_index: usize,
) -> Result<Vec<u8>, &'static str> {
    let observed = lines(Observation {
        bytes: current.bytes,
        complete: current.complete,
    })?;
    let scrub_offset = usize::from(observed.first() == Some(&SYSTEM_SCRUB));
    let display_index = native_index
        .checked_add(scrub_offset)
        .ok_or("invalid insertion index")?;
    let call = format!("anchor \"{anchor}\" all\n");
    if observed.get(display_index) != Some(&call.as_bytes()) {
        return Err("root call missing, malformed, or at wrong index");
    }
    let mut baseline = Vec::with_capacity(current.bytes.len().saturating_sub(call.len()));
    for (index, line) in observed.into_iter().enumerate() {
        if index != display_index {
            baseline.extend_from_slice(line);
        }
    }
    verify(
        Observation {
            bytes: &baseline,
            complete: true,
        },
        current,
        anchor,
        native_index,
    )?;
    Ok(baseline)
}

/// Validate an insertion position in the native PF_PASS filter ruleset.
pub fn validate_index(
    baseline: Observation<'_>,
    anchor: &str,
    native_index: usize,
) -> Result<(), &'static str> {
    display_index(&baseline_without_call(baseline, anchor)?, native_index).map(|_| ())
}

fn display_index(baseline: &[&[u8]], native_index: usize) -> Result<usize, &'static str> {
    let scrub_offset = usize::from(baseline.first() == Some(&SYSTEM_SCRUB));
    if native_index > baseline.len() - scrub_offset {
        return Err("invalid insertion index");
    }
    Ok(scrub_offset + native_index)
}

/// Require the complete current root filter to equal the baseline after removal.
/// This comparison does not establish authority to remove any rule.
pub fn verify_detached(
    baseline: Observation<'_>,
    current: Observation<'_>,
    anchor: &str,
) -> Result<(), &'static str> {
    if baseline_without_call(baseline, anchor)? != lines(current)? {
        return Err("detached root rules differ from the baseline");
    }
    Ok(())
}

fn baseline_without_call<'a>(
    baseline: Observation<'a>,
    anchor: &str,
) -> Result<Vec<&'a [u8]>, &'static str> {
    let suffix = anchor
        .strip_prefix("tunlatch-lab-")
        .ok_or("invalid anchor")?;
    if suffix.len() != 32
        || suffix.bytes().all(|byte| byte == b'0')
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid anchor");
    }
    let baseline = lines(baseline)?;
    if baseline.iter().any(|line| {
        line.windows(anchor.len())
            .any(|part| part == anchor.as_bytes())
    }) {
        return Err("preexisting anchor reference");
    }
    Ok(baseline)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANCHOR: &str = "tunlatch-lab-0123456789abcdef0123456789abcdef";
    const BASE: &[u8] = b"pass in all\nanchor \"com.apple/*\" all\nblock out all\n";

    fn observe(bytes: &[u8]) -> Observation<'_> {
        Observation {
            bytes,
            complete: true,
        }
    }

    fn call() -> String {
        format!("anchor \"{ANCHOR}\" all\n")
    }

    #[test]
    fn accepts_exact_insertion_at_each_native_index() {
        let foreign: Vec<_> = BASE.split_inclusive(|b| *b == b'\n').collect();
        for index in 0..=foreign.len() {
            let mut current = foreign[..index].concat();
            current.extend_from_slice(call().as_bytes());
            current.extend_from_slice(&foreign[index..].concat());
            assert!(verify(observe(BASE), observe(&current), ANCHOR, index).is_ok());
        }
        assert!(verify(observe(b""), observe(call().as_bytes()), ANCHOR, 0).is_ok());
    }

    #[test]
    fn removal_baseline_preserves_foreign_rules_changed_during_session() -> Result<(), &'static str>
    {
        let current = format!(
            "pass in all\n{}anchor \"com.apple/*\" all\nblock out all\npass out proto tcp all\n",
            call()
        );
        let before_removal = baseline_for_removal(observe(current.as_bytes()), ANCHOR, 1)?;
        assert_eq!(
            before_removal,
            b"pass in all\nanchor \"com.apple/*\" all\nblock out all\npass out proto tcp all\n"
        );
        assert!(
            verify_detached(observe(&before_removal), observe(&before_removal), ANCHOR).is_ok()
        );
        assert!(baseline_for_removal(observe(current.as_bytes()), ANCHOR, 0).is_err());
        let duplicate = format!("{current}{}", call());
        assert!(baseline_for_removal(observe(duplicate.as_bytes()), ANCHOR, 1).is_err());
        assert!(
            baseline_for_removal(
                Observation {
                    bytes: current.as_bytes(),
                    complete: false
                },
                ANCHOR,
                1
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn removal_baseline_accounts_for_system_scrub() -> Result<(), &'static str> {
        let current = format!(
            "scrub-anchor \"com.apple/*\" all fragment reassemble\n{}pass all\n",
            call()
        );
        let before_removal = baseline_for_removal(observe(current.as_bytes()), ANCHOR, 0)?;
        assert_eq!(
            before_removal,
            b"scrub-anchor \"com.apple/*\" all fragment reassemble\npass all\n"
        );
        Ok(())
    }

    #[test]
    fn maps_native_indices_after_the_system_scrub_line() {
        let baseline = b"scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\nblock drop all\npass all\n";
        let display: Vec<_> = baseline.split_inclusive(|b| *b == b'\n').collect();
        for index in 0..=3 {
            let mut current = display[..index + 1].concat();
            current.extend_from_slice(call().as_bytes());
            current.extend_from_slice(&display[index + 1..].concat());
            assert!(verify(observe(baseline), observe(&current), ANCHOR, index).is_ok());
            assert!(verify(observe(baseline), observe(&current), ANCHOR, index + 1).is_err());
        }
        let bad_baselines: &[&[u8]] = &[
            b"scrub-anchor \"com.apple/*\" all\npass all\n",
            b"scrub-anchor \"other\" all fragment reassemble\npass all\n",
            b"pass all\nscrub-anchor \"com.apple/*\" all fragment reassemble\n",
            b"scrub-anchor \"com.apple/*\" all fragment reassemble\nscrub-anchor \"com.apple/*\" all fragment reassemble\n",
            b"nat-anchor \"other\" all\n",
            b"anchor missing-quotes all\n",
            b"pass\n",
        ];
        for bad in bad_baselines {
            assert!(verify_detached(observe(bad), observe(bad), ANCHOR).is_err());
        }
        assert!(validate_index(observe(baseline), ANCHOR, 3).is_ok());
        assert!(validate_index(observe(baseline), ANCHOR, 4).is_err());
        let current = format!("{}{}", String::from_utf8_lossy(baseline), call());
        assert!(verify(observe(baseline), observe(current.as_bytes()), ANCHOR, 3).is_ok());
        assert!(verify(observe(baseline), observe(current.as_bytes()), ANCHOR, 4).is_err());
        let changed = current.replace("fragment reassemble", "fragment crop");
        assert!(verify(observe(baseline), observe(changed.as_bytes()), ANCHOR, 3).is_err());
        let extra = format!("{current}pass all\n");
        assert!(verify(observe(baseline), observe(extra.as_bytes()), ANCHOR, 3).is_err());
    }

    #[test]
    fn rejects_position_criteria_duplicates_and_foreign_changes() {
        let valid = format!(
            "pass in all\n{}anchor \"com.apple/*\" all\nblock out all\n",
            call()
        );
        assert!(verify(observe(BASE), observe(valid.as_bytes()), ANCHOR, 2).is_err());
        for bad in [
            valid.replace(" all\nanchor \"com.apple", " quick all\nanchor \"com.apple"),
            valid.replace(&call(), &format!("anchor \"{ANCHOR}\" in all\n")),
            valid.replace(&call(), &format!("{}{}", call(), call())),
            valid.replace("block out all", "pass out all"),
            valid.replace("pass in all\n", ""),
            valid.replace(
                "anchor \"com.apple/*\" all\nblock out all\n",
                "block out all\nanchor \"com.apple/*\" all\n",
            ),
        ] {
            assert!(verify(observe(BASE), observe(bad.as_bytes()), ANCHOR, 1).is_err());
        }
        assert!(
            verify(
                observe(valid.as_bytes()),
                observe(valid.as_bytes()),
                ANCHOR,
                1
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_invalid_identity_incomplete_and_unbounded_observations() {
        let current = format!("{}{}", call(), String::from_utf8_lossy(BASE));
        assert!(
            verify(
                observe(BASE),
                observe(current.as_bytes()),
                "tunlatch-lab-ABC",
                0
            )
            .is_err()
        );
        assert!(
            verify(
                Observation {
                    bytes: BASE,
                    complete: false
                },
                observe(current.as_bytes()),
                ANCHOR,
                0
            )
            .is_err()
        );
        assert!(
            verify(
                observe(BASE),
                Observation {
                    bytes: current.as_bytes(),
                    complete: false
                },
                ANCHOR,
                0
            )
            .is_err()
        );
        assert!(
            verify(
                observe(b"pass in all"),
                observe(current.as_bytes()),
                ANCHOR,
                0
            )
            .is_err()
        );
        assert!(
            verify(
                observe(&vec![b'x'; MAX_BYTES + 1]),
                observe(current.as_bytes()),
                ANCHOR,
                0
            )
            .is_err()
        );
        assert!(
            verify(
                observe(&b"pass\n".repeat(MAX_RULES + 1)),
                observe(current.as_bytes()),
                ANCHOR,
                0
            )
            .is_err()
        );
        assert!(verify(observe(b"\xff\n"), observe(current.as_bytes()), ANCHOR, 0).is_err());
        assert!(verify(observe(b"pass\r\n"), observe(current.as_bytes()), ANCHOR, 0).is_err());
    }
}
