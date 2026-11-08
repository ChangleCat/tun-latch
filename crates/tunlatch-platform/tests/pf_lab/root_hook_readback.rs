//! Offline comparison of complete root filter readbacks; this performs no PF operations.

const MAX_BYTES: usize = 65_536;
const MAX_RULES: usize = 256;

/// Bytes from one root filter query. `complete` must reflect successful, untruncated capture.
pub(crate) struct Observation<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) complete: bool,
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
    Ok(rules)
}

/// Require exactly one canonical call at the zero-based native readback rule index.
/// All other rules must match the complete baseline byte-for-byte and in order. This
/// comparison alone does not establish exclusivity, freshness, or kernel ownership.
pub(crate) fn verify(
    baseline: Observation<'_>,
    current: Observation<'_>,
    anchor: &str,
    native_index: usize,
) -> Result<(), &'static str> {
    let baseline = baseline_without_call(baseline, anchor)?;
    let current = lines(current)?;
    if native_index > baseline.len() {
        return Err("invalid insertion index");
    }
    let call = format!("anchor \"{anchor}\" all\n");
    if current.len() != baseline.len() + 1 || current.get(native_index) != Some(&call.as_bytes()) {
        return Err("root call missing, malformed, or at wrong index");
    }
    if current[..native_index] != baseline[..native_index]
        || current[native_index + 1..] != baseline[native_index..]
    {
        return Err("foreign root rules changed");
    }
    Ok(())
}

pub(crate) fn verify_detached(
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
