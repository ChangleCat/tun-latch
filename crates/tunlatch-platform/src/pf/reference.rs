//! Parse and inspect PF starter references, without executing commands or granting authority.
//!
//! A token and creator PID parsed here are observations, not proof of ownership: the caller
//! must protect the receipt, bind it to the current boot and serialize writers before using it.

use sha2::{Digest, Sha256};
use std::num::NonZeroU64;

const MAX_OUTPUT: usize = 65_536;
const MAX_ROWS: usize = 256;
const ALTQ_NOTICE: &str = "No ALTQ support in kernel\nALTQ related functions disabled\n";

/// A complete, syntactically valid PF starter-reference token.
///
/// This value does not establish who acquired it or whether it is still present in the kernel.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReferenceToken(NonZeroU64);

impl std::fmt::Debug for ReferenceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReferenceToken([redacted])")
    }
}

impl ReferenceToken {
    /// Return the raw value for a checked release operation.
    pub fn get(self) -> u64 {
        self.0.get()
    }
}

/// Parsing failed; the corresponding PF state must be treated as unknown.
#[derive(Debug, thiserror::Error)]
#[error("invalid or incomplete PF reference output")]
pub struct InvalidReferenceOutput;

fn text(bytes: &[u8]) -> Result<&str, InvalidReferenceOutput> {
    if bytes.len() > MAX_OUTPUT || (!bytes.is_empty() && !bytes.ends_with(b"\n")) {
        return Err(InvalidReferenceOutput);
    }
    let value = std::str::from_utf8(bytes).map_err(|_| InvalidReferenceOutput)?;
    if !value.is_ascii()
        || value
            .bytes()
            .any(|b| b.is_ascii_control() && !matches!(b, b'\n' | b'\t'))
    {
        return Err(InvalidReferenceOutput);
    }
    Ok(value)
}

fn decimal(value: &str) -> Result<NonZeroU64, InvalidReferenceOutput> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(InvalidReferenceOutput);
    }
    value
        .parse::<u64>()
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(InvalidReferenceOutput)
}

/// Parse a successful, complete `/sbin/pfctl -E` return.
///
/// The caller must distinguish a complete child return from a timeout or truncated output.
/// A returned token is not itself an ownership or persistence guarantee.
pub fn parse_acquisition(
    exit_success: bool,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<ReferenceToken, InvalidReferenceOutput> {
    if !exit_success || stdout.len().saturating_add(stderr.len()) > MAX_OUTPUT {
        return Err(InvalidReferenceOutput);
    }
    let stdout = text(stdout)?;
    let stderr = text(stderr)?;
    let stderr = stderr.strip_prefix(ALTQ_NOTICE).unwrap_or(stderr);
    let mut token = None;
    let mut enabled = false;
    for line in stdout.lines().chain(stderr.lines()) {
        if line == "pf enabled" && !enabled {
            enabled = true;
        } else if let Some(value) = line.strip_prefix("Token : ") {
            if token.replace(ReferenceToken(decimal(value)?)).is_some() {
                return Err(InvalidReferenceOutput);
            }
        } else {
            return Err(InvalidReferenceOutput);
        }
    }
    token.ok_or(InvalidReferenceOutput)
}

/// Check whether a complete reference listing contains the given token and creator PID.
///
/// Other well-formed references are permitted. A mismatch or a duplicate token is an error;
/// absence is reported as `false`. This check cannot prove provenance or rule effectiveness.
pub fn contains_reference(
    listing: &[u8],
    token: ReferenceToken,
    creator_pid: u32,
) -> Result<bool, InvalidReferenceOutput> {
    if creator_pid == 0 {
        return Err(InvalidReferenceOutput);
    }
    for row in rows(listing)? {
        if row.token == token.0 {
            if row.pid != creator_pid || row.process != "pfctl" {
                return Err(InvalidReferenceOutput);
            }
            return Ok(true);
        }
    }
    Ok(false)
}

struct Row<'a> {
    pid: u32,
    process: &'a str,
    token: NonZeroU64,
}

fn take_last_field(line: &str) -> Result<(&str, &str), InvalidReferenceOutput> {
    let line = line.trim_end_matches([' ', '\t']);
    let split = line.rfind([' ', '\t']).ok_or(InvalidReferenceOutput)?;
    let head = line[..split].trim_end_matches([' ', '\t']);
    let tail = &line[split + 1..];
    if head.is_empty() || tail.is_empty() {
        return Err(InvalidReferenceOutput);
    }
    Ok((head, tail))
}

fn rows(listing: &[u8]) -> Result<Vec<Row<'_>>, InvalidReferenceOutput> {
    let listing = text(listing)?;
    if listing == "No pf starter references held\n" {
        return Ok(Vec::new());
    }
    let mut lines = listing.lines();
    if lines.next() != Some("TOKENS:")
        || !lines.next().is_some_and(|header| {
            header
                .split_ascii_whitespace()
                .eq(["PID", "Process", "Name", "TOKEN", "TIMESTAMP"])
        })
    {
        return Err(InvalidReferenceOutput);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut result = Vec::new();
    for line in lines {
        if result.len() >= MAX_ROWS {
            return Err(InvalidReferenceOutput);
        }
        let (rest, clock_text) = take_last_field(line.trim_start_matches([' ', '\t']))?;
        let (rest, days_word) = take_last_field(rest)?;
        let (rest, days) = take_last_field(rest)?;
        let (rest, token_text) = take_last_field(rest)?;
        let split = rest.find([' ', '\t']).ok_or(InvalidReferenceOutput)?;
        let process = rest[split..].trim_matches([' ', '\t']);
        if process.is_empty() || process.len() > 255 || days_word != "days" {
            return Err(InvalidReferenceOutput);
        }
        let pid = decimal(&rest[..split])?.get();
        if pid > u64::from(u32::MAX) {
            return Err(InvalidReferenceOutput);
        }
        let row_token = decimal(token_text)?;
        if !seen.insert(row_token) || days.parse::<u32>().is_err() {
            return Err(InvalidReferenceOutput);
        }
        let mut clock = clock_text.split(':');
        for max in [23_u8, 59, 59] {
            let component = clock.next().ok_or(InvalidReferenceOutput)?;
            if component.len() != 2
                || !component.bytes().all(|byte| byte.is_ascii_digit())
                || component.parse::<u8>().map_or(true, |value| value > max)
            {
                return Err(InvalidReferenceOutput);
            }
        }
        if clock.next().is_some() {
            return Err(InvalidReferenceOutput);
        }
        result.push(Row {
            pid: pid as u32,
            process,
            token: row_token,
        });
    }
    if result.is_empty() {
        return Err(InvalidReferenceOutput);
    }
    Ok(result)
}

/// Count and order-independent digest of the complete starter-reference inventory.
/// Timestamp changes do not change the digest. This does not establish ownership or exclusivity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Inventory {
    pub(super) count: u16,
    pub(super) digest: [u8; 32],
}

pub(super) fn inventory(listing: &[u8]) -> Result<Inventory, InvalidReferenceOutput> {
    let mut entries = rows(listing)?;
    entries.sort_unstable_by_key(|row| row.token);
    let count = u16::try_from(entries.len()).map_err(|_| InvalidReferenceOutput)?;
    let mut hash = Sha256::new();
    hash.update(b"tunlatch-pf-reference-inventory-v1\0");
    hash.update(count.to_be_bytes());
    for row in entries {
        hash.update(row.token.get().to_be_bytes());
        hash.update(row.pid.to_be_bytes());
        hash.update((row.process.len() as u32).to_be_bytes());
        hash.update(row.process.as_bytes());
    }
    Ok(Inventory {
        count,
        digest: hash.finalize().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquisition_rejects_ambiguous_or_incomplete_returns() -> Result<(), InvalidReferenceOutput> {
        let token = parse_acquisition(true, b"pf enabled\nToken : 42\n", b"")?;
        assert_eq!(token.get(), 42);
        assert_eq!(format!("{token:?}"), "ReferenceToken([redacted])");
        for (ok, stdout, stderr) in [
            (false, &b"Token : 42\n"[..], &b""[..]),
            (true, b"Token : 42", b""),
            (true, b"Token : 0\n", b""),
            (true, b"Token : 42\nToken : 43\n", b""),
            (true, b"Token : 42\n", b"unexpected\n"),
            (true, b"", b""),
        ] {
            assert!(parse_acquisition(ok, stdout, stderr).is_err());
        }
        assert!(
            parse_acquisition(true, b"", format!("{ALTQ_NOTICE}Token : 42\n").as_bytes()).is_ok()
        );
        Ok(())
    }

    #[test]
    fn listing_checks_owner_and_accepts_other_references() -> Result<(), InvalidReferenceOutput> {
        let token = parse_acquisition(true, b"Token : 42\n", b"")?;
        let header = "TOKENS:\nPID Process Name TOKEN TIMESTAMP\n";
        let own = "123 pfctl 42 0 days 00:00:01\n";
        let other = "99 pfctl 43 1 days 12:30:59\n";
        assert!(contains_reference(
            format!("{header}{other}{own}").as_bytes(),
            token,
            123
        )?);
        assert!(!contains_reference(
            format!("{header}{other}").as_bytes(),
            token,
            123
        )?);
        assert!(!contains_reference(
            b"No pf starter references held\n",
            token,
            123
        )?);
        for bad in [
            format!("{header}{own}{own}"),
            format!("{header}124 pfctl 42 0 days 00:00:01\n"),
            format!("{header}123 other 42 0 days 00:00:01\n"),
            format!("{header}123 pfctl 42 0 days 24:00:00\n"),
            format!("{header}123 pfctl 42 0 days 00:00:01"),
            header.to_owned(),
        ] {
            assert!(contains_reference(bad.as_bytes(), token, 123).is_err());
        }
        Ok(())
    }

    #[test]
    fn inventory_ignores_order_and_age_but_detects_identity_changes()
    -> Result<(), InvalidReferenceOutput> {
        let header = "TOKENS:\nPID Process Name TOKEN TIMESTAMP\n";
        let first = format!("{header}123 pfctl 42 0 days 00:00:01\n99 daemon 43 0 days 00:00:02\n");
        let reordered =
            format!("{header}99 daemon 43 2 days 12:30:00\n123 pfctl 42 1 days 01:00:00\n");
        let changed = reordered.replace("99 daemon 43", "98 daemon 43");
        let expected = inventory(first.as_bytes())?;
        assert_eq!(expected.count, 2);
        assert!(expected == inventory(reordered.as_bytes())?);
        assert!(expected != inventory(changed.as_bytes())?);
        assert_eq!(inventory(b"No pf starter references held\n")?.count, 0);
        assert!(
            inventory(
                format!("{header}123 pfctl 42 0 days 00:00:01\n123 pfctl 42 0 days 00:00:01\n")
                    .as_bytes()
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn accepts_foreign_process_names_with_spaces_without_weakening_owner_checks()
    -> Result<(), InvalidReferenceOutput> {
        let header = "TOKENS:\nPID Process Name TOKEN TIMESTAMP\n";
        let listing = format!(
            "{header}   99 Network Extension 43 0 days 00:00:02\n123 pfctl 42 0 days 00:00:01\n"
        );
        let token = parse_acquisition(true, b"Token : 42\n", b"")?;
        assert!(contains_reference(listing.as_bytes(), token, 123)?);
        let expected = inventory(listing.as_bytes())?;
        assert_eq!(expected.count, 2);
        assert!(
            expected
                != inventory(
                    listing
                        .replace("Network Extension", "Network  Extension")
                        .as_bytes()
                )?
        );
        let wrong_owner = listing.replace("123 pfctl 42", "123 pfctl helper 42");
        assert!(contains_reference(wrong_owner.as_bytes(), token, 123).is_err());
        Ok(())
    }
}
