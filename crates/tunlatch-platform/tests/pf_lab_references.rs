//! Ordinary-file durability and enable-reference protocol fault tests; never runs pfctl.
#[path = "pf_lab/driver.rs"]
mod driver;
#[path = "pf_lab/references.rs"]
mod references;
use driver::{Error, Guard, Identity, Observation, Result};
use references::{
    AcquireOutcome, Acquisition, Boundary, Phase, Record, Reference, References, Reply, Token,
};
use std::io::{Read, Seek, SeekFrom, Write};
fn id() -> Identity {
    Identity {
        boot: [1; 32],
        session: [2; 32],
        plan: [3; 32],
        controller_birth: 7,
        lock_inode: 9,
    }
}
struct Fake {
    seq: u64,
    refs: Vec<Reference>,
    writes: usize,
    releases: usize,
    acquires: usize,
    file: std::fs::File,
    fault: Option<&'static str>,
    reply_file: std::fs::File,
}
impl Fake {
    fn new() -> std::io::Result<Self> {
        Ok(Self {
            seq: 0,
            refs: vec![Reference {
                token: 99,
                creator_birth: 33,
            }],
            writes: 0,
            releases: 0,
            acquires: 0,
            file: tempfile::tempfile()?,
            fault: None,
            reply_file: tempfile::tempfile()?,
        })
    }
}
impl Boundary for Fake {
    fn observe(&mut self) -> Result<Observation> {
        self.seq += 1;
        Ok(Observation {
            identity: id(),
            sequence: self.seq,
            at_ms: self.seq,
            complete: true,
            exclusive: true,
            writers_reclaimed: self.fault != Some("writers"),
        })
    }
    fn list(&mut self) -> Result<Vec<Reference>> {
        Ok(self.refs.clone())
    }
    fn persist(&mut self, bytes: &[u8]) -> Result<()> {
        self.writes += 1;
        if self.fault == Some("disk") && self.writes == 2 {
            return Err(Error("disk failure after acquisition"));
        }
        self.file
            .set_len(0)
            .and_then(|()| self.file.seek(SeekFrom::Start(0)))
            .and_then(|_| self.file.write_all(bytes))
            .and_then(|()| self.file.sync_all())
            .map_err(|_| Error("journal I/O"))
    }
    fn persist_reply(&mut self, reply: &Reply) -> Result<()> {
        if self.fault == Some("reply-disk") {
            return Err(Error("reply persistence failed"));
        }
        self.reply_file
            .write_all(&reply.exit_code.to_be_bytes())
            .and_then(|()| self.reply_file.write_all(&[u8::from(reply.truncated)]))
            .and_then(|()| {
                self.reply_file
                    .write_all(&reply.creator_birth.to_be_bytes())
            })
            .and_then(|()| {
                self.reply_file
                    .write_all(&(reply.stdout.len() as u64).to_be_bytes())
            })
            .and_then(|()| {
                self.reply_file
                    .write_all(&(reply.stderr.len() as u64).to_be_bytes())
            })
            .and_then(|()| self.reply_file.write_all(&reply.stdout))
            .and_then(|()| self.reply_file.write_all(&reply.stderr))
            .and_then(|()| self.reply_file.sync_all())
            .map_err(|_| Error("reply I/O"))
    }
    fn acquire(&mut self) -> Result<Acquisition> {
        self.acquires += 1;
        if self.fault == Some("canceled") {
            return Ok(Acquisition::CanceledBeforeStart);
        }
        self.refs.push(Reference {
            token: 123,
            creator_birth: if self.fault == Some("wrong-child") {
                57
            } else {
                56
            },
        });
        if self.fault == Some("lost-reply") {
            return Err(Error("lost reply after acquiring"));
        }
        Ok(Acquisition::Returned(Reply {
            stdout: Vec::new(),
            stderr: b"pf enabled\nToken : 123\n".to_vec(),
            exit_code: 0,
            truncated: false,
            creator_birth: 56,
        }))
    }
    fn release(&mut self, token: Token) -> Result<()> {
        self.releases += 1;
        self.refs.retain(|r| r.token != token.value());
        if self.fault == Some("release-reply") {
            return Err(Error("release reply lost"));
        }
        Ok(())
    }
}
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn acquire_persist_explicit_release_preserve_other_references() -> TestResult {
    let mut f = Fake::new()?;
    let original = f.refs.clone();
    let mut session = References::new(Guard::new(id(), 0)?);
    assert_eq!(session.acquire(&mut f)?, AcquireOutcome::Held);
    f.reply_file.seek(SeekFrom::Start(0))?;
    let mut reply = Vec::new();
    f.reply_file.read_to_end(&mut reply)?;
    assert_eq!(&reply[..5], &[0, 0, 0, 0, 0]);
    assert_eq!(&reply[5..13], &56_u64.to_be_bytes());
    assert_eq!(&reply[13..21], &0_u64.to_be_bytes());
    assert_eq!(&reply[21..29], &23_u64.to_be_bytes());
    assert_eq!(&reply[29..], b"pf enabled\nToken : 123\n");
    session.release(&mut f)?;
    assert_eq!(f.refs, original);
    assert!(!session.unknown());
    f.file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    f.file.read_to_end(&mut bytes)?;
    let record = Record::decode(&bytes)?;
    assert_eq!(record.phase, Phase::Closed);
    assert!(!record.requires_takeover());
    assert!(session.release(&mut f).is_err());
    assert_eq!(f.releases, 1);
    Ok(())
}
#[test]
fn token_parser_is_bounded_closed_and_never_guesses_from_warning_text() {
    for text in [
        "",
        "Token : 0\n",
        "Token : 01\n",
        "Token : -1\n",
        "Token : 18446744073709551616\n",
        "Token : 1\nToken : 2\n",
        "Token : 1",
        "warning\nToken : 1\n",
        "Token : 1; -d\n",
    ] {
        assert!(
            references::parse_token(&Reply {
                stdout: text.as_bytes().to_vec(),
                stderr: Vec::new(),
                exit_code: 0,
                truncated: false,
                creator_birth: 56,
            })
            .is_err()
        );
    }
    for (exit_code, truncated) in [(1, false), (0, true)] {
        assert!(
            references::parse_token(&Reply {
                stdout: b"Token : 1\n".to_vec(),
                stderr: Vec::new(),
                exit_code,
                truncated,
                creator_birth: 56,
            })
            .is_err()
        );
    }
}
#[test]
fn journal_corruption_wrong_shape_and_cross_session_records_never_mint_release_authority()
-> TestResult {
    let token = references::parse_token(&Reply {
        stdout: b"Token : 1\n".to_vec(),
        stderr: Vec::new(),
        exit_code: 0,
        truncated: false,
        creator_birth: 56,
    })?;
    let record = Record {
        identity: id(),
        phase: Phase::Held,
        token: Some(token),
        operation: 1,
    };
    let bytes = record.encode();
    assert_eq!(Record::decode(&bytes)?, record);
    assert!(record.requires_takeover());
    for i in [0, 8, 40, 104, 120, 128, 137, 168] {
        let mut bad = bytes.clone();
        bad[i] ^= 1;
        assert!(Record::decode(&bad).is_err());
    }
    assert!(Record::decode(&bytes[..168]).is_err());
    let mut long = bytes;
    long.push(0);
    assert!(Record::decode(&long).is_err());
    let mut f = Fake::new()?;
    let mut new_controller = References::new(Guard::new(id(), 0)?);
    assert!(new_controller.release(&mut f).is_err());
    assert_eq!(f.releases, 0);
    Ok(())
}
#[test]
fn acquired_but_unrecorded_or_lost_reply_is_unknown_and_not_released_by_drop() -> TestResult {
    for fault in ["disk", "reply-disk", "lost-reply", "wrong-child"] {
        let mut f = Fake::new()?;
        f.fault = Some(fault);
        let mut session = References::new(Guard::new(id(), 0)?);
        assert!(session.acquire(&mut f).is_err());
        assert!(session.unknown());
        assert!(f.refs.iter().any(|r| r.token == 123));
        assert!(session.acquire(&mut f).is_err());
        assert!(session.release(&mut f).is_err());
        drop(session);
        assert_eq!(f.releases, 0);
        assert_eq!(f.acquires, 1);
    }
    Ok(())
}
#[test]
fn proven_cancellation_is_persisted_and_cannot_be_retried() -> TestResult {
    let mut f = Fake::new()?;
    f.fault = Some("canceled");
    let mut session = References::new(Guard::new(id(), 0)?);
    assert_eq!(
        session.acquire(&mut f)?,
        AcquireOutcome::CanceledBeforeStart
    );
    assert!(!session.unknown());
    assert!(session.acquire(&mut f).is_err());
    assert!(session.release(&mut f).is_err());
    f.file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    f.file.read_to_end(&mut bytes)?;
    let record = Record::decode(&bytes)?;
    assert_eq!(record.phase, Phase::Canceled);
    assert!(!record.requires_takeover());
    assert_eq!(f.releases, 0);
    Ok(())
}
#[test]
fn invalidation_other_writer_or_unreaped_process_blocks_release() -> TestResult {
    for fault in ["invalidate", "foreign", "writers"] {
        let mut f = Fake::new()?;
        let mut s = References::new(Guard::new(id(), 0)?);
        assert_eq!(s.acquire(&mut f)?, AcquireOutcome::Held);
        match fault {
            "invalidate" => f.refs.clear(),
            "foreign" => f.refs.push(Reference {
                token: 456,
                creator_birth: 88,
            }),
            _ => f.fault = Some("writers"),
        }
        assert!(s.release(&mut f).is_err());
        assert!(s.unknown());
        assert_eq!(f.releases, 0);
    }
    Ok(())
}
#[test]
fn release_lost_reply_never_replays_an_already_consumed_token() -> TestResult {
    let mut f = Fake::new()?;
    let mut s = References::new(Guard::new(id(), 0)?);
    assert_eq!(s.acquire(&mut f)?, AcquireOutcome::Held);
    f.fault = Some("release-reply");
    assert!(s.release(&mut f).is_err());
    assert!(s.release(&mut f).is_err());
    assert_eq!(f.releases, 1);
    assert!(s.unknown());
    Ok(())
}
#[test]
fn closed_commands_cannot_request_global_disable() -> TestResult {
    assert_eq!(references::acquire_argv(), ["-E"]);
    let token = references::parse_token(&Reply {
        stdout: b"Token : 18446744073709551615\n".to_vec(),
        stderr: Vec::new(),
        exit_code: 0,
        truncated: false,
        creator_birth: 56,
    })?;
    assert_eq!(
        references::release_argv(token),
        ["-X", "18446744073709551615"]
    );
    Ok(())
}
