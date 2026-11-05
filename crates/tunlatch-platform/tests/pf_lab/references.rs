//! Fixed enable-reference experiment and checksummed audit journal. No PF executor is linked.
//! A parsed token or disk receipt never constructs ownership; lost replies require takeover.
use super::driver::{Error, Guard, Identity, Observation, Result};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Token(u64);
impl Token {
    pub(crate) fn value(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Reply {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) success: bool,
    pub(crate) truncated: bool,
}
pub(crate) fn parse_token(reply: &Reply) -> Result<Token> {
    if !reply.success || reply.truncated || reply.stdout.len() + reply.stderr.len() > 1024 {
        return Err(Error("incomplete enable reply"));
    }
    let mut found = None;
    for bytes in [&reply.stdout, &reply.stderr] {
        let text = std::str::from_utf8(bytes).map_err(|_| Error("non-text enable reply"))?;
        if !text.is_empty() && !text.ends_with('\n') {
            return Err(Error("partial enable reply"));
        }
        for line in text.lines() {
            if line == "pf enabled" {
                continue;
            }
            let digits = line
                .strip_prefix("Token : ")
                .ok_or(Error("unknown enable output"))?;
            if digits.is_empty()
                || !digits.bytes().all(|b| b.is_ascii_digit())
                || digits.starts_with('0')
                || found.is_some()
            {
                return Err(Error("ambiguous token"));
            }
            found = Some(Token(digits.parse().map_err(|_| Error("token overflow"))?));
        }
    }
    found.ok_or(Error("enable token missing"))
}
pub(crate) fn acquire_argv() -> [&'static str; 1] {
    ["-E"]
}
pub(crate) fn release_argv(token: Token) -> [String; 2] {
    ["-X".into(), token.value().to_string()]
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Phase {
    AcquireIntent = 1,
    Held = 2,
    ReleaseIntent = 3,
    Closed = 4,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Record {
    pub(crate) identity: Identity,
    pub(crate) phase: Phase,
    pub(crate) token: Option<Token>,
    pub(crate) operation: u64,
}
impl Record {
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut bytes = b"TLREF001".to_vec();
        bytes.extend(self.identity.boot);
        bytes.extend(self.identity.session);
        bytes.extend(self.identity.plan);
        bytes.extend(self.identity.controller_birth.to_be_bytes());
        bytes.extend(self.identity.lock_inode.to_be_bytes());
        bytes.push(self.phase as u8);
        bytes.extend(self.token.map_or(0, Token::value).to_be_bytes());
        bytes.extend(self.operation.to_be_bytes());
        let hash = Sha256::digest(&bytes);
        bytes.extend(hash);
        bytes
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 169
            || &bytes[..8] != b"TLREF001"
            || Sha256::digest(&bytes[..137]).as_slice() != &bytes[137..]
        {
            return Err(Error("corrupt reference journal"));
        }
        let array = |start: usize| -> Result<[u8; 32]> {
            bytes[start..start + 32]
                .try_into()
                .map_err(|_| Error("bad identity field"))
        };
        let number = |start: usize| -> Result<u64> {
            Ok(u64::from_be_bytes(
                bytes[start..start + 8]
                    .try_into()
                    .map_err(|_| Error("bad integer field"))?,
            ))
        };
        let identity = Identity {
            boot: array(8)?,
            session: array(40)?,
            plan: array(72)?,
            controller_birth: number(104)?,
            lock_inode: number(112)?,
        };
        let phase = match bytes[120] {
            1 => Phase::AcquireIntent,
            2 => Phase::Held,
            3 => Phase::ReleaseIntent,
            4 => Phase::Closed,
            _ => return Err(Error("unknown reference stage")),
        };
        let value = number(121)?;
        let operation = number(129)?;
        if identity.boot == [0; 32]
            || identity.session == [0; 32]
            || identity.plan == [0; 32]
            || identity.controller_birth == 0
            || identity.lock_inode == 0
            || operation == 0
            || (phase == Phase::AcquireIntent) != (value == 0)
        {
            return Err(Error("inconsistent reference record"));
        }
        Ok(Self {
            identity,
            phase,
            token: if value == 0 { None } else { Some(Token(value)) },
            operation,
        })
    }
    /// An audit classification, never authorization to resume a previous process's cleanup.
    pub(crate) fn requires_takeover(self) -> bool {
        self.phase != Phase::Closed
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Reference {
    pub(crate) token: u64,
    pub(crate) creator_birth: u64,
}
pub(crate) trait Boundary {
    fn observe(&mut self) -> Result<Observation>;
    fn list(&mut self) -> Result<Vec<Reference>>;
    fn persist(&mut self, record: &[u8]) -> Result<()>;
    fn acquire(&mut self) -> Result<Reply>;
    fn release(&mut self, token: Token) -> Result<()>;
}
pub(crate) struct References {
    guard: Guard,
    phase: Option<Phase>,
    token: Option<Token>,
    before: Vec<Reference>,
    unknown: bool,
}
impl References {
    pub(crate) fn new(guard: Guard) -> Self {
        Self {
            guard,
            phase: None,
            token: None,
            before: Vec::new(),
            unknown: false,
        }
    }
    pub(crate) fn unknown(&self) -> bool {
        self.unknown
    }
    fn persist(&mut self, b: &mut impl Boundary, phase: Phase) -> Result<()> {
        let record = Record {
            identity: self.guard.identity(),
            phase,
            token: self.token,
            operation: 1,
        };
        b.persist(&record.encode())?;
        self.phase = Some(phase);
        Ok(())
    }
    fn list(b: &mut impl Boundary) -> Result<Vec<Reference>> {
        let mut list = b.list()?;
        list.sort_by_key(|r| r.token);
        if list.len() > 64
            || list.iter().any(|r| r.token == 0 || r.creator_birth == 0)
            || list.windows(2).any(|r| r[0].token == r[1].token)
        {
            return Err(Error("incomplete reference inventory"));
        }
        Ok(list)
    }
    pub(crate) fn acquire(&mut self, b: &mut impl Boundary) -> Result<()> {
        if self.unknown || self.phase.is_some() {
            return Err(Error("reference acquisition not repeatable"));
        }
        let result = (|| {
            self.guard.check(b.observe()?)?;
            self.before = Self::list(b)?;
            self.persist(b, Phase::AcquireIntent)?;
            let token = parse_token(&b.acquire()?)?;
            self.token = Some(token);
            self.guard.check(b.observe()?)?;
            let after = Self::list(b)?;
            if self.before.iter().any(|r| r.token == token.value()) {
                return Err(Error("token existed before acquisition"));
            }
            let mut expected = self.before.clone();
            expected.push(Reference {
                token: token.value(),
                creator_birth: self.guard.identity().controller_birth,
            });
            expected.sort_by_key(|r| r.token);
            if after != expected {
                return Err(Error("acquisition not independently associated"));
            }
            self.persist(b, Phase::Held)
        })();
        if result.is_err() {
            self.unknown = true;
        }
        result
    }
    pub(crate) fn release(&mut self, b: &mut impl Boundary) -> Result<()> {
        if self.unknown || self.phase != Some(Phase::Held) {
            return Err(Error("no continuously held owned reference"));
        }
        let result = (|| {
            self.guard.check(b.observe()?)?;
            let current = Self::list(b)?;
            let token = self.token.ok_or(Error("owned token lost"))?;
            let mut expected = self.before.clone();
            expected.push(Reference {
                token: token.value(),
                creator_birth: self.guard.identity().controller_birth,
            });
            expected.sort_by_key(|r| r.token);
            if current != expected {
                return Err(Error("reference set changed or token invalidated"));
            }
            self.persist(b, Phase::ReleaseIntent)?;
            b.release(token)?;
            self.guard.check(b.observe()?)?;
            if Self::list(b)? != self.before {
                return Err(Error(
                    "other references changed or owned release unconfirmed",
                ));
            }
            self.persist(b, Phase::Closed)
        })();
        if result.is_err() {
            self.unknown = true;
        }
        result
    }
}
