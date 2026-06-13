//! Parser for the binary trace format (`docs/trace-format.md`).
//!
//! Robustness rule from the spec: a process may die mid-write, so a truncated
//! *final* record is end-of-file, not corruption. Only a bad magic or an
//! unreadable header is a hard error; a short record sets `truncated` and
//! stops.

use crate::model::{EnvOp, Event, EventKind, FileOp, ProcessOp, RegistryOp, Trace, record_type};

const MAGIC: &[u8; 4] = b"SBZT";
const SUPPORTED_VERSION: u32 = 0;

/// Upper bound on a single string field, in UTF-16 code units. The writer
/// never emits anything near this; it exists so a corrupt length prefix can't
/// trigger a multi-gigabyte allocation.
const MAX_STRING_UNITS: u32 = 1 << 24; // 16M chars = 32 MiB

#[derive(Debug)]
pub enum ParseError {
    BadMagic,
    ShortHeader,
    UnsupportedVersion(u32),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::BadMagic => write!(f, "not a Sembazuru trace (bad magic)"),
            ParseError::ShortHeader => write!(f, "file too short for a trace header"),
            ParseError::UnsupportedVersion(v) => {
                write!(f, "unsupported trace version {v}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// A forward cursor over the byte buffer. Every read is bounds-checked and
/// returns `None` past the end, which the record loop treats as truncation.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// `u32` count followed by `count` UTF-16LE code units. Invalid UTF-16 is
    /// rendered with replacement characters rather than rejected — a mangled
    /// path is still evidence, and the writer records paths verbatim.
    fn string(&mut self) -> Option<String> {
        let count = self.u32()?;
        if count > MAX_STRING_UNITS {
            return None; // treat an absurd length as truncation/corruption
        }
        let bytes = self.take(count as usize * 2)?;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }
}

/// Parses one trace file's bytes. Hard-errors only on magic/header/version;
/// a short record body ends the event stream with `truncated = true`.
pub fn parse(buf: &[u8]) -> Result<Trace, ParseError> {
    let mut cur = Cursor::new(buf);

    let magic = cur.take(4).ok_or(ParseError::ShortHeader)?;
    if magic != MAGIC {
        return Err(ParseError::BadMagic);
    }
    let version = cur.u32().ok_or(ParseError::ShortHeader)?;
    if version != SUPPORTED_VERSION {
        return Err(ParseError::UnsupportedVersion(version));
    }
    let pid = cur.u32().ok_or(ParseError::ShortHeader)?;
    let parent_pid = cur.u32().ok_or(ParseError::ShortHeader)?;
    let qpc_frequency = cur.u64().ok_or(ParseError::ShortHeader)?;
    let start_qpc = cur.u64().ok_or(ParseError::ShortHeader)?;
    let start_filetime = cur.u64().ok_or(ParseError::ShortHeader)?;
    let exe_path = cur.string().ok_or(ParseError::ShortHeader)?;
    let command_line = cur.string().ok_or(ParseError::ShortHeader)?;
    let cwd = cur.string().ok_or(ParseError::ShortHeader)?;

    let mut events = Vec::new();
    let mut truncated = false;

    loop {
        // A failed read inside parse_record does not advance the cursor, so
        // compare against the position *before* the attempt: any bytes left
        // at the start of a record that then fails to parse mean the final
        // record was cut short (writer killed mid-write). Starting a record
        // exactly at EOF is a clean end.
        let before = cur.pos;
        match parse_record(&mut cur) {
            Some(ev) => events.push(ev),
            None => {
                if before != cur.buf.len() {
                    truncated = true;
                }
                break;
            }
        }
    }

    Ok(Trace {
        version,
        pid,
        parent_pid,
        qpc_frequency,
        start_qpc,
        start_filetime,
        exe_path,
        command_line,
        cwd,
        events,
        truncated,
    })
}

fn parse_record(cur: &mut Cursor) -> Option<Event> {
    let record_type = cur.u8()?;
    let op = cur.u8()?;
    let _reserved = cur.u16()?;
    let status = cur.u32()?;
    let tid = cur.u32()?;
    let qpc = cur.u64()?;
    let extra = cur.u64()?;
    let path = cur.string()?;
    let aux = cur.string()?;

    let kind = match record_type {
        record_type::FILE => match FileOp::from_u8(op) {
            Some(op) => EventKind::File { op, extra },
            None => EventKind::Unknown { record_type, op },
        },
        record_type::PROCESS => match ProcessOp::from_u8(op) {
            Some(op) => EventKind::Process {
                op,
                child_pid: extra as u32,
            },
            None => EventKind::Unknown { record_type, op },
        },
        record_type::REGISTRY => match RegistryOp::from_u8(op) {
            Some(op) => EventKind::Registry {
                op,
                value_type: extra as u32,
            },
            None => EventKind::Unknown { record_type, op },
        },
        record_type::ENV => match EnvOp::from_u8(op) {
            Some(op) => EventKind::Env { op },
            None => EventKind::Unknown { record_type, op },
        },
        _ => EventKind::Unknown { record_type, op },
    };

    Some(Event {
        kind,
        status,
        tid,
        qpc,
        path,
        aux,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal valid trace: header + one CreateFile-read record.
    fn sample() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&0u32.to_le_bytes()); // version
        b.extend_from_slice(&100u32.to_le_bytes()); // pid
        b.extend_from_slice(&50u32.to_le_bytes()); // parent_pid
        b.extend_from_slice(&10_000_000u64.to_le_bytes()); // qpc_freq
        b.extend_from_slice(&1u64.to_le_bytes()); // start_qpc
        b.extend_from_slice(&2u64.to_le_bytes()); // start_filetime
        push_string(&mut b, "C:\\cl.exe");
        push_string(&mut b, "cl /c a.c");
        push_string(&mut b, "C:\\work"); // cwd
        // one FILE/OpenRead record
        b.push(record_type::FILE);
        b.push(1); // OpenRead
        b.extend_from_slice(&0u16.to_le_bytes()); // reserved
        b.extend_from_slice(&0u32.to_le_bytes()); // status
        b.extend_from_slice(&7u32.to_le_bytes()); // tid
        b.extend_from_slice(&123u64.to_le_bytes()); // qpc
        b.extend_from_slice(&0x8000_0000u64.to_le_bytes()); // extra (access)
        push_string(&mut b, "C:\\src\\a.c");
        push_string(&mut b, "");
        b
    }

    fn push_string(b: &mut Vec<u8>, s: &str) {
        let units: Vec<u16> = s.encode_utf16().collect();
        b.extend_from_slice(&(units.len() as u32).to_le_bytes());
        for u in units {
            b.extend_from_slice(&u.to_le_bytes());
        }
    }

    #[test]
    fn parses_header_and_one_record() {
        let t = parse(&sample()).unwrap();
        assert_eq!(t.pid, 100);
        assert_eq!(t.parent_pid, 50);
        assert_eq!(t.exe_path, "C:\\cl.exe");
        assert_eq!(t.command_line, "cl /c a.c");
        assert_eq!(t.cwd, "C:\\work");
        assert_eq!(t.events.len(), 1);
        assert_eq!(t.events[0].path, "C:\\src\\a.c");
        assert!(!t.truncated);
    }

    #[test]
    fn truncated_final_record_is_eof_not_error() {
        let mut b = sample();
        b.truncate(b.len() - 4); // chop the trailing aux string
        let t = parse(&b).unwrap();
        assert!(t.truncated);
        // The header and any complete prior records still parse.
        assert_eq!(t.pid, 100);
    }

    #[test]
    fn bad_magic_is_hard_error() {
        let mut b = sample();
        b[0] = b'X';
        assert!(matches!(parse(&b), Err(ParseError::BadMagic)));
    }

    #[test]
    fn unknown_record_type_is_preserved() {
        let mut b = sample();
        // Flip the record's type byte (first byte after the two header
        // strings) to an unknown value by appending a fresh unknown record.
        b.push(99); // unknown record_type
        b.push(1);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        push_string(&mut b, "x");
        push_string(&mut b, "");
        let t = parse(&b).unwrap();
        assert_eq!(t.events.len(), 2);
        assert!(matches!(
            t.events[1].kind,
            EventKind::Unknown {
                record_type: 99,
                op: 1
            }
        ));
    }
}
