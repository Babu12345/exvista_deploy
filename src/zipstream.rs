//! A streaming zip extractor: bytes in, [`Storage`] entries out, no seeking, no
//! buffering of whole files. Enough zip to unpack what ExVista serves (a
//! checkpoint directory zipped STORED, zip64 for the multi-gigabyte weights) and
//! what users upload (STORED or DEFLATE), and nothing more.
//!
//! What it deliberately does not do: encryption, spanning, STORED entries whose
//! sizes only appear in a trailing data descriptor (undecidable without seeking),
//! and CRC-32 checking — the artifact's SHA-256, verified by the caller over the
//! same bytes, already covers integrity end to end.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

use crate::traits::Storage;

/// Why extraction stopped.
#[derive(Debug)]
pub enum ZipError<S> {
    /// Your storage failed.
    Storage(S),
    /// The bytes are not a zip this extractor can stream.
    Archive(String),
    /// An entry name that would escape the checkpoint directory.
    UnsafeEntry(String),
}

const LOCAL_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const CENTRAL_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const END_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const LOCAL_HEADER_LEN: usize = 30;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;
const FLAG_ENCRYPTED: u16 = 1;
const ZIP64_EXTRA_ID: u16 = 0x0001;
const INFLATE_OUT: usize = 32 * 1024;

enum State {
    /// Expecting a local file header (or the central directory, which ends us).
    Header,
    /// Copying a STORED entry's bytes straight through.
    Stored { remaining: u64 },
    /// Inflating a DEFLATE entry.
    Inflate {
        state: Box<InflateState>,
        out: Vec<u8>,
        descriptor: bool,
    },
    /// Skipping a data descriptor: resync on the next signature.
    Skip,
    /// Central directory reached; everything after it is ignored.
    Done,
}

/// Feed it the artifact as it downloads; it writes entries into your storage.
pub struct ZipStream<'a, S: Storage> {
    storage: &'a mut S,
    pending: Vec<u8>,
    state: State,
    entries: usize,
}

enum Parsed {
    NeedMore,
    Central,
    Entry {
        header_len: usize,
        name: String,
        method: u16,
        flags: u16,
        compressed: u64,
        is_dir: bool,
    },
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn u64_at(b: &[u8], i: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[i..i + 8]);
    u64::from_le_bytes(a)
}

/// Reject anything that could write outside the checkpoint directory.
pub(crate) fn check_rel_path(name: &str) -> Result<(), String> {
    if name.is_empty() || name.starts_with('/') || name.contains('\\') || name.contains('\0') {
        return Err(name.into());
    }
    if name.len() > 1 && name.as_bytes()[1] == b':' {
        return Err(name.into()); // a Windows drive prefix
    }
    if name.split('/').any(|c| c == "..") {
        return Err(name.into());
    }
    Ok(())
}

fn parse_local_header<S>(buf: &[u8]) -> Result<Parsed, ZipError<S>> {
    if buf.len() < 4 {
        return Ok(Parsed::NeedMore);
    }
    if buf[..4] == CENTRAL_SIG || buf[..4] == END_SIG {
        return Ok(Parsed::Central);
    }
    if buf[..4] != LOCAL_SIG {
        return Err(ZipError::Archive(String::from(
            "expected a local file header",
        )));
    }
    if buf.len() < LOCAL_HEADER_LEN {
        return Ok(Parsed::NeedMore);
    }
    let flags = u16_at(buf, 6);
    let method = u16_at(buf, 8);
    let mut compressed = u32_at(buf, 18) as u64;
    let mut uncompressed = u32_at(buf, 22) as u64;
    let name_len = u16_at(buf, 26) as usize;
    let extra_len = u16_at(buf, 28) as usize;
    let header_len = LOCAL_HEADER_LEN + name_len + extra_len;
    if buf.len() < header_len {
        return Ok(Parsed::NeedMore);
    }
    if flags & FLAG_ENCRYPTED != 0 {
        return Err(ZipError::Archive(String::from(
            "encrypted entries are not supported",
        )));
    }
    let name: String = core::str::from_utf8(&buf[LOCAL_HEADER_LEN..LOCAL_HEADER_LEN + name_len])
        .map_err(|_| ZipError::Archive(String::from("entry name is not UTF-8")))?
        .into();

    // zip64: a 0xFFFFFFFF size means "look in the extra field", where the local
    // header carries the original then the compressed size as u64s.
    let extra = &buf[LOCAL_HEADER_LEN + name_len..header_len];
    if compressed == 0xFFFF_FFFF || uncompressed == 0xFFFF_FFFF {
        let mut i = 0;
        let mut found = false;
        while i + 4 <= extra.len() {
            let id = u16_at(extra, i);
            let size = u16_at(extra, i + 2) as usize;
            let data_end = i + 4 + size;
            if data_end > extra.len() {
                break;
            }
            if id == ZIP64_EXTRA_ID {
                let d = &extra[i + 4..data_end];
                let mut j = 0;
                if uncompressed == 0xFFFF_FFFF {
                    if d.len() < j + 8 {
                        return Err(ZipError::Archive(String::from("short zip64 extra")));
                    }
                    uncompressed = u64_at(d, j);
                    j += 8;
                }
                if compressed == 0xFFFF_FFFF {
                    if d.len() < j + 8 {
                        return Err(ZipError::Archive(String::from("short zip64 extra")));
                    }
                    compressed = u64_at(d, j);
                }
                found = true;
                break;
            }
            i = data_end;
        }
        if !found {
            return Err(ZipError::Archive(String::from(
                "zip64 sizes without a zip64 extra field",
            )));
        }
    }
    let _ = uncompressed; // informational; STORED copies `compressed` bytes, DEFLATE ends itself
    Ok(Parsed::Entry {
        header_len,
        is_dir: name.ends_with('/'),
        name,
        method,
        flags,
        compressed,
    })
}

fn find_signature(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == LOCAL_SIG || w == CENTRAL_SIG || w == END_SIG)
}

impl<'a, S: Storage> ZipStream<'a, S> {
    /// Start extracting into `storage` (between its `begin` and `commit`).
    pub fn new(storage: &'a mut S) -> Self {
        Self {
            storage,
            pending: Vec::new(),
            state: State::Header,
            entries: 0,
        }
    }

    /// Entries completed so far.
    pub fn entries(&self) -> usize {
        self.entries
    }

    /// Feed the next chunk of the archive.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), ZipError<S::Error>> {
        self.pending.extend_from_slice(chunk);
        loop {
            match self.state {
                State::Done => {
                    self.pending.clear();
                    return Ok(());
                }
                State::Header => match parse_local_header::<S::Error>(&self.pending)? {
                    Parsed::NeedMore => return Ok(()),
                    Parsed::Central => {
                        self.state = State::Done;
                    }
                    Parsed::Entry {
                        header_len,
                        name,
                        method,
                        flags,
                        compressed,
                        is_dir,
                    } => {
                        self.pending.drain(..header_len);
                        if is_dir {
                            continue; // directories materialize through their files
                        }
                        check_rel_path(&name).map_err(ZipError::UnsafeEntry)?;
                        let descriptor = flags & FLAG_DATA_DESCRIPTOR != 0;
                        self.state = match method {
                            METHOD_STORED => {
                                if descriptor {
                                    return Err(ZipError::Archive(format!(
                                        "{name}: STORED with a data descriptor cannot be streamed"
                                    )));
                                }
                                State::Stored {
                                    remaining: compressed,
                                }
                            }
                            METHOD_DEFLATE => State::Inflate {
                                state: InflateState::new_boxed(DataFormat::Raw),
                                out: alloc::vec![0u8; INFLATE_OUT],
                                descriptor,
                            },
                            other => {
                                return Err(ZipError::Archive(format!(
                                    "{name}: compression method {other} is not supported"
                                )))
                            }
                        };
                        self.storage.begin_entry(&name).map_err(ZipError::Storage)?;
                        if let State::Stored { remaining: 0 } = self.state {
                            self.storage.end_entry().map_err(ZipError::Storage)?;
                            self.entries += 1;
                            self.state = State::Header;
                        }
                    }
                },
                State::Stored { ref mut remaining } => {
                    if self.pending.is_empty() {
                        return Ok(());
                    }
                    let n = (*remaining).min(self.pending.len() as u64) as usize;
                    self.storage
                        .write(&self.pending[..n])
                        .map_err(ZipError::Storage)?;
                    self.pending.drain(..n);
                    *remaining -= n as u64;
                    if *remaining == 0 {
                        self.storage.end_entry().map_err(ZipError::Storage)?;
                        self.entries += 1;
                        self.state = State::Header;
                    }
                }
                State::Inflate {
                    ref mut state,
                    ref mut out,
                    descriptor,
                } => {
                    if self.pending.is_empty() {
                        return Ok(());
                    }
                    let res = inflate(state, &self.pending, out, MZFlush::None);
                    if res.bytes_written > 0 {
                        self.storage
                            .write(&out[..res.bytes_written])
                            .map_err(ZipError::Storage)?;
                    }
                    self.pending.drain(..res.bytes_consumed);
                    match res.status {
                        Ok(MZStatus::StreamEnd) => {
                            self.storage.end_entry().map_err(ZipError::Storage)?;
                            self.entries += 1;
                            self.state = if descriptor {
                                State::Skip
                            } else {
                                State::Header
                            };
                        }
                        Ok(_) | Err(MZError::Buf) => {
                            if res.bytes_consumed == 0 && res.bytes_written == 0 {
                                // Neither progress nor an end: need more input.
                                return Ok(());
                            }
                        }
                        Err(e) => return Err(ZipError::Archive(format!("inflate failed: {e:?}"))),
                    }
                }
                State::Skip => match find_signature(&self.pending) {
                    Some(pos) => {
                        self.pending.drain(..pos);
                        self.state = State::Header;
                    }
                    None => {
                        // Keep a signature that may straddle this chunk and the next.
                        let keep = self.pending.len().saturating_sub(3);
                        self.pending.drain(..keep);
                        return Ok(());
                    }
                },
            }
        }
    }

    /// The download ended: make sure the archive did too. Returns the number of
    /// file entries written.
    pub fn finish(self) -> Result<usize, ZipError<S::Error>> {
        match self.state {
            State::Done | State::Header | State::Skip
                if self.pending.len() < 4 || matches!(self.state, State::Done) =>
            {
                Ok(self.entries)
            }
            State::Header | State::Skip => Err(ZipError::Archive(String::from(
                "trailing bytes that are not a local header or central directory",
            ))),
            State::Stored { .. } | State::Inflate { .. } => Err(ZipError::Archive(String::from(
                "archive ended inside an entry",
            ))),
            State::Done => Ok(self.entries),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn zip64_sizes_come_from_the_extra_field() {
        // A local header whose 32-bit sizes are 0xFFFFFFFF and whose zip64 extra
        // carries original=5_000_000_000, compressed=5_000_000_000.
        let name = b"model.safetensors";
        let mut h = Vec::new();
        h.extend_from_slice(&LOCAL_SIG);
        h.extend_from_slice(&45u16.to_le_bytes()); // version needed (zip64)
        h.extend_from_slice(&0u16.to_le_bytes()); // flags
        h.extend_from_slice(&METHOD_STORED.to_le_bytes());
        h.extend_from_slice(&[0, 0, 0, 0]); // time, date
        h.extend_from_slice(&0u32.to_le_bytes()); // crc
        h.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // csize
        h.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // usize
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&20u16.to_le_bytes()); // extra len
        h.extend_from_slice(name);
        h.extend_from_slice(&ZIP64_EXTRA_ID.to_le_bytes());
        h.extend_from_slice(&16u16.to_le_bytes());
        h.extend_from_slice(&5_000_000_000u64.to_le_bytes());
        h.extend_from_slice(&5_000_000_000u64.to_le_bytes());
        match parse_local_header::<()>(&h).unwrap() {
            Parsed::Entry {
                compressed, name, ..
            } => {
                assert_eq!(compressed, 5_000_000_000);
                assert_eq!(name, "model.safetensors");
            }
            _ => panic!("expected an entry"),
        }
    }

    #[test]
    fn unsafe_names_are_rejected() {
        for bad in ["../x", "a/../../x", "/etc/passwd", "C:\\x", "a\\b", ""] {
            assert!(check_rel_path(bad).is_err(), "{bad:?} must be rejected");
        }
        for good in ["config.json", "sub/dir/file.bin", "a..b/c"] {
            assert!(check_rel_path(good).is_ok(), "{good:?} must be accepted");
        }
    }
}
