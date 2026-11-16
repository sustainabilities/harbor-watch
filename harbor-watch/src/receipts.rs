//! The shift log: hash-chained, append-only JSONL — one file per model.
//! Every fitness check appends one line; the chain is tamper-evident and
//! re-derivable from bytes alone (the Waterfront receipts pattern).
//!
//! Line shape:
//! {"ts":"...","event":"enrolled|shift_check","result":"fit|unfit|enrolled",
//!  "file_sha512":"...","tensors_checked":N,"tensors_changed":N,
//!  "changed":["tensor.name",...],"prev_hash":"...","line_hash":"..."}

use crate::sha512;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct ShiftLog {
    path: PathBuf,
}

/// A parsed line of the shift log.
#[derive(Debug, Clone)]
pub struct Entry {
    pub ts: String,
    pub event: String,
    pub result: String,
    pub file_sha512: String,
    pub detail: String,
}

impl ShiftLog {
    pub fn open(dir: &Path, model: &str) -> ShiftLog {
        ShiftLog { path: dir.join(format!("{}.jsonl", model)) }
    }

    /// Append one event. Never panics; failures print to stderr — a
    /// receipt failure is loud but must not stop the check itself.
    pub fn append(&self, event: &str, result: &str, file_sha512: &str, detail: &str) {
        if let Err(e) = self.append_inner(event, result, file_sha512, detail) {
            eprintln!("shift-log append failed (the check itself still ran): {}", e);
        }
    }

    fn append_inner(&self, event: &str, result: &str, file_sha512: &str, detail: &str) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {}", parent.display(), e))?;
        }
        let prev = self.tail_hash()?;
        let mut line = format!(
            "{{\"ts\":\"{}\",\"event\":\"{}\",\"result\":\"{}\",\"file_sha512\":\"{}\"",
            crate::now_ts(), event, result, file_sha512
        );
        if !detail.is_empty() {
            line.push_str(&format!(",\"detail\":\"{}\"", json_escape(detail)));
        }
        line.push_str(&format!(",\"prev_hash\":\"{}\"", prev));
        let line_hash = sha512::hex(&sha512::digest(line.as_bytes()));
        let full = format!("{},\"line_hash\":\"{}\"}}\n", line, line_hash);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("open {}: {}", self.path.display(), e))?;
        f.write_all(full.as_bytes()).map_err(|e| format!("write: {}", e))?;
        f.flush().ok();
        Ok(())
    }

    fn tail_hash(&self) -> Result<String, String> {
        if !self.path.exists() {
            return Ok(GENESIS.to_string());
        }
        let f = std::fs::File::open(&self.path).map_err(|e| format!("open {}: {}", self.path.display(), e))?;
        let last = BufReader::new(f).lines().filter_map(|l| l.ok()).filter(|l| !l.trim().is_empty()).last();
        match last {
            None => Ok(GENESIS.to_string()),
            Some(line) => {
                let idx = line.rfind(",\"line_hash\":\"").ok_or_else(|| format!("{}: corrupt tail", self.path.display()))?;
                Ok(line[idx + 14..].trim_end_matches("\"}").to_string())
            }
        }
    }

    /// Read every entry.
    pub fn entries(&self) -> Result<Vec<Entry>, String> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let f = std::fs::File::open(&self.path).map_err(|e| format!("open {}: {}", self.path.display(), e))?;
        let mut out = Vec::new();
        for line in BufReader::new(f).lines().filter_map(|l| l.ok()) {
            if line.trim().is_empty() {
                continue;
            }
            out.push(Entry {
                ts: grab(&line, "ts").unwrap_or_default(),
                event: grab(&line, "event").unwrap_or_default(),
                result: grab(&line, "result").unwrap_or_default(),
                file_sha512: grab(&line, "file_sha512").unwrap_or_default(),
                detail: grab(&line, "detail").unwrap_or_default(),
            });
        }
        Ok(out)
    }

    /// Re-hash the whole chain: tamper evidence.
    pub fn verify(&self) -> Result<usize, String> {
        if !self.path.exists() {
            return Err(format!("no shift log at {}", self.path.display()));
        }
        let f = std::fs::File::open(&self.path).map_err(|e| format!("open {}: {}", self.path.display(), e))?;
        let mut prev = GENESIS.to_string();
        let mut count = 0usize;
        for (i, raw) in BufReader::new(f).lines().enumerate() {
            let line = raw.map_err(|e| format!("line {}: {}", i + 1, e))?;
            if line.trim().is_empty() {
                continue;
            }
            let idx = line.rfind(",\"line_hash\":\"").ok_or_else(|| format!("{}:{}: no line_hash", self.path.display(), i + 1))?;
            let body = &line[..idx];
            let stated = line[idx + 14..].trim_end_matches("\"}").to_string();
            check_entry(body, &stated, &prev).map_err(|e| format!("{}:{}: {}", self.path.display(), i + 1, e))?;
            prev = stated;
            count += 1;
        }
        Ok(count)
    }
}

/// The pure chain-check core — the Kani/Lean target. Given an entry's
/// body (everything before the line_hash field), its stated hash, and
/// the previous entry's hash: verify the hash recomputes and the chain
/// links. This function carries the tool's tamper-evidence property.
pub fn check_entry(body: &str, stated: &str, prev: &str) -> Result<(), String> {
    let computed = sha512::hex(&sha512::digest(body.as_bytes()));
    if computed != stated {
        return Err("line_hash mismatch — the chain is broken or a line was altered".to_string());
    }
    let stated_prev = grab(body, "prev_hash").ok_or("no prev_hash field")?;
    if stated_prev != prev {
        return Err("prev_hash does not chain".to_string());
    }
    Ok(())
}

fn grab(line: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\":\"", key);
    let i = line.find(&pat)? + pat.len();
    let rest = &line[i..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn json_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '"' => "\\\"".to_string(),
            '\\' => "\\\\".to_string(),
            c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32),
            c => c.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_roundtrip_and_tamper() {
        let dir = std::env::temp_dir().join(format!("hw-log-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = ShiftLog::open(&dir, "test-model");
        log.append("enrolled", "enrolled", "aaa", "baseline");
        log.append("shift_check", "fit", "aaa", "");
        log.append("shift_check", "fit", "aaa", "");
        assert_eq!(log.verify().unwrap(), 3);
        assert_eq!(log.entries().unwrap().len(), 3);
        // tamper: rewrite line 2
        let path = dir.join("test-model.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        let tampered = text.replace("\"result\":\"fit\",\"file_sha512\":\"aaa\"", "\"result\":\"fit\",\"file_sha512\":\"bbb\"");
        std::fs::write(&path, tampered).unwrap();
        assert!(log.verify().is_err(), "tampered chain must fail");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
