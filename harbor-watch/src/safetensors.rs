//! The safetensors reader: parse the header (8-byte LE length + JSON),
//! then hash the whole file and every tensor's byte range. A Lazarus-
//! class edit — a few neurons in one layer — changes exactly one
//! tensor's hash and the whole-file hash: that is the detection.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::sha512;

#[derive(Debug, Clone)]
pub struct TensorInfo {
    pub name: String,
    pub dtype: String,
    pub shape: Vec<u64>,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone)]
pub struct WeightFile {
    pub size: u64,
    pub whole_sha512: String,
    /// Per-tensor hashes for safetensors files; empty for opaque files.
    pub tensors: Vec<(TensorInfo, String)>,
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    Safetensors,
    Opaque,
}

/// Hash a file: whole-file sha512 always; per-tensor when safetensors.
pub fn hash_file(path: &Path) -> Result<WeightFile, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let whole = sha512::hex(&sha512::digest(&bytes));
    let size = bytes.len() as u64;

    match parse_header(&bytes) {
        Some(tensors) => {
            let mut hashed = Vec::new();
            for t in tensors {
                let (s, e) = (t.start as usize + 8 + header_len(&bytes), t.end as usize + 8 + header_len(&bytes));
                let end = e.min(bytes.len());
                if s > end {
                    return Err(format!("tensor {} offsets out of range", t.name));
                }
                let h = sha512::hex(&sha512::digest(&bytes[s..end]));
                hashed.push((t, h));
            }
            Ok(WeightFile { size, whole_sha512: whole, tensors: hashed, kind: Kind::Safetensors })
        }
        None => Ok(WeightFile { size, whole_sha512: whole, tensors: vec![], kind: Kind::Opaque }),
    }
}

fn header_len(bytes: &[u8]) -> usize {
    if bytes.len() < 8 {
        return 0;
    }
    u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize
}

/// Parse the safetensors JSON header into tensor infos.
fn parse_header(bytes: &[u8]) -> Option<Vec<TensorInfo>> {
    if bytes.len() < 8 {
        return None;
    }
    let n = header_len(bytes);
    if n == 0 || 8 + n > bytes.len() {
        return None;
    }
    let header = std::str::from_utf8(&bytes[8..8 + n]).ok()?;
    if !header.trim_start().starts_with('{') {
        return None;
    }
    let v = crate::json::parse(header).ok()?;
    let obj = match v {
        crate::json::Value::Obj(m) => m,
        _ => return None,
    };
    let mut out = Vec::new();
    for (name, spec) in obj {
        if name == "__metadata__" {
            continue;
        }
        let dtype = spec.get("dtype").and_then(|d| d.as_str())?.to_string();
        let shape: Vec<u64> = match spec.get("shape") {
            Some(crate::json::Value::Arr(a)) => a.iter().filter_map(|x| x.as_f64().map(|f| f as u64)).collect(),
            _ => vec![],
        };
        let offs = match spec.get("data_offsets") {
            Some(crate::json::Value::Arr(a)) => a,
            _ => return None,
        };
        let start = offs.first().and_then(|x| x.as_f64()).map(|f| f as u64)?;
        let end = offs.get(1).and_then(|x| x.as_f64()).map(|f| f as u64)?;
        out.push(TensorInfo { name: name.clone(), dtype, shape, start, end });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Some(out)
}

/// A compact description for receipts: "name dtype [shape] hash".
pub fn tensor_line(t: &TensorInfo, hash: &str) -> String {
    format!("{} {} {:?} {}", t.name, t.dtype, t.shape, &hash[..16])
}

/// Compare two weight files; returns the changed tensor names (and the
/// whole-file verdict). Empty names + same whole hash = identical.
pub fn diff(a: &WeightFile, b: &WeightFile) -> Vec<String> {
    if a.whole_sha512 == b.whole_sha512 {
        return vec![];
    }
    let amap: BTreeMap<&str, &str> = a.tensors.iter().map(|(t, h)| (t.name.as_str(), h.as_str())).collect();
    let bmap: BTreeMap<&str, &str> = b.tensors.iter().map(|(t, h)| (t.name.as_str(), h.as_str())).collect();
    let mut changed = Vec::new();
    for (name, ah) in &amap {
        match bmap.get(name) {
            Some(bh) if bh == ah => {}
            _ => changed.push(name.to_string()),
        }
    }
    for name in bmap.keys() {
        if !amap.contains_key(name) {
            changed.push(name.to_string());
        }
    }
    if changed.is_empty() && !a.tensors.is_empty() {
        changed.push("(header or layout changed)".to_string());
    }
    if changed.is_empty() {
        changed.push("(opaque file changed)".to_string());
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_hashing() {
        let dir = std::env::temp_dir().join(format!("hw-st-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("x.bin");
        std::fs::write(&p, b"hello harbor").unwrap();
        let wf = hash_file(&p).unwrap();
        assert_eq!(wf.kind, Kind::Opaque);
        assert_eq!(wf.whole_sha512, sha512::hex(&sha512::digest(b"hello harbor")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn safetensors_roundtrip() {
        // hand-build a minimal safetensors file: header + one F32 tensor
        let header = r#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#;
        let hlen = (header.len() as u64).to_le_bytes();
        let mut f = Vec::new();
        f.extend_from_slice(&hlen);
        f.extend_from_slice(header.as_bytes());
        f.extend_from_slice(&1.0f32.to_le_bytes());
        f.extend_from_slice(&2.0f32.to_le_bytes());
        let dir = std::env::temp_dir().join(format!("hw-st2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("m.safetensors");
        std::fs::write(&p, &f).unwrap();
        let wf = hash_file(&p).unwrap();
        assert_eq!(wf.kind, Kind::Safetensors);
        assert_eq!(wf.tensors.len(), 1);
        assert_eq!(wf.tensors[0].0.name, "w");
        assert_eq!(wf.tensors[0].0.dtype, "F32");
        // tamper one tensor byte -> whole hash changes, tensor detected
        let mut f2 = f.clone();
        f2[8 + header.len()] = 0x7F;
        std::fs::write(&p, &f2).unwrap();
        let wf2 = hash_file(&p).unwrap();
        let changed = diff(&wf, &wf2);
        assert_eq!(changed, vec!["w".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
