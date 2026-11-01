//! Minimal MaxMind DB (`.mmdb`) reader.
//!
//! Implements the parts GeoLite2 / DB-IP Lite need: the binary search tree,
//! record sizes 24/28/32, the data section's type system (pointer, string,
//! double, bytes, uint16/32/64/128, map, array, boolean, float) and the
//! metadata block. Tested against synthetic trees here and against real
//! DB-IP Lite files at runtime.

use std::net::IpAddr;

const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
/// All-zero padding between the search tree and the data section.
const DATA_SEPARATOR: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Double(f64),
    Bytes(Vec<u8>),
    UInt(u64),
    Map(Vec<(String, Value)>),
    Array(Vec<Value>),
    Bool(bool),
    Float(f32),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::UInt(n) => Some(*n),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Mmdb {
    data: Vec<u8>,
    node_count: usize,
    record_size: u32,
    ip_version: u16,
    #[cfg(test)]
    tree_size: usize,
    data_start: usize,
}

impl Mmdb {
    pub fn open(data: Vec<u8>) -> Option<Self> {
        let marker = find_last(&data, METADATA_MARKER)?;
        let meta_start = marker + METADATA_MARKER.len();
        let db = Mmdb {
            data,
            node_count: 0,
            record_size: 0,
            ip_version: 0,
            #[cfg(test)]
            tree_size: 0,
            data_start: 0,
        };
        let metadata = db.decode_at(meta_start, 0)?.0;
        let node_count = metadata.get("node_count")?.as_u64()? as usize;
        let record_size = metadata.get("record_size")?.as_u64()? as u32;
        let ip_version = metadata.get("ip_version")?.as_u64()? as u16;
        if !matches!(record_size, 24 | 28 | 32) || !matches!(ip_version, 4 | 6) {
            return None;
        }
        let tree_size = node_count * (record_size as usize) / 4;
        if tree_size > marker {
            return None;
        }
        Some(Self {
            node_count,
            record_size,
            ip_version,
            #[cfg(test)]
            tree_size,
            data_start: tree_size,
            ..db
        })
    }

    pub fn ip_version(&self) -> u16 {
        self.ip_version
    }

    /// Look up an address; `None` when the tree has no record for it.
    pub fn lookup(&self, ip: IpAddr) -> Option<Value> {
        match (ip, self.ip_version) {
            (IpAddr::V4(v4), 4) => self.walk(&v4.octets()),
            (IpAddr::V4(v4), _) => {
                // MaxMind maps IPv4 into `::ffff:0:0/96`; DB-IP has used
                // `::/96` in the past, so try both.
                let mut mapped = vec![0u8; 10];
                mapped.extend_from_slice(&[0xff, 0xff]);
                mapped.extend_from_slice(&v4.octets());
                self.walk(&mapped)
                    .or_else(|| self.walk(&[&[0u8; 12][..], &v4.octets()].concat()))
            }
            (IpAddr::V6(v6), _) => self.walk(&v6.octets()),
        }
    }

    fn walk(&self, bits: &[u8]) -> Option<Value> {
        let mut node: usize = 0;
        for byte in bits {
            for shift in (0..8).rev() {
                let bit = (byte >> shift) & 1;
                let record = self.record(node, bit as u8)? as usize;
                if record == self.node_count {
                    return None; // empty record
                }
                if record < self.node_count {
                    node = record;
                } else {
                    let offset = record - self.node_count + self.data_start;
                    return self.decode_at(offset, 0).map(|(v, _)| v);
                }
            }
        }
        None
    }

    fn record(&self, node: usize, right: u8) -> Option<u32> {
        let base = node * (self.record_size as usize) / 4;
        let d = &self.data;
        Some(match self.record_size {
            24 => {
                let off = base + if right == 1 { 3 } else { 0 };
                u24(d.get(off..off + 3)?)?
            }
            28 => {
                let b = d.get(base..base + 7)?;
                let left = ((b[0] as u32) << 20)
                    | ((b[1] as u32) << 12)
                    | ((b[2] as u32) << 4)
                    | ((b[3] as u32) >> 4);
                if right == 0 {
                    left
                } else {
                    (((b[3] as u32) & 0x0f) << 24)
                        | ((b[4] as u32) << 16)
                        | ((b[5] as u32) << 8)
                        | b[6] as u32
                }
            }
            32 => {
                let off = base + if right == 1 { 4 } else { 0 };
                u32::from_be_bytes(d.get(off..off + 4)?.try_into().ok()?)
            }
            _ => return None,
        })
    }

    /// Decode one value at `pos`. Returns the value and the position after it.
    fn decode_at(&self, pos: usize, depth: usize) -> Option<(Value, usize)> {
        if depth > 32 {
            return None; // malformed / cyclic pointers
        }
        let ctrl = *self.data.get(pos)?;
        let mut p = pos + 1;
        let mut kind = ctrl >> 5;

        if kind == 0 {
            // Extended type: the next byte carries type - 7.
            kind = self.data.get(p)? + 7;
            p += 1;
        }
        let mut size = (ctrl & 0x1f) as usize;
        match size {
            29 => {
                size = 29 + *self.data.get(p)? as usize;
                p += 1;
            }
            30 => {
                let b = self.data.get(p..p + 2)?;
                size = 285 + u16::from_be_bytes([b[0], b[1]]) as usize;
                p += 2;
            }
            31 => {
                let b = self.data.get(p..p + 3)?;
                size = 65_821 + u24(b)? as usize;
                p += 3;
            }
            _ => {}
        }

        Some(match kind {
            1 => {
                // Pointer: offset relative to the data section.
                let psize = ((ctrl >> 3) & 0x3) as usize + 1;
                let v = (ctrl & 0x7) as usize;
                let target = if psize == 4 {
                    let b = self.data.get(p..p + 4)?;
                    u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize
                } else {
                    let b = self.data.get(p..p + psize)?;
                    let mut acc = v << (8 * psize);
                    for (i, byte) in b.iter().enumerate() {
                        acc |= (*byte as usize) << (8 * (psize - 1 - i));
                    }
                    acc
                };
                // Pointers are relative to the data section, which starts
                // 16 bytes (the all-zero separator) after the search tree.
                return Some((
                    self.decode_at(self.data_start + DATA_SEPARATOR + target, depth + 1)?.0,
                    p + psize,
                ));
            }
            2 => {
                let b = self.data.get(p..p + size)?;
                (Value::String(String::from_utf8_lossy(b).to_string()), p + size)
            }
            3 => {
                if size == 8 {
                    let b = self.data.get(p..p + 8)?;
                    (Value::Double(f64::from_be_bytes(b.try_into().ok()?)), p + 8)
                } else {
                    return None;
                }
            }
            4 => {
                let b = self.data.get(p..p + size)?;
                (Value::Bytes(b.to_vec()), p + size)
            }
            5 | 6 | 9 | 10 => {
                let b = self.data.get(p..p + size)?;
                (Value::UInt(be_uint(b)), p + size)
            }
            8 => {
                let b = self.data.get(p..p + size)?;
                (Value::UInt(be_uint(b)), p + size)
            }
            7 => {
                let mut entries = Vec::with_capacity(size);
                let mut q = p;
                for _ in 0..size {
                    let (k, next) = self.decode_at(q, depth + 1)?;
                    q = next;
                    let (v, next) = self.decode_at(q, depth + 1)?;
                    q = next;
                    entries.push((k.as_str()?.to_string(), v));
                }
                (Value::Map(entries), q)
            }
            11 => {
                let mut items = Vec::with_capacity(size);
                let mut q = p;
                for _ in 0..size {
                    let (v, next) = self.decode_at(q, depth + 1)?;
                    q = next;
                    items.push(v);
                }
                (Value::Array(items), q)
            }
            14 => (Value::Bool(size != 0), p),
            15 => {
                if size == 4 {
                    let b = self.data.get(p..p + 4)?;
                    (Value::Float(f32::from_be_bytes(b.try_into().ok()?)), p + 4)
                } else if size == 8 {
                    let b = self.data.get(p..p + 8)?;
                    (Value::Double(f64::from_be_bytes(b.try_into().ok()?)), p + 8)
                } else {
                    return None;
                }
            }
            _ => return None,
        })
    }
}

fn u24(b: &[u8]) -> Option<u32> {
    let b = b.get(..3)?;
    Some(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32)
}

fn be_uint(b: &[u8]) -> u64 {
    b.iter()
        .take(8)
        .fold(0u64, |acc, byte| (acc << 8) | *byte as u64)
}

fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// Country ISO code from a lookup, preferring `country`, then
/// `registered_country` (DB-IP stores it under `country`).
pub fn country_code(value: &Value) -> Option<String> {
    for key in ["country", "registered_country"] {
        if let Some(code) = value
            .get(key)
            .and_then(|m| m.get("iso_code"))
            .and_then(Value::as_str)
        {
            return Some(code.to_string());
        }
    }
    None
}

/// ASN number from a lookup (`autonomous_system_number`).
pub fn asn_number(value: &Value) -> Option<u64> {
    value
        .get("autonomous_system_number")
        .and_then(Value::as_u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny one-node database: 0.0.0.0/0 → the data at `data`.
    fn tiny_db(payload: &[u8], record_size: u32) -> Vec<u8> {
        // node_count = 1; both records point into the data section.
        let node_count = 1usize;
        let tree_bytes = node_count * record_size as usize / 4;
        let mut out = vec![0u8; tree_bytes];
        // A record equal to node_count means "no data". The data section
        // starts DATA_SEPARATOR bytes after the tree, so the first payload
        // byte is at record = node_count + DATA_SEPARATOR.
        let rec = (node_count + DATA_SEPARATOR) as u32;
        match record_size {
            24 => {
                out[0..3].copy_from_slice(&rec.to_be_bytes()[1..4]);
                out[3..6].copy_from_slice(&rec.to_be_bytes()[1..4]);
            }
            28 => {
                // Packed: left = b0<<20 | b1<<12 | b2<<4 | b3>>4,
                //         right = (b3 & 0xF)<<24 | b4<<16 | b5<<8 | b6
                out[0] = (rec >> 20) as u8;
                out[1] = (rec >> 12) as u8;
                out[2] = (rec >> 4) as u8;
                out[3] = (((rec & 0xF) << 4) | ((rec >> 24) & 0xF)) as u8;
                out[4] = (rec >> 16) as u8;
                out[5] = (rec >> 8) as u8;
                out[6] = rec as u8;
            }
            32 => {
                out[0..4].copy_from_slice(&rec.to_be_bytes());
                out[4..8].copy_from_slice(&rec.to_be_bytes());
            }
            _ => unreachable!(),
        }
        out.extend(std::iter::repeat(0u8).take(DATA_SEPARATOR));
        out.extend_from_slice(payload);

        // Metadata: a map with node_count, record_size, ip_version.
        let mut meta = Vec::new();
        meta.push(0xE0 | 3); // map, 3 entries
        push_str(&mut meta, "node_count");
        push_uint(&mut meta, node_count as u64);
        push_str(&mut meta, "record_size");
        push_uint(&mut meta, record_size as u64);
        push_str(&mut meta, "ip_version");
        push_uint(&mut meta, 4);
        out.extend_from_slice(METADATA_MARKER);
        out.extend_from_slice(&meta);
        out
    }

    fn push_str(out: &mut Vec<u8>, s: &str) {
        out.push(0x40 | s.len() as u8); // type 2 (string), size
        out.extend_from_slice(s.as_bytes());
    }

    fn push_uint(out: &mut Vec<u8>, n: u64) {
        if n <= u16::MAX as u64 {
            out.push(0xA0 | 2); // type 5 (uint16), size 2
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            out.push(0xC0 | 4); // type 6 (uint32), size 4
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }

    /// A map {"country": {"iso_code": "ZZ"}} as data-section bytes.
    fn country_payload() -> Vec<u8> {
        let mut d = Vec::new();
        d.push(0xE0 | 1); // map, 1 entry
        push_str(&mut d, "country");
        d.push(0xE0 | 1);
        push_str(&mut d, "iso_code");
        push_str(&mut d, "ZZ");
        d
    }

    #[test]
    fn reads_all_record_sizes() {
        for size in [24, 28, 32] {
            let db = Mmdb::open(tiny_db(&country_payload(), size)).expect("open");
            let v = db.lookup("8.8.8.8".parse().unwrap()).expect("lookup");
            assert_eq!(country_code(&v).as_deref(), Some("ZZ"), "record_size {size}");
        }
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert!(Mmdb::open(vec![]).is_none());
        assert!(Mmdb::open(b"not a database".to_vec()).is_none());
        let mut bad = tiny_db(&country_payload(), 24);
        // Corrupt the metadata marker.
        let pos = find_last(&bad, METADATA_MARKER).unwrap();
        bad[pos] = 0;
        assert!(Mmdb::open(bad).is_none());
    }
}

#[cfg(test)]
mod real_world {
    use super::*;

    /// Runs against a downloaded database: `CAP_TEST_MMDB=/path/to.mmdb`.
    #[test]
    fn looks_up_public_addresses() {
        let Ok(path) = std::env::var("CAP_TEST_MMDB") else {
            return;
        };
        let db = Mmdb::open(std::fs::read(path).expect("read")).expect("open real mmdb");
        println!(
            "nodes={} record_size={} ip_version={} tree={} data_start={}",
            db.node_count, db.record_size, db.ip_version, db.tree_size, db.data_start
        );
        let r0 = db.record(0, 0);
        let r1 = db.record(0, 1);
        println!("node0: left={r0:?} right={r1:?}");
        for (ip, want) in [("8.8.8.8", "US"), ("1.1.1.1", "AU"), ("114.114.114.114", "CN")] {
            let value = db.lookup(ip.parse().unwrap()).expect("lookup");
            let code = country_code(&value).expect("country");
            assert_eq!(code, want, "{ip}");
        }
        assert!(db.lookup("10.1.2.3".parse().unwrap()).is_none());
    }
}
