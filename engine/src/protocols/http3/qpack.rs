//! QPACK Header Compression for HTTP/3 per RFC 9204.
//!
//! Implements static & dynamic table compression, RFC 7541 Appendix B Huffman
//! literal encoding (`H=1`) & decoding, encoder/decoder unidirectional stream
//! instructions (`0x02`/`0x03`), and `Insert Count` tracking.

use std::collections::VecDeque;

/// RFC 7541 Appendix B Huffman code table (256 byte symbols: (code, bit_len)).
const HUFFMAN_ENCODE_TABLE: [(u32, u8); 256] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
    (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
    (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
    (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
    (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),
    (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22),
    (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),
    (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),
    (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19),
    (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27),
    (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25),
    (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26),
    (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
];

/// Encode `input` bytes using RFC 7541 Appendix B Huffman coding.
pub fn huffman_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut bit_buf: u64 = 0;
    let mut bit_count: u8 = 0;

    for &b in input {
        let (code, len) = HUFFMAN_ENCODE_TABLE[b as usize];
        bit_buf = (bit_buf << len) | (code as u64);
        bit_count += len;
        while bit_count >= 8 {
            bit_count -= 8;
            out.push(((bit_buf >> bit_count) & 0xFF) as u8);
        }
    }

    if bit_count > 0 {
        let pad = 8 - bit_count;
        let last = (((bit_buf << pad) | ((1u64 << pad) - 1)) & 0xFF) as u8;
        out.push(last);
    }

    out
}

fn encode_prefix_int(buf: &mut Vec<u8>, first_byte_mask: u8, prefix_bits: u8, val: u64) {
    let max_prefix = (1u64 << prefix_bits) - 1;
    if val < max_prefix {
        buf.push(first_byte_mask | (val as u8));
    } else {
        buf.push(first_byte_mask | (max_prefix as u8));
        let mut rem = val - max_prefix;
        while rem >= 128 {
            buf.push(((rem as u8) & 0x7F) | 0x80);
            rem >>= 7;
        }
        buf.push(rem as u8);
    }
}

/// Encode a QPACK string with prefix length `prefix_bits`, setting `H=1` (Huffman)
/// whenever Huffman encoding is strictly shorter than raw UTF-8 bytes.
fn encode_string(buf: &mut Vec<u8>, first_byte_mask: u8, prefix_bits: u8, s: &str) {
    let raw = s.as_bytes();
    let huff = huffman_encode(raw);
    if !raw.is_empty() && huff.len() < raw.len() {
        let h_bit = 1u8 << prefix_bits;
        encode_prefix_int(buf, first_byte_mask | h_bit, prefix_bits, huff.len() as u64);
        buf.extend_from_slice(&huff);
    } else {
        encode_prefix_int(buf, first_byte_mask, prefix_bits, raw.len() as u64);
        buf.extend_from_slice(raw);
    }
}

/// RFC 9204 §3.2 QPACK Dynamic Table with FIFO eviction and `Insert Count` tracking.
#[derive(Debug, Clone)]
pub struct QpackDynamicTable {
    entries: VecDeque<(String, String)>,
    size: usize,
    capacity: usize,
    max_capacity: usize,
    insert_count: u64,
    dropped_count: u64,
}

impl QpackDynamicTable {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            capacity: max_capacity,
            max_capacity,
            insert_count: 0,
            dropped_count: 0,
        }
    }

    #[inline]
    pub fn entry_size(name: &str, value: &str) -> usize {
        name.len() + value.len() + 32
    }

    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped_count
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    pub fn max_entries(&self) -> u64 {
        (self.max_capacity / 32) as u64
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn set_capacity(&mut self, new_cap: usize) -> Result<(), String> {
        if new_cap > self.max_capacity {
            return Err(format!(
                "QPACK dynamic table capacity {} exceeds max {}",
                new_cap, self.max_capacity
            ));
        }
        self.capacity = new_cap;
        while self.size > self.capacity {
            if let Some((n, v)) = self.entries.pop_front() {
                self.size -= Self::entry_size(&n, &v);
                self.dropped_count += 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Insert a new `(name, value)` entry into the dynamic table, evicting oldest entries
    /// as needed, and return its absolute index.
    pub fn insert(&mut self, name: String, value: String) -> Result<u64, String> {
        let esize = Self::entry_size(&name, &value);
        if esize > self.capacity {
            return Err(format!(
                "QPACK entry size {} exceeds table capacity {}",
                esize, self.capacity
            ));
        }
        while self.size + esize > self.capacity {
            if let Some((n, v)) = self.entries.pop_front() {
                self.size -= Self::entry_size(&n, &v);
                self.dropped_count += 1;
            } else {
                break;
            }
        }
        let abs_idx = self.insert_count;
        self.entries.push_back((name, value));
        self.size += esize;
        self.insert_count += 1;
        Ok(abs_idx)
    }

    /// Look up an entry by RFC 9204 absolute index.
    pub fn get_absolute(&self, abs_idx: u64) -> Option<(&str, &str)> {
        if abs_idx < self.dropped_count || abs_idx >= self.insert_count {
            return None;
        }
        let offset = (abs_idx - self.dropped_count) as usize;
        self.entries
            .get(offset)
            .map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// Find an exact `(name, value)` match, returning its absolute index (newest first).
    pub fn find_exact(&self, name: &str, value: &str) -> Option<u64> {
        for (rev_i, (n, v)) in self.entries.iter().rev().enumerate() {
            if n == name && v == value {
                return Some(self.insert_count - 1 - rev_i as u64);
            }
        }
        None
    }

    /// Find a matching header name, returning its absolute index (newest first).
    pub fn find_name(&self, name: &str) -> Option<u64> {
        for (rev_i, (n, _)) in self.entries.iter().rev().enumerate() {
            if n == name {
                return Some(self.insert_count - 1 - rev_i as u64);
            }
        }
        None
    }
}

/// Stateful QPACK encoder (RFC 9204) managing dynamic table insertions,
/// unidirectional encoder stream (`0x02`) instructions, and decoder stream (`0x03`) feedback.
#[derive(Debug, Clone)]
pub struct QpackEncoder {
    pub table: QpackDynamicTable,
    pub known_received_count: u64,
    capacity_sent: bool,
}

impl QpackEncoder {
    pub fn new(max_table_capacity: usize) -> Self {
        Self {
            table: QpackDynamicTable::new(max_table_capacity),
            known_received_count: 0,
            capacity_sent: false,
        }
    }

    /// Encode Set Dynamic Table Capacity instruction (RFC 9204 §4.3.1: `001 | 5-bit prefix`).
    pub fn encode_set_capacity(capacity: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4);
        encode_prefix_int(&mut buf, 0x20, 5, capacity as u64);
        buf
    }

    /// Encode Insert With Name Reference instruction (RFC 9204 §4.3.2: `1 | T | 6-bit prefix`).
    fn encode_insert_with_name_ref(
        buf: &mut Vec<u8>,
        is_static: bool,
        index: u64,
        value: &str,
    ) {
        let mask = if is_static { 0xC0 } else { 0x80 };
        encode_prefix_int(buf, mask, 6, index);
        encode_string(buf, 0x00, 7, value);
    }

    /// Encode Insert With Literal Name instruction (RFC 9204 §4.3.3: `01 | H | 5-bit prefix`).
    fn encode_insert_literal(buf: &mut Vec<u8>, name: &str, value: &str) {
        encode_string(buf, 0x40, 5, name);
        encode_string(buf, 0x00, 7, value);
    }

    /// Encode request headers using both static and dynamic QPACK tables.
    /// Returns `(encoder_stream_instructions, encoded_field_section)`.
    pub fn encode_headers(
        &mut self,
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> (Vec<u8>, Vec<u8>) {
        let mut enc_stream = Vec::new();
        if !self.capacity_sent && self.table.capacity() > 0 {
            enc_stream.extend_from_slice(&Self::encode_set_capacity(self.table.capacity()));
            self.capacity_sent = true;
        }

        // Build ordered field list (Chrome pseudo-header order: :method, :authority, :scheme, :path)
        let mut fields: Vec<(String, String)> = Vec::with_capacity(4 + headers.len());
        fields.push((":method".to_string(), method.to_string()));
        fields.push((":authority".to_string(), authority.to_string()));
        fields.push((":scheme".to_string(), scheme.to_string()));
        fields.push((":path".to_string(), path.to_string()));
        for (k, v) in headers {
            fields.push((k.to_ascii_lowercase(), v.clone()));
        }

        // Phase 1: Insert eligible non-static headers into dynamic table when capacity allows
        let mut refs: Vec<FieldEncodingRef> = Vec::with_capacity(fields.len());
        let mut required_insert_count: u64 = 0;

        for (name, value) in &fields {
            if let Some(static_idx) = find_static_exact(name, value) {
                refs.push(FieldEncodingRef::StaticExact(static_idx));
                continue;
            }
            if let Some(dyn_idx) = self.table.find_exact(name, value) {
                required_insert_count = required_insert_count.max(dyn_idx + 1);
                refs.push(FieldEncodingRef::DynamicExact(dyn_idx));
                continue;
            }

            // Insert into dynamic table if it fits and is reusable (skip sensitive/ephemeral cookies/auth)
            let sensitive = name == "cookie" || name == "authorization";
            let esize = QpackDynamicTable::entry_size(name, value);
            if !sensitive && self.table.capacity() > 0 && esize <= self.table.capacity() / 2 {
                if let Some(static_name_idx) = find_static_name(name) {
                    if let Ok(abs_idx) = self.table.insert(name.clone(), value.clone()) {
                        Self::encode_insert_with_name_ref(
                            &mut enc_stream,
                            true,
                            static_name_idx as u64,
                            value,
                        );
                        required_insert_count = required_insert_count.max(abs_idx + 1);
                        refs.push(FieldEncodingRef::DynamicExact(abs_idx));
                        continue;
                    }
                } else if let Ok(abs_idx) = self.table.insert(name.clone(), value.clone()) {
                    Self::encode_insert_literal(&mut enc_stream, name, value);
                    required_insert_count = required_insert_count.max(abs_idx + 1);
                    refs.push(FieldEncodingRef::DynamicExact(abs_idx));
                    continue;
                }
            }

            if let Some(static_name_idx) = find_static_name(name) {
                refs.push(FieldEncodingRef::StaticNameRef(static_name_idx, value.clone()));
            } else {
                refs.push(FieldEncodingRef::Literal(name.clone(), value.clone()));
            }
        }

        // Phase 2: Encode Field Section Prefix (RFC 9204 §4.5.1)
        let mut block = Vec::with_capacity(64 + fields.len() * 16);
        let base = required_insert_count;
        if required_insert_count == 0 {
            block.push(0x00);
            block.push(0x00);
        } else {
            let max_entries = self.table.max_entries().max(1);
            let encoded_ric = (required_insert_count % (2 * max_entries)) + 1;
            encode_prefix_int(&mut block, 0x00, 8, encoded_ric);
            // S=0, Delta Base=0 => Base = Required Insert Count
            block.push(0x00);
        }

        // Phase 3: Encode field lines
        for r in refs {
            match r {
                FieldEncodingRef::StaticExact(idx) => {
                    // 1 | T=1 | 6-bit index
                    encode_prefix_int(&mut block, 0xC0, 6, idx as u64);
                }
                FieldEncodingRef::DynamicExact(abs_idx) => {
                    // Base == required_insert_count > abs_idx, so pre-base relative index = base - abs_idx - 1
                    let rel_idx = base - abs_idx - 1;
                    // 1 | T=0 | 6-bit relative index
                    encode_prefix_int(&mut block, 0x80, 6, rel_idx);
                }
                FieldEncodingRef::StaticNameRef(idx, val) => {
                    // 01 | N=0 | T=1 | 4-bit index
                    encode_prefix_int(&mut block, 0x50, 4, idx as u64);
                    encode_string(&mut block, 0x00, 7, &val);
                }
                FieldEncodingRef::Literal(name, val) => {
                    QpackCodec::encode_literal(&mut block, &name, &val);
                }
            }
        }

        (enc_stream, block)
    }

    /// Process incoming bytes from the peer's unidirectional QPACK Decoder stream (`0x03`).
    pub fn process_decoder_stream(&mut self, data: &[u8]) -> Result<(), String> {
        let mut pos = 0;
        while pos < data.len() {
            let b = data[pos];
            if b & 0x80 != 0 {
                // Section Acknowledgment: 1 | 7-bit stream_id
                let _stream_id = QpackCodec::decode_prefix_int(data, &mut pos, 7)?;
                self.known_received_count = self.known_received_count.max(self.table.insert_count());
            } else if b & 0xC0 == 0x40 {
                // Stream Cancellation: 01 | 6-bit stream_id
                let _stream_id = QpackCodec::decode_prefix_int(data, &mut pos, 6)?;
            } else {
                // Insert Count Increment: 00 | 6-bit increment
                let inc = QpackCodec::decode_prefix_int(data, &mut pos, 6)?;
                if inc == 0 {
                    return Err("Invalid QPACK Insert Count Increment of 0".to_string());
                }
                self.known_received_count = self.known_received_count.saturating_add(inc);
            }
        }
        Ok(())
    }
}

enum FieldEncodingRef {
    StaticExact(usize),
    DynamicExact(u64),
    StaticNameRef(usize, String),
    Literal(String, String),
}

/// Outcome of decoding a QPACK field section with dynamic table support.
#[derive(Debug, PartialEq, Eq)]
pub enum QpackDecodeOutcome {
    /// Successfully decoded status code, headers, and optional Section Acknowledgment bytes (`0x03` stream).
    Decoded {
        status: u16,
        headers: Vec<(String, String)>,
        section_ack: Vec<u8>,
    },
    /// Header block references dynamic table entries not yet received on the encoder stream (`0x02`).
    Blocked { required_insert_count: u64 },
}

/// Stateful QPACK decoder (RFC 9204) managing dynamic table state, incoming encoder
/// stream (`0x02`) instructions, `Insert Count` tracking, and decoder stream (`0x03`) acknowledgments.
#[derive(Debug, Clone)]
pub struct QpackDecoder {
    pub table: QpackDynamicTable,
    pending_encoder_bytes: Vec<u8>,
}

impl QpackDecoder {
    pub fn new(max_table_capacity: usize) -> Self {
        Self {
            table: QpackDynamicTable::new(max_table_capacity),
            pending_encoder_bytes: Vec::new(),
        }
    }

    /// Encode an Insert Count Increment decoder stream instruction (RFC 9204 §4.4.3: `00 | 6-bit increment`).
    pub fn encode_insert_count_increment(increment: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4);
        if increment > 0 {
            encode_prefix_int(&mut buf, 0x00, 6, increment);
        }
        buf
    }

    /// Encode a Section Acknowledgment decoder stream instruction (RFC 9204 §4.4.1: `1 | 7-bit stream_id`).
    pub fn encode_section_ack(stream_id: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4);
        encode_prefix_int(&mut buf, 0x80, 7, stream_id);
        buf
    }

    /// Feed bytes from the peer's unidirectional QPACK Encoder stream (`0x02`).
    /// Returns any Insert Count Increment bytes to send back on our QPACK Decoder stream (`0x03`).
    pub fn process_encoder_stream(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.pending_encoder_bytes.extend_from_slice(data);
        let start_insert_count = self.table.insert_count();
        let mut pos = 0;

        while pos < self.pending_encoder_bytes.len() {
            let saved_pos = pos;
            let b = self.pending_encoder_bytes[pos];

            let step_res: Result<(), String> = if b & 0x80 != 0 {
                // §4.3.2 Insert With Name Reference: 1 | T | 6-bit name_index
                let is_static = (b & 0x40) != 0;
                match QpackCodec::decode_prefix_int(&self.pending_encoder_bytes, &mut pos, 6) {
                    Ok(idx) => {
                        match QpackCodec::decode_string(&self.pending_encoder_bytes, &mut pos, 7) {
                            Ok(val) => {
                                let name = if is_static {
                                    STATIC_TABLE
                                        .get(idx as usize)
                                        .map(|(n, _)| (*n).to_string())
                                        .ok_or_else(|| {
                                            format!("Invalid static name index {}", idx)
                                        })?
                                } else {
                                    let abs = self
                                        .table
                                        .insert_count()
                                        .checked_sub(idx + 1)
                                        .ok_or_else(|| {
                                            format!("Invalid dynamic relative index {}", idx)
                                        })?;
                                    self.table
                                        .get_absolute(abs)
                                        .map(|(n, _)| n.to_string())
                                        .ok_or_else(|| {
                                            format!("Evicted dynamic name index {}", abs)
                                        })?
                                };
                                self.table.insert(name, val).map(|_| ())
                            }
                            Err(e) if is_eof_err(&e) => {
                                pos = saved_pos;
                                break;
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) if is_eof_err(&e) => {
                        pos = saved_pos;
                        break;
                    }
                    Err(e) => Err(e),
                }
            } else if b & 0xC0 == 0x40 {
                // §4.3.3 Insert With Literal Name: 01 | H | 5-bit name_len
                match QpackCodec::decode_string(&self.pending_encoder_bytes, &mut pos, 5) {
                    Ok(name) => {
                        match QpackCodec::decode_string(&self.pending_encoder_bytes, &mut pos, 7) {
                            Ok(val) => self.table.insert(name, val).map(|_| ()),
                            Err(e) if is_eof_err(&e) => {
                                pos = saved_pos;
                                break;
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) if is_eof_err(&e) => {
                        pos = saved_pos;
                        break;
                    }
                    Err(e) => Err(e),
                }
            } else if b & 0xE0 == 0x20 {
                // §4.3.1 Set Dynamic Table Capacity: 001 | 5-bit capacity
                match QpackCodec::decode_prefix_int(&self.pending_encoder_bytes, &mut pos, 5) {
                    Ok(cap) => self.table.set_capacity(cap as usize),
                    Err(e) if is_eof_err(&e) => {
                        pos = saved_pos;
                        break;
                    }
                    Err(e) => Err(e),
                }
            } else {
                // §4.3.4 Duplicate: 000 | 5-bit relative_index
                match QpackCodec::decode_prefix_int(&self.pending_encoder_bytes, &mut pos, 5) {
                    Ok(rel_idx) => {
                        let abs = self
                            .table
                            .insert_count()
                            .checked_sub(rel_idx + 1)
                            .ok_or_else(|| format!("Invalid duplicate index {}", rel_idx))?;
                        let (n, v) = self
                            .table
                            .get_absolute(abs)
                            .map(|(n, v)| (n.to_string(), v.to_string()))
                            .ok_or_else(|| format!("Evicted duplicate index {}", abs))?;
                        self.table.insert(n, v).map(|_| ())
                    }
                    Err(e) if is_eof_err(&e) => {
                        pos = saved_pos;
                        break;
                    }
                    Err(e) => Err(e),
                }
            };

            step_res?;
        }

        if pos > 0 {
            self.pending_encoder_bytes.drain(..pos);
        }

        let delta = self.table.insert_count().saturating_sub(start_insert_count);
        Ok(Self::encode_insert_count_increment(delta))
    }

    /// Decode an RFC 9204 §4.5 Encoded Field Section using both static and dynamic tables.
    pub fn decode_field_section(
        &self,
        stream_id: u64,
        data: &[u8],
    ) -> Result<QpackDecodeOutcome, String> {
        if data.len() < 2 {
            return Err("QPACK data too short for prefix".to_string());
        }

        let mut pos = 0;
        // §4.5.1.1 Encoded Insert Count (8-bit prefix)
        let encoded_ric = QpackCodec::decode_prefix_int(data, &mut pos, 8)?;
        let req_insert_count = if encoded_ric == 0 {
            0
        } else {
            let max_entries = self.table.max_entries();
            if max_entries == 0 {
                return Err("QPACK dynamic table referenced when max_entries == 0".to_string());
            }
            let full_range = 2 * max_entries;
            if encoded_ric > full_range {
                return Err("Encoded Required Insert Count out of range".to_string());
            }
            let max_value = self.table.insert_count() + max_entries;
            let max_wrapped = (max_value / full_range) * full_range;
            let mut ric = max_wrapped + encoded_ric - 1;
            if ric > max_value {
                if ric <= full_range {
                    return Err("Invalid Required Insert Count wrap".to_string());
                }
                ric -= full_range;
            }
            if ric == 0 {
                return Err("Decoded Required Insert Count cannot be 0".to_string());
            }
            ric
        };

        if req_insert_count > self.table.insert_count() {
            return Ok(QpackDecodeOutcome::Blocked {
                required_insert_count: req_insert_count,
            });
        }

        // §4.5.1.2 Sign (1-bit) | Delta Base (7-bit prefix)
        let sign = (data[pos] & 0x80) != 0;
        let delta_base = QpackCodec::decode_prefix_int(data, &mut pos, 7)?;
        let base = if !sign {
            req_insert_count
                .checked_add(delta_base)
                .ok_or_else(|| "QPACK Base overflow".to_string())?
        } else {
            req_insert_count
                .checked_sub(delta_base + 1)
                .ok_or_else(|| "QPACK Base underflow".to_string())?
        };

        let mut status_code: u16 = 200;
        let mut headers = Vec::new();

        while pos < data.len() {
            let b = data[pos];
            if b & 0x80 != 0 {
                // §4.5.2 Indexed Field Line: 1 | T | Index (6-bit prefix)
                let is_static = (b & 0x40) != 0;
                let idx = QpackCodec::decode_prefix_int(data, &mut pos, 6)?;
                let pair = if is_static {
                    STATIC_TABLE.get(idx as usize).copied()
                } else {
                    base.checked_sub(idx + 1)
                        .and_then(|abs| self.table.get_absolute(abs))
                };
                if let Some((name, val)) = pair {
                    push_decoded_header(&mut status_code, &mut headers, name, val);
                }
            } else if b & 0xC0 == 0x40 {
                // §4.5.4 Literal Field Line with Name Reference: 01 | N | T | NameIndex (4-bit prefix)
                let is_static = (b & 0x10) != 0;
                let name_idx = QpackCodec::decode_prefix_int(data, &mut pos, 4)?;
                let value = QpackCodec::decode_string(data, &mut pos, 7)?;
                let name_opt = if is_static {
                    STATIC_TABLE.get(name_idx as usize).map(|(n, _)| *n)
                } else {
                    base.checked_sub(name_idx + 1)
                        .and_then(|abs| self.table.get_absolute(abs).map(|(n, _)| n))
                };
                if let Some(name) = name_opt {
                    push_decoded_header(&mut status_code, &mut headers, name, &value);
                }
            } else if b & 0xE0 == 0x20 {
                // §4.5.6 Literal Field Line with Literal Name: 001 | N | H | NameLen (3-bit prefix)
                let name = QpackCodec::decode_string(data, &mut pos, 3)?;
                let value = QpackCodec::decode_string(data, &mut pos, 7)?;
                push_decoded_header(&mut status_code, &mut headers, &name, &value);
            } else if b & 0xF0 == 0x10 {
                // §4.5.3 Indexed Field Line with Post-Base Index: 0001 | Index (4-bit prefix)
                let idx = QpackCodec::decode_prefix_int(data, &mut pos, 4)?;
                if let Some((name, val)) = base
                    .checked_add(idx)
                    .and_then(|abs| self.table.get_absolute(abs))
                {
                    push_decoded_header(&mut status_code, &mut headers, name, val);
                }
            } else {
                // §4.5.5 Literal Field Line with Post-Base Name Reference: 0000 | N | NameIndex (3-bit prefix)
                let name_idx = QpackCodec::decode_prefix_int(data, &mut pos, 3)?;
                let value = QpackCodec::decode_string(data, &mut pos, 7)?;
                if let Some((name, _)) = base
                    .checked_add(name_idx)
                    .and_then(|abs| self.table.get_absolute(abs))
                {
                    push_decoded_header(&mut status_code, &mut headers, name, &value);
                }
            }
        }

        let section_ack = if req_insert_count > 0 {
            Self::encode_section_ack(stream_id)
        } else {
            Vec::new()
        };

        Ok(QpackDecodeOutcome::Decoded {
            status: status_code,
            headers,
            section_ack,
        })
    }
}

fn is_eof_err(e: &str) -> bool {
    e.starts_with("Unexpected EOF") || e.starts_with("Incomplete integer")
}

fn push_decoded_header(
    status_code: &mut u16,
    headers: &mut Vec<(String, String)>,
    name: &str,
    value: &str,
) {
    if name == ":status" {
        if let Ok(st) = value.parse::<u16>() {
            *status_code = st;
        }
    } else if !name.starts_with(':') {
        headers.push((name.to_string(), value.to_string()));
    }
}

fn find_static_exact(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|&(n, v)| n == name && v == value)
}

fn find_static_name(name: &str) -> Option<usize> {
    STATIC_TABLE.iter().position(|&(n, _)| n == name)
}

/// Stateless QPACK helper (static table + Huffman literal encoding).
pub struct QpackCodec;

impl QpackCodec {
    /// Encode request headers into a stateless QPACK encoded byte block using
    /// static table references and Huffman literal encoding (`H=1`).
    pub fn encode_headers(
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        // 1. QPACK Prefix (RFC 9204 Section 4.5.1):
        // Required Insert Count = 0, Sign bit = 0, Delta Base = 0
        buf.push(0x00);
        buf.push(0x00);

        // 2. Encode Pseudo-headers (RFC 9204 §4.5.2: 1 | T=1 | 6-bit static index => 0xC0 | idx)
        // :method
        if method.eq_ignore_ascii_case("GET") {
            buf.push(0xC0 | 17);
        } else if method.eq_ignore_ascii_case("POST") {
            buf.push(0xC0 | 20);
        } else {
            Self::encode_literal(&mut buf, ":method", method);
        }

        // :scheme
        if scheme.eq_ignore_ascii_case("https") {
            buf.push(0xC0 | 23);
        } else if scheme.eq_ignore_ascii_case("http") {
            buf.push(0xC0 | 22);
        } else {
            Self::encode_literal(&mut buf, ":scheme", scheme);
        }

        // :authority
        Self::encode_literal(&mut buf, ":authority", authority);

        // :path
        if path == "/" {
            buf.push(0xC0 | 1);
        } else {
            Self::encode_literal(&mut buf, ":path", path);
        }

        // 3. Encode regular headers
        for (name, value) in headers {
            let lower_name = name.to_ascii_lowercase();
            if lower_name == "accept-encoding" && value == "gzip, deflate, br" {
                buf.push(0xC0 | 31);
            } else {
                Self::encode_literal(&mut buf, &lower_name, value);
            }
        }

        buf
    }

    /// Encode a Literal Field Line with Literal Name (RFC 9204 Section 4.5.6)
    /// Pattern: 001 N H | name_len (3-bit prefix) | name | H | value_len (7-bit prefix) | value
    /// Automatically uses Huffman coding (`H=1`) whenever shorter than raw bytes.
    pub fn encode_literal(buf: &mut Vec<u8>, name: &str, value: &str) {
        encode_string(buf, 0x20, 3, name);
        encode_string(buf, 0x00, 7, value);
    }

    /// Decode stateless QPACK encoded response headers into status code and header list (RFC 9204 §4.5).
    pub fn decode_response_headers(data: &[u8]) -> Result<(u16, Vec<(String, String)>), String> {
        let decoder = QpackDecoder::new(0);
        match decoder.decode_field_section(0, data)? {
            QpackDecodeOutcome::Decoded {
                status, headers, ..
            } => Ok((status, headers)),
            QpackDecodeOutcome::Blocked { .. } => {
                Err("Stateless QPACK decoder encountered dynamic table reference".to_string())
            }
        }
    }

    pub(crate) fn decode_prefix_int(
        data: &[u8],
        pos: &mut usize,
        prefix_bits: u8,
    ) -> Result<u64, String> {
        if *pos >= data.len() {
            return Err("Unexpected EOF in QPACK prefix integer".to_string());
        }
        let mask = ((1u16 << prefix_bits) - 1) as u8;
        let mut val = (data[*pos] & mask) as u64;
        *pos += 1;
        if val < mask as u64 {
            return Ok(val);
        }
        let mut shift = 0u32;
        loop {
            if *pos >= data.len() {
                return Err("Incomplete integer in QPACK decode".to_string());
            }
            let b = data[*pos];
            *pos += 1;
            val = val
                .checked_add(((b & 0x7F) as u64) << shift)
                .ok_or_else(|| "Integer overflow in QPACK decode".to_string())?;
            if b & 0x80 == 0 {
                return Ok(val);
            }
            shift += 7;
            if shift >= 63 {
                return Err("Integer overflow in QPACK decode".to_string());
            }
        }
    }

    pub(crate) fn decode_string(
        data: &[u8],
        pos: &mut usize,
        prefix_bits: u8,
    ) -> Result<String, String> {
        if *pos >= data.len() {
            return Err("Unexpected EOF in QPACK string header".to_string());
        }
        let huffman = (data[*pos] & (1u8 << prefix_bits)) != 0;
        let len = Self::decode_prefix_int(data, pos, prefix_bits)? as usize;
        if *pos + len > data.len() {
            return Err(format!(
                "Unexpected EOF in QPACK string (need {} bytes, have {})",
                len,
                data.len() - *pos
            ));
        }
        let slice = &data[*pos..*pos + len];
        *pos += len;
        if huffman {
            let mut dec = fluke_hpack::huffman::HuffmanDecoder::new();
            let decoded = dec
                .decode(slice)
                .map_err(|e| format!("QPACK Huffman decode error: {:?}", e))?;
            Ok(String::from_utf8_lossy(&decoded).to_string())
        } else {
            Ok(String::from_utf8_lossy(slice).to_string())
        }
    }
}

/// RFC 9204 Appendix A Static Table (99 entries, indices 0..98).
const STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qpack_encode_and_decode_roundtrip() {
        let method = "GET";
        let scheme = "https";
        let authority = "www.youtube.com";
        let path = "/watch?v=123";
        let headers = vec![
            ("user-agent".to_string(), "ZNet/1.0".to_string()),
            ("accept".to_string(), "*/*".to_string()),
        ];

        let encoded = QpackCodec::encode_headers(method, scheme, authority, path, &headers);
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x00);
        // Verify T=1 (static table) bit is set on indexed pseudo-headers
        assert_eq!(encoded[2], 0xC0 | 17); // :method GET
        assert_eq!(encoded[3], 0xC0 | 23); // :scheme https (index 23 in RFC 9204 Appendix A)
    }

    #[test]
    fn test_qpack_huffman_literal_encoding_sets_h_bit_and_roundtrips() {
        let mut encoded = vec![0x00, 0x00];
        QpackCodec::encode_literal(&mut encoded, "x-custom-header", "www.example.com/index.html");
        // Byte 2 is 001 | N=0 | H=1 | 3-bit len => H bit (0x08) must be set
        assert_ne!(encoded[2] & 0x08, 0, "Expected Huffman H=1 bit on literal name");
        // Encoded block must be strictly smaller than raw uncompressed length
        let raw_len = 2 + 2 + "x-custom-header".len() + "www.example.com/index.html".len();
        assert!(encoded.len() < raw_len, "Huffman encoding should compress ASCII headers");

        let (status, headers) = QpackCodec::decode_response_headers(&encoded).expect("decode");
        assert_eq!(status, 200);
        assert_eq!(
            headers,
            vec![(
                "x-custom-header".to_string(),
                "www.example.com/index.html".to_string()
            )]
        );
    }

    #[test]
    fn test_qpack_dynamic_table_encoder_decoder_stream_roundtrip() {
        let mut encoder = QpackEncoder::new(4096);
        let mut decoder = QpackDecoder::new(4096);

        let req_headers = vec![
            ("user-agent".to_string(), "Zawra/1.0".to_string()),
            ("x-trace-id".to_string(), "trace-998877".to_string()),
            ("accept-encoding".to_string(), "gzip, deflate, br, zstd".to_string()),
        ];

        let (enc_stream, field_section) = encoder.encode_headers(
            "GET",
            "https",
            "api.example.com",
            "/v2/items",
            &req_headers,
        );
        assert!(!enc_stream.is_empty(), "Encoder stream must emit dynamic inserts");
        assert!(encoder.table.insert_count() >= 3);

        // Before feeding encoder stream, decoder must report Blocked
        let blocked = decoder
            .decode_field_section(4, &field_section)
            .expect("decode check");
        assert!(matches!(blocked, QpackDecodeOutcome::Blocked { .. }));

        // Feed encoder stream (0x02) -> returns Insert Count Increment for decoder stream (0x03)
        let inc_bytes = decoder
            .process_encoder_stream(&enc_stream)
            .expect("process encoder stream");
        assert!(!inc_bytes.is_empty());
        assert_eq!(decoder.table.insert_count(), encoder.table.insert_count());

        // Now field section decodes cleanly and emits Section Acknowledgment
        let decoded = decoder
            .decode_field_section(4, &field_section)
            .expect("decode field section");
        match decoded {
            QpackDecodeOutcome::Decoded {
                headers,
                section_ack,
                ..
            } => {
                assert!(!section_ack.is_empty(), "Must emit Section Acknowledgment for dynamic refs");
                assert!(headers.contains(&("user-agent".to_string(), "Zawra/1.0".to_string())));
                assert!(headers.contains(&("x-trace-id".to_string(), "trace-998877".to_string())));
                assert!(headers.contains(&(
                    "accept-encoding".to_string(),
                    "gzip, deflate, br, zstd".to_string()
                )));
                // Feed decoder stream acknowledgments back to encoder
                encoder
                    .process_decoder_stream(&inc_bytes)
                    .expect("process inc");
                encoder
                    .process_decoder_stream(&section_ack)
                    .expect("process ack");
                assert!(encoder.known_received_count >= encoder.table.insert_count());
            }
            QpackDecodeOutcome::Blocked { .. } => panic!("Expected Decoded after encoder stream"),
        }
    }

    #[test]
    fn test_qpack_decode_response_static_200() {
        // Prefix: 0x00, 0x00, Static Index 25 (1 | T=1 | 25 => 0xC0 | 25)
        let data = vec![0x00, 0x00, 0xC0 | 25];
        let (status, headers) = QpackCodec::decode_response_headers(&data).expect("decode");
        assert_eq!(status, 200);
        assert!(headers.is_empty());
    }

    #[test]
    fn test_qpack_decode_response_name_ref_and_huffman() {
        // Static index 25 (:status 200) + Literal with Name Reference (server, T=1, idx=92 => 0101_1111 + (92-15))
        let mut data = vec![0x00, 0x00, 0xC0 | 25];
        data.push(0x5F); // 01 | N=0 | T=1 | 15
        data.push(92 - 15); // index 92 ("server")
        data.push(3); // H=0, len=3
        data.extend_from_slice(b"gws");

        let (status, headers) = QpackCodec::decode_response_headers(&data).expect("decode");
        assert_eq!(status, 200);
        assert_eq!(headers, vec![("server".to_string(), "gws".to_string())]);
    }

    #[test]
    fn test_qpack_decode_response_literal_status_and_header() {
        let mut data = vec![0x00, 0x00];
        QpackCodec::encode_literal(&mut data, ":status", "404");
        QpackCodec::encode_literal(&mut data, "content-type", "text/html");

        let (status, headers) = QpackCodec::decode_response_headers(&data).expect("decode");
        assert_eq!(status, 404);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "content-type");
        assert_eq!(headers[0].1, "text/html");
    }
}
