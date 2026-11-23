//! DEFLATE streams made by hand, for tests that need far more inflated bytes than they hold: runs
//! of zeros as copies of the byte before, in about 13 bits for each 258 of them.

use duvet_e2e::messages::Record;

/// A raw DEFLATE stream that inflates to each part's bytes, then its zeros, in turn: one block of
/// fixed Huffman codes, each run of zeros a literal zero, then copies of the byte before (length
/// 258, distance 1).
pub fn bomb<'a>(parts: impl IntoIterator<Item = (&'a [u8], u64)>) -> Vec<u8> {
    let mut bits = Bits::default();
    bits.put(1, 1); // the last block,
    bits.put(1, 2); // of fixed codes
    // Length 258 is code 285, 8 bits (11000101); distance 1 is code 0, 5 bits.
    let copy = reversed(0b1100_0101, 8);
    for (prefix, zeros) in parts {
        for &byte in prefix {
            bits.literal(byte);
        }
        if zeros == 0 {
            continue;
        }
        bits.literal(0);
        let mut left = zeros - 1;
        while left >= 258 {
            bits.put(copy, 13);
            left -= 258;
        }
        for _ in 0..left {
            bits.literal(0);
        }
    }
    bits.put(0, 7); // the end of the block: code 256, seven zero bits
    bits.finish()
}

/// `record`'s CBOR up to its envelope's bytes, for an envelope of `len` bytes: what goes before
/// that envelope's zeros. `record`'s envelope must be empty, and its last field written.
pub fn record_head(record: &Record, len: u64) -> Vec<u8> {
    let mut head = Vec::new();
    ciborium::into_writer(record, &mut head).unwrap();
    assert_eq!(
        head.pop(),
        Some(0x40),
        "the record ends with its empty envelope"
    );
    head.push(0x5B); // a byte string, its length in 8 bytes
    head.extend(len.to_be_bytes());
    head
}

/// Bits as DEFLATE packs them: from each byte's least significant bit on, but Huffman codes from
/// their most significant bit.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    acc: u64,
    len: u32,
}

impl Bits {
    fn put(&mut self, value: u64, count: u32) {
        self.acc |= value << self.len;
        self.len += count;
        while self.len >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.len -= 8;
        }
    }

    /// A literal byte in fixed codes: 0 to 143 in 8 bits from 00110000, 144 to 255 in 9 bits
    /// from 110010000.
    fn literal(&mut self, byte: u8) {
        let byte = u64::from(byte);
        if byte <= 143 {
            self.put(reversed(0b0011_0000 + byte, 8), 8);
        } else {
            self.put(reversed(0b1_1001_0000 + byte - 144, 9), 9);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.len > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// A Huffman code of `count` bits, its bits in the order DEFLATE packs them.
fn reversed(code: u64, count: u32) -> u64 {
    (0..count).fold(0, |out, bit| out | ((code >> bit) & 1) << (count - 1 - bit))
}
