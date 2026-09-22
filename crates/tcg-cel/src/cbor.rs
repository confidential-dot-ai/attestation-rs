//! Deterministic CBOR (RFC 8949 section 4.2.1): the reader rejects anything
//! the writer would not produce.

use crate::error::Error;

/// Nesting allowed inside content this crate does not interpret.
const MAX_DEPTH: usize = 16;

pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

type R<T> = std::result::Result<T, Error>;

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn err(&self, at: usize, reason: impl Into<String>) -> Error {
        Error::Cbor {
            offset: at,
            reason: reason.into(),
        }
    }

    fn byte(&mut self) -> R<u8> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| self.err(self.pos, "truncated"))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| self.err(self.pos, "truncated"))?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Major type and argument; indefinite lengths, reserved additional
    /// information and non-minimal arguments are errors.
    pub fn head(&mut self) -> R<(u8, u64)> {
        let at = self.pos;
        let b = self.byte()?;
        let (major, info) = (b >> 5, b & 0x1f);
        let (arg, min) = match info {
            0..=23 => return Ok((major, u64::from(info))),
            24 => (u64::from(self.byte()?), 24),
            25 => (
                u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap())),
                0x100,
            ),
            26 => (
                u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
                0x1_0000,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
                0x1_0000_0000,
            ),
            _ => return Err(self.err(at, "indefinite length or reserved additional information")),
        };
        // Major 7 carries floats in these widths; they are refused by the caller.
        if major != 7 && arg < min {
            return Err(self.err(at, "non-minimal integer encoding"));
        }
        Ok((major, arg))
    }

    fn len(&self, at: usize, n: u64, max: usize, what: &str) -> R<usize> {
        match usize::try_from(n) {
            Ok(n) if n <= max => Ok(n),
            _ => Err(self.err(at, format!("{what} longer than {max}"))),
        }
    }

    fn expect(&mut self, want: u8, what: &str) -> R<(usize, u64)> {
        let at = self.pos;
        let (major, arg) = self.head()?;
        if major != want {
            return Err(self.err(at, format!("expected {what}, found major type {major}")));
        }
        Ok((at, arg))
    }

    pub fn uint(&mut self) -> R<u64> {
        self.expect(0, "an unsigned integer").map(|(_, v)| v)
    }

    pub fn bstr(&mut self, max: usize) -> R<&'a [u8]> {
        let (at, n) = self.expect(2, "a byte string")?;
        let n = self.len(at, n, max, "byte string")?;
        self.take(n)
    }

    pub fn tstr(&mut self, max: usize) -> R<&'a str> {
        let (at, n) = self.expect(3, "a text string")?;
        let n = self.len(at, n, max, "text string")?;
        std::str::from_utf8(self.take(n)?).map_err(|_| self.err(at, "text string is not UTF-8"))
    }

    pub fn array(&mut self, max: usize) -> R<usize> {
        let (at, n) = self.expect(4, "an array")?;
        self.len(at, n, max, "array")
    }

    pub fn map(&mut self, max: usize) -> R<usize> {
        let (at, n) = self.expect(5, "a map")?;
        self.len(at, n, max, "map")
    }

    /// The major type of the next item, without consuming it.
    pub fn peek_major(&self) -> Option<u8> {
        self.data.get(self.pos).map(|b| b >> 5)
    }

    /// Read a map key that must equal `key`.
    pub fn key(&mut self, key: u64, what: &str) -> R<()> {
        let at = self.pos;
        match self.uint() {
            Ok(k) if k == key => Ok(()),
            Ok(k) => Err(self.err(at, format!("expected key {key} ({what}), found {k}"))),
            Err(_) => Err(self.err(at, format!("expected key {key} ({what})"))),
        }
    }

    /// The bytes of one well-formed deterministic item, which may be of any
    /// type except a float: map keys must be distinct and in bytewise order.
    pub fn item(&mut self) -> R<&'a [u8]> {
        let start = self.pos;
        self.skip(0)?;
        Ok(&self.data[start..self.pos])
    }

    fn skip(&mut self, depth: usize) -> R<()> {
        let at = self.pos;
        if depth > MAX_DEPTH {
            return Err(self.err(at, "nesting too deep"));
        }
        let (major, arg) = self.head()?;
        match major {
            0 | 1 => Ok(()),
            2 | 3 => {
                let n = self.len(at, arg, usize::MAX, "string")?;
                let s = self.take(n)?;
                if major == 3 && std::str::from_utf8(s).is_err() {
                    return Err(self.err(at, "text string is not UTF-8"));
                }
                Ok(())
            }
            4 => (0..arg).try_for_each(|_| self.skip(depth + 1)),
            5 => {
                let mut prev: Option<&[u8]> = None;
                for _ in 0..arg {
                    let k = self.pos;
                    self.skip(depth + 1)?;
                    let key = &self.data[k..self.pos];
                    if prev.is_some_and(|p| p >= key) {
                        return Err(self.err(k, "map keys out of order or repeated"));
                    }
                    prev = Some(key);
                    self.skip(depth + 1)?;
                }
                Ok(())
            }
            6 => self.skip(depth + 1),
            // false, true, null, undefined; floats and other simple values are refused.
            _ if (20..=23).contains(&arg) && self.data[at] & 0x1f == arg as u8 => Ok(()),
            _ => Err(self.err(
                at,
                "floats and simple values other than false, true, null and undefined are not used",
            )),
        }
    }
}

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

pub(crate) fn uint(n: u64, out: &mut Vec<u8>) {
    head(0, n, out);
}

pub(crate) fn bstr(b: &[u8], out: &mut Vec<u8>) {
    head(2, b.len() as u64, out);
    out.extend_from_slice(b);
}

pub(crate) fn tstr(s: &str, out: &mut Vec<u8>) {
    head(3, s.len() as u64, out);
    out.extend_from_slice(s.as_bytes());
}

pub(crate) fn array(n: usize, out: &mut Vec<u8>) {
    head(4, n as u64, out);
}

/// Callers write unsigned integer keys in ascending order, which is the
/// deterministic order for them.
pub(crate) fn map(n: usize, out: &mut Vec<u8>) {
    head(5, n as u64, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_are_minimal() {
        let mut v = Vec::new();
        for n in [23, 24, 255, 256, 65535, 65536, 1 << 32] {
            uint(n, &mut v);
        }
        assert_eq!(
            hex::encode(&v),
            "171818\
             18ff\
             190100\
             19ffff\
             1a00010000\
             1b0000000100000000"
        );
        let mut r = Reader::new(&v);
        for n in [23, 24, 255, 256, 65535, 65536, 1 << 32] {
            assert_eq!(r.uint().unwrap(), n);
        }
        assert!(r.at_end());
        for bad in [
            "1817",
            "1900ff",
            "1a0000ffff",
            "1b00000000ffffffff",
            "5f",
            "9f",
            "bf",
            "1c",
        ] {
            let b = hex::decode(bad).unwrap();
            assert!(Reader::new(&b).item().is_err(), "{bad}");
        }
    }

    #[test]
    fn items_must_be_deterministic() {
        // {1: 0, 0: 0}: keys out of order; {0: 0, 0: 0}: repeated
        for bad in ["a201000000", "a200000000", "f93c00", "f820", "62ff00"] {
            let b = hex::decode(bad).unwrap();
            assert!(Reader::new(&b).item().is_err(), "{bad}");
        }
        for good in ["a2000001f5", "c24100", "f6", "8201a16161f4"] {
            let b = hex::decode(good).unwrap();
            let mut r = Reader::new(&b);
            assert_eq!(r.item().unwrap(), b.as_slice(), "{good}");
        }
    }
}
