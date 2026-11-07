//! Reading input without leaving copies of it in memory.
//!
//! Input lines carry keys (`init`, `add_key`). The standard library's stdin
//! keeps an 8 KiB buffer that is never erased, so the text of a key could stay
//! there long after the key itself is gone. [`ErasingReader`] reads through a
//! larger buffer of its own instead, and erases each byte as soon as it is
//! consumed. The standard library skips its own buffer for reads at least as
//! large as it, so with stdin underneath, the input passes through no buffer
//! that isn't erased (the operating system's pipe buffer is out of reach).

use std::io::{self, BufRead, Read};

use hmac::digest::zeroize::Zeroize;

/// The buffer size: well above the standard library's 8 KiB, so stdin hands
/// its data straight to this buffer.
pub const CAPACITY: usize = 64 * 1024;

/// A buffered reader that erases what it has handed out.
#[derive(Debug)]
pub struct ErasingReader<R> {
    inner: R,
    buf: Box<[u8]>,
    /// The bytes not yet consumed are `buf[start..end]`; everything else is
    /// zeros.
    start: usize,
    end: usize,
}

impl<R: Read> ErasingReader<R> {
    /// A reader over `inner` with a [`CAPACITY`]-byte buffer.
    #[must_use]
    pub fn new(inner: R) -> Self {
        Self::with_capacity(CAPACITY, inner)
    }

    fn with_capacity(capacity: usize, inner: R) -> Self {
        Self {
            inner,
            buf: vec![0; capacity].into_boxed_slice(),
            start: 0,
            end: 0,
        }
    }
}

impl<R: Read> BufRead for ErasingReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.start == self.end {
            // Everything read so far has been consumed, and so erased.
            self.start = 0;
            self.end = 0;
            let read = self.inner.read(&mut self.buf)?;
            // A reader can't return more than it was given room for.
            self.end = read.min(self.buf.len());
        }
        Ok(self.buf.get(self.start..self.end).unwrap_or_default())
    }

    fn consume(&mut self, amount: usize) {
        let end = self.start.saturating_add(amount).min(self.end);
        if let Some(consumed) = self.buf.get_mut(self.start..end) {
            consumed.zeroize();
        }
        self.start = end;
    }
}

impl<R: Read> Read for ErasingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let count = available.len().min(out.len());
        if let (Some(to), Some(from)) = (out.get_mut(..count), available.get(..count)) {
            to.copy_from_slice(from);
        }
        self.consume(count);
        Ok(count)
    }
}

impl<R> Drop for ErasingReader<R> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_everything_through_in_order() {
        let data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let mut reader = ErasingReader::with_capacity(64, data.as_slice());
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
        // Line by line, too.
        let mut reader = ErasingReader::with_capacity(4, &b"one\ntwo\nthree"[..]);
        let lines: Vec<String> = reader.by_ref().lines().map(Result::unwrap).collect();
        assert_eq!(lines, ["one", "two", "three"]);
    }

    #[test]
    fn consumed_bytes_are_erased_at_once() {
        let mut reader = ErasingReader::with_capacity(16, &b"secret,rest"[..]);
        assert_eq!(reader.fill_buf().unwrap(), b"secret,rest");
        reader.consume(7);
        assert_eq!(&reader.buf[..7], &[0; 7]);
        assert_eq!(&reader.buf[7..11], b"rest");
        // Consuming more than is there consumes what is there.
        reader.consume(100);
        assert!(reader.buf.iter().all(|&byte| byte == 0));
        assert_eq!(reader.fill_buf().unwrap(), b"");
    }

    #[test]
    fn a_small_read_takes_part_of_the_buffer() {
        let mut reader = ErasingReader::with_capacity(16, &b"abcdef"[..]);
        let mut out = [0; 4];
        assert_eq!(reader.read(&mut out).unwrap(), 4);
        assert_eq!(&out, b"abcd");
        assert_eq!(&reader.buf[..6], b"\0\0\0\0ef");
        assert_eq!(reader.read(&mut out).unwrap(), 2);
        assert_eq!(&out[..2], b"ef");
    }

    #[test]
    fn a_standard_buffered_reader_underneath_is_bypassed() {
        // Stdin is a standard buffered reader with an 8 KiB buffer; this one
        // has 8 bytes, against this reader's 64.
        let data = b"0123456789abcdef0123456789abcdef".repeat(4);
        let mut reader =
            ErasingReader::with_capacity(64, io::BufReader::with_capacity(8, &data[..]));
        let mut out = Vec::new();
        while !reader.fill_buf().unwrap().is_empty() {
            assert!(
                reader.inner.buffer().is_empty(),
                "the inner buffer held input"
            );
            let len = reader.fill_buf().unwrap().len();
            out.extend_from_slice(reader.fill_buf().unwrap());
            reader.consume(len);
        }
        assert_eq!(out, data);
    }

    /// The real reader's buffer is larger than stdin's, so stdin bypasses its
    /// own buffer.
    const _: () = assert!(CAPACITY >= 8 * 1024);

    #[test]
    fn errors_from_the_input_are_passed_on() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            }
        }
        let mut reader = ErasingReader::new(Broken);
        assert_eq!(
            reader.fill_buf().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }
}
