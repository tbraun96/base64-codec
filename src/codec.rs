use std::{io, cmp};
use bytes::{BufMut, BytesMut, Buf, Bytes};
//use futures_codec::{Encoder, Decoder};
use tokio_util::codec::{Encoder, Decoder};
/// for benches irrelevant side note: (unused_results, warnings, unused_features, warnings above)
/// `codec` contains optimized and unique algorithms for encoding/decoding that aren't present in rust's crate repository (e.g., base64)
/// A simple `Codec` implementation that splits up data into lines.
pub struct Base64Codec {
    // Stored index of the next index to examine for a `\n` character.
    // This is used to optimize searching.
    // For example, if `decode` was called with `abc`, it would hold `3`,
    // because that is the next index to examine.
    // The next time `decode` is called with `abcde\n`, the method will
    // only look at `de\n` before returning.
    next_index: usize,

    /// The maximum length for a given line. If `usize::MAX`, lines will be
    /// read until a `\n` character is reached.
    max_length: usize,

    min_capacity: usize,
    /// Are we currently discarding the remainder of a line which was over
    /// the length limit?
    is_discarding: bool
}


impl Base64Codec{
    /// Returns a `Base64Codec` for splitting up data into lines.
    ///
    /// # Note
    ///
    /// The returned `Base64Codec` will not have an upper bound on the length
    /// of a buffered line. See the documentation for [`new_with_max_length`]
    /// for information on why this could be a potential security risk.
    ///
    /// [`new_with_max_length`]: #method.new_with_max_length
    pub fn new(min_capacity: usize) -> Self {
        Base64Codec {
            next_index: 0,
            min_capacity,
            max_length: usize::max_value(),
            is_discarding: false
        }
    }

    /// Returns a `Base64Codec` with a maximum line length limit.
    ///
    /// If this is set, calls to `Base64Codec::decode` will return a
    /// [`LengthError`] when a line exceeds the length limit. Subsequent calls
    /// will discard up to `limit` bytes from that line until a newline
    /// character is reached, returning `None` until the line over the limit
    /// has been fully discarded. After that point, calls to `decode` will
    /// function as normal.
    ///
    /// # Note
    ///
    /// Setting a length limit is highly recommended for any `Base64Codec` which
    /// will be exposed to untrusted input. Otherwise, the size of the buffer
    /// that holds the line currently being read is unbounded. An attacker could
    /// exploit this unbounded buffer by sending an unbounded amount of input
    /// without any `\n` characters, causing unbounded memory consumption.
    ///
    /// [`LengthError`]: ../struct.LengthError
    pub fn new_with_max_length(max_length: usize, min_capacity: usize) -> Self {
        Base64Codec {
            max_length,
            ..Base64Codec::new(min_capacity)
        }
    }

    /// Returns the maximum line length when decoding.
    ///
    /// ```
    /// use std::usize;
    /// use base64_codec::codec::Base64Codec;
    ///
    /// let codec = Base64Codec::new(64);
    /// assert_eq!(codec.max_length(), usize::MAX);
    /// ```
    /// ```
    ///
    /// use base64_codec::codec::Base64Codec;
    /// let codec = Base64Codec::new_with_max_length(256, 64);
    /// assert_eq!(codec.max_length(), 256);
    /// ```
    pub fn max_length(&self) -> usize {
        self.max_length
    }

    fn discard(&mut self, newline_offset: Option<usize>, read_to: usize, buf: &mut BytesMut) {
        let discard_to = if let Some(offset) = newline_offset {
            // If we found a newline, discard up to that offset and
            // then stop discarding. On the next iteration, we'll try
            // to read a line normally.
            self.is_discarding = false;
            offset + self.next_index + 1
        } else {
            // Otherwise, we didn't find a newline, so we'll discard
            // everything we read. On the next iteration, we'll continue
            // discarding up to max_len bytes unless we find a newline.
            read_to
        };
        buf.advance(discard_to);
        self.next_index = 0;
    }
}

impl Decoder for Base64Codec {
    type Item = Bytes;
    // TODO: in the next breaking change, this should be changed to a custom
    // error type that indicates the "max length exceeded" condition better.
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, io::Error> {
        //println!("[CODEC] RECV {}", buf.len());
        //println!("CAP: {}", buf.capacity());
        if buf.capacity() < self.min_capacity {
            buf.reserve(self.max_length - buf.capacity());
        }

        if buf.len() > self.min_capacity {
            println!("[codec] Oversized packet received. Dropping");
            return Ok(None)
        }

        loop {
            // Determine how far into the buffer we'll search for a newline. If
            // there's no max_length set, we'll read to the end of the buffer.
            let read_to = cmp::min(self.max_length.saturating_add(1), buf.len());


            let newline_offset = buf[self.next_index..read_to]
                .iter()
                .position(|b| *b == b'\n');

            if self.is_discarding {
                self.discard(newline_offset, read_to, buf);
            } else {
                return if let Some(offset) = newline_offset {
                    // Found a line!
                    let newline_index = offset + self.next_index;
                    self.next_index = 0;

                    let mut line = buf.split_to(newline_index + 1); // use to be newline_index + 1

                    // Get rid of the '\n' at the end of line
                    line.truncate(line.len() - 1);

                    match base64::decode_config_bytes_auto(&mut line, base64::STANDARD_NO_PAD) {
                        Ok(_) => {
                            Ok(Some(line.freeze()))
                        }

                        Err(_) => {
                            //println!("Decode Err: {}", err.to_string());
                            //TODO: [ON-RELEASE] remove below to not stop entire program
                            Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Unable to decode inbound packet via base64 algorithm"))
                        }
                    }
                } else if buf.len() > self.max_length {
                    // Reached the maximum length without finding a
                    // newline, return an error and start discarding on the
                    // next call.
                    self.is_discarding = true;
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        "CODEC line length limit exceeded",
                    ))
                } else {
                    // We didn't find a line or reach the length limit, so the next
                    // call will resume searching at the current offset.
                    self.next_index = read_to;
                    Ok(None)
                };
            }
        }
    }
}

impl Encoder<Bytes> for Base64Codec {
//    type Item = Bytes;
    type Error = io::Error;

    fn encode(&mut self, line: Bytes, buf: &mut BytesMut) -> Result<(), io::Error> {
        // Add +1 for the \n
        let line = line.as_ref();
        let expected_max = ((line.len() + 3) * 3 / 4) + 1;
        if buf.remaining_mut() <= expected_max {
            buf.reserve(expected_max + 1);
        }

        match base64::encode_config_bytes(line, base64::STANDARD_NO_PAD, buf) {
            Ok(_) => {
                buf.put_u8(b'\n');
                Ok(())
            }

            Err(err) => {
                Err(err)
            }
        }
    }
}