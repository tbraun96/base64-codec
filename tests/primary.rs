#[cfg(test)]
mod tests {
    use bytes::{BytesMut, Buf, BufMut, Bytes};
    use base64_codec::codec::Base64Codec;
    use tokio_util::codec::{Decoder, Encoder};

    #[test]
    fn encode_decode() {
        let original = b"Hello, World!";
        let mut data = BytesMut::from(original.as_ref());
        let mut codec = Base64Codec::new_with_max_length(u16::max_value() as usize, 32000);
        let mut buffer = BytesMut::new();

        let data = &mut data;
        for x in 0..1000 {
            data.put_i32(x);
            assert!(codec.encode(data.clone().freeze(), &mut buffer).is_ok());
            let res: Bytes = codec.decode(&mut buffer).unwrap().unwrap();
            let bytes_ret = res.bytes();

            debug_assert_eq!(bytes_ret, data.bytes())
        }
    }
}