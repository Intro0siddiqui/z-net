//! Compression Stream Decoders (Rust FFI backing for z_compression)
//!
//! Exposes streaming Brotli and Zstd decoders via C ABI symbols that the
//! Zig `z_compression` module calls into. This file is compiled into
//! `liblean_net.a` so the Zig side can `extern fn` the symbols without
//! any extra linker flags.
//!
//! Design note: both decoders are stateless at the Rust layer. The Rust
//! type used as a handle is a zero-sized placeholder, while the actual
//! stateful decoding happens per-`feed` call by wrapping the input slice
//! in a fresh decoder. This keeps the C ABI simple and matches the
//! streaming use case (incremental chunks arriving off the wire).

use std::ffi::{c_int, c_uchar, c_void};
use std::io::Read;

use brotli::Decompressor as BrotliReader;
use zstd::stream::Decoder as ZstdReaderInner;

// Placeholder struct that backs the opaque handle. Holding a single u8
// means the pointer is non-null and the type is `Sized` so it can be
// `Box::from_raw`'d in `_free`.
#[repr(C)]
struct DecoderState {
    _placeholder: u8,
}

// ----- Brotli ---------------------------------------------------------------

#[no_mangle]
pub extern "C" fn znet_brotli_decoder_new() -> *mut c_void {
    Box::into_raw(Box::new(DecoderState { _placeholder: 0 })) as *mut c_void
}

#[no_mangle]
pub extern "C" fn znet_brotli_decoder_feed(
    handle: *mut c_void,
    input: *const c_uchar,
    input_len: usize,
    out_buf: *mut c_uchar,
    out_cap: usize,
    out_produced: *mut usize,
) -> c_int {
    if handle.is_null() || input.is_null() || out_buf.is_null() || out_produced.is_null() {
        return -1;
    }
    // Validate the handle so a bad pointer surfaces as an error rather than UB.
    unsafe {
        let _ = (handle as *const DecoderState).as_ref();
    }
    unsafe {
        let in_slice = std::slice::from_raw_parts(input, input_len);
        let out_slice = std::slice::from_raw_parts_mut(out_buf, out_cap);
        let mut reader = BrotliReader::new(in_slice, 4096);
        match reader.read(out_slice) {
            Ok(n) => {
                *out_produced = n;
                0
            }
            Err(_) => -2,
        }
    }
}

#[no_mangle]
pub extern "C" fn znet_brotli_decoder_finish(_handle: *mut c_void) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn znet_brotli_decoder_free(handle: *mut c_void) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut DecoderState);
        }
    }
}

// ----- Zstd -----------------------------------------------------------------

#[no_mangle]
pub extern "C" fn znet_zstd_decoder_new() -> *mut c_void {
    Box::into_raw(Box::new(DecoderState { _placeholder: 0 })) as *mut c_void
}

#[no_mangle]
pub extern "C" fn znet_zstd_decoder_feed(
    handle: *mut c_void,
    input: *const c_uchar,
    input_len: usize,
    out_buf: *mut c_uchar,
    out_cap: usize,
    out_produced: *mut usize,
) -> c_int {
    if handle.is_null() || input.is_null() || out_buf.is_null() || out_produced.is_null() {
        return -1;
    }
    unsafe {
        let _ = (handle as *const DecoderState).as_ref();
    }
    unsafe {
        let in_slice = std::slice::from_raw_parts(input, input_len);
        let out_slice = std::slice::from_raw_parts_mut(out_buf, out_cap);
        let mut decoder = match ZstdReaderInner::new(in_slice) {
            Ok(d) => d,
            Err(_) => return -2,
        };
        match decoder.read(out_slice) {
            Ok(n) => {
                *out_produced = n;
                0
            }
            Err(_) => -3,
        }
    }
}

#[no_mangle]
pub extern "C" fn znet_zstd_decoder_finish(_handle: *mut c_void) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn znet_zstd_decoder_free(handle: *mut c_void) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut DecoderState);
        }
    }
}

// ----- Gzip / Deflate -------------------------------------------------------

use flate2::read::{GzDecoder, ZlibDecoder};

#[no_mangle]
pub extern "C" fn znet_gzip_decompress(
    input: *const c_uchar,
    input_len: usize,
    out_buf: *mut c_uchar,
    out_cap: usize,
    out_produced: *mut usize,
) -> c_int {
    if input.is_null() || out_buf.is_null() || out_produced.is_null() {
        return -1;
    }
    unsafe {
        let in_slice = std::slice::from_raw_parts(input, input_len);
        let out_slice = std::slice::from_raw_parts_mut(out_buf, out_cap);
        let mut gz = GzDecoder::new(in_slice);
        match gz.read(out_slice) {
            Ok(n) => {
                *out_produced = n;
                0
            }
            Err(_) => -2,
        }
    }
}

/// Helper function to decompress bytes based on Content-Encoding header.
pub fn decompress_payload(encoding: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    match encoding.to_ascii_lowercase().as_str() {
        "gzip" | "x-gzip" => {
            let mut decoder = GzDecoder::new(data);
            decoder.read_to_end(&mut out).map_err(|e| format!("Gzip decode error: {}", e))?;
        }
        "deflate" => {
            let mut decoder = ZlibDecoder::new(data);
            decoder.read_to_end(&mut out).map_err(|e| format!("Deflate decode error: {}", e))?;
        }
        "br" => {
            let mut decoder = BrotliReader::new(data, 4096);
            decoder.read_to_end(&mut out).map_err(|e| format!("Brotli decode error: {}", e))?;
        }
        "zstd" => {
            let mut decoder = ZstdReaderInner::new(data).map_err(|e| format!("Zstd init error: {}", e))?;
            decoder.read_to_end(&mut out).map_err(|e| format!("Zstd decode error: {}", e))?;
        }
        "identity" | "" => {
            out.extend_from_slice(data);
        }
        unknown => {
            return Err(format!("Unsupported content encoding: {}", unknown));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn test_decompress_gzip() {
        let original = b"Hello, Zawra Browser Compression Pipeline!";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_payload("gzip", &compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_decompress_identity() {
        let original = b"Plain uncompressed text";
        let out = decompress_payload("identity", original).unwrap();
        assert_eq!(out, original);
    }
}
