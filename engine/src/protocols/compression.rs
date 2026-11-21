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
use std::io::{Read, Write};

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

/// Progressive streaming decompressor supporting gzip, deflate, br, and zstd.
pub enum StreamDecompressor {
    Gzip(flate2::write::MultiGzDecoder<Vec<u8>>),
    Deflate(flate2::write::ZlibDecoder<Vec<u8>>),
    Brotli(brotli::DecompressorWriter<Vec<u8>>),
    Zstd(zstd::stream::write::Decoder<'static, Vec<u8>>),
}

impl StreamDecompressor {
    /// Create a decompressor instance for the given encoding string.
    pub fn new(encoding: &str) -> Option<Self> {
        match encoding.trim().to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(StreamDecompressor::Gzip(flate2::write::MultiGzDecoder::new(Vec::new()))),
            "deflate" => Some(StreamDecompressor::Deflate(flate2::write::ZlibDecoder::new(Vec::new()))),
            "br" => Some(StreamDecompressor::Brotli(brotli::DecompressorWriter::new(Vec::new(), 4096))),
            "zstd" => {
                let decoder = zstd::stream::write::Decoder::new(Vec::new()).ok()?;
                Some(StreamDecompressor::Zstd(decoder))
            }
            _ => None,
        }
    }

    /// Feed a compressed chunk into the decompressor, invoking `on_output` with any decompressed bytes.
    pub fn feed<F: FnMut(&[u8])>(&mut self, chunk: &[u8], mut on_output: F) -> Result<(), String> {
        if chunk.is_empty() {
            return Ok(());
        }
        match self {
            StreamDecompressor::Gzip(d) => {
                d.write_all(chunk).map_err(|e| format!("Gzip streaming decompression error: {}", e))?;
                let buf = d.get_mut();
                if !buf.is_empty() {
                    on_output(buf);
                    buf.clear();
                }
            }
            StreamDecompressor::Deflate(d) => {
                d.write_all(chunk).map_err(|e| format!("Deflate streaming decompression error: {}", e))?;
                let buf = d.get_mut();
                if !buf.is_empty() {
                    on_output(buf);
                    buf.clear();
                }
            }
            StreamDecompressor::Brotli(d) => {
                d.write_all(chunk).map_err(|e| format!("Brotli streaming decompression error: {}", e))?;
                let buf = d.get_mut();
                if !buf.is_empty() {
                    on_output(buf);
                    buf.clear();
                }
            }
            StreamDecompressor::Zstd(d) => {
                d.write_all(chunk).map_err(|e| format!("Zstd streaming decompression error: {}", e))?;
                d.flush().map_err(|e| format!("Zstd flush error: {}", e))?;
                let buf = d.get_mut();
                if !buf.is_empty() {
                    on_output(buf);
                    buf.clear();
                }
            }
        }
        Ok(())
    }

    /// Complete decompression, flushing any remaining buffered bytes.
    pub fn finish<F: FnMut(&[u8])>(self, mut on_output: F) -> Result<(), String> {
        let remaining = match self {
            StreamDecompressor::Gzip(d) => {
                d.finish().map_err(|e| format!("Gzip finish error: {}", e))?
            }
            StreamDecompressor::Deflate(d) => {
                d.finish().map_err(|e| format!("Deflate finish error: {}", e))?
            }
            StreamDecompressor::Brotli(mut d) => {
                let _ = d.close();
                d.into_inner().map_err(|_| "Brotli close/finish error".to_string())?
            }
            StreamDecompressor::Zstd(mut d) => {
                let _ = d.flush();
                d.into_inner()
            }
        };
        if !remaining.is_empty() {
            on_output(&remaining);
        }
        Ok(())
    }
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

    #[test]
    fn test_streaming_decompress_gzip_chunks() {
        let original = b"Chunked progressive streaming gzip test payload with lots of repetitive text for good compression ratios! ".repeat(50);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut decompressor = StreamDecompressor::new("gzip").expect("create gzip decompressor");
        let mut output = Vec::new();

        // Feed in small arbitrary chunk sizes (e.g. 17 bytes)
        for chunk in compressed.chunks(17) {
            decompressor.feed(chunk, |decompressed| {
                output.extend_from_slice(decompressed);
            }).expect("feed chunk");
        }

        decompressor.finish(|decompressed| {
            output.extend_from_slice(decompressed);
        }).expect("finish gzip decompressor");

        assert_eq!(output, original);
    }

    #[test]
    fn test_streaming_decompress_deflate_chunks() {
        use flate2::write::ZlibEncoder;
        let original = b"Chunked progressive streaming deflate test payload! ".repeat(40);
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut decompressor = StreamDecompressor::new("deflate").expect("create deflate decompressor");
        let mut output = Vec::new();

        for chunk in compressed.chunks(13) {
            decompressor.feed(chunk, |decompressed| {
                output.extend_from_slice(decompressed);
            }).expect("feed chunk");
        }

        decompressor.finish(|decompressed| {
            output.extend_from_slice(decompressed);
        }).expect("finish deflate decompressor");

        assert_eq!(output, original);
    }

    #[test]
    fn test_streaming_decompress_brotli_chunks() {
        use brotli::CompressorWriter;
        let original = b"Chunked progressive streaming brotli test payload! ".repeat(40);
        let mut compressed = Vec::new();
        {
            let mut writer = CompressorWriter::new(&mut compressed, 4096, 5, 22);
            writer.write_all(&original).unwrap();
        }

        let mut decompressor = StreamDecompressor::new("br").expect("create br decompressor");
        let mut output = Vec::new();

        for chunk in compressed.chunks(11) {
            decompressor.feed(chunk, |decompressed| {
                output.extend_from_slice(decompressed);
            }).expect("feed chunk");
        }

        decompressor.finish(|decompressed| {
            output.extend_from_slice(decompressed);
        }).expect("finish br decompressor");

        assert_eq!(output, original);
    }

    #[test]
    fn test_streaming_decompress_zstd_chunks() {
        let original = b"Chunked progressive streaming zstd test payload! ".repeat(40);
        let compressed = zstd::encode_all(&original[..], 3).unwrap();

        let mut decompressor = StreamDecompressor::new("zstd").expect("create zstd decompressor");
        let mut output = Vec::new();

        for chunk in compressed.chunks(19) {
            decompressor.feed(chunk, |decompressed| {
                output.extend_from_slice(decompressed);
            }).expect("feed chunk");
        }

        decompressor.finish(|decompressed| {
            output.extend_from_slice(decompressed);
        }).expect("finish zstd decompressor");

        assert_eq!(output, original);
    }
}
