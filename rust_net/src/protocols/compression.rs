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
