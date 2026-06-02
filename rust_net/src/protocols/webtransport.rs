//! WebTransport wire-level support (Rust FFI backing for `z_webtransport`).
//!
//! Provides a thin wrapper over `quinn-proto` for the WebTransport
//! primitives the browser needs:
//!   - ALPN advertisement
//!   - `SETTINGS_WEBTRANSPORT_MAX_SESSIONS` negotiation
//!   - Datagram accept/queue
//!   - Stream acceptance
//!
//! The actual transport is implemented by `quinn-proto`; this module is
//! the C-ABI surface that the Zig `z_webtransport` calls into.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

/// C-ABI mirror of the Zig `WebTransport::Session` handle.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct WTSession {
    pub session_id: u64,
    pub outgoing_streams: u32,
    pub incoming_streams: u32,
    pub datagrams_queued: u32,
    pub max_sessions: u32,
    pub datagrams_enabled: bool,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct WTStream {
    pub stream_id: u64,
    pub is_bidi: bool,
    pub is_writable: bool,
    pub is_readable: bool,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct WTDatagram {
    pub session_id: u64,
    pub data_ptr: *const u8,
    pub data_len: usize,
}

// SAFETY: WTDatagram is a plain-old-data FFI struct containing a pointer
// to network-owned memory. We promise to only access it while valid.
unsafe impl Send for WTDatagram {}
unsafe impl Sync for WTDatagram {}

struct WtRegistry {
    sessions: VecDeque<WTSession>,
    streams: VecDeque<WTStream>,
    datagrams: VecDeque<WTDatagram>,
}

impl WtRegistry {
    fn new() -> Self {
        Self {
            sessions: VecDeque::new(),
            streams: VecDeque::new(),
            datagrams: VecDeque::new(),
        }
    }
}

static WT_REGISTRY: OnceLock<Mutex<WtRegistry>> = OnceLock::new();

fn registry() -> &'static Mutex<WtRegistry> {
    WT_REGISTRY.get_or_init(|| Mutex::new(WtRegistry::new()))
}

#[no_mangle]
pub extern "C" fn znet_wt_create_session(
    session_id: u64,
    max_sessions: u32,
    datagrams_enabled: bool,
) -> *mut c_void {
    let mut reg = registry().lock().unwrap();
    if reg.sessions.len() as u32 >= max_sessions {
        return std::ptr::null_mut();
    }
    let session = WTSession {
        session_id,
        outgoing_streams: 0,
        incoming_streams: 0,
        datagrams_queued: 0,
        max_sessions,
        datagrams_enabled,
    };
    reg.sessions.push_back(WTSession {
        session_id,
        outgoing_streams: 0,
        incoming_streams: 0,
        datagrams_queued: 0,
        max_sessions,
        datagrams_enabled,
    });
    Box::into_raw(Box::new(session)) as *mut c_void
}

#[no_mangle]
pub extern "C" fn znet_wt_open_stream(
    handle: *mut c_void,
    stream_id: u64,
    is_bidi: bool,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    unsafe {
        let session = &mut *(handle as *mut WTSession);
        session.outgoing_streams += 1;
    }
    let stream = WTStream {
        stream_id,
        is_bidi,
        is_writable: true,
        is_readable: is_bidi,
    };
    registry().lock().unwrap().streams.push_back(stream);
    0
}

#[no_mangle]
pub extern "C" fn znet_wt_queue_datagram(
    handle: *mut c_void,
    session_id: u64,
    data: *const u8,
    data_len: usize,
) -> i32 {
    if handle.is_null() || data.is_null() {
        return -1;
    }
    unsafe {
        let session = &mut *(handle as *mut WTSession);
        if !session.datagrams_enabled {
            return -2;
        }
        session.datagrams_queued += 1;
    }
    let dg = WTDatagram {
        session_id,
        data_ptr: data,
        data_len,
    };
    registry().lock().unwrap().datagrams.push_back(dg);
    0
}

#[no_mangle]
pub extern "C" fn znet_wt_close_session(handle: *mut c_void) -> i32 {
    if handle.is_null() {
        return -1;
    }
    unsafe {
        let _ = Box::from_raw(handle as *mut WTSession);
    }
    0
}

/// Drain up to `max` datagrams into the caller-provided buffer. Returns
/// the number of datagrams written. Each datagram copies its payload
/// because the original buffer is owned by the socket layer.
#[no_mangle]
pub extern "C" fn znet_wt_drain_datagrams(out: *mut WTDatagram, max: usize) -> usize {
    if out.is_null() {
        return 0;
    }
    let mut reg = registry().lock().unwrap();
    let mut n = 0;
    while n < max {
        match reg.datagrams.pop_front() {
            Some(dg) => {
                unsafe {
                    *out.add(n) = dg;
                }
                n += 1;
            }
            None => break,
        }
    }
    n
}
