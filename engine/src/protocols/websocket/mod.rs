//! WebSocket protocol support (RFC 6455 and RFC 9220).

pub mod frame;
pub mod h3_ws;

pub use frame::{Opcode, WebSocketFrame};
pub use h3_ws::{H3WebSocketHandshake, H3WebSocketSession};
