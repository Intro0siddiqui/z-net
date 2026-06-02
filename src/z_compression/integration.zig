//! z_compression integration into the response body pipeline.
//!
//! Given an HTTP response header block, `wrapWithDecompression` chooses
//! the correct streaming decoder (or the identity passthrough) and binds
//! it to a `BodyRingDescriptor`. The caller then drives the socket's
//! read loop and feeds every chunk into the returned `DecompressingStream`.

const std = @import("std");
const body_ring_mod = @import("z_body_ring");
const BodyRingDescriptor = body_ring_mod.BodyRingDescriptor;
const compression = @import("z_compression");
const Encoding = compression.Encoding;
const DecompressingStream = compression.DecompressingStream;

/// Header keys we inspect when picking a decoder. We support both the
/// "modern" RFC 7231 `Content-Encoding` and the legacy `Content-Encoding`
/// variants plus `Transfer-Encoding` for chunked compressed bodies.
pub fn detectEncoding(headers: []const u8) Encoding {
    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, &.{ ' ', '\t', '\r' });
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], &.{ ' ', '\t' });
        if (std.ascii.eqlIgnoreCase(name, "content-encoding")) {
            return Encoding.parse(line[colon + 1..]);
        }
    }
    return .identity;
}

pub const WrapError = error{
    BodyRingRequired,
    UnsupportedEncoding,
};

/// Build a `DecompressingStream` that writes plaintext into `ring`.
/// Returns `null` if the encoding is `identity` / `unknown` so the caller
/// can avoid the indirection entirely.
pub fn wrapWithDecompression(
    coding: Encoding,
    ring: *BodyRingDescriptor,
) !?DecompressingStream {
    if (coding == .identity or coding == .unknown) return null;
    return DecompressingStream.init(coding, ring);
}

test "detectEncoding picks the right coding" {
    try std.testing.expectEqual(Encoding.gzip, detectEncoding("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n"));
    try std.testing.expectEqual(Encoding.br, detectEncoding("HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n\r\n"));
    try std.testing.expectEqual(Encoding.zstd, detectEncoding("HTTP/1.1 200 OK\r\ncontent-encoding: zstd\r\n\r\n"));
    try std.testing.expectEqual(Encoding.identity, detectEncoding("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"));
}
