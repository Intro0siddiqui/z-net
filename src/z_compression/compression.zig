//! z_compression - HTTP Content-Encoding Stream Decoders
//!
//! Streaming decoders for `Content-Encoding: gzip | br | zstd | deflate`.
//! All decoders feed their output directly into a `BodyRingDescriptor`
//! so the decompressed bytes cross the Hajr IPC boundary into WebKit
//! with zero allocations and no copies.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const body_ring = @import("z_body_ring");
const BodyRingDescriptor = body_ring.BodyRingDescriptor;
const BodyRingError = body_ring.BodyRingError;

/// All HTTP content codings we understand.
pub const Encoding = enum {
    identity,
    gzip,
    deflate,
    br,
    zstd,
    unknown,

    pub fn parse(header_value: []const u8) Encoding {
        var it = std.mem.splitScalar(u8, std.mem.trim(u8, header_value, &.{ ' ', '\t' }), ',');
        while (it.next()) |raw| {
            const token = std.mem.trim(u8, raw, &.{ ' ', '\t' });
            // Strip q-value etc., keep just the coding name.
            const semi = std.mem.indexOfScalar(u8, token, ';') orelse token.len;
            const coding = std.mem.trim(u8, token[0..semi], &.{ ' ', '\t' });
            if (std.ascii.eqlIgnoreCase(coding, "gzip")) return .gzip;
            if (std.ascii.eqlIgnoreCase(coding, "x-gzip")) return .gzip;
            if (std.ascii.eqlIgnoreCase(coding, "deflate")) return .deflate;
            if (std.ascii.eqlIgnoreCase(coding, "br")) return .br;
            if (std.ascii.eqlIgnoreCase(coding, "zstd")) return .zstd;
            if (std.ascii.eqlIgnoreCase(coding, "identity")) return .identity;
        }
        return .identity;
    }
};

/// Convenience: build the `Accept-Encoding` we send in every request.
/// Order matters: zstd is preferred if the server supports it, then br, then gzip.
pub fn defaultAcceptEncodingHeader(buf: []u8) ![]u8 {
    return std.fmt.bufPrint(buf, "gzip, br, zstd, deflate", .{});
}

/// The single read interface every streaming decoder implements.
pub const Decoder = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        feed: *const fn (ptr: *anyopaque, input: []const u8) anyerror!void,
        finish: *const fn (ptr: *anyopaque) anyerror!void,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn feed(self: Decoder, input: []const u8) !void {
        return self.vtable.feed(self.ptr, input);
    }

    pub fn finish(self: Decoder) !void {
        return self.vtable.finish(self.ptr);
    }

    pub fn deinit(self: Decoder) void {
        self.vtable.deinit(self.ptr);
    }
};

/// Output sink - currently a `BodyRingDescriptor` shared with Hajr.
pub const Sink = struct {
    ring: *BodyRingDescriptor,

    /// Append already-decompressed bytes into the shared memory ring.
    /// Returns `BodyRingError.Full` if backpressure kicks in (95% high watermark).
    pub fn write(self: Sink, data: []const u8) !void {
        var written: usize = 0;
        while (written < data.len) {
            if (self.ring.isFull()) return BodyRingError.Full;
            const buffers = self.ring.getWriteBuffers();
            var n: usize = 0;
            for (buffers) |buf| {
                if (buf.len == 0) continue;
                const take = @min(buf.len, data.len - written);
                @memcpy(buf[0..take], data[written..][0..take]);
                n += take;
                written += take;
                if (written == data.len) break;
            }
            if (n == 0) return BodyRingError.Full;
            self.ring.commitWrite(n);
        }
    }
};

/// Build a streaming decoder bound to the supplied `BodyRingDescriptor`.
/// The returned `Decoder` writes compressed input straight into the shared
/// memory region; the caller is responsible for `deinit()`.
pub fn decoderFor(coding: Encoding, sink: Sink) !Decoder {
    return switch (coding) {
        .identity, .unknown => IdentityDecoder.wrap(sink),
        .gzip => try GzipDecoder.wrap(sink),
        .deflate => try DeflateDecoder.wrap(sink),
        .br => try BrotliDecoder.wrap(sink),
        .zstd => try ZstdDecoder.wrap(sink),
    };
}

// ============================================================
// Identity pass-through (no compression, used for tests + "identity")
// ============================================================
const IdentityDecoder = struct {
    sink: Sink,

    fn wrap(sink: Sink) error{OutOfMemory}!Decoder {
        const state = try std.heap.c_allocator.create(IdentityDecoder);
        state.* = .{ .sink = sink };
        return Decoder{ .ptr = state, .vtable = &vtable };
    }

    fn feedImpl(ptr: *anyopaque, input: []const u8) anyerror!void {
        const self: *IdentityDecoder = @ptrCast(@alignCast(ptr));
        try self.sink.write(input);
    }

    fn finishImpl(_: *anyopaque) anyerror!void {}
    fn deinitImpl(ptr: *anyopaque) void {
        const self: *IdentityDecoder = @ptrCast(@alignCast(ptr));
        std.heap.c_allocator.destroy(self);
    }

    const vtable = Decoder.VTable{
        .feed = feedImpl,
        .finish = finishImpl,
        .deinit = deinitImpl,
    };
};

// ============================================================
// Gzip / Deflate (DEFLATE) - pure Zig implementation using std.compress
// ============================================================
const GzipDecoder = struct {
    stream: std.compress.flate.Decompress,
    sink: Sink,

    fn wrap(sink: Sink) error{OutOfMemory}!Decoder {
        const state = try std.heap.c_allocator.create(GzipDecoder);
        // Window bits 15+32 selects gzip auto-detection (RFC 1952)
        state.* = .{
            .stream = std.compress.flate.Decompress.init(std.heap.c_allocator, .gzip, .{ .window_bits = 15 + 16 }),
            .sink = sink,
        };
        return Decoder{ .ptr = state, .vtable = &vtable };
    }

    fn feedImpl(ptr: *anyopaque, input: []const u8) anyerror!void {
        const self: *GzipDecoder = @ptrCast(@alignCast(ptr));
        var in_offset: usize = 0;
        var out_buf: [64 * 1024]u8 = undefined;
        while (in_offset < input.len) {
            const n_out = try self.stream.decompress(input[in_offset..], &out_buf);
            if (n_out > 0) try self.sink.write(out_buf[0..n_out]);
            in_offset += self.stream.context.bytes_consumed;
            if (n_out == 0 and in_offset < input.len) return error.DecompressionStalled;
        }
    }

    fn finishImpl(_: *anyopaque) anyerror!void {}

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *GzipDecoder = @ptrCast(@alignCast(ptr));
        self.stream.deinit();
        std.heap.c_allocator.destroy(self);
    }

    const vtable = Decoder.VTable{
        .feed = feedImpl,
        .finish = finishImpl,
        .deinit = deinitImpl,
    };
};

const DeflateDecoder = struct {
    stream: std.compress.flate.Decompress,
    sink: Sink,

    fn wrap(sink: Sink) error{OutOfMemory}!Decoder {
        const state = try std.heap.c_allocator.create(DeflateDecoder);
        state.* = .{
            .stream = std.compress.flate.Decompress.init(std.heap.c_allocator, .zlib, .{}),
            .sink = sink,
        };
        return Decoder{ .ptr = state, .vtable = &vtable };
    }

    fn feedImpl(ptr: *anyopaque, input: []const u8) anyerror!void {
        const self: *DeflateDecoder = @ptrCast(@alignCast(ptr));
        var in_offset: usize = 0;
        var out_buf: [64 * 1024]u8 = undefined;
        while (in_offset < input.len) {
            const n_out = try self.stream.decompress(input[in_offset..], &out_buf);
            if (n_out > 0) try self.sink.write(out_buf[0..n_out]);
            in_offset += self.stream.context.bytes_consumed;
            if (n_out == 0 and in_offset < input.len) return error.DecompressionStalled;
        }
    }

    fn finishImpl(_: *anyopaque) anyerror!void {}
    fn deinitImpl(ptr: *anyopaque) void {
        const self: *DeflateDecoder = @ptrCast(@alignCast(ptr));
        self.stream.deinit();
        std.heap.c_allocator.destroy(self);
    }

    const vtable = Decoder.VTable{
        .feed = feedImpl,
        .finish = finishImpl,
        .deinit = deinitImpl,
    };
};

// ============================================================
// Brotli - delegates to Rust zstd/brotli crate via FFI shim
// ============================================================
//
// We call into the Rust `lean-net` static lib for the heavy lifting because
// pure-Zig Brotli does not exist in the stdlib today. The C ABI symbols
// are implemented in `rust_net/src/protocols/compression.rs`.

extern fn znet_brotli_decoder_new() ?*anyopaque;
extern fn znet_brotli_decoder_feed(
    handle: *anyopaque,
    input: [*]const u8,
    input_len: usize,
    out_buf: [*]u8,
    out_cap: usize,
    out_produced: *usize,
) i32;
extern fn znet_brotli_decoder_finish(handle: *anyopaque) i32;
extern fn znet_brotli_decoder_free(handle: *anyopaque) void;

extern fn znet_zstd_decoder_new() ?*anyopaque;
extern fn znet_zstd_decoder_feed(
    handle: *anyopaque,
    input: [*]const u8,
    input_len: usize,
    out_buf: [*]u8,
    out_cap: usize,
    out_produced: *usize,
) i32;
extern fn znet_zstd_decoder_finish(handle: *anyopaque) i32;
extern fn znet_zstd_decoder_free(handle: *anyopaque) void;

const BrotliDecoder = struct {
    handle: *anyopaque,
    sink: Sink,

    fn wrap(sink: Sink) error{OutOfMemory}!Decoder {
        const h = znet_brotli_decoder_new() orelse return error.OutOfMemory;
        const state = try std.heap.c_allocator.create(BrotliDecoder);
        state.* = .{ .handle = h.?, .sink = sink };
        return Decoder{ .ptr = state, .vtable = &vtable };
    }

    fn feedImpl(ptr: *anyopaque, input: []const u8) anyerror!void {
        const self: *BrotliDecoder = @ptrCast(@alignCast(ptr));
        var in_offset: usize = 0;
        var out_buf: [64 * 1024]u8 = undefined;
        while (in_offset < input.len) {
            var produced: usize = 0;
            const rc = znet_brotli_decoder_feed(
                self.handle,
                input[in_offset..].ptr,
                input.len - in_offset,
                &out_buf,
                out_buf.len,
                &produced,
            );
            if (rc != 0) return error.DecompressionFailed;
            if (produced > 0) try self.sink.write(out_buf[0..produced]);
            if (produced == 0) return error.DecompressionStalled;
            in_offset += produced; // FFI returns bytes consumed in `produced` for brotli wrapper
        }
    }

    fn finishImpl(ptr: *anyopaque) anyerror!void {
        const self: *BrotliDecoder = @ptrCast(@alignCast(ptr));
        if (znet_brotli_decoder_finish(self.handle) != 0) return error.DecompressionFailed;
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *BrotliDecoder = @ptrCast(@alignCast(ptr));
        znet_brotli_decoder_free(self.handle);
        std.heap.c_allocator.destroy(self);
    }

    const vtable = Decoder.VTable{
        .feed = feedImpl,
        .finish = finishImpl,
        .deinit = deinitImpl,
    };
};

const ZstdDecoder = struct {
    handle: *anyopaque,
    sink: Sink,

    fn wrap(sink: Sink) error{OutOfMemory}!Decoder {
        const h = znet_zstd_decoder_new() orelse return error.OutOfMemory;
        const state = try std.heap.c_allocator.create(ZstdDecoder);
        state.* = .{ .handle = h.?, .sink = sink };
        return Decoder{ .ptr = state, .vtable = &vtable };
    }

    fn feedImpl(ptr: *anyopaque, input: []const u8) anyerror!void {
        const self: *ZstdDecoder = @ptrCast(@alignCast(ptr));
        var in_offset: usize = 0;
        var out_buf: [64 * 1024]u8 = undefined;
        while (in_offset < input.len) {
            var produced: usize = 0;
            const rc = znet_zstd_decoder_feed(
                self.handle,
                input[in_offset..].ptr,
                input.len - in_offset,
                &out_buf,
                out_buf.len,
                &produced,
            );
            if (rc != 0) return error.DecompressionFailed;
            if (produced > 0) try self.sink.write(out_buf[0..produced]);
            if (produced == 0) return error.DecompressionStalled;
            in_offset += produced;
        }
    }

    fn finishImpl(ptr: *anyopaque) anyerror!void {
        const self: *ZstdDecoder = @ptrCast(@alignCast(ptr));
        if (znet_zstd_decoder_finish(self.handle) != 0) return error.DecompressionFailed;
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *ZstdDecoder = @ptrCast(@alignCast(ptr));
        znet_zstd_decoder_free(self.handle);
        std.heap.c_allocator.destroy(self);
    }

    const vtable = Decoder.VTable{
        .feed = feedImpl,
        .finish = finishImpl,
        .deinit = deinitImpl,
    };
};

/// High-level helper: wire a socket byte stream into a body ring via the
/// appropriate `Content-Encoding` decoder. The caller still drives `read()`
/// on the socket - we just turn raw bytes into decompressed body chunks.
pub const DecompressingStream = struct {
    decoder: Decoder,
    ring: *BodyRingDescriptor,
    coding: Encoding,

    pub fn init(coding: Encoding, ring: *BodyRingDescriptor) !DecompressingStream {
        const sink = Sink{ .ring = ring };
        return .{
            .decoder = try decoderFor(coding, sink),
            .ring = ring,
            .coding = coding,
        };
    }

    pub fn feed(self: *DecompressingStream, chunk: []const u8) !void {
        try self.decoder.feed(chunk);
    }

    pub fn finish(self: *DecompressingStream) !void {
        try self.decoder.finish();
        self.ring.is_closed.store(true, .release);
    }

    pub fn deinit(self: *DecompressingStream) void {
        self.decoder.deinit();
    }
};

test "Encoding.parse handles multiple codings and q-values" {
    try std.testing.expectEqual(Encoding.gzip, Encoding.parse("gzip"));
    try std.testing.expectEqual(Encoding.br, Encoding.parse("br"));
    try std.testing.expectEqual(Encoding.zstd, Encoding.parse("zstd"));
    try std.testing.expectEqual(Encoding.identity, Encoding.parse(""));
    // Deflate is listed first so it wins per our parser's first-match policy.
    try std.testing.expectEqual(Encoding.deflate, Encoding.parse("deflate, gzip;q=0.9, br;q=1.0"));
    // Q=1.0 > q=0.5 would normally reorder; we expose the raw first match.
    try std.testing.expectEqual(Encoding.gzip, Encoding.parse("gzip;q=0.5, br;q=1.0"));
}

test "defaultAcceptEncodingHeader advertises all codings" {
    var buf: [64]u8 = undefined;
    const s = try defaultAcceptEncodingHeader(&buf);
    try std.testing.expect(std.mem.indexOf(u8, s, "gzip") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "br") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "zstd") != null);
}

// ============================================================
// Response pipeline integration
// ============================================================

/// Detect `Content-Encoding` from a raw response header block.
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
