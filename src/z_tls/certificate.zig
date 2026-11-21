//! Bounds-checked X.509 certificate parser.
//!
//! `std.crypto.Certificate.parse` assumes its input is well-formed DER and
//! indexes the buffer without bounds checks, which makes it unsuitable for
//! certificates received from the network. This module mirrors the standard
//! parser's field layout but returns `error.MalformedCertificate` instead of
//! reading out of bounds.

const std = @import("std");
const Certificate = std.crypto.Certificate;
const der = Certificate.der;

pub const ParseError = Certificate.ParseError || error{MalformedCertificate};

/// Parse one DER-encoded certificate, returning the same `Parsed` structure
/// as the standard library parser after validating every element boundary.
pub fn parse(der_bytes: []const u8) ParseError!Certificate.Parsed {
    const cert: Certificate = .{ .buffer = der_bytes, .index = 0 };

    const certificate = try element(der_bytes, 0);
    if (certificate.identifier.tag != .sequence) return error.MalformedCertificate;

    const tbs_certificate = try element(der_bytes, certificate.slice.start);
    if (tbs_certificate.identifier.tag != .sequence) return error.MalformedCertificate;

    const version_elem = try element(der_bytes, tbs_certificate.slice.start);
    const version = try Certificate.parseVersion(der_bytes, version_elem);
    const serial_number = if (@as(u8, @bitCast(version_elem.identifier)) == 0xa0)
        try element(der_bytes, version_elem.slice.end)
    else
        version_elem;

    const tbs_signature = try element(der_bytes, serial_number.slice.end);
    const issuer = try element(der_bytes, tbs_signature.slice.end);
    const validity = try element(der_bytes, issuer.slice.end);
    if (validity.identifier.tag != .sequence) return error.MalformedCertificate;

    const not_before = try element(der_bytes, validity.slice.start);
    const not_before_utc = try Certificate.parseTime(cert, not_before);
    const not_after = try element(der_bytes, not_before.slice.end);
    const not_after_utc = try Certificate.parseTime(cert, not_after);
    const subject = try element(der_bytes, validity.slice.end);

    const pub_key_info = try element(der_bytes, subject.slice.end);
    const pub_key_signature_algorithm = try element(der_bytes, pub_key_info.slice.start);
    const pub_key_algo_elem = try element(der_bytes, pub_key_signature_algorithm.slice.start);
    const pub_key_algo: Certificate.Parsed.PubKeyAlgo = switch (try Certificate.parseAlgorithmCategory(der_bytes, pub_key_algo_elem)) {
        inline else => |tag| @unionInit(Certificate.Parsed.PubKeyAlgo, @tagName(tag), {}),
        .X9_62_id_ecPublicKey => blk: {
            const params_elem = try element(der_bytes, pub_key_algo_elem.slice.end);
            const named_curve = try Certificate.parseNamedCurve(der_bytes, params_elem);
            break :blk .{ .X9_62_id_ecPublicKey = named_curve };
        },
    };
    const pub_key_elem = try element(der_bytes, pub_key_signature_algorithm.slice.end);
    const pub_key = try parseBitString(cert, pub_key_elem);

    var common_name = der.Element.Slice.empty;
    var name_i = subject.slice.start;
    while (name_i < subject.slice.end) {
        const rdn = try element(der_bytes, name_i);
        var rdn_i = rdn.slice.start;
        while (rdn_i < rdn.slice.end) {
            const atav = try element(der_bytes, rdn_i);
            var atav_i = atav.slice.start;
            while (atav_i < atav.slice.end) {
                const ty_elem = try element(der_bytes, atav_i);
                const val = try element(der_bytes, ty_elem.slice.end);
                atav_i = val.slice.end;
                const ty = Certificate.parseAttribute(der_bytes, ty_elem) catch |err| switch (err) {
                    error.CertificateHasUnrecognizedObjectId => continue,
                    else => |e| return e,
                };
                switch (ty) {
                    .commonName => common_name = val.slice,
                    else => {},
                }
            }
            rdn_i = atav.slice.end;
        }
        name_i = rdn.slice.end;
    }

    const sig_algo = try element(der_bytes, tbs_certificate.slice.end);
    const algo_elem = try element(der_bytes, sig_algo.slice.start);
    const signature_algorithm = try Certificate.parseAlgorithm(der_bytes, algo_elem);
    const sig_elem = try element(der_bytes, sig_algo.slice.end);
    const signature = try parseBitString(cert, sig_elem);

    var subject_alt_name_slice = der.Element.Slice.empty;
    ext: {
        if (version == .v1) break :ext;
        if (pub_key_info.slice.end >= tbs_certificate.slice.end) break :ext;

        const outer_extensions = try element(der_bytes, pub_key_info.slice.end);
        if (outer_extensions.identifier.tag != .bitstring) break :ext;

        const extensions = try element(der_bytes, outer_extensions.slice.start);
        var ext_i = extensions.slice.start;
        while (ext_i < extensions.slice.end) {
            const extension = try element(der_bytes, ext_i);
            ext_i = extension.slice.end;
            const oid_elem = try element(der_bytes, extension.slice.start);
            const ext_id = Certificate.parseExtensionId(der_bytes, oid_elem) catch |err| switch (err) {
                error.CertificateHasUnrecognizedObjectId => continue,
                else => |e| return e,
            };
            const critical_elem = try element(der_bytes, oid_elem.slice.end);
            const ext_bytes_elem = if (critical_elem.identifier.tag != .boolean)
                critical_elem
            else
                try element(der_bytes, critical_elem.slice.end);
            switch (ext_id) {
                .subject_alt_name => subject_alt_name_slice = ext_bytes_elem.slice,
                else => continue,
            }
        }
    }

    return .{
        .certificate = cert,
        .common_name_slice = common_name,
        .issuer_slice = issuer.slice,
        .subject_slice = subject.slice,
        .signature_slice = signature,
        .signature_algorithm = signature_algorithm,
        .message_slice = .{ .start = certificate.slice.start, .end = tbs_certificate.slice.end },
        .pub_key_algo = pub_key_algo,
        .pub_key_slice = pub_key,
        .validity = .{
            .not_before = not_before_utc,
            .not_after = not_after_utc,
        },
        .subject_alt_name_slice = subject_alt_name_slice,
        .version = version,
    };
}

/// True when a SubjectAltName extension payload is a self-contained DER
/// SEQUENCE of GeneralName elements. `Parsed.verifyHostName` parses this
/// slice without bounds checks.
pub fn subjectAltNameIsWellFormed(san: []const u8) bool {
    if (san.len == 0) return true;

    const sequence = element(san, 0) catch return false;
    if (sequence.identifier.tag != .sequence) return false;
    if (sequence.slice.end != san.len) return false;

    var index = sequence.slice.start;
    while (index < sequence.slice.end) {
        const general_name = element(san, index) catch return false;
        index = general_name.slice.end;
    }
    return index == sequence.slice.end;
}

fn element(bytes: []const u8, index: usize) ParseError!der.Element {
    if (index + 2 > bytes.len) return error.MalformedCertificate;

    var i = index;
    const identifier: der.Identifier = @bitCast(bytes[i]);
    i += 1;
    const size_byte = bytes[i];
    i += 1;

    var size: u32 = 0;
    if ((size_byte >> 7) == 0) {
        size = size_byte;
    } else {
        const len_size: u7 = @truncate(size_byte);
        if (len_size > @sizeOf(u32)) return error.MalformedCertificate;
        if (i + len_size > bytes.len) return error.MalformedCertificate;

        const end_i = i + len_size;
        while (i < end_i) : (i += 1) {
            size = (size << 8) | bytes[i];
        }
    }

    const end = @as(u64, i) + size;
    if (end > bytes.len) return error.MalformedCertificate;

    return .{
        .identifier = identifier,
        .slice = .{
            .start = @intCast(i),
            .end = @intCast(end),
        },
    };
}

fn parseBitString(cert: Certificate, elem: der.Element) ParseError!der.Element.Slice {
    if (elem.identifier.tag != .bitstring) return error.CertificateFieldHasWrongDataType;
    if (elem.slice.start >= elem.slice.end) return error.CertificateHasInvalidBitString;
    if (cert.buffer[elem.slice.start] != 0) return error.CertificateHasInvalidBitString;
    return .{ .start = elem.slice.start + 1, .end = elem.slice.end };
}
