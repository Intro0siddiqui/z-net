//! z_http - HTTP/1.1 and HTTP/2 Protocol Layer
//! Mojo logic with Zig parsing for high performance

const std = @import("std");

// HTTP/1.1 implementation
pub const HttpMethod = enum {
    GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT
};

pub const HttpVersion = enum {
    HTTP_1_1, HTTP_2_0, HTTP_3_0
};

pub const HttpHeader = struct {
    name: String,
    value: String,
};

pub const HttpRequest = struct {
    method: HttpMethod,
    path: String,
    version: HttpVersion,
    headers: Array(HttpHeader),
    body: Array(UInt8),
    timeout: UInt32 = 30000, // 30 seconds
    keep_alive: Bool = true,
};

pub const HttpResponse = struct {
    status_code: UInt16,
    status_text: String,
    version: HttpVersion,
    headers: Array(HttpHeader),
    body: Array(UInt8),
    content_length: Int64 = -1,
    chunked_transfer: Bool = false,
};

// HTTP/2 Types
pub struct Http2Frame:
    var frame_type: UInt8
    var frame_flags: UInt8  
    var stream_id: UInt32
    var payload: Array(UInt8)

pub struct Http2HeadersFrame:
    var end_stream: Bool
    var end_headers: Bool
    var headers: Array(HttpHeader)

pub struct Http2Stream:
    var id: UInt32
    var state: String  # idle, open, half_closed_local, half_closed_remote, closed
    var window_size: Int32 = 65535
    var priority: UInt8 = 0

pub struct Http2Connection:
    var streams: Dict[UInt32, Http2Stream]
    var next_stream_id: UInt32 = 1
    var peer_window_size: Int32 = 65535
    var settings: Dict[String, Int64]

# HTTP/1.1 Parser (High Performance)
fn parse_http_request(buffer: String, allocator: Allocator) -> Result[HttpRequest, String]:
    var lines = buffer.split("\r\n")
    var request_line = lines[0].split(" ")
    
    if request_line.length != 3:
        return Error("Invalid request line")
    
    method_str = request_line[0].upper()
    method = match method_str:
        case "GET": HttpMethod.GET
        case "POST": HttpMethod.POST  
        case "PUT": HttpMethod.PUT
        case "DELETE": HttpMethod.DELETE
        case "PATCH": HttpMethod.PATCH
        case "HEAD": HttpMethod.HEAD
        case "OPTIONS": HttpMethod.OPTIONS
        case "TRACE": HttpMethod.TRACE
        case "CONNECT": HttpMethod.CONNECT
        case _: HttpMethod.GET
    
    path = request_line[1]
    version = request_line[2]
    http_version = if version == "HTTP/2.0": HttpVersion.HTTP_2_0
                  elif version == "HTTP/1.1": HttpVersion.HTTP_1_1
                  else: HttpVersion.HTTP_1_1
    
    # Parse headers
    headers = Array(HttpHeader)()
    body_start = 0
    var i = 1
    while i < lines.length and lines[i].length > 0:
        var header_line = lines[i]
        colon_pos = header_line.find(":")
        if colon_pos != -1:
            name = header_line[0:colon_pos].strip()
            value = header_line[colon_pos+1:].strip()
            headers.append(HttpHeader(name, value))
        i += 1
    
    # Find body
    body_start = buffer.find("\r\n\r\n")
    if body_start == -1:
        return Error("Invalid headers")
    
    body = buffer[body_start+4:] if body_start + 4 < buffer.length else ""
    
    return HttpRequest(
        method=method,
        path=path,
        version=http_version,
        headers=headers,
        body=body.encode('utf-8'),
        timeout=30000,
        keep_alive=True
    )

# HTTP/1.1 Response Parser
fn parse_http_response(buffer: String, allocator: Allocator) -> Result[HttpResponse, String]:
    lines = buffer.split("\r\n")
    status_line = lines[0]
    
    # Parse status line
    parts = status_line.split(" ")
    if parts.length < 2:
        return Error("Invalid status line")
    
    version = parts[0]
    status_code = parts[1].to_int()
    
    status_text = " ".join(parts[2:]) if parts.length > 2 else ""
    http_version = if version == "HTTP/2.0": HttpVersion.HTTP_2_0
                  elif version == "HTTP/1.1": HttpVersion.HTTP_1_1
                  else: HttpVersion.HTTP_1_1
    
    # Parse headers
    headers = Array(HttpHeader)()
    body_start = 0
    i = 1
    while i < lines.length and lines[i].length > 0:
        header_line = lines[i]
        colon_pos = header_line.find(":")
        if colon_pos != -1:
            name = header_line[0:colon_pos].strip()
            value = header_line[colon_pos+1:].strip()
            headers.append(HttpHeader(name, value))
        i += 1
    
    # Check for chunked transfer encoding
    chunked = False
    content_length = -1
    
    for header in headers:
        if header.name.lower() == "transfer-encoding" and "chunked" in header.value.lower():
            chunked = True
        elif header.name.lower() == "content-length":
            try:
                content_length = header.value.strip().to_int()
            except:
                content_length = -1
    
    # Find body
    body = ""
    body_start = buffer.find("\r\n\r\n")
    if body_start != -1:
        body = buffer[body_start+4:]
    
    return HttpResponse(
        status_code=status_code,
        status_text=status_text,
        version=http_version,
        headers=headers,
        body=body.encode('utf-8'),
        content_length=content_length,
        chunked_transfer=chunked
    )

# HTTP/2 Header Compression (HPACK)
class HpackDecoder:
    var header_table: Array[(String, String)]
    var allocator: Allocator
    
    def __init__(self, allocator: Allocator):
        self.allocator = allocator
        self.header_table = Array((String, String))()
        self._initialize_static_table()
    
    def _initialize_static_table(self):
        # Static header table initialization (simplified)
        static_headers = [
            (":authority", ""),
            (":method", "GET"),
            (":method", "POST"),
            (":path", "/"),
            (":path", "/index.html"),
            (":scheme", "http"),
            (":scheme", "https"),
            (":status", "200"),
            (":status", "204"),
            (":status", "206"),
            (":status", "304"),
            (":status", "400"),
            (":status", "404"),
            (":status", "500"),
            ("accept-charset", ""),
            ("accept-encoding", ""),
            ("accept-language", ""),
            ("accept-ranges", ""),
            ("accept", ""),
            ("access-control-allow-origin", ""),
            ("age", ""),
            ("allow", ""),
            ("authorization", ""),
            ("cache-control", ""),
            ("content-disposition", ""),
            ("content-encoding", ""),
            ("content-language", ""),
            ("content-length", ""),
            ("content-location", ""),
            ("content-range", ""),
            ("content-type", ""),
            ("date", ""),
            ("etag", ""),
            ("expect", ""),
            ("expires", ""),
            ("from", ""),
            ("host", ""),
            ("if-match", ""),
            ("if-modified-since", ""),
            ("if-none-match", ""),
            ("if-range", ""),
            ("if-unmodified-since", ""),
            ("last-modified", ""),
            ("link", ""),
            ("location", ""),
            ("max-forwards", ""),
            ("proxy-authenticate", ""),
            ("proxy-authorization", ""),
            ("range", ""),
            ("referer", ""),
            ("refresh", ""),
            ("retry-after", ""),
            ("server", ""),
            ("set-cookie", ""),
            ("strict-transport-security", ""),
            ("transfer-encoding", ""),
            ("user-agent", ""),
            ("vary", ""),
            ("via", ""),
            ("www-authenticate", "")
        ]
        
        for name, value in static_headers:
            self.header_table.append((name, value))
    
    def decode_headers(self, data: Array(UInt8)) -> Result[Array(HttpHeader), String]:
        headers = Array(HttpHeader)()
        var i = 0
        
        while i < data.length:
            if data[i] & 0x80 != 0:  # Indexed header
                index = ((data[i] & 0x7F) << 8) | data[i+1]
                if index < self.header_table.length:
                    name, value = self.header_table[index]
                    headers.append(HttpHeader(name, value))
                i += 2
            elif data[i] & 0x40 != 0:  # Literal header with indexing
                index = data[i] & 0x3F
                if index < self.header_table.length:
                    # Indexed name
                    name, _ = self.header_table[index]
                    # Parse value
                    var value_bytes = Array(UInt8)()
                    i += 1
                    while i < data.length and data[i] != 0xFF:
                        value_bytes.append(data[i])
                        i += 1
                    value = String.from_utf8(value_bytes).decode('utf-8')
                    headers.append(HttpHeader(name, value))
                    self.header_table.append((name, value))
                i += 1
            elif data[i] & 0x20 != 0:  # Dynamic table size update
                i += 1  # Simplified
            else:  # Literal header without indexing
                # Parse name and value
                name = String()
                value = String()
                i += 1
                
                # Parse name
                while i < data.length and data[i] != 0x00:
                    name += String.from_utf8([data[i]]).decode('utf-8')
                    i += 1
                i += 1  # Skip null
                
                # Parse value
                while i < data.length and data[i] != 0x00:
                    value += String.from_utf8([data[i]]).decode('utf-8')
                    i += 1
                i += 1  # Skip null
                
                headers.append(HttpHeader(name, value))
        
        return Ok(headers)

# HTTP/2 Connection Manager
fn create_http2_connection(stream_socket, allocator: Allocator) -> Result[Http2Connection, String]:
    connection = Http2Connection(
        streams=Dict[UInt32, Http2Stream](),
        next_stream_id=1,
        peer_window_size=65535,
        settings=Dict[String, Int64]()
    )
    
    # Send SETTINGS frame
    settings_frame = create_settings_frame()
    var sent = stream_socket.write(settings_frame.encode('utf-8'))
    
    if sent < settings_frame.length:
        return Error("Failed to send SETTINGS frame")
    
    return Ok(connection)

fn create_http2_request(method: HttpMethod, path: String, headers: Array(HttpHeader), body: String) -> Array(UInt8):
    # Create HTTP/2 pseudo-headers
    pseudo_headers = Array((String, String))()
    pseudo_headers.append((":method", method_to_string(method)))
    pseudo_headers.append((":path", path))
    pseudo_headers.append((":scheme", "https"))
    pseudo_headers.append((":authority", get_authority_from_headers(headers)))
    
    # Combine pseudo-headers with regular headers
    all_headers = Array(HttpHeader)()
    for name, value in pseudo_headers:
        all_headers.append(HttpHeader(name, value))
    for header in headers:
        all_headers.append(header)
    
    # Encode headers using HPACK
    hpack_encoder = HpackEncoder()
    encoded_headers = hpack_encoder.encode_headers(all_headers)
    
    # Create HEADERS frame
    headers_frame = Array(UInt8)()
    headers_frame.extend(encoded_headers)
    
    return headers_frame

# HTTP/1.1 Client
class Http1Client:
    var socket: Socket
    var allocator: Allocator
    var keep_alive: Bool = True
    var current_request: Maybe[HttpRequest] = Nothing()
    
    def __init__(self, allocator: Allocator):
        self.allocator = allocator
        self.socket = Socket()
        self.keep_alive = True
    
    def connect(self, host: String, port: Int64) -> Result[None, String]:
        try:
            self.socket.connect(host, port)
            return Ok(None)
        except Exception as e:
            return Error(str(e))
    
    def send_request(self, request: HttpRequest) -> Result[HttpResponse, String]:
        # Build HTTP/1.1 request
        request_line = "{} {} HTTP/1.1\r\n".format(
            method_to_string(request.method), 
            request.path
        )
        
        headers_str = request_line
        
        # Add headers
        for header in request.headers:
            headers_str += "{}: {}\r\n".format(header.name, header.value)
        
        # Add connection header
        if request.keep_alive:
            headers_str += "Connection: keep-alive\r\n"
        else:
            headers_str += "Connection: close\r\n"
        
        headers_str += "\r\n"
        
        # Send headers
        headers_bytes = headers_str.encode('utf-8')
        sent = self.socket.write(headers_bytes)
        
        if sent < headers_bytes.length:
            return Error("Failed to send headers")
        
        # Send body if present
        if request.body.length > 0:
            sent = self.socket.write(request.body)
            if sent < request.body.length:
                return Error("Failed to send body")
        
        # Read response
        return self._read_response()
    
    def _read_response(self) -> Result[HttpResponse, String]:
        # Read until we have complete response
        buffer = Array(UInt8)()
        var chunk = self.socket.read(8192)
        
        while chunk.is_some() and chunk.value().length > 0:
            buffer.extend(chunk.value())
            
            # Check if we have a complete response
            buffer_str = String.from_utf8(buffer).decode('utf-8')
            if buffer_str.contains("\r\n\r\n"):
                # We might have the full response, try to parse
                response = parse_http_response(buffer_str, self.allocator)
                if response.is_ok():
                    return response
                # Continue reading if parsing failed
            chunk = self.socket.read(8192)
        
        return Error("Incomplete response")
    
    def close(self):
        self.socket.close()

# HTTP/2 Client
class Http2Client:
    var connection: Maybe[Http2Connection]
    var socket: Socket
    var allocator: Allocator
    var hpack_decoder: HpackDecoder
    
    def __init__(self, allocator: Allocator):
        self.allocator = allocator
        self.socket = Socket()
        self.connection = Nothing()
        self.hpack_decoder = HpackDecoder(allocator)
    
    def connect(self, host: String, port: Int64) -> Result[None, String]:
        try:
            self.socket.connect(host, port)
            
            # Upgrade to HTTP/2 if server supports it
            # For now, assume HTTP/2
            self.connection = Just(create_http2_connection(self.socket, self.allocator))
            return Ok(None)
        except Exception as e:
            return Error(str(e))
    
    def send_request(self, request: HttpRequest) -> Result[HttpResponse, String]:
        if self.connection.is_nothing():
            return Error("Not connected")
        
        conn = self.connection.value()
        
        # Create stream
        stream_id = conn.next_stream_id
        conn.next_stream_id += 2
        
        stream = Http2Stream(id=stream_id, state="open", window_size=65535)
        conn.streams[stream_id] = stream
        
        # Create HTTP/2 request
        request_frame_data = create_http2_request(request.method, request.path, request.headers, String.from_utf8(request.body).decode('utf-8'))
        
        # Send HEADERS frame
        headers_frame = Array(UInt8)()
        headers_frame.append(0)  # Length (24-bit)
        headers_frame.append(0)  # Length (continued)
        headers_frame.append(0)  # Length (continued)
        headers_frame.append(1)  # Type = HEADERS
        headers_frame.append(5)  # Flags = END_HEADERS | END_STREAM
        headers_frame.append((stream_id >> 24) & 0xFF)  # Stream ID (big-endian)
        headers_frame.append((stream_id >> 16) & 0xFF)
        headers_frame.append((stream_id >> 8) & 0xFF)
        headers_frame.append(stream_id & 0xFF)
        headers_frame.extend(request_frame_data)
        
        sent = self.socket.write(headers_frame)
        if sent < headers_frame.length:
            return Error("Failed to send request")
        
        # Read response frames
        return self._read_response(stream_id)
    
    def _read_response(self, stream_id: UInt32) -> Result[HttpResponse, String]:
        response_headers = Array(HttpHeader)()
        response_body = Array(UInt8)()
        status_code = 200
        
        while True:
            frame_data = self.socket.read(9)  # Frame header
            if frame_data.is_none() or frame_data.value().length < 9:
                break
            
            frame_header = parse_http2_frame_header(frame_data.value())
            
            if frame_header.frame_type == 0:  # DATA frame
                payload = self.socket.read(frame_header.payload_length)
                if payload.is_some():
                    response_body.extend(payload.value())
            
            elif frame_header.frame_type == 1:  # HEADERS frame
                payload = self.socket.read(frame_header.payload_length)
                if payload.is_some():
                    headers = self.hpack_decoder.decode_headers(payload.value())
                    if headers.is_ok():
                        # Extract status from pseudo-headers
                        for header in headers.value():
                            if header.name == ":status":
                                try:
                                    status_code = header.value.to_int()
                                except:
                                    status_code = 200
                            response_headers.append(header)
                
                if frame_header.frame_flags & 4 != 0:  # END_HEADERS
                    break
            
            elif frame_header.frame_type == 7:  # GOAWAY frame
                break
        
        # Build response
        response = HttpResponse(
            status_code=status_code,
            status_text="",
            version=HttpVersion.HTTP_2_0,
            headers=response_headers,
            body=response_body,
            content_length=response_body.length,
            chunked_transfer=False
        )
        
        return Ok(response)
    
    def close(self):
        self.socket.close()

# Helper functions
fn method_to_string(method: HttpMethod) -> String:
    match method:
        case HttpMethod.GET: return "GET"
        case HttpMethod.POST: return "POST"
        case HttpMethod.PUT: return "PUT"
        case HttpMethod.DELETE: return "DELETE"
        case HttpMethod.PATCH: return "PATCH"
        case HttpMethod.HEAD: return "HEAD"
        case HttpMethod.OPTIONS: return "OPTIONS"
        case HttpMethod.TRACE: return "TRACE"
        case HttpMethod.CONNECT: return "CONNECT"
        case _: return "GET"

fn get_authority_from_headers(headers: Array(HttpHeader)) -> String:
    for header in headers:
        if header.name.lower() == "host":
            return header.value
    return ""

fn parse_http2_frame_header(data: Array(UInt8)) -> Http2Frame:
    var length = (data[0] << 16) | (data[1] << 8) | data[2]
    return Http2Frame(
        frame_type=data[3],
        frame_flags=data[4],
        stream_id=((data[5] << 24) | (data[6] << 16) | (data[7] << 8) | data[8]) & 0x7FFFFFFF,
        payload_length=length
    )

# HPACK Encoder for HTTP/2
class HpackEncoder:
    var header_table: Array[(String, String)]
    var allocator: Allocator
    
    def __init__(self, allocator: Allocator = None):
        self.allocator = allocator if allocator is not None else Allocator()
        self.header_table = Array((String, String))()
    
    def encode_headers(self, headers: Array(HttpHeader)) -> Array(UInt8):
        encoded = Array(UInt8)()
        
        for header in headers:
            # Check if header is in static table
            index = self._find_header_index(header.name, header.value)
            if index != -1 and header.value == self.header_table[index][1]:
                # Use indexed representation
                encoded.append(((index >> 8) & 0x7F) | 0x80)
                encoded.append(index & 0xFF)
            else:
                # Use literal representation
                encoded.append(self._encode_header_name(header.name))
                encoded.extend(self._encode_header_value(header.value))
        
        return encoded
    
    def _find_header_index(self, name: String, value: String) -> Int64:
        for i, (static_name, static_value) in enumerate(self.header_table):
            if static_name.lower() == name.lower() and static_value == value:
                return i + 1  # Static table indices start at 1
        return -1
    
    def _encode_header_name(self, name: String) -> UInt8:
        # Simplified: use literal without indexing
        return 0
    
    def _encode_header_value(self, value: String) -> Array(UInt8):
        encoded = Array(UInt8)()
        value_bytes = value.encode('utf-8')
        
        # Huffman encoding would go here (simplified)
        encoded.extend(value_bytes)
        encoded.append(0)  # End of header value
        
        return encoded