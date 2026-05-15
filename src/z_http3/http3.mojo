from socket import Connection, Manager
from crypto import hashlib, random_bytes
from collections import Dict, List
from time import monotonic_ns
from logging import Logger

# Zawra HTTP/3 Implementation v1.0
# HTTP/3 protocol layer built on QUIC with push streams,
# QPACK compression, and server-driven prioritization.

alias HTTP3_VERSION = "h3-32"
alias DEFAULT_QPACK_TABLE_SIZE = 4096
alias MAX_HEADER_LIST_SIZE = 16384
alias MAX_PUSH_STREAMS = 100
alias MAX_CONCURRENT_STREAMS = 100

# HTTP/3 Frame Types
alias FRAME_TYPE_DATA = 0x0
alias FRAME_TYPE_HEADERS = 0x1
alias FRAME_TYPE_PRIORITY = 0x2
alias FRAME_TYPE_PRIORITY_UPDATE = 0x5
alias FRAME_TYPE_CANCEL_PUSH = 0x3
alias FRAME_TYPE_SETTINGS = 0x4
alias FRAME_TYPE_GOAWAY = 0x7
alias FRAME_TYPE_MAX_PUSH_ID = 0xD

# HTTP/3 Settings
alias SETTINGS_MAX_HEADER_LIST_SIZE = 0x6
alias SETTINGS_QPACK_BLOCKED_STREAMS = 0x7
alias SETTINGS_QPACK_TABLE_SIZE = 0x8

# HTTP Status Codes
alias STATUS_OK = 200
alias STATUS_BAD_REQUEST = 400
alias STATUS_NOT_FOUND = 404
alias STATUS_INTERNAL_SERVER_ERROR = 500

@register_passable
struct HTTP3Stream:
    var stream_id: Int
    var is_client_initiated: Bool
    var headers_sent: Bool
    var body_sent: Bool
    var headers_received: Bool
    var body_received: Bool
    var request_method: String
    var request_path: String
    var status_code: Int
    var headers: Dict[String, String]
    var priority: Int = 0
    var weight: Int = 16
    var parent_stream_id: Int = 0
    var exclusive: Bool = False
    var push_promise: Bool = False
    
    def __init__(inout self, stream_id: Int, is_client_initiated: Bool = True):
        self.stream_id = stream_id
        self.is_client_initiated = is_client_initiated
        self.headers_sent = False
        self.body_sent = False
        self.headers_received = False
        self.body_received = False
        self.request_method = ""
        self.request_path = ""
        self.status_code = 0
        self.headers = Dict[String, String]()
    
    def sendHeaders(self, headers: Dict[String, String], end_stream: Bool) -> Bool:
        """Send HTTP headers over the stream."""
        if self.headers_sent:
            return False
        
        # Serialize headers into HTTP/3 format
        var header_data = self.serialize_headers(headers)
        
        # Send HEADERS frame
        var frame_data = self.create_headers_frame(header_data, end_stream)
        
        # Note: In actual implementation, would send over QUIC connection
        # send_quic_frame(self.stream_id, frame_data)
        
        self.headers_sent = True
        if end_stream:
            self.body_sent = True
        
        return True
    
    def sendBody(self, data: Bytes, end_stream: Bool) -> Bool:
        """Send HTTP request/response body."""
        if not self.headers_sent:
            return False
        
        # Send DATA frame
        var frame_data = self.create_data_frame(data)
        
        # send_quic_frame(self.stream_id, frame_data)
        
        if end_stream:
            self.body_sent = True
        
        return True
    
    def receiveHeaders(self, headers: Dict[String, String]) -> Bool:
        """Receive HTTP headers."""
        if self.headers_received:
            return False
        
        self.headers = headers
        self.headers_received = True
        
        # Parse request line for client streams
        if self.is_client_initiated and self.status_code == 0:
            self.parse_request_line(headers)
        
        return True
    
    def receiveBody(self, data: Bytes, end_stream: Bool) -> Bool:
        """Receive HTTP request/response body."""
        if not self.headers_received:
            return False
        
        # Process received data
        # store_data(data)
        
        if end_stream:
            self.body_received = True
        
        return True
    
    def serialize_headers(self, headers: Dict[String, String]) -> Bytes:
        """Serialize headers to QPACK format."""
        var result = Bytes()
        
        for key, value in headers:
            # QPACK encoding would be more complex
            # This is simplified representation
            var line = key.encode_utf8() + b": " + value.encode_utf8() + b"\r\n"
            result += line
        
        result += b"\r\n"
        return result
    
    def create_headers_frame(self, header_data: Bytes, end_stream: Bool) -> Bytes:
        """Create HTTP/3 HEADERS frame."""
        var frame_type: UInt8 = FRAME_TYPE_HEADERS
        var frame_flags: UInt8 = 0
        
        if end_stream:
            frame_flags |= 0x1
        
        # Simple length encoding for header data
        var frame_len = len(header_data)
        if frame_len < 127:
            var len_bytes = Bytes([UInt8(frame_len)])
        elif frame_len < 16384:
            var len_bytes = Bytes([0x80 | UInt8(frame_len >> 8), UInt8(frame_len & 0xFF)])
        else:
            raise "Header size too large"
        
        var frame = Bytes([frame_type, frame_flags]) + len_bytes + header_data
        return frame
    
    def create_data_frame(self, data: Bytes) -> Bytes:
        """Create HTTP/3 DATA frame."""
        var frame_type: UInt8 = FRAME_TYPE_DATA
        var frame_flags: UInt8 = 0
        
        var frame_len = len(data)
        var len_bytes = Bytes([UInt8(frame_len)])  # Simplified
        
        var frame = Bytes([frame_type, frame_flags]) + len_bytes + data
        return frame
    
    def parse_request_line(self, headers: Dict[String, String]):
        """Parse HTTP request line from headers."""
        if "request-line" in headers:
            # Simplified parsing
            # In real implementation, would parse: METHOD SP REQUEST-URI SP HTTP-VERSION CRLF
            self.request_method = "GET"  # Default
            self.request_path = "/"      # Default
    
    def sendPriority(self, priority_group: Int, weight: Int, parent: Int, exclusive: Bool):
        """Send priority information."""
        var frame_data = self.create_priority_frame(priority_group, weight, parent, exclusive)
        # send_quic_frame(self.stream_id, frame_data)
    
    def create_priority_frame(self, priority_group: Int, weight: Int, parent: Int, exclusive: Bool) -> Bytes:
        """Create PRIORITY frame."""
        var frame_type: UInt8 = FRAME_TYPE_PRIORITY_UPDATE
        
        # Stream ID (variable-length integer encoding)
        var stream_id_bytes = encode_varint(self.stream_id)
        
        # Priority fields
        var priority_group_bytes = encode_varint(priority_group)
        var weight_bytes = Bytes([UInt8(weight)])
        var parent_bytes = encode_varint(parent)
        
        var frame = Bytes([frame_type]) + stream_id_bytes + priority_group_bytes + weight_bytes + parent_bytes
        return frame

@register_passable  
struct QPACKEncoder:
    """QPACK encoder for header compression."""
    var table: Dict[String, String]
    var dynamic_table_size: Int
    var dynamic_table_capacity: Int
    var header_block: List[UInt8]
    
    def __init__(inout self):
        self.table = Dict[String, String]()
        self.dynamic_table_size = 0
        self.dynamic_table_capacity = DEFAULT_QPACK_TABLE_SIZE
        self.header_block = List[UInt8]()
    
    def encodeHeader(self, name: String, value: String) -> Bytes:
        """Encode a header field."""
        # Check if header exists in dynamic table
        var dynamic_index = self.find_dynamic_entry(name, value)
        
        if dynamic_index >= 0:
            # Reference dynamic table entry
            var encoded = encode_varint(0x80 | dynamic_index)
            self.header_block.extend(encoded)
            return encoded
        
        # Check static table (simplified)
        var static_index = self.find_static_entry(name, value)
        if static_index >= 0:
            # Reference static table entry
            var encoded = encode_varint(static_index)
            self.header_block.extend(encoded)
            return encoded
        
        # Literal header field with or without name/old name/weight
        # This is simplified QPACK encoding
        var name_len = name.encode_utf8()
        var value_len = value.encode_utf8()
        
        var header_field: List[UInt8] = []
        
        # Name (literal)
        if len(name_len) < 128:
            header_field.append(UInt8(len(name_len) | 0x40))
        else:
            var encoded_name_len = encode_varint(len(name_len) | 0x4000)
            header_field.extend(encoded_name_len)
        
        header_field.extend(name_len)
        
        # Value (literal)
        if len(value_len) < 128:
            header_field.append(UInt8(len(value_len)))
        else:
            var encoded_value_len = encode_varint(len(value_len))
            header_field.extend(encoded_value_len)
        
        header_field.extend(value_len)
        
        var encoded = Bytes(header_field)
        self.header_block.extend(encoded)
        return encoded
    
    def find_dynamic_entry(self, name: String, value: String) -> Int:
        """Find header in dynamic table."""
        var full_header = name + ": " + value
        var index = 0
        for entry_name, entry_value in self.table:
            if entry_name == name and entry_value == value:
                return index
            index += 1
        return -1
    
    def find_static_entry(self, name: String, value: String) -> Int:
        """Find header in static table (simplified)."""
        # Static table lookup would be more complex
        # This is a simplified example
        var static_headers = [
            ":method", ":authority", ":path", ":scheme",
            ":status", "accept", "accept-encoding", "accept-language",
            "content-length", "content-type", "cookie", "host",
            "user-agent"
        ]
        
        for i, header_name in enumerate(static_headers):
            if header_name == name:
                return i
        
        return -1
    
    def getHeaderBlock(self) -> Bytes:
        """Get the complete encoded header block."""
        return Bytes(self.header_block)

@register_passable
struct QPACKDecoder:
    """QPACK decoder for header compression."""
    var table: Dict[String, String]
    var dynamic_table_size: Int
    
    def __init__(inout self):
        self.table = Dict[String, String]()
        self.dynamic_table_size = 0
    
    def decodeHeaderBlock(self, data: Bytes, table_size: Int = DEFAULT_QPACK_TABLE_SIZE) -> Dict[String, String]:
        """Decode a header block."""
        var headers = Dict[String, String]()
        var i = 0
        
        while i < len(data):
            var first_byte = data[i]
            var prefix = first_byte >> 5
            
            if prefix == 0b111:  # 7-bit prefix
                var (index, new_i) = decode_varint(data, i)
                i = new_i
                
                if index < len(static_headers):
                    var header_name = static_headers[index]
                    var header_value = self.decodeHeaderValue(data, i)
                    headers[header_name] = header_value
                    i = len(data)  # Simplified
            else:
                # Literal header field
                var (name, value, new_i) = decode_literal_header(data, i)
                headers[name] = value
                i = new_i
        
        return headers
    
    def decodeHeaderValue(self, data: Bytes, i: Int) -> String:
        """Decode header value from data."""
        # Simplified header value decoding
        var value_end = len(data)
        return data[i:value_end].decode_utf8()
    
    def decode_literal_header(self, data: Bytes, i: Int) -> Tuple[String, String, Int]:
        """Decode literal header field."""
        var first_byte = data[i]
        i += 1
        
        # Decode name length
        var (name_len, name_i) = decode_varint(data, i)
        
        # Decode name
        var name = data[name_i:name_i + name_len].decode_utf8()
        name_i += name_len
        
        # Decode value length
        var (value_len, value_i) = decode_varint(data, name_i)
        
        # Decode value
        var value = data[value_i:value_i + value_len].decode_utf8()
        value_i += value_len
        
        return (name, value, value_i)

@register_passable
struct HTTP3Connection:
    """HTTP/3 connection manager."""
    var quic_connection: Any
    var streams: Dict[Int, HTTP3Stream]
    var next_stream_id: Int
    var is_server: Bool
    var settings: Dict[Int, Int]
    var encoder: QPACKEncoder
    var decoder: QPACKDecoder
    var push_enabled: Bool
    var pending_streams: List[Int]
    var closed_streams: List[Int]
    var goaway_sent: Bool
    var goaway_received: Bool
    var last_stream_id: Int
    var logger: Logger
    
    def __init__(inout self, quic_conn: Any, is_server: Bool = False):
        self.quic_connection = quic_conn
        self.streams = Dict[Int, HTTP3Stream]()
        self.next_stream_id = 0 if is_server else 1
        self.is_server = is_server
        self.settings = Dict[Int, Int]()
        self.encoder = QPACKEncoder()
        self.decoder = QPACKDecoder()
        self.push_enabled = True
        self.pending_streams = List[Int]()
        self.closed_streams = List[Int]()
        self.goaway_sent = False
        self.goaway_received = False
        self.last_stream_id = 0
        self.logger = Logger("HTTP3Connection")
    
    def initialize(self) -> Bool:
        """Initialize HTTP/3 connection."""
        # Send SETTINGS frame
        var settings_frame = self.create_settings_frame()
        # self.send_frame(settings_frame)
        
        # Set default settings
        self.settings[SETTINGS_QPACK_TABLE_SIZE] = DEFAULT_QPACK_TABLE_SIZE
        self.settings[SETTINGS_MAX_HEADER_LIST_SIZE] = MAX_HEADER_LIST_SIZE
        self.settings[SETTINGS_QPACK_BLOCKED_STREAMS] = 100
        
        return True
    
    def createSettingsFrame(self) -> Bytes:
        """Create SETTINGS frame."""
        var frame_type: UInt8 = FRAME_TYPE_SETTINGS
        var frame_data = Bytes()
        
        for param, value in self.settings:
            var param_bytes = encode_varint(param)
            var value_bytes = encode_varint(value)
            frame_data += param_bytes + value_bytes
        
        var frame = Bytes([frame_type]) + encode_varint(len(frame_data)) + frame_data
        return frame
    
    def createStream(self) -> HTTP3Stream:
        """Create new HTTP/3 stream."""
        var stream_id = self.next_stream_id
        self.next_stream_id += 4  # Even for client, odd for server
        
        var stream = HTTP3Stream(stream_id, not self.is_server)
        self.streams[stream_id] = stream
        
        return stream
    
    def sendRequest(self, method: String, path: String, headers: Dict[String, String], body: Bytes) -> Bool:
        """Send HTTP/3 request."""
        var stream = self.createStream()
        
        # Prepare request headers
        var request_headers = Dict[String, String]()
        request_headers[":method"] = method
        request_headers[":scheme"] = "https"
        request_headers[":path"] = path
        request_headers[":authority"] = headers.get("host", "")
        
        # Add other headers
        for key, value in headers:
            if not key.startswith(":"):
                request_headers[key] = value
        
        # Add content-length if body provided
        if body and len(body) > 0:
            request_headers["content-length"] = str(len(body))
        
        # Send headers
        var end_headers = len(body) == 0
        if not stream.sendHeaders(request_headers, end_headers):
            return False
        
        # Send body if present
        if body and len(body) > 0:
            var end_stream = True
            if not stream.sendBody(body, end_stream):
                return False
        
        return True
    
    def sendResponse(self, stream_id: Int, status_code: Int, headers: Dict[String, String], body: Bytes) -> Bool:
        """Send HTTP/3 response."""
        var stream = self.streams.get(stream_id)
        if stream == None:
            return False
        
        # Prepare response headers
        var response_headers = Dict[String, String]()
        response_headers[":status"] = str(status_code)
        response_headers["server"] = "Zawra/1.0"
        
        # Add other headers
        for key, value in headers:
            response_headers[key] = value
        
        # Add content-length if body provided
        if body and len(body) > 0:
            response_headers["content-length"] = str(len(body))
        
        # Send headers
        var end_headers = len(body) == 0
        if not stream.sendHeaders(response_headers, end_headers):
            return False
        
        # Send body if present
        if body and len(body) > 0:
            var end_stream = True
            if not stream.sendBody(body, end_stream):
                return False
        
        return True
    
    def process_frame(self, frame_type: UInt8, frame_data: Bytes, stream_id: Int) -> Bool:
        """Process incoming HTTP/3 frame."""
        match frame_type:
            case FRAME_TYPE_DATA:
                return self.process_data_frame(frame_data, stream_id)
            case FRAME_TYPE_HEADERS:
                return self.process_headers_frame(frame_data, stream_id)
            case FRAME_TYPE_PRIORITY:
                return self.process_priority_frame(frame_data, stream_id)
            case FRAME_TYPE_SETTINGS:
                return self.process_settings_frame(frame_data)
            case FRAME_TYPE_GOAWAY:
                return self.process_goaway_frame(frame_data)
            case FRAME_TYPE_CANCEL_PUSH:
                return self.process_cancel_push_frame(frame_data)
            case FRAME_TYPE_MAX_PUSH_ID:
                return self.process_max_push_id_frame(frame_data)
            case _:
                self.logger.warning("Unknown frame type: {}".format(frame_type))
                return False
    
    def process_data_frame(self, frame_data: Bytes, stream_id: Int) -> Bool:
        """Process DATA frame."""
        var stream = self.streams.get(stream_id)
        if stream == None:
            return False
        
        var end_stream = (frame_data[1] & 0x1) != 0  # Check if end of stream
        
        return stream.receiveBody(frame_data[4:], end_stream)  # Skip header
    
    def process_headers_frame(self, frame_data: Bytes, stream_id: Int) -> Bool:
        """Process HEADERS frame."""
        var stream = self.streams.get(stream_id)
        if stream == None:
            return False
        
        var end_stream = (frame_data[1] & 0x1) != 0
        
        # Decode headers using QPACK
        var headers = self.decoder.decodeHeaderBlock(frame_data[4:])
        
        if not stream.receiveHeaders(headers):
            return False
        
        if end_stream:
            stream.body_received = True
        
        return True
    
    def process_priority_frame(self, frame_data: Bytes, stream_id: Int) -> Bool:
        """Process PRIORITY frame."""
        # Parse priority information
        var i = 4  # Skip frame header
        var (priority_group, i) = decode_varint(frame_data, i)
        var weight = frame_data[i]
        i += 1
        var (parent_stream_id, i) = decode_varint(frame_data, i)
        var exclusive = (frame_data[i] & 0x80) != 0
        
        var stream = self.streams.get(stream_id)
        if stream == None:
            return False
        
        # Update stream priority
        stream.priority = priority_group
        stream.weight = weight
        stream.parent_stream_id = parent_stream_id
        stream.exclusive = exclusive
        
        return True
    
    def process_settings_frame(self, frame_data: Bytes) -> Bool:
        """Process SETTINGS frame."""
        var i = 0
        while i + 4 <= len(frame_data):
            var (param, i) = decode_varint(frame_data, i)
            var (value, i) = decode_varint(frame_data, i)
            self.settings[param] = value
        return True
    
    def process_goaway_frame(self, frame_data: Bytes) -> Bool:
        """Process GOAWAY frame."""
        self.goaway_received = True
        var (last_stream_id, _) = decode_varint(frame_data, 0)
        self.last_stream_id = last_stream_id
        return True
    
    def process_cancel_push_frame(self, frame_data: Bytes) -> Bool:
        """Process CANCEL_PUSH frame."""
        var (push_id, _) = decode_varint(frame_data, 0)
        # Handle push cancellation
        return True
    
    def process_max_push_id_frame(self, frame_data: Bytes) -> Bool:
        """Process MAX_PUSH_ID frame."""
        var (max_push_id, _) = decode_varint(frame_data, 0)
        # Update max push ID
        return True
    
    def send_goaway(self, error_code: Int = 0, debug_data: String = "") -> Bool:
        """Send GOAWAY frame."""
        if self.goaway_sent:
            return False
        
        var frame_data = encode_varint(self.last_stream_id)
        if debug_data:
            frame_data += debug_data.encode_utf8()
        
        var frame = Bytes([FRAME_TYPE_GOAWAY]) + encode_varint(len(frame_data)) + frame_data
        # send_quic_frame(0, frame)  # GOAWAY sent on control stream
        
        self.goaway_sent = True
        return True
    
    def close_stream(self, stream_id: Int) -> Bool:
        """Close HTTP/3 stream."""
        if stream_id not in self.streams:
            return False
        
        del self.streams[stream_id]
        self.closed_streams.append(stream_id)
        return True
    
    def get_stream_status(self, stream_id: Int) -> Dict[String, Any]:
        """Get stream status information."""
        var stream = self.streams.get(stream_id)
        if stream == None:
            return {"status": "closed"}
        
        var status = Dict[String, Any]()
        status["stream_id"] = stream.stream_id
        status["headers_sent"] = stream.headers_sent
        status["body_sent"] = stream.body_sent
        status["headers_received"] = stream.headers_received
        status["body_received"] = stream.body_received
        status["status_code"] = stream.status_code
        status["priority"] = stream.priority
        
        return status

# Utility functions
def encode_varint(value: Int) -> Bytes:
    """Encode a variable-length integer as per RFC 7540."""
    if value < 128:
        return Bytes([UInt8(value)])
    elif value < 16384:
        var bytes = Bytes([UInt8(0x80 | (value >> 8)), UInt8(value & 0xFF)])
        return bytes
    elif value < 2097152:
        var bytes = Bytes([
            UInt8(0x80 | ((value >> 16) & 0xFF)),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF)
        ])
        return bytes
    else:
        raise "Varint too large"

def decode_varint(data: Bytes, i: Int) -> Tuple[Int, Int]:
    """Decode a variable-length integer."""
    var first_byte = data[i]
    var prefix = first_byte >> 5
    
    if prefix < 0b111:
        return (first_byte & 0x7F, i + 1)
    
    var num_bytes = prefix - 0b110
    var result = first_byte & 0x1F
    var j = i + 1
    
    for _ in range(num_bytes):
        result = (result << 8) | data[j]
        j += 1
    
    return (result, j)

# Static header table (simplified)
var static_headers: List[String] = [
    ":authority", ":method", ":path", ":scheme", ":status",
    "accept", "accept-encoding", "accept-language", 
    "access-control-allow-credentials", "access-control-allow-origin",
    "access-control-allow-headers", "access-control-allow-methods",
    "cache-control", "content-encoding", "content-language",
    "content-length", "content-type", "cookie", "date",
    "etag", "expires", "from", "host", "if-modified-since",
    "if-none-match", "if-unmodified-since", "last-modified",
    "link", "location", "origin", "referer", "retry-after",
    "server", "trailer", "transfer-encoding", "user-agent",
    "vary", "x-content-type-options", "x-frame-options",
    "x-xss-protection"
]

# Example usage and testing
def create_http3_client(quic_conn: Any) -> HTTP3Connection:
    """Create HTTP/3 client connection."""
    return HTTP3Connection(quic_conn, is_server=False)

def create_http3_server(quic_conn: Any) -> HTTP3Connection:
    """Create HTTP/3 server connection."""
    return HTTP3Connection(quic_conn, is_server=True)

def make_http3_request(conn: HTTP3Connection, url: String, method: String = "GET", headers: Dict[String, String] = None, body: Bytes = None) -> Bool:
    """Make HTTP/3 request helper."""
    if headers == None:
        headers = Dict[String, String]()
    
    if body == None:
        body = Bytes()
    
    # Parse URL
    # Extract path from URL (simplified)
    var path = "/" if "/" in url else url.split("/")[-1]
    
    # Set default headers
    headers["host"] = "example.com"  # Should extract from URL
    
    return conn.sendRequest(method, path, headers, body)

def create_http3_response(status: Int = 200, headers: Dict[String, String] = None, body: Bytes = None) -> Dict[String, Any]:
    """Create HTTP/3 response helper."""
    if headers == None:
        headers = Dict[String, String]()
    
    if body == None:
        body = b"OK"
    
    headers["content-type"] = "text/plain"
    headers["content-length"] = str(len(body))
    
    return {
        "status": status,
        "headers": headers,
        "body": body
    }