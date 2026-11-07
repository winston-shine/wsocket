package ows

import "core:mem"
import "core:net"
import "core:time"

// RFC 6455 WebSocket Opcodes
Opcode :: enum u8 {
    Continuation = 0x0,
    Text         = 0x1,
    Binary       = 0x2,
    // 0x3 - 0x7 reserved for non-control frames
    Close        = 0x8,
    Ping         = 0x9,
    Pong         = 0xA,
    // 0xB - 0xF reserved for control frames
}

// Check if an opcode is a control frame (Close, Ping, Pong)
opcode_is_control :: proc(op: Opcode) -> bool {
    return u8(op) >= 0x8
}

// Check if raw opcode byte is a known/valid opcode
opcode_is_valid :: proc(op_byte: u8) -> bool {
    switch op_byte {
    case 0x0, 0x1, 0x2, 0x8, 0x9, 0xA:
        return true
    case:
        return false
    }
}

// RFC 6455 WebSocket Close Status Codes
Close_Code :: enum u16 {
    Normal_Closure        = 1000,
    Going_Away            = 1001,
    Protocol_Error        = 1002,
    Unsupported_Data      = 1003,
    No_Status_Received    = 1005, // Internal use only
    Abnormal_Closure      = 1006, // Internal use only
    Invalid_Payload_Data  = 1007,
    Policy_Violation      = 1008,
    Message_Too_Big       = 1009,
    Mandatory_Extension   = 1010,
    Internal_Server_Error = 1011,
    Service_Restart       = 1012,
    Try_Again_Later       = 1013,
    Bad_Gateway           = 1014,
    TLS_Handshake_Failure = 1015, // Internal use only
}

// Checks if a close code is valid to be sent/received in a Close frame per RFC 6455
is_valid_close_code :: proc(code: u16) -> bool {
    switch code {
    case 1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014:
        return true
    case 3000 ..= 4999:
        // Reserved for libraries and applications
        return true
    case:
        // 0-999 undefined
        // 1004 reserved
        // 1005, 1006, 1015 MUST NOT be sent over the wire
        // 1016-2999 reserved for IANA
        // 5000+ invalid
        return false
    }
}

// WebSocket message type
Message_Type :: enum {
    Text,
    Binary,
}

// Received WebSocket message
Message :: struct {
    type: Message_Type,
    data: []byte,
    text: string, // Sliced view when type == .Text
}

// Connection state machine
Connection_State :: enum {
    Connecting,
    Open,
    Closing,
    Closed,
}

// Library error types
Error :: enum {
    None,
    Socket_Error,
    Handshake_Failed,
    Protocol_Error,
    Invalid_UTF8,
    Message_Too_Big,
    Frame_Too_Big,
    Connection_Closed,
    Timeout,
    Would_Block,
    Invalid_State,
    Out_Of_Memory,
}

// HTTP Header field
Header_Field :: struct {
    name:  string,
    value: string,
}

// Handshake Request representation
Request :: struct {
    method:       string,
    path:         string,
    raw_query:    string,
    http_version: string,
    headers:      map[string]string, // Normalized lower-case names
    subprotocols: [dynamic]string,
    cookies:      map[string]string,
    allocator:    mem.Allocator,
}

// Handshake Response representation
Handshake_Response :: struct {
    status_code:       int,
    status_text:       string,
    selected_protocol: string,
    extra_headers:     [dynamic]Header_Field,
    body:              string,
}

// Callback signatures
OnHandshake :: #type proc(req: ^Request, res: ^Handshake_Response, user_data: rawptr) -> bool
OnConnect :: #type proc(conn: ^Connection, user_data: rawptr)
OnMessage :: #type proc(conn: ^Connection, msg: Message, user_data: rawptr)
OnClose :: #type proc(conn: ^Connection, code: Close_Code, reason: string, user_data: rawptr)
OnPing :: #type proc(conn: ^Connection, data: []byte, user_data: rawptr)
OnPong :: #type proc(conn: ^Connection, data: []byte, user_data: rawptr)
OnError :: #type proc(conn: ^Connection, err: Error, user_data: rawptr)

// Default server configuration values
DEFAULT_PORT :: 8080
DEFAULT_BACKLOG :: 128
DEFAULT_READ_TIMEOUT :: 60 * time.Second
DEFAULT_HANDSHAKE_TIMEOUT :: 10 * time.Second
DEFAULT_MAX_MESSAGE_SIZE :: 16 * 1024 * 1024 // 16 MB
DEFAULT_MAX_FRAME_SIZE :: 16 * 1024 * 1024 // 16 MB

// Configuration options for WebSocket server
Server_Config :: struct {
    host:              string,
    port:              int,
    backlog:           int,
    read_timeout:      time.Duration,
    handshake_timeout: time.Duration,
    max_message_size:  int,
    max_frame_size:    int,
    tcp_nodelay:       bool,
    on_handshake:      OnHandshake,
    on_connect:        OnConnect,
    on_message:        OnMessage,
    on_close:          OnClose,
    on_ping:           OnPing,
    on_pong:           OnPong,
    on_error:          OnError,
    user_data:         rawptr,
    allocator:         mem.Allocator,
}

// Returns a Server_Config initialized with default values
default_server_config :: proc() -> Server_Config {
    return Server_Config {
        host = "0.0.0.0",
        port = DEFAULT_PORT,
        backlog = DEFAULT_BACKLOG,
        read_timeout = DEFAULT_READ_TIMEOUT,
        handshake_timeout = DEFAULT_HANDSHAKE_TIMEOUT,
        max_message_size = DEFAULT_MAX_MESSAGE_SIZE,
        max_frame_size = DEFAULT_MAX_FRAME_SIZE,
        tcp_nodelay = true,
        allocator = context.allocator,
    }
}
