package wsocket

import "core:fmt"
import "core:mem"
import "core:net"
import "core:strings"
import "core:sync"
import "core:time"

// Represents a connected WebSocket client
Connection :: struct {
    id:                u64,
    socket:            net.TCP_Socket,
    endpoint:          net.Endpoint,
    server:            ^Server,
    state:             Connection_State,
    user_data:         rawptr,
    path:              string,
    raw_query:         string,
    selected_protocol: string,
    headers:           map[string]string,
    send_mutex:        sync.Mutex,
    read_buf:          [dynamic]byte,
    read_offset:       int,
    fragment_opcode:   Opcode,
    fragment_buffer:   [dynamic]byte,
    is_fragmenting:    bool,
    close_code:        Close_Code,
    close_reason:      string,
    close_sent:        bool,
    close_notified:    bool,
    allocator:         mem.Allocator,
}

// Sends a UTF-8 text message to the client. Thread-safe.
send_text :: proc(conn: ^Connection, text: string) -> Error {
    if conn == nil || conn.state != .Open {
        return .Invalid_State
    }
    return connection_send_frame(conn, true, .Text, transmute([]byte)text)
}

// Sends a binary message to the client. Thread-safe.
send_binary :: proc(conn: ^Connection, data: []byte) -> Error {
    if conn == nil || conn.state != .Open {
        return .Invalid_State
    }
    return connection_send_frame(conn, true, .Binary, data)
}

// Sends a Ping control frame to the client. Thread-safe.
send_ping :: proc(conn: ^Connection, data: []byte = nil) -> Error {
    if conn == nil || conn.state != .Open {
        return .Invalid_State
    }
    if len(data) > 125 {
        return .Protocol_Error
    }
    return connection_send_frame(conn, true, .Ping, data)
}

// Sends a Pong control frame to the client. Thread-safe.
send_pong :: proc(conn: ^Connection, data: []byte = nil) -> Error {
    if conn == nil || conn.state != .Open {
        return .Invalid_State
    }
    if len(data) > 125 {
        return .Protocol_Error
    }
    return connection_send_frame(conn, true, .Pong, data)
}

// Initiates a clean close handshake from the server side. Thread-safe.
close :: proc(
    conn: ^Connection,
    code: Close_Code = .Normal_Closure,
    reason: string = "",
) -> Error {
    if conn == nil {
        return .None
    }

    sync.mutex_lock(&conn.send_mutex)
    if conn.state == .Closed {
        sync.mutex_unlock(&conn.send_mutex)
        return .None
    }
    conn.state = .Closing
    conn.close_code = code
    conn.close_reason = reason
    sync.mutex_unlock(&conn.send_mutex)

    connection_send_close_frame(conn, code, reason)

    // Shutdown TCP socket to signal reader loop to exit
    net.shutdown(conn.socket, .Both)
    return .None
}

// Returns the remote IP address and port as a string
connection_endpoint_string :: proc(
    conn: ^Connection,
    allocator := context.temp_allocator,
) -> string {
    return fmt.aprintf("%v", conn.endpoint, allocator = allocator)
}

// Internal: sends a close frame if not already sent
connection_send_close_frame :: proc(conn: ^Connection, code: Close_Code, reason: string) {
    sync.mutex_lock(&conn.send_mutex)
    defer sync.mutex_unlock(&conn.send_mutex)

    if conn.close_sent {
        return
    }
    conn.close_sent = true

    payload := encode_close_payload(code, reason, context.temp_allocator)
    frame := encode_frame(true, .Close, payload, context.temp_allocator)
    net.send_tcp(conn.socket, frame)
}

// Internal: low-level frame sending with mutex protection
connection_send_frame :: proc(
    conn: ^Connection,
    fin: bool,
    opcode: Opcode,
    payload: []byte,
) -> Error {
    sync.mutex_lock(&conn.send_mutex)
    defer sync.mutex_unlock(&conn.send_mutex)

    if conn.state == .Closed || (conn.close_sent && opcode != .Close) {
        return .Connection_Closed
    }

    frame := encode_frame(fin, opcode, payload, context.temp_allocator)
    _, send_err := net.send_tcp(conn.socket, frame)
    if send_err != nil {
        return .Socket_Error
    }
    return .None
}

// Internal: Connection worker procedure executing on a dedicated thread
connection_worker :: proc(data: rawptr) {
    conn := cast(^Connection)data
    server := conn.server

    defer {
        // Ensure socket is closed
        net.shutdown(conn.socket, .Both)
        net.close(conn.socket)

        conn.state = .Closed

        // Trigger on_close callback if not already done
        if !conn.close_notified && server.config.on_close != nil {
            conn.close_notified = true
            code := conn.close_code
            if code == Close_Code(0) {
                code = .Abnormal_Closure
            }
            server.config.on_close(conn, code, conn.close_reason, server.config.user_data)
        }

        // Unregister from server
        server_remove_connection(server, conn.id)

        // Free connection allocations
        destroy_connection(conn)

        // Notify server Wait_Group
        sync.wait_group_done(&server.wait_group)
    }

    // Set handshake timeout on socket
    if server.config.handshake_timeout > 0 {
        net.set_option(conn.socket, .Receive_Timeout, server.config.handshake_timeout)
    }

    // Phase 1: HTTP Handshake
    if !connection_perform_handshake(conn) {
        return
    }

    // Restore configured read timeout for the WebSocket session
    if server.config.read_timeout > 0 {
        net.set_option(conn.socket, .Receive_Timeout, server.config.read_timeout)
    } else {
        // Disable timeout (0 duration in socket option resets it)
        net.set_option(conn.socket, .Receive_Timeout, time.Duration(0))
    }

    // Notify on_connect callback
    if server.config.on_connect != nil {
        server.config.on_connect(conn, server.config.user_data)
    }

    // Phase 2: Frame Read Loop
    connection_frame_loop(conn)
}

// Internal: Performs the HTTP WebSocket upgrade handshake
connection_perform_handshake :: proc(conn: ^Connection) -> bool {
    server := conn.server
    temp_buf: [4096]byte

    for {
        // Check if we have received complete HTTP headers (\r\n\r\n or \n\n)
        header_end := -1
        delimiter_len := 0

        // Look for \r\n\r\n
        crlf_pos := strings.index(transmute(string)conn.read_buf[:], "\r\n\r\n")
        if crlf_pos >= 0 {
            header_end = crlf_pos
            delimiter_len = 4
        } else {
            // Check for \n\n
            lf_pos := strings.index(transmute(string)conn.read_buf[:], "\n\n")
            if lf_pos >= 0 {
                header_end = lf_pos
                delimiter_len = 2
            }
        }

        if header_end >= 0 {
            // Full HTTP headers received
            raw_req := transmute(string)conn.read_buf[:header_end]
            req: Request
            ok, status_code, status_text := parse_handshake_request(raw_req, &req, conn.allocator)
            defer destroy_request(&req)

            if !ok {
                err_resp := build_error_response(
                    status_code,
                    status_text,
                    nil,
                    status_text,
                    context.temp_allocator,
                )
                net.send_tcp(conn.socket, transmute([]byte)err_resp)
                return false
            }

            // User handshake hook
            res := Handshake_Response {
                status_code   = 101,
                status_text   = "Switching Protocols",
                extra_headers = make([dynamic]Header_Field, context.temp_allocator),
            }

            if server.config.on_handshake != nil {
                allowed := server.config.on_handshake(&req, &res, server.config.user_data)
                if !allowed {
                    code := res.status_code != 101 ? res.status_code : 403
                    text := len(res.status_text) > 0 ? res.status_text : "Forbidden"
                    err_resp := build_error_response(
                        code,
                        text,
                        res.extra_headers[:],
                        res.body,
                        context.temp_allocator,
                    )
                    net.send_tcp(conn.socket, transmute([]byte)err_resp)
                    return false
                }
            }

            // Compute Sec-WebSocket-Accept
            sec_key, _ := req.headers["sec-websocket-key"]
            accept_key, accept_ok := compute_accept_key(sec_key, context.temp_allocator)
            if !accept_ok {
                err_resp := build_error_response(
                    400,
                    "Bad Request: Invalid Key",
                    nil,
                    "",
                    context.temp_allocator,
                )
                net.send_tcp(conn.socket, transmute([]byte)err_resp)
                return false
            }

            // Send 101 Switching Protocols
            handshake_resp := build_handshake_response(res, accept_key, context.temp_allocator)
            _, send_err := net.send_tcp(conn.socket, transmute([]byte)handshake_resp)
            if send_err != nil {
                return false
            }

            // Store connection info
            conn.path = strings.clone(req.path, conn.allocator)
            conn.raw_query = strings.clone(req.raw_query, conn.allocator)
            if len(res.selected_protocol) > 0 {
                conn.selected_protocol = strings.clone(res.selected_protocol, conn.allocator)
            }
            for k, v in req.headers {
                conn.headers[strings.clone(k, conn.allocator)] = strings.clone(v, conn.allocator)
            }

            conn.state = .Open
            conn.read_offset = header_end + delimiter_len
            return true
        }

        // Buffer limit for handshake (prevent memory DoS from huge headers)
        if len(conn.read_buf) > 64 * 1024 {
            err_resp := build_error_response(
                431,
                "Request Header Fields Too Large",
                nil,
                "",
                context.temp_allocator,
            )
            net.send_tcp(conn.socket, transmute([]byte)err_resp)
            return false
        }

        // Read more data from socket
        bytes_read, rerr := net.recv_tcp(conn.socket, temp_buf[:])
        if rerr != nil || bytes_read == 0 {
            return false
        }
        append(&conn.read_buf, ..temp_buf[:bytes_read])
    }
}

// Internal: Main loop reading and processing WebSocket frames
connection_frame_loop :: proc(conn: ^Connection) {
    server := conn.server
    temp_buf: [8192]byte

    for conn.state == .Open || conn.state == .Closing {
        // Process any frames available in read_buf
        for {
            available := conn.read_buf[conn.read_offset:]
            if len(available) == 0 {
                break
            }

            hdr, res := parse_frame_header(available)
            if res == .Incomplete {
                // Need more bytes from network
                break
            }
            if res == .Protocol_Error {
                connection_send_close_frame(conn, .Protocol_Error, "Frame format error")
                conn.state = .Closed
                return
            }

            // RFC 6455 5.1: Client-to-server frames MUST be masked
            if !hdr.masked {
                connection_send_close_frame(conn, .Protocol_Error, "Client frames must be masked")
                conn.state = .Closed
                return
            }

            // Check max frame size
            if int(hdr.payload_len) > server.config.max_frame_size {
                connection_send_close_frame(
                    conn,
                    .Message_Too_Big,
                    "Frame exceeds max allowed size",
                )
                conn.state = .Closed
                return
            }

            total_frame_len := hdr.header_size + int(hdr.payload_len)
            if len(available) < total_frame_len {
                // Wait for the full payload to arrive
                break
            }

            // Extract and unmask payload
            payload := available[hdr.header_size:total_frame_len]
            unmask_payload(payload, hdr.mask_key)

            // Advance offset
            conn.read_offset += total_frame_len

            // Handle frame based on opcode
            if !connection_handle_frame(conn, hdr, payload) {
                return
            }
        }

        // Compact read buffer if offset is large
        if conn.read_offset > 8192 {
            remaining := len(conn.read_buf) - conn.read_offset
            if remaining > 0 {
                copy(conn.read_buf[:remaining], conn.read_buf[conn.read_offset:])
                resize(&conn.read_buf, remaining)
            } else {
                clear(&conn.read_buf)
            }
            conn.read_offset = 0
        }

        // Read more data from socket
        bytes_read, rerr := net.recv_tcp(conn.socket, temp_buf[:])
        if rerr != nil {
            if rerr == .Timeout || rerr == .Would_Block {
                if server.config.on_error != nil {
                    server.config.on_error(conn, .Timeout, server.config.user_data)
                }
            }
            break
        }
        if bytes_read == 0 {
            // Client cleanly shut down TCP connection
            break
        }

        append(&conn.read_buf, ..temp_buf[:bytes_read])
    }
}

// Internal: Handles a single unmasked frame. Returns false if connection should close.
connection_handle_frame :: proc(conn: ^Connection, hdr: Frame_Header, payload: []byte) -> bool {
    server := conn.server

    if opcode_is_control(hdr.opcode) {
        #partial switch hdr.opcode {
        case .Close:
            code, reason, err := parse_close_payload(payload)
            if err != .None {
                close_code :=
                    (err == .Invalid_UTF8) ? Close_Code.Invalid_Payload_Data : Close_Code.Protocol_Error
                connection_send_close_frame(conn, close_code, "Invalid close payload")
                conn.state = .Closed
                return false
            }

            conn.close_code = code
            conn.close_reason = reason

            if conn.state == .Open {
                conn.state = .Closing
                reply_code := (code == .No_Status_Received) ? Close_Code.Normal_Closure : code
                connection_send_close_frame(conn, reply_code, "")
            }

            conn.state = .Closed
            return false

        case .Ping:
            // RFC 6455 5.5.2: MUST respond with Pong with identical payload
            connection_send_frame(conn, true, .Pong, payload)
            if server.config.on_ping != nil {
                server.config.on_ping(conn, payload, server.config.user_data)
            }

        case .Pong:
            if server.config.on_pong != nil {
                server.config.on_pong(conn, payload, server.config.user_data)
            }
        }
        return true
    }

    // Data frame handling (.Text, .Binary, .Continuation)
    if hdr.opcode == .Continuation {
        if !conn.is_fragmenting {
            connection_send_close_frame(conn, .Protocol_Error, "Unexpected continuation frame")
            conn.state = .Closed
            return false
        }

        if len(conn.fragment_buffer) + len(payload) > server.config.max_message_size {
            connection_send_close_frame(conn, .Message_Too_Big, "Message too big")
            conn.state = .Closed
            return false
        }

        append(&conn.fragment_buffer, ..payload)

        if hdr.fin {
            // Fragmented message complete
            conn.is_fragmenting = false
            if conn.fragment_opcode == .Text {
                if !is_valid_utf8(conn.fragment_buffer[:]) {
                    connection_send_close_frame(
                        conn,
                        .Invalid_Payload_Data,
                        "Invalid UTF-8 in message",
                    )
                    conn.state = .Closed
                    return false
                }
            }

            if server.config.on_message != nil {
                msg := Message {
                    type = (conn.fragment_opcode == .Text) ? .Text : .Binary,
                    data = conn.fragment_buffer[:],
                    text = (conn.fragment_opcode == .Text) ? string(conn.fragment_buffer[:]) : "",
                }
                server.config.on_message(conn, msg, server.config.user_data)
            }
            clear(&conn.fragment_buffer)
        }
        return true
    }

    // New Data frame (.Text or .Binary)
    if conn.is_fragmenting {
        connection_send_close_frame(
            conn,
            .Protocol_Error,
            "Previous fragmented message incomplete",
        )
        conn.state = .Closed
        return false
    }

    if !hdr.fin {
        // Start of fragmented message
        conn.is_fragmenting = true
        conn.fragment_opcode = hdr.opcode
        clear(&conn.fragment_buffer)

        if len(payload) > server.config.max_message_size {
            connection_send_close_frame(conn, .Message_Too_Big, "Message too big")
            conn.state = .Closed
            return false
        }
        append(&conn.fragment_buffer, ..payload)
        return true
    }

    // Complete unfragmented message
    if hdr.opcode == .Text {
        if !is_valid_utf8(payload) {
            connection_send_close_frame(conn, .Invalid_Payload_Data, "Invalid UTF-8 in text frame")
            conn.state = .Closed
            return false
        }
    }

    if len(payload) > server.config.max_message_size {
        connection_send_close_frame(conn, .Message_Too_Big, "Message too big")
        conn.state = .Closed
        return false
    }

    if server.config.on_message != nil {
        msg := Message {
            type = (hdr.opcode == .Text) ? .Text : .Binary,
            data = payload,
            text = (hdr.opcode == .Text) ? string(payload) : "",
        }
        server.config.on_message(conn, msg, server.config.user_data)
    }

    return true
}

// Internal: Frees all allocated memory for a connection
destroy_connection :: proc(conn: ^Connection) {
    delete(conn.read_buf)
    delete(conn.fragment_buffer)
    delete(conn.path, conn.allocator)
    delete(conn.raw_query, conn.allocator)
    if len(conn.selected_protocol) > 0 {
        delete(conn.selected_protocol, conn.allocator)
    }
    for k, v in conn.headers {
        delete(k, conn.allocator)
        delete(v, conn.allocator)
    }
    delete(conn.headers)
    free(conn, conn.allocator)
}
