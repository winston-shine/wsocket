package ows

import "core:crypto/legacy/sha1"
import "core:encoding/base64"
import "core:fmt"
import "core:mem"
import "core:strings"

WS_GUID :: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Computes the Sec-WebSocket-Accept key response for the given Sec-WebSocket-Key.
// Returns accept key and true if key is valid (base64 decodes to 16 bytes),
// or ("", false) if invalid.
compute_accept_key :: proc(sec_ws_key: string, allocator := context.allocator) -> (string, bool) {
    trimmed := strings.trim_space(sec_ws_key)
    if len(trimmed) == 0 {
        return "", false
    }

    // RFC 6455 4.2.1: key must be 16 bytes when base64 decoded
    decoded, decode_err := base64.decode(trimmed, allocator = context.temp_allocator)
    if decode_err != nil || len(decoded) != 16 {
        return "", false
    }

    // Concatenate key + GUID
    combined := fmt.aprintf("%s%s", trimmed, WS_GUID, allocator = context.temp_allocator)

    ctx: sha1.Context
    sha1.init(&ctx)
    sha1.update(&ctx, transmute([]byte)combined)
    hash: [sha1.DIGEST_SIZE]byte
    sha1.final(&ctx, hash[:])

    encoded, enc_err := base64.encode(hash[:], allocator = allocator)
    if enc_err != nil {
        return "", false
    }
    return encoded, true
}

// Checks if a comma-separated header value contains a specific token (case-insensitive)
header_contains_token :: proc(header_value: string, token: string) -> bool {
    tokens := strings.split(header_value, ",", context.temp_allocator)
    for t in tokens {
        trimmed := strings.trim_space(t)
        if strings.equal_fold(trimmed, token) {
            return true
        }
    }
    return false
}

// Parses an incoming HTTP handshake request.
// Populates req and returns ok = true, or ok = false with HTTP error status code and message.
parse_handshake_request :: proc(
    raw_data: string,
    req: ^Request,
    allocator: mem.Allocator,
) -> (
    ok: bool,
    status_code: int,
    status_text: string,
) {
    req.allocator = allocator
    req.headers = make(map[string]string, 16, allocator)
    req.subprotocols = make([dynamic]string, allocator)
    req.cookies = make(map[string]string, 8, allocator)

    // Normalize CRLF
    lines := strings.split(raw_data, "\r\n", context.temp_allocator)
    if len(lines) <= 1 {
        // Fallback for LF only
        lines = strings.split(raw_data, "\n", context.temp_allocator)
    }

    if len(lines) == 0 || len(strings.trim_space(lines[0])) == 0 {
        return false, 400, "Bad Request: Empty request"
    }

    // Parse Request-Line: METHOD PATH HTTP-VERSION
    request_line := strings.trim_space(lines[0])
    req_parts := strings.split(request_line, " ", context.temp_allocator)
    if len(req_parts) < 3 {
        return false, 400, "Bad Request: Malformed request line"
    }

    req.method = strings.clone(req_parts[0], allocator)
    raw_uri := req_parts[1]
    req.http_version = strings.clone(req_parts[2], allocator)

    // Check HTTP Method: WebSocket opening handshake MUST be GET
    if req.method != "GET" {
        return false, 405, "Method Not Allowed: Must be GET"
    }

    // Check HTTP Version: Must be HTTP/1.1 or higher
    if !strings.has_prefix(req.http_version, "HTTP/1.1") &&
       !strings.has_prefix(req.http_version, "HTTP/2") &&
       !strings.has_prefix(req.http_version, "HTTP/3") {
        return false, 400, "Bad Request: HTTP version must be 1.1 or higher"
    }

    // Parse URI into path and raw query
    q_idx := strings.index_byte(raw_uri, '?')
    if q_idx >= 0 {
        req.path = strings.clone(raw_uri[:q_idx], allocator)
        req.raw_query = strings.clone(raw_uri[q_idx + 1:], allocator)
    } else {
        req.path = strings.clone(raw_uri, allocator)
        req.raw_query = strings.clone("", allocator)
    }

    // Parse Headers
    for i := 1; i < len(lines); i += 1 {
        line := strings.trim_space(lines[i])
        if len(line) == 0 {
            // End of HTTP headers
            break
        }

        colon_idx := strings.index_byte(line, ':')
        if colon_idx <= 0 {
            continue
        }

        header_name := strings.to_lower(strings.trim_space(line[:colon_idx]), allocator)
        header_val := strings.clone(strings.trim_space(line[colon_idx + 1:]), allocator)

        // Store in headers map
        req.headers[header_name] = header_val

        // Parse Sec-WebSocket-Protocol
        if header_name == "sec-websocket-protocol" {
            protos := strings.split(header_val, ",", context.temp_allocator)
            for p in protos {
                trimmed_proto := strings.trim_space(p)
                if len(trimmed_proto) > 0 {
                    append(&req.subprotocols, strings.clone(trimmed_proto, allocator))
                }
            }
        }

        // Parse Cookies
        if header_name == "cookie" {
            cookie_pairs := strings.split(header_val, ";", context.temp_allocator)
            for cp in cookie_pairs {
                pair := strings.trim_space(cp)
                eq_idx := strings.index_byte(pair, '=')
                if eq_idx > 0 {
                    c_name := strings.clone(strings.trim_space(pair[:eq_idx]), allocator)
                    c_val := strings.clone(strings.trim_space(pair[eq_idx + 1:]), allocator)
                    req.cookies[c_name] = c_val
                }
            }
        }
    }

    // RFC 6455 4.2.1 Verification:
    // 1. Host header must be present
    if _, has_host := req.headers["host"]; !has_host {
        return false, 400, "Bad Request: Missing Host header"
    }

    // 2. Upgrade header must be present and contain "websocket"
    upgrade, has_upgrade := req.headers["upgrade"]
    if !has_upgrade || !strings.equal_fold(upgrade, "websocket") {
        return false, 400, "Bad Request: Missing or invalid Upgrade header"
    }

    // 3. Connection header must contain "upgrade" token
    connection, has_conn := req.headers["connection"]
    if !has_conn || !header_contains_token(connection, "upgrade") {
        return false, 400, "Bad Request: Missing or invalid Connection header"
    }

    // 4. Sec-WebSocket-Version must be 13
    version, has_ver := req.headers["sec-websocket-version"]
    if !has_ver || strings.trim_space(version) != "13" {
        return false, 426, "Upgrade Required: Sec-WebSocket-Version must be 13"
    }

    // 5. Sec-WebSocket-Key must be present and valid
    key, has_key := req.headers["sec-websocket-key"]
    if !has_key {
        return false, 400, "Bad Request: Missing Sec-WebSocket-Key header"
    }

    // Validate key
    _, key_ok := compute_accept_key(key, context.temp_allocator)
    if !key_ok {
        return false, 400, "Bad Request: Invalid Sec-WebSocket-Key"
    }

    return true, 101, "Switching Protocols"
}

// Retrieves a header by name (case-insensitive)
request_header :: proc(req: ^Request, name: string) -> (string, bool) {
    lower_name := strings.to_lower(name, context.temp_allocator)
    val, ok := req.headers[lower_name]
    return val, ok
}

// Checks if the request advertised support for a specific subprotocol
request_has_subprotocol :: proc(req: ^Request, protocol: string) -> bool {
    for p in req.subprotocols {
        if strings.equal_fold(p, protocol) {
            return true
        }
    }
    return false
}

// Retrieves a cookie value by name
request_cookie :: proc(req: ^Request, name: string) -> (string, bool) {
    val, ok := req.cookies[name]
    return val, ok
}

// Retrieves a query parameter by key from raw_query
request_query_param :: proc(
    req: ^Request,
    key: string,
    allocator := context.temp_allocator,
) -> (
    string,
    bool,
) {
    if len(req.raw_query) == 0 {
        return "", false
    }

    pairs := strings.split(req.raw_query, "&", context.temp_allocator)
    for p in pairs {
        eq_idx := strings.index_byte(p, '=')
        if eq_idx >= 0 {
            k := p[:eq_idx]
            if k == key {
                val := p[eq_idx + 1:]
                return strings.clone(val, allocator), true
            }
        } else if p == key {
            return "", true
        }
    }
    return "", false
}

// Deallocates all resources stored in Request
destroy_request :: proc(req: ^Request) {
    delete(req.method, req.allocator)
    delete(req.path, req.allocator)
    delete(req.raw_query, req.allocator)
    delete(req.http_version, req.allocator)

    for k, v in req.headers {
        delete(k, req.allocator)
        delete(v, req.allocator)
    }
    delete(req.headers)

    for p in req.subprotocols {
        delete(p, req.allocator)
    }
    delete(req.subprotocols)

    for k, v in req.cookies {
        delete(k, req.allocator)
        delete(v, req.allocator)
    }
    delete(req.cookies)
}

// Formats a standard HTTP 101 Switching Protocols response
build_handshake_response :: proc(
    res: Handshake_Response,
    accept_key: string,
    allocator := context.allocator,
) -> string {
    var_builder: strings.Builder
    strings.builder_init(&var_builder, allocator)
    defer strings.builder_destroy(&var_builder)

    strings.write_string(&var_builder, "HTTP/1.1 101 Switching Protocols\r\n")
    strings.write_string(&var_builder, "Upgrade: websocket\r\n")
    strings.write_string(&var_builder, "Connection: Upgrade\r\n")
    fmt.sbprintf(&var_builder, "Sec-WebSocket-Accept: %s\r\n", accept_key)

    if len(res.selected_protocol) > 0 {
        fmt.sbprintf(&var_builder, "Sec-WebSocket-Protocol: %s\r\n", res.selected_protocol)
    }

    for h in res.extra_headers {
        fmt.sbprintf(&var_builder, "%s: %s\r\n", h.name, h.value)
    }

    strings.write_string(&var_builder, "\r\n")
    return strings.clone(strings.to_string(var_builder), allocator)
}

// Formats an HTTP error response for failed handshakes
build_error_response :: proc(
    status_code: int,
    status_text: string,
    extra_headers: []Header_Field = nil,
    body: string = "",
    allocator := context.allocator,
) -> string {
    var_builder: strings.Builder
    strings.builder_init(&var_builder, allocator)
    defer strings.builder_destroy(&var_builder)

    fmt.sbprintf(&var_builder, "HTTP/1.1 %d %s\r\n", status_code, status_text)
    fmt.sbprintf(&var_builder, "Content-Length: %d\r\n", len(body))
    strings.write_string(&var_builder, "Connection: close\r\n")
    strings.write_string(&var_builder, "Content-Type: text/plain; charset=utf-8\r\n")

    if status_code == 426 {
        strings.write_string(&var_builder, "Sec-WebSocket-Version: 13\r\n")
    }

    for h in extra_headers {
        fmt.sbprintf(&var_builder, "%s: %s\r\n", h.name, h.value)
    }

    strings.write_string(&var_builder, "\r\n")
    if len(body) > 0 {
        strings.write_string(&var_builder, body)
    }

    return strings.clone(strings.to_string(var_builder), allocator)
}
