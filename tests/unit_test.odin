package tests

import ws ".."
import "core:fmt"
import "core:mem"
import "core:strings"
import "core:testing"

@(test)
test_accept_key_rfc_vector :: proc(t: ^testing.T) {
    // RFC 6455 Section 1.3 test vector
    test_key := "dGhlIHNhbXBsZSBub25jZQ=="
    expected_accept := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

    accept, ok := ws.compute_accept_key(test_key, context.temp_allocator)
    testing.expect(t, ok, "compute_accept_key returned false")
    testing.expect_value(t, accept, expected_accept)
}

@(test)
test_accept_key_invalid :: proc(t: ^testing.T) {
    // Key that is not 16 bytes decoded
    _, ok1 := ws.compute_accept_key("short", context.temp_allocator)
    testing.expect(t, !ok1, "Short key should fail")

    // Empty key
    _, ok2 := ws.compute_accept_key("", context.temp_allocator)
    testing.expect(t, !ok2, "Empty key should fail")

    // Non-base64 characters
    _, ok3 := ws.compute_accept_key("dGhlIHNhbXBsZSBub25j!!!", context.temp_allocator)
    testing.expect(t, !ok3, "Invalid base64 key should fail")
}

@(test)
test_handshake_parsing_valid :: proc(t: ^testing.T) {
    raw_req :=
        "GET /chat?room=general&user=alice HTTP/1.1\r\n" +
        "Host: localhost:8080\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: keep-alive, Upgrade\r\n" +
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
        "Sec-WebSocket-Version: 13\r\n" +
        "Sec-WebSocket-Protocol: chat, superchat\r\n" +
        "Cookie: session=xyz123; theme=dark\r\n" +
        "Origin: http://localhost:8080\r\n\r\n"

    req: ws.Request
    ok, code, text := ws.parse_handshake_request(raw_req, &req, context.allocator)
    defer ws.destroy_request(&req)

    testing.expect(t, ok, "Handshake should succeed")
    testing.expect_value(t, code, 101)
    testing.expect_value(t, req.method, "GET")
    testing.expect_value(t, req.path, "/chat")
    testing.expect_value(t, req.raw_query, "room=general&user=alice")

    // Test query params
    room_param, has_room := ws.request_query_param(&req, "room")
    testing.expect(t, has_room, "room param should exist")
    testing.expect_value(t, room_param, "general")

    user_param, has_user := ws.request_query_param(&req, "user")
    testing.expect(t, has_user, "user param should exist")
    testing.expect_value(t, user_param, "alice")

    // Test subprotocols
    testing.expect(t, ws.request_has_subprotocol(&req, "chat"), "chat subprotocol should exist")
    testing.expect(
        t,
        ws.request_has_subprotocol(&req, "superchat"),
        "superchat subprotocol should exist",
    )
    testing.expect(
        t,
        !ws.request_has_subprotocol(&req, "binary"),
        "binary subprotocol should not exist",
    )

    // Test cookies
    session_cookie, has_session := ws.request_cookie(&req, "session")
    testing.expect(t, has_session, "session cookie should exist")
    testing.expect_value(t, session_cookie, "xyz123")

    // Test headers (case-insensitive)
    upgrade_hdr, has_upgrade := ws.request_header(&req, "Upgrade")
    testing.expect(t, has_upgrade, "Upgrade header should exist")
    testing.expect_value(t, upgrade_hdr, "websocket")
}

@(test)
test_handshake_parsing_invalid :: proc(t: ^testing.T) {
    // Non-GET method
    {
        raw := "POST /chat HTTP/1.1\r\nHost: localhost\r\n\r\n"
        req: ws.Request
        ok, code, _ := ws.parse_handshake_request(raw, &req, context.allocator)
        defer ws.destroy_request(&req)
        testing.expect(t, !ok, "POST should fail")
        testing.expect_value(t, code, 405)
    }

    // Missing Host header
    {
        raw := "GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        req: ws.Request
        ok, code, _ := ws.parse_handshake_request(raw, &req, context.allocator)
        defer ws.destroy_request(&req)
        testing.expect(t, !ok, "Missing Host should fail")
        testing.expect_value(t, code, 400)
    }

    // Invalid Version (e.g. 8)
    {
        raw := "GET /chat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n"
        req: ws.Request
        ok, code, _ := ws.parse_handshake_request(raw, &req, context.allocator)
        defer ws.destroy_request(&req)
        testing.expect(t, !ok, "Version 8 should fail")
        testing.expect_value(t, code, 426)
    }
}

@(test)
test_frame_encoding_and_header_parsing :: proc(t: ^testing.T) {
    // Test small frame (<= 125 bytes)
    {
        payload := transmute([]byte)string("Hello, WebSocket!")
        encoded := ws.encode_frame(true, .Text, payload, context.temp_allocator)

        hdr, res := ws.parse_frame_header(encoded)
        testing.expect_value(t, res, ws.Frame_Parse_Result.Ok)
        testing.expect(t, hdr.fin, "FIN should be true")
        testing.expect_value(t, hdr.opcode, ws.Opcode.Text)
        testing.expect_value(t, hdr.payload_len, u64(len(payload)))
        testing.expect(t, !hdr.masked, "Server frame should not be masked")
        testing.expect_value(t, hdr.header_size, 2)
    }

    // Test medium frame (126 to 65535 bytes)
    {
        med_payload := make([]byte, 500, context.temp_allocator)
        encoded := ws.encode_frame(true, .Binary, med_payload, context.temp_allocator)

        hdr, res := ws.parse_frame_header(encoded)
        testing.expect_value(t, res, ws.Frame_Parse_Result.Ok)
        testing.expect(t, hdr.fin, "FIN should be true")
        testing.expect_value(t, hdr.opcode, ws.Opcode.Binary)
        testing.expect_value(t, hdr.payload_len, 500)
        testing.expect_value(t, hdr.header_size, 4)
    }

    // Test large frame (> 65535 bytes)
    {
        large_len := 70000
        large_payload := make([]byte, large_len, context.temp_allocator)
        encoded := ws.encode_frame(false, .Binary, large_payload, context.temp_allocator)

        hdr, res := ws.parse_frame_header(encoded)
        testing.expect_value(t, res, ws.Frame_Parse_Result.Ok)
        testing.expect(t, !hdr.fin, "FIN should be false")
        testing.expect_value(t, hdr.opcode, ws.Opcode.Binary)
        testing.expect_value(t, hdr.payload_len, u64(large_len))
        testing.expect_value(t, hdr.header_size, 10)
    }
}

@(test)
test_frame_masking :: proc(t: ^testing.T) {
    original_text := "The quick brown fox jumps over the lazy dog"
    payload := transmute([]byte)strings.clone(original_text, context.temp_allocator)
    mask_key := [4]byte{0x37, 0xfa, 0x21, 0x3d}

    // Mask payload
    ws.unmask_payload(payload, mask_key)
    // Payload should now differ from original
    testing.expect(t, string(payload) != original_text, "Payload should be masked")

    // Unmask payload with same key
    ws.unmask_payload(payload, mask_key)
    testing.expect_value(t, string(payload), original_text)
}

@(test)
test_close_payload_parsing :: proc(t: ^testing.T) {
    // Empty payload: valid .No_Status_Received
    {
        code, reason, err := ws.parse_close_payload(nil)
        testing.expect_value(t, err, ws.Error.None)
        testing.expect_value(t, code, ws.Close_Code.No_Status_Received)
        testing.expect_value(t, reason, "")
    }

    // 1-byte payload: RFC 6455 5.5.1 protocol error
    {
        one_byte := []byte{0x03}
        _, _, err := ws.parse_close_payload(one_byte)
        testing.expect_value(t, err, ws.Error.Protocol_Error)
    }

    // Valid code + reason
    {
        encoded := ws.encode_close_payload(.Normal_Closure, "Goodbye", context.temp_allocator)
        code, reason, err := ws.parse_close_payload(encoded)
        testing.expect_value(t, err, ws.Error.None)
        testing.expect_value(t, code, ws.Close_Code.Normal_Closure)
        testing.expect_value(t, reason, "Goodbye")
    }

    // Invalid status code (e.g. 1005 cannot be in Close frame)
    {
        encoded := ws.encode_close_payload(.No_Status_Received, "", context.temp_allocator)
        _, _, err := ws.parse_close_payload(encoded)
        testing.expect_value(t, err, ws.Error.Protocol_Error)
    }
}

@(test)
test_utf8_validation :: proc(t: ^testing.T) {
    // Valid cases
    testing.expect(
        t,
        ws.is_valid_utf8(transmute([]byte)string("Hello, World!")),
        "ASCII should be valid",
    )
    testing.expect(
        t,
        ws.is_valid_utf8(transmute([]byte)string("你好世界 🚀")),
        "Multibyte and emojis should be valid",
    )

    // Invalid cases
    testing.expect(t, !ws.is_valid_utf8([]byte{0x80}), "0x80 alone is invalid")
    testing.expect(t, !ws.is_valid_utf8([]byte{0xc0, 0xaf}), "Overlong ASCII is invalid")
    testing.expect(t, !ws.is_valid_utf8([]byte{0xed, 0xa0, 0x80}), "Surrogate half is invalid")
}
