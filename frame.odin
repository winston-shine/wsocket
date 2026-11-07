package wsocket

import "core:encoding/endian"

// Frame parsing outcome
Frame_Parse_Result :: enum {
    Ok,
    Incomplete,
    Protocol_Error,
}

// Internal representation of a parsed WebSocket frame header
Frame_Header :: struct {
    fin:         bool,
    rsv1:        bool,
    rsv2:        bool,
    rsv3:        bool,
    opcode:      Opcode,
    masked:      bool,
    mask_key:    [4]byte,
    payload_len: u64,
    header_size: int,
}

// Parses WebSocket frame header from the beginning of data slice.
// If not enough bytes are present to complete header, returns .Incomplete.
// If any RFC 6455 framing violation is found, returns .Protocol_Error.
parse_frame_header :: proc(data: []byte) -> (hdr: Frame_Header, res: Frame_Parse_Result) {
    if len(data) < 2 {
        return {}, .Incomplete
    }

    b0 := data[0]
    b1 := data[1]

    hdr.fin = (b0 & 0x80) != 0
    hdr.rsv1 = (b0 & 0x40) != 0
    hdr.rsv2 = (b0 & 0x20) != 0
    hdr.rsv3 = (b0 & 0x10) != 0

    // Reserved bits MUST be 0 unless negotiated via extension
    if hdr.rsv1 || hdr.rsv2 || hdr.rsv3 {
        return {}, .Protocol_Error
    }

    raw_opcode := b0 & 0x0F
    if !opcode_is_valid(raw_opcode) {
        return {}, .Protocol_Error
    }
    hdr.opcode = Opcode(raw_opcode)

    // Control frame rules (RFC 6455 5.5)
    if opcode_is_control(hdr.opcode) {
        // Control frames MUST NOT be fragmented
        if !hdr.fin {
            return {}, .Protocol_Error
        }
    }

    hdr.masked = (b1 & 0x80) != 0
    payload_len_indicator := b1 & 0x7F

    // Control frame payload MUST be <= 125 bytes
    if opcode_is_control(hdr.opcode) && payload_len_indicator > 125 {
        return {}, .Protocol_Error
    }

    hdr.header_size = 2

    if payload_len_indicator <= 125 {
        hdr.payload_len = u64(payload_len_indicator)
    } else if payload_len_indicator == 126 {
        if len(data) < 4 {
            return {}, .Incomplete
        }
        hdr.payload_len = u64(endian.unchecked_get_u16be(data[2:4]))
        // RFC 6455 5.2: 126 indicator requires length >= 126
        if hdr.payload_len < 126 {
            return {}, .Protocol_Error
        }
        hdr.header_size = 4
    } else {     // 127
        if len(data) < 10 {
            return {}, .Incomplete
        }
        hdr.payload_len = endian.unchecked_get_u64be(data[2:10])
        // RFC 6455 5.2: 127 indicator requires length >= 65536
        if hdr.payload_len < 65536 {
            return {}, .Protocol_Error
        }
        hdr.header_size = 10

        // RFC 6455 5.2: Most significant bit of 64-bit length MUST be 0
        if (hdr.payload_len & (1 << 63)) != 0 {
            return {}, .Protocol_Error
        }
    }

    if hdr.masked {
        if len(data) < hdr.header_size + 4 {
            return {}, .Incomplete
        }
        copy(hdr.mask_key[:], data[hdr.header_size:hdr.header_size + 4])
        hdr.header_size += 4
    }

    return hdr, .Ok
}

// In-place unmasking of payload data with the 4-byte masking key
unmask_payload :: proc(payload: []byte, mask_key: [4]byte) {
    for i in 0 ..< len(payload) {
        payload[i] ~= mask_key[i % 4]
    }
}

// Encodes a complete server-to-client WebSocket frame (unmasked)
encode_frame :: proc(
    fin: bool,
    opcode: Opcode,
    payload: []byte,
    allocator := context.allocator,
) -> []byte {
    payload_len := len(payload)
    header_size := 2
    if payload_len <= 125 {
        header_size = 2
    } else if payload_len <= 65535 {
        header_size = 4
    } else {
        header_size = 10
    }

    frame := make([]byte, header_size + payload_len, allocator)

    // Byte 0: FIN + RSV + Opcode
    b0: u8 = u8(opcode) & 0x0F
    if fin {
        b0 |= 0x80
    }
    frame[0] = b0

    // Byte 1..N: Payload length (Mask bit is 0 for server frames)
    if payload_len <= 125 {
        frame[1] = u8(payload_len)
    } else if payload_len <= 65535 {
        frame[1] = 126
        endian.unchecked_put_u16be(frame[2:4], u16(payload_len))
    } else {
        frame[1] = 127
        endian.unchecked_put_u64be(frame[2:10], u64(payload_len))
    }

    // Append payload
    if payload_len > 0 {
        copy(frame[header_size:], payload)
    }

    return frame
}

// Encodes close payload with 2-byte big-endian status code followed by UTF-8 reason string
encode_close_payload :: proc(
    code: Close_Code,
    reason: string,
    allocator := context.allocator,
) -> []byte {
    total_len := 2 + len(reason)
    buf := make([]byte, total_len, allocator)
    endian.unchecked_put_u16be(buf[0:2], u16(code))
    if len(reason) > 0 {
        copy(buf[2:], transmute([]byte)reason)
    }
    return buf
}

// Parses close frame payload into close code and reason string.
// Validates status code ranges and UTF-8 validity per RFC 6455.
parse_close_payload :: proc(payload: []byte) -> (code: Close_Code, reason: string, err: Error) {
    if len(payload) == 0 {
        return .No_Status_Received, "", .None
    }

    // RFC 6455 5.5.1: Payload cannot be 1 byte
    if len(payload) == 1 {
        return .Protocol_Error, "", .Protocol_Error
    }

    raw_code := endian.unchecked_get_u16be(payload[0:2])
    if !is_valid_close_code(raw_code) {
        return .Protocol_Error, "", .Protocol_Error
    }

    reason_bytes := payload[2:]
    if len(reason_bytes) > 0 {
        if !is_valid_utf8(reason_bytes) {
            return .Invalid_Payload_Data, "", .Invalid_UTF8
        }
        return Close_Code(raw_code), string(reason_bytes), .None
    }

    return Close_Code(raw_code), "", .None
}
