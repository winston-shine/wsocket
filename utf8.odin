package ows

import "core:unicode/utf8"

// Validates whether the given byte slice represents a sequence of valid UTF-8 code points
// conforming to RFC 3629 / RFC 6455.
is_valid_utf8 :: proc(data: []byte) -> bool {
    if len(data) == 0 {
        return true
    }
    return utf8.valid_string(transmute(string)data)
}
