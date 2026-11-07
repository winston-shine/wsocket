package wsocket

/*
Package wsocket implements a full-featured, RFC 6455 compliant WebSocket server library in Odin.

Features:
- Complete RFC 6455 opening handshake with Sec-WebSocket-Key / Sec-WebSocket-Accept validation
- Full frame decoding and encoding (text, binary, ping, pong, close, continuation)
- Transparent unmasking and validation (client frame masking enforcement)
- Message fragmentation reassembly with interleaved control frame support
- Full UTF-8 validation for text messages and close reason payloads per RFC 3629
- Subprotocol negotiation (Sec-WebSocket-Protocol)
- Custom handshake authentication, cookies, and query parameter extraction
- Thread-safe sending and broadcasting across all connected clients
- Non-blocking server background startup option and graceful shutdown
*/
