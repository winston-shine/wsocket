# ows - Odin WebSocket Server Library

`ows` is a fast, lightweight, and fully RFC 6455 compliant WebSocket server library written in the [Odin programming language](https://odin-lang.org/).

## Features

- **Full RFC 6455 Compliance**:
  - Standard HTTP/1.1 opening handshake with `Sec-WebSocket-Key` verification and `Sec-WebSocket-Accept` calculation (SHA-1 + Base64).
  - Strict framing rules: client-to-server frames must be masked; unmasked client frames are rejected with close code `1002 (Protocol Error)`.
  - Automatic control frame handling (`Ping` frames automatically answered with `Pong` containing identical payload).
  - Full close handshake protocol supporting standard close codes and reason strings.
  - Message fragmentation support: seamless reassembly of multi-frame messages with support for interleaved control frames.
  - Strict UTF-8 validation conforming to RFC 3629 for text frames and close reason payloads (rejects invalid UTF-8 with close code `1007 (Invalid Payload Data)`).
  - Payloads up to 64-bit length (tested with small, 126 medium, and 127 large payloads up to megabytes).
- **Subprotocol Negotiation & Path Routing**:
  - Negotiate requested subprotocols via `Sec-WebSocket-Protocol`.
  - Inspect path, query parameters, cookies, and HTTP headers in handshake hooks.
- **Concurrent & Thread-Safe**:
  - Accept loop spawns a dedicated worker thread per connection.
  - Thread-safe sending: `send_text`, `send_binary`, `send_ping`, `send_pong`, and `close` can be called concurrently from any thread.
  - Built-in broadcasting methods to push messages across all active clients.
- **Clean Lifecycle & Resource Management**:
  - Graceful shutdown with automatic `Going_Away (1001)` close notification and thread synchronization.
  - Zero memory leaks, verified with Odin's testing tracking allocator.

---

### Installation & Import

Clone this repository into your project or Odin collection path:

```bash
git clone https://github.com/username/ows.git
```

Since the library files reside at the root of the project, you can import it directly by directory:

```odin
import ws "path/to/ows" // or import ws "ows" if placed in an Odin collection
```

---

## Quick Start

### 1. Simple Echo Server

```odin
package main

import "core:fmt"
import ws "ows" // or relative path to ows root

main :: proc() {
    server: ws.Server
    defer ws.server_destroy(&server)

    config := ws.default_server_config()
    config.host = "127.0.0.1"
    config.port = 8080

    // Callback when client connects
    config.on_connect = proc(conn: ^ws.Connection, user_data: rawptr) {
        fmt.printf("Client #%d connected from %s\n", conn.id, ws.connection_endpoint_string(conn))
        ws.send_text(conn, "Welcome to the ows WebSocket Server!")
    }

    // Callback when message arrives
    config.on_message = proc(conn: ^ws.Connection, msg: ws.Message, user_data: rawptr) {
        #partial switch msg.type {
        case .Text:
            fmt.printf("Received text: %s\n", msg.text)
            ws.send_text(conn, fmt.tprintf("Echo: %s", msg.text))
        case .Binary:
            fmt.printf("Received %d bytes binary\n", len(msg.data))
            ws.send_binary(conn, msg.data)
        }
    }

    // Callback on disconnect
    config.on_close = proc(conn: ^ws.Connection, code: ws.Close_Code, reason: string, user_data: rawptr) {
        fmt.printf("Client #%d disconnected (code: %v, reason: %s)\n", conn.id, code, reason)
    }

    err := ws.server_init(&server, config)
    if err != .None {
        fmt.eprintln("Server initialization error:", err)
        return
    }

    fmt.println("Starting server on ws://127.0.0.1:8080 ...")
    ws.server_start(&server)
}
```

---

## Advanced Usage

### Custom Handshake & Authentication

You can intercept handshakes before upgrading to check credentials, paths, cookies, or subprotocols:

```odin
config.on_handshake = proc(req: ^ws.Request, res: ^ws.Handshake_Response, user_data: rawptr) -> bool {
    // Path routing
    if req.path != "/chat" {
        res.status_code = 404
        res.status_text = "Not Found"
        return false
    }

    // Query parameters (e.g. /chat?token=secret123)
    token, ok := ws.request_query_param(req, "token")
    if !ok || token != "secret123" {
        res.status_code = 401
        res.status_text = "Unauthorized"
        return false
    }

    // Subprotocol negotiation
    if ws.request_has_subprotocol(req, "v1.chat") {
        res.selected_protocol = "v1.chat"
    }

    return true
}
```

### Broadcasting to All Clients

```odin
// Broadcast text to all active clients in the Open state
ws.server_broadcast_text(&server, "Server notice: restart in 5 minutes.")

// Broadcast binary payload
ws.server_broadcast_binary(&server, payload_bytes)
```

### Running Server in the Background

```odin
// Start server on a background thread
thread_handle, err := ws.server_start_background(&server)

// Do other work or wait on shutdown signal...

// Graceful shutdown
ws.server_shutdown(&server)
```

---

## API Reference

### `Server_Config`

| Field | Type | Default | Description |
|---|---|---|---|
| `host` | `string` | `"0.0.0.0"` | Bind IP or hostname |
| `port` | `int` | `8080` | Bind port number |
| `backlog` | `int` | `128` | TCP listen queue backlog |
| `read_timeout` | `time.Duration` | `60s` | Socket read timeout (0 to disable) |
| `handshake_timeout`| `time.Duration` | `10s` | Max time for handshake completion |
| `max_message_size` | `int` | `16 MB` | Maximum allowed fragmented message size |
| `max_frame_size` | `int` | `16 MB` | Maximum allowed single frame size |
| `tcp_nodelay` | `bool` | `true` | Disables Nagle algorithm for low latency |
| `on_handshake` | `OnHandshake` | `nil` | Handshake validator and router hook |
| `on_connect` | `OnConnect` | `nil` | Invoked when client handshake completes |
| `on_message` | `OnMessage` | `nil` | Invoked on complete message delivery |
| `on_close` | `OnClose` | `nil` | Invoked on client disconnect or close |
| `on_ping` | `OnPing` | `nil` | Invoked on received ping |
| `on_pong` | `OnPong` | `nil` | Invoked on received pong |
| `on_error` | `OnError` | `nil` | Invoked on socket or protocol errors |
| `user_data` | `rawptr` | `nil` | User context passed to callbacks |

### Procedures

#### Server Lifecycle
- `server_init(server: ^Server, config: Server_Config = default_server_config()) -> Error`
- `server_start(server: ^Server) -> Error` (blocking accept loop)
- `server_start_background(server: ^Server) -> (thread: ^thread.Thread, err: Error)`
- `server_shutdown(server: ^Server)` (graceful close & thread synchronization)
- `server_destroy(server: ^Server)` (releases allocated server memory)

#### Connection Operations
- `send_text(conn: ^Connection, text: string) -> Error`
- `send_binary(conn: ^Connection, data: []byte) -> Error`
- `send_ping(conn: ^Connection, data: []byte = nil) -> Error`
- `send_pong(conn: ^Connection, data: []byte = nil) -> Error`
- `close(conn: ^Connection, code: Close_Code = .Normal_Closure, reason: string = "") -> Error`
- `connection_endpoint_string(conn: ^Connection) -> string`

#### Broadcast & Management
- `server_broadcast_text(server: ^Server, text: string)`
- `server_broadcast_binary(server: ^Server, data: []byte)`
- `server_active_connections_count(server: ^Server) -> int`
- `server_get_connection(server: ^Server, id: u64) -> (^Connection, bool)`

#### Request Helpers (Handshake & Inspection)
- `request_header(req: ^Request, name: string) -> (string, bool)`
- `request_has_subprotocol(req: ^Request, protocol: string) -> bool`
- `request_cookie(req: ^Request, name: string) -> (string, bool)`
- `request_query_param(req: ^Request, key: string) -> (string, bool)`

---

## Build and Test

Using `task` or `go-task`:

```bash
# Build the example executable (bin/ows-example)
task build

# Run example server
task run

# Run Odin unit tests
task test

# Run Python integration test suite (full RFC 6455 end-to-end tests)
task test:integration

# Format code
task fmt
```

Or directly using `odin`:

```bash
# Build example
odin build examples/ -out:bin/ows-example

# Run unit tests
odin test tests/
```

---

## License

MIT
