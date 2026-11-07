package main

import ws ".."
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"

main :: proc() {
    port := 8080
    if len(os.args) > 1 {
        if p, ok := strconv.parse_int(os.args[1]); ok {
            port = p
        }
    }

    server: ws.Server
    defer ws.server_destroy(&server)

    config := ws.default_server_config()
    config.host = "127.0.0.1"
    config.port = port

    // Custom handshake validation & subprotocol negotiation hook
    config.on_handshake =
    proc(req: ^ws.Request, res: ^ws.Handshake_Response, user_data: rawptr) -> bool {
        // Support path routing
        if req.path != "/" && req.path != "/ws" && req.path != "/echo" && req.path != "/chat" {
            res.status_code = 404
            res.status_text = "Not Found"
            res.body = "WebSocket endpoint not found. Use /, /ws, /echo, or /chat\n"
            return false
        }

        // Subprotocol negotiation
        if ws.request_has_subprotocol(req, "chat") {
            res.selected_protocol = "chat"
        } else if ws.request_has_subprotocol(req, "echo") {
            res.selected_protocol = "echo"
        }

        return true
    }

    // Client connected callback
    config.on_connect = proc(conn: ^ws.Connection, user_data: rawptr) {
        fmt.printf(
            "[WS] Client #%d connected from %s (path: %s)\n",
            conn.id,
            ws.connection_endpoint_string(conn),
            conn.path,
        )

        // Send a greeting to the newly connected client
        welcome_msg := fmt.tprintf("Welcome client #%d! Connected to wsocket server.", conn.id)
        ws.send_text(conn, welcome_msg)
    }

    // Message received callback (Text & Binary)
    config.on_message = proc(conn: ^ws.Connection, msg: ws.Message, user_data: rawptr) {
        server := conn.server

        switch msg.type {
        case .Text:
            fmt.printf("[WS #%d Text]: %s\n", conn.id, msg.text)

            // Command: /broadcast <text>
            if strings.has_prefix(msg.text, "/broadcast ") {
                broadcast_content := strings.trim_space(msg.text[11:])
                broadcast_msg := fmt.tprintf(
                    "[Broadcast from #%d]: %s",
                    conn.id,
                    broadcast_content,
                )
                ws.server_broadcast_text(server, broadcast_msg)
                return
            }

            // Command: /stats
            if msg.text == "/stats" {
                count := ws.server_active_connections_count(server)
                stats_msg := fmt.tprintf("[Stats] Active connections: %d", count)
                ws.send_text(conn, stats_msg)
                return
            }

            // Command: /close
            if msg.text == "/close" {
                ws.close(conn, .Normal_Closure, "Closed by request")
                return
            }

            // Default: Echo text back
            echo_msg := fmt.tprintf("Echo: %s", msg.text)
            ws.send_text(conn, echo_msg)

        case .Binary:
            fmt.printf("[WS #%d Binary]: %d bytes received\n", conn.id, len(msg.data))
            // Echo binary data directly back
            ws.send_binary(conn, msg.data)
        }
    }

    // Client disconnected callback
    config.on_close =
    proc(conn: ^ws.Connection, code: ws.Close_Code, reason: string, user_data: rawptr) {
        fmt.printf(
            "[WS] Client #%d disconnected (code: %d, reason: '%s')\n",
            conn.id,
            u16(code),
            reason,
        )
    }

    // Ping received callback
    config.on_ping = proc(conn: ^ws.Connection, data: []byte, user_data: rawptr) {
        fmt.printf("[WS #%d Ping] payload: %d bytes\n", conn.id, len(data))
    }

    // Error callback
    config.on_error = proc(conn: ^ws.Connection, err: ws.Error, user_data: rawptr) {
        fmt.printf("[WS #%d Error]: %v\n", conn.id, err)
    }

    err := ws.server_init(&server, config)
    if err != .None {
        fmt.eprintln("Failed to initialize server:", err)
        return
    }

    fmt.printf("==========================================\n")
    fmt.printf("  wsocket WebSocket Server running on ws://%s:%d\n", config.host, config.port)
    fmt.printf("  Endpoints: /, /ws, /echo, /chat\n")
    fmt.printf("  Commands:  /broadcast <msg>, /stats, /close\n")
    fmt.printf("==========================================\n")

    // Run blocking accept loop
    ws.server_start(&server)
}
