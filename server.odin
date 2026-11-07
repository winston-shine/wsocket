package ows

import "core:mem"
import "core:net"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

// WebSocket Server
Server :: struct {
    config:            Server_Config,
    listener:          net.TCP_Socket,
    bound_endpoint:    net.Endpoint,
    running:           bool,
    next_conn_id:      u64,
    connections:       map[u64]^Connection,
    connections_mutex: sync.RW_Mutex,
    wait_group:        sync.Wait_Group,
    allocator:         mem.Allocator,
}

// Initializes a WebSocket Server instance with custom configuration
server_init_config :: proc(server: ^Server, config: Server_Config) -> Error {
    server.config = config
    server.allocator = config.allocator != {} ? config.allocator : context.allocator
    server.connections = make(map[u64]^Connection, 64, server.allocator)
    server.running = false
    server.next_conn_id = 1
    return .None
}

// Initializes a WebSocket Server instance with default configuration
server_init_default :: proc(server: ^Server) -> Error {
    return server_init_config(server, default_server_config())
}

// Overloaded server initialization
server_init :: proc {
    server_init_config,
    server_init_default,
}

// Resolves configured host string to net.Address
resolve_server_address :: proc(host: string) -> net.Address {
    if len(host) == 0 || host == "0.0.0.0" {
        return net.IP4_Any
    }
    if host == "127.0.0.1" || host == "localhost" {
        return net.IP4_Loopback
    }
    if ip4, ok := net.parse_ip4_address(host); ok {
        return ip4
    }
    if ip6, ok := net.parse_ip6_address(host); ok {
        return ip6
    }
    return net.IP4_Any
}

// Accept loop shared by server_start and background mode.
@(private)
_server_accept_loop :: proc(server: ^Server) {
    for server.running {
        client_sock, client_ep, aerr := net.accept_tcp(server.listener)
        if aerr != nil {
            if !server.running {
                break
            }
            continue
        }

        if server.config.tcp_nodelay {
            net.set_option(client_sock, .TCP_Nodelay, true)
        }

        conn := new(Connection, server.allocator)
        conn.id = sync.atomic_add(&server.next_conn_id, 1)
        conn.socket = client_sock
        conn.endpoint = client_ep
        conn.server = server
        conn.state = .Connecting
        conn.headers = make(map[string]string, 16, server.allocator)
        conn.read_buf = make([dynamic]byte, server.allocator)
        conn.fragment_buffer = make([dynamic]byte, server.allocator)
        conn.allocator = server.allocator

        // Register connection
        server_add_connection(server, conn)

        // Increment wait group
        sync.wait_group_add(&server.wait_group, 1)

        // Launch reader worker thread
        thread.create_and_start_with_data(
            conn,
            connection_worker,
            priority = .Normal,
            self_cleanup = true,
        )
    }
}

// Starts the WebSocket server and enters the accept loop (blocking).
// Call server_shutdown from another thread or signal handler to stop.
server_start :: proc(server: ^Server) -> Error {
    addr := resolve_server_address(server.config.host)
    ep := net.Endpoint {
        address = addr,
        port    = server.config.port,
    }

    listener, lerr := net.listen_tcp(ep, server.config.backlog)
    if lerr != nil {
        return .Socket_Error
    }
    server.listener = listener
    server.bound_endpoint, _ = net.bound_endpoint(listener)
    server.running = true

    _server_accept_loop(server)
    return .None
}

// Background listener runner
@(private)
_server_background_proc :: proc(data: rawptr) {
    server := cast(^Server)data
    _server_accept_loop(server)
}

// Starts the server in a separate background thread and returns immediately.
server_start_background :: proc(server: ^Server) -> (t: ^thread.Thread, err: Error) {
    addr := resolve_server_address(server.config.host)
    ep := net.Endpoint {
        address = addr,
        port    = server.config.port,
    }

    listener, lerr := net.listen_tcp(ep, server.config.backlog)
    if lerr != nil {
        return nil, .Socket_Error
    }
    server.listener = listener
    server.bound_endpoint, _ = net.bound_endpoint(listener)
    server.running = true

    t = thread.create_and_start_with_data(
        server,
        _server_background_proc,
        priority = .Normal,
        self_cleanup = true,
    )
    return t, .None
}

// Gracefully shuts down the server, closes listener, sends close frames to all clients,
// and waits for connection threads to complete.
server_shutdown :: proc(server: ^Server) {
    if !server.running {
        return
    }
    server.running = false

    // Close listener socket to unblock accept_tcp
    net.shutdown(server.listener, .Both)
    net.close(server.listener)

    // Snapshot active connections
    sync.rw_mutex_shared_lock(&server.connections_mutex)
    active_conns := make([dynamic]^Connection, context.temp_allocator)
    for _, conn in server.connections {
        append(&active_conns, conn)
    }
    sync.rw_mutex_shared_unlock(&server.connections_mutex)

    // Send Going_Away close frames to all active clients
    for conn in active_conns {
        close(conn, .Going_Away, "Server shutting down")
    }

    // Force-close sockets to unblock any worker threads stuck in recv
    for conn in active_conns {
        net.shutdown(conn.socket, .Both)
        net.close(conn.socket)
    }

    // Wait for all connection workers to exit cleanly (up to 5 seconds timeout)
    sync.wait_group_wait_with_timeout(&server.wait_group, 5 * time.Second)
}

// Deallocates server resources
server_destroy :: proc(server: ^Server) {
    if server.running {
        server_shutdown(server)
    }

    sync.rw_mutex_lock(&server.connections_mutex)
    delete(server.connections)
    sync.rw_mutex_unlock(&server.connections_mutex)
}

// Broadcasts a text message to all currently connected clients in the Open state.
server_broadcast_text :: proc(server: ^Server, text: string) {
    sync.rw_mutex_shared_lock(&server.connections_mutex)
    defer sync.rw_mutex_shared_unlock(&server.connections_mutex)

    for _, conn in server.connections {
        if conn.state == .Open {
            send_text(conn, text)
        }
    }
}

// Broadcasts a binary message to all currently connected clients in the Open state.
server_broadcast_binary :: proc(server: ^Server, data: []byte) {
    sync.rw_mutex_shared_lock(&server.connections_mutex)
    defer sync.rw_mutex_shared_unlock(&server.connections_mutex)

    for _, conn in server.connections {
        if conn.state == .Open {
            send_binary(conn, data)
        }
    }
}

// Looks up a connection by its unique ID
server_get_connection :: proc(server: ^Server, id: u64) -> (^Connection, bool) {
    sync.rw_mutex_shared_lock(&server.connections_mutex)
    defer sync.rw_mutex_shared_unlock(&server.connections_mutex)

    conn, ok := server.connections[id]
    return conn, ok
}

// Returns the count of currently connected clients
server_active_connections_count :: proc(server: ^Server) -> int {
    sync.rw_mutex_shared_lock(&server.connections_mutex)
    defer sync.rw_mutex_shared_unlock(&server.connections_mutex)

    return len(server.connections)
}

// Internal: registers a connection in the server's map
server_add_connection :: proc(server: ^Server, conn: ^Connection) {
    sync.rw_mutex_lock(&server.connections_mutex)
    defer sync.rw_mutex_unlock(&server.connections_mutex)

    server.connections[conn.id] = conn
}

// Internal: unregisters a connection from the server's map
server_remove_connection :: proc(server: ^Server, id: u64) {
    sync.rw_mutex_lock(&server.connections_mutex)
    defer sync.rw_mutex_unlock(&server.connections_mutex)

    delete_key(&server.connections, id)
}
