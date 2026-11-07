#!/usr/bin/env python3
"""
End-to-end integration test suite for the `ows` Odin WebSocket server library.
Tests RFC 6455 compliance, text, binary, ping/pong, large frames, broadcast,
subprotocols, error rejection, and close codes.
"""

import asyncio
import os
import signal
import socket
import struct
import subprocess
import sys
import time
import websockets

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 18080
WS_URI = f"ws://{SERVER_HOST}:{SERVER_PORT}"


def wait_for_port(port, timeout=5.0):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((SERVER_HOST, port), timeout=0.2):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.05)
    return False


async def test_text_echo():
    print("Testing text echo...")
    async with websockets.connect(f"{WS_URI}/echo") as ws:
        # Receive greeting
        welcome = await ws.recv()
        assert "Welcome" in welcome, f"Unexpected greeting: {welcome}"

        # Send test message
        msg = "Hello, Odin WebSockets!"
        await ws.send(msg)
        response = await ws.recv()
        assert response == f"Echo: {msg}", f"Unexpected response: {response}"
    print("  [PASS] text echo")


async def test_binary_echo():
    print("Testing binary echo...")
    async with websockets.connect(f"{WS_URI}/") as ws:
        # Receive greeting
        _ = await ws.recv()

        # Send binary bytes
        data = bytes(range(256))
        await ws.send(data)
        response = await ws.recv()
        assert response == data, f"Binary mismatch! len={len(response)}"
    print("  [PASS] binary echo")


async def test_large_messages():
    print("Testing medium and large message payloads (>64KB, 1MB)...")
    async with websockets.connect(f"{WS_URI}/") as ws:
        _ = await ws.recv()

        # 128 KB
        data_128k = os.urandom(128 * 1024)
        await ws.send(data_128k)
        res_128k = await ws.recv()
        assert res_128k == data_128k, "128KB payload mismatch"

        # 1 MB
        data_1m = os.urandom(1024 * 1024)
        await ws.send(data_1m)
        res_1m = await ws.recv()
        assert res_1m == data_1m, "1MB payload mismatch"
    print("  [PASS] large messages")


async def test_ping_pong():
    print("Testing ping / pong...")
    async with websockets.connect(f"{WS_URI}/") as ws:
        _ = await ws.recv()

        pong_waiter = await ws.ping(b"heartbeat-123")
        await asyncio.wait_for(pong_waiter, timeout=2.0)
    print("  [PASS] ping / pong")


async def test_subprotocol_negotiation():
    print("Testing subprotocol negotiation...")
    async with websockets.connect(f"{WS_URI}/chat", subprotocols=["chat", "other"]) as ws:
        assert ws.subprotocol == "chat", f"Expected 'chat', got {ws.subprotocol}"
        _ = await ws.recv()
    print("  [PASS] subprotocol negotiation")


async def test_broadcast():
    print("Testing broadcast...")
    async with websockets.connect(f"{WS_URI}/chat") as ws1, \
               websockets.connect(f"{WS_URI}/chat") as ws2:
        # Read greetings
        _ = await ws1.recv()
        _ = await ws2.recv()

        # Client 1 broadcasts
        await ws1.send("/broadcast Hello everyone!")

        # Both clients should receive broadcast
        msg1 = await ws1.recv()
        msg2 = await ws2.recv()

        assert "Hello everyone!" in msg1, f"ws1 didn't receive broadcast: {msg1}"
        assert "Hello everyone!" in msg2, f"ws2 didn't receive broadcast: {msg2}"
    print("  [PASS] broadcast")


async def test_path_routing_404():
    print("Testing invalid path rejection (404)...")
    try:
        async with websockets.connect(f"{WS_URI}/nonexistent"):
            assert False, "Should have failed with 404"
    except Exception as e:
        assert "404" in str(e), f"Expected 404 in exception, got: {e}"
    print("  [PASS] invalid path 404")


async def test_clean_close():
    print("Testing client clean close with custom code and reason...")
    async with websockets.connect(f"{WS_URI}/") as ws:
        _ = await ws.recv()
        await ws.close(code=1000, reason="Normal test shutdown")
        assert ws.close_code == 1000
    print("  [PASS] clean close")


async def test_unmasked_client_frame_rejection():
    print("Testing rejection of unmasked client frame (RFC 6455 1002 Protocol Error)...")
    s = socket.create_connection((SERVER_HOST, SERVER_PORT))
    try:
        # Perform HTTP Handshake manually
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {SERVER_HOST}:{SERVER_PORT}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        s.sendall(req.encode("utf-8"))

        # Read HTTP response
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        assert b"101 Switching Protocols" in resp, "Handshake failed"

        # Drain the greeting message sent by server
        # Send an UNMASKED text frame:
        # Byte 0: 0x81 (FIN=1, Opcode=1 text)
        # Byte 1: 0x05 (MASK=0, Payload len=5)
        # Payload: "Hello"
        unmasked_frame = bytes([0x81, 0x05]) + b"Hello"
        s.sendall(unmasked_frame)

        # Server MUST send a Close frame with status code 1002 and close connection
        # Read all bytes returned by server until socket is closed by server
        reply = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            reply += chunk

        print(f"DEBUG: unmasked test received total bytes: {len(reply)}")
        # Check if reply contains close frame (opcode 0x8)
        idx = 0
        found_close = False
        while idx < len(reply):
            b0 = reply[idx]
            opcode = b0 & 0x0F
            b1 = reply[idx + 1]
            payload_len = b1 & 0x7F
            idx += 2
            if payload_len == 126:
                payload_len = struct.unpack(">H", reply[idx:idx + 2])[0]
                idx += 2
            elif payload_len == 127:
                payload_len = struct.unpack(">Q", reply[idx:idx + 8])[0]
                idx += 8

            frame_payload = reply[idx:idx + payload_len]
            idx += payload_len

            if opcode == 0x8:  # Close frame
                found_close = True
                if len(frame_payload) >= 2:
                    code = struct.unpack(">H", frame_payload[:2])[0]
                    assert code == 1002, f"Expected close code 1002, got {code}"
                break

        assert found_close, "Did not find expected close frame for unmasked payload"
    finally:
        s.close()
    print("  [PASS] unmasked client frame rejection (1002)")


async def test_invalid_utf8_rejection():
    print("Testing rejection of invalid UTF-8 in text frame (RFC 6455 1007)...")
    s = socket.create_connection((SERVER_HOST, SERVER_PORT))
    try:
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {SERVER_HOST}:{SERVER_PORT}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        s.sendall(req.encode("utf-8"))

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        assert b"101 Switching Protocols" in resp

        # Send a MASKED text frame containing invalid UTF-8 (e.g. 0xC0 0xAF overlong)
        mask_key = b"\x12\x34\x56\x78"
        raw_payload = b"\xc0\xaf"
        masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(raw_payload))

        frame = bytes([0x81, 0x80 | len(raw_payload)]) + mask_key + masked_payload
        s.sendall(frame)

        reply = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            reply += chunk

        # Look for close frame with 1007
        idx = 0
        found_close = False
        while idx < len(reply):
            b0 = reply[idx]
            opcode = b0 & 0x0F
            b1 = reply[idx + 1]
            payload_len = b1 & 0x7F
            idx += 2
            if payload_len == 126:
                payload_len = struct.unpack(">H", reply[idx:idx + 2])[0]
                idx += 2
            elif payload_len == 127:
                payload_len = struct.unpack(">Q", reply[idx:idx + 8])[0]
                idx += 8

            frame_payload = reply[idx:idx + payload_len]
            idx += payload_len

            if opcode == 0x8:  # Close frame
                found_close = True
                if len(frame_payload) >= 2:
                    code = struct.unpack(">H", frame_payload[:2])[0]
                    assert code == 1007, f"Expected close code 1007, got {code}"
                break

        assert found_close, "Did not find expected close frame for invalid UTF-8"
    finally:
        s.close()
    print("  [PASS] invalid UTF-8 rejection (1007)")


async def test_fragmented_frames_with_interleaved_ping():
    print("Testing fragmented message reassembly with interleaved Ping frame...")
    s = socket.create_connection((SERVER_HOST, SERVER_PORT))
    try:
        req = (
            f"GET /echo HTTP/1.1\r\n"
            f"Host: {SERVER_HOST}:{SERVER_PORT}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        s.sendall(req.encode("utf-8"))

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        assert b"101 Switching Protocols" in resp

        def send_masked_frame(fin, opcode, payload):
            mask_key = os.urandom(4)
            masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
            b0 = (0x80 if fin else 0x00) | (opcode & 0x0F)
            b1 = 0x80 | len(payload)
            s.sendall(bytes([b0, b1]) + mask_key + masked)

        # Send Frame 1: Opcode=1 (Text), FIN=0, Payload="Fragmented "
        send_masked_frame(False, 0x1, b"Fragmented ")

        # Interleave Ping: Opcode=9 (Ping), FIN=1, Payload="ping-in-frag"
        send_masked_frame(True, 0x9, b"ping-in-frag")

        # Send Frame 2: Opcode=0 (Continuation), FIN=1, Payload="Message!"
        send_masked_frame(True, 0x0, b"Message!")

        # Read replies
        # We expect:
        # 1. Greeting text frame from server
        # 2. Pong frame with "ping-in-frag"
        # 3. Echo text frame with "Echo: Fragmented Message!"
        received = b""
        s.settimeout(2.0)
        while True:
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                received += chunk
                if b"Echo: Fragmented Message!" in received and b"ping-in-frag" in received:
                    break
            except socket.timeout:
                break

        assert b"ping-in-frag" in received, "Pong not received for interleaved ping"
        assert b"Echo: Fragmented Message!" in received, "Echo not received for fragmented message"
    finally:
        s.close()
    print("  [PASS] fragmented frames with interleaved ping")


async def main():
    print(f"Starting server process on port {SERVER_PORT}...")
    server_bin = os.path.abspath("bin/ows-example")
    proc = subprocess.Popen([server_bin, str(SERVER_PORT)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        if not wait_for_port(SERVER_PORT):
            print("Failed to start server within timeout!")
            stdout, stderr = proc.communicate(timeout=1)
            print("Server stdout:", stdout.decode())
            print("Server stderr:", stderr.decode())
            sys.exit(1)

        print("Server is listening. Running integration test suite...")

        await test_text_echo()
        await test_binary_echo()
        await test_large_messages()
        await test_ping_pong()
        await test_subprotocol_negotiation()
        await test_broadcast()
        await test_fragmented_frames_with_interleaved_ping()
        await test_path_routing_404()
        await test_clean_close()
        await test_unmasked_client_frame_rejection()
        await test_invalid_utf8_rejection()

        print("\nALL INTEGRATION TESTS PASSED SUCCESSFULLY!")
    finally:
        print("Stopping server process...")
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    asyncio.run(main())
