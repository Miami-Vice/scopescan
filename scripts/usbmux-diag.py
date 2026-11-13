#!/usr/bin/env python3
"""Probe the Apple usbmuxd service for attached iOS devices.

Speaks the usbmux plist protocol directly over 127.0.0.1:27015. This is what
AltServer, Xcode and libimobiledevice all use to enumerate devices, so it isolates
"the device stack is broken" from "the sideloading tool is broken" -- a distinction
that is otherwise invisible, because Windows will happily show the iPhone as a WPD
device while AMDS has not claimed it at all.

Prerequisite: Apple Mobile Device Support installed and
`Apple Mobile Device Service` running (net start "Apple Mobile Device Service").

    python scripts/usbmux-diag.py

Expected healthy output:

    device count: 1
     DeviceID: 1
     Serial:   00008140-000A19213CFA801C
     ConnType: USB
"""

import plistlib
import socket
import struct
import sys

USBMUX_HOST = "127.0.0.1"
USBMUX_PORT = 27015

# usbmuxd message types, from libusbmuxd's usbmuxd-proto.h
MESSAGE_PLIST = 8
PROTOCOL_VERSION = 1


def request(message: dict) -> dict:
    """Send one length-prefixed plist request and read the reply."""
    body = plistlib.dumps(message, fmt=plistlib.FMT_XML)
    # length includes the 16-byte header itself
    header = struct.pack("<IIII", len(body) + 16, PROTOCOL_VERSION, MESSAGE_PLIST, 1)

    with socket.create_connection((USBMUX_HOST, USBMUX_PORT), timeout=5) as sock:
        sock.sendall(header + body)
        payload = _read_exactly(sock, 16)
        if payload is None:
            raise RuntimeError("usbmux closed the connection before sending a header")
        total = struct.unpack("<I", payload[:4])[0]
        body_bytes = _read_exactly(sock, total - 16)
        if body_bytes is None:
            raise RuntimeError("usbmux truncated the reply body")
        return plistlib.loads(body_bytes)


def _read_exactly(sock: socket.socket, count: int):
    buffer = b""
    while len(buffer) < count:
        chunk = sock.recv(count - len(buffer))
        if not chunk:
            return None
        buffer += chunk
    return buffer


def main() -> int:
    try:
        reply = request(
            {
                "MessageType": "ListDevices",
                "ClientVersionString": "scopescan-diag",
                "ProgName": "scopescan",
                "kLibUSBMuxVersion": 3,
            }
        )
    except OSError as error:
        print(f"cannot reach usbmux on {USBMUX_HOST}:{USBMUX_PORT}: {error}")
        print('Is "Apple Mobile Device Service" running?  net start "Apple Mobile Device Service"')
        return 2

    devices = reply.get("DeviceList", [])
    print(f"device count: {len(devices)}")
    for device in devices:
        properties = device.get("Properties", {})
        print(f" DeviceID: {device.get('DeviceID')}")
        print(f" Serial:   {properties.get('SerialNumber')}")
        print(f" ConnType: {properties.get('ConnectionType')}")
        print(f" Location: {properties.get('LocationID')} ProductID: {properties.get('ProductID')}")

    return 0 if devices else 1


if __name__ == "__main__":
    sys.exit(main())
