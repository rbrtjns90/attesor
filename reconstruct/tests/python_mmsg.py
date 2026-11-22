"""Exercise recvmmsg/sendmmsg semantics via ctypes on the guest libc.

Checks:
  - a zero-length datagram counts as a received message
  - MSG_WAITFORONE drains queued datagrams without blocking
  - nonblocking recvmmsg reports only the queued messages
  - sendmmsg sends a batch and reports the count
"""
import ctypes
import socket
import struct

libc = ctypes.CDLL("libc.so.6", use_errno=True)

MSG_WAITFORONE = 0x10000
MSG_DONTWAIT = 0x40


class Iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


class Msghdr(ctypes.Structure):
    _fields_ = [("msg_name", ctypes.c_void_p),
                ("msg_namelen", ctypes.c_uint32),
                ("msg_iov", ctypes.c_void_p),
                ("msg_iovlen", ctypes.c_size_t),
                ("msg_control", ctypes.c_void_p),
                ("msg_controllen", ctypes.c_size_t),
                ("msg_flags", ctypes.c_int32)]


class Mmsghdr(ctypes.Structure):
    _fields_ = [("msg_hdr", Msghdr), ("msg_len", ctypes.c_uint32),
                ("pad", ctypes.c_uint32)]


def make_vector(count, size=256):
    bufs = [ctypes.create_string_buffer(size) for _ in range(count)]
    iovecs = [Iovec(ctypes.cast(buf, ctypes.c_void_p), size) for buf in bufs]
    iov_arrays = [(Iovec * 1)(iov) for iov in iovecs]
    msgs = (Mmsghdr * count)()
    for i in range(count):
        msgs[i].msg_hdr.msg_iov = ctypes.addressof(iov_arrays[i])
        msgs[i].msg_hdr.msg_iovlen = 1
    return msgs, bufs, iov_arrays


def recvmmsg(fd, msgs, count, flags):
    libc.recvmmsg.restype = ctypes.c_int
    return libc.recvmmsg(fd, ctypes.byref(msgs), count, flags, None)


def sendmmsg(fd, msgs, count):
    libc.sendmmsg.restype = ctypes.c_int
    return libc.sendmmsg(fd, ctypes.byref(msgs), count, 0)


def udp_pair():
    recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv.bind(("127.0.0.1", 0))
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send.connect(recv.getsockname())
    return recv, send


# 1. Zero-length datagram must be counted, then EAGAIN ends the batch.
rx, tx = udp_pair()
rx.setblocking(False)
tx.send(b"")
tx.send(b"x")
msgs, bufs, _ = make_vector(4)
n = recvmmsg(rx.fileno(), msgs, 4, MSG_DONTWAIT)
assert n == 2, f"expected 2 messages (incl. empty), got {n}"
assert msgs[0].msg_len == 0, f"empty datagram len {msgs[0].msg_len}"
assert msgs[1].msg_len == 1, f"second datagram len {msgs[1].msg_len}"
assert bufs[1].raw[0] == ord("x"), "wrong payload"
rx.close(); tx.close()

# 2. MSG_WAITFORONE on a blocking socket: first blocks, rest drain
#    nonblocking — a single queued datagram returns exactly 1.
rx, tx = udp_pair()
tx.send(b"one")
msgs, bufs, _ = make_vector(4)
n = recvmmsg(rx.fileno(), msgs, 4, MSG_WAITFORONE)
assert n == 1, f"WAITFORONE should drain and return 1, got {n}"
assert msgs[0].msg_len == 3, f"len {msgs[0].msg_len}"
rx.close(); tx.close()

# 3. Blocking socket without WAITFORONE uses caller flags verbatim:
#    with a timeout the kernel may still wait per-message, so use a
#    nonblocking socket to pin the return count deterministically.
rx, tx = udp_pair()
rx.setblocking(False)
tx.send(b"a")
tx.send(b"b")
tx.send(b"c")
msgs, bufs, _ = make_vector(4)
n = recvmmsg(rx.fileno(), msgs, 4, 0)
assert n == 3, f"expected 3 queued datagrams, got {n}"
assert [msgs[i].msg_len for i in range(3)] == [1, 1, 1], "bad lengths"
rx.close(); tx.close()

# 4. sendmmsg sends a batch in one call.
rx, tx = udp_pair()
msgs, bufs, iov_arrays = make_vector(3)
for i, data in enumerate((b"p", b"q", b"r")):
    bufs[i].raw = data
    iov_arrays[i][0].iov_len = len(data)
n = sendmmsg(tx.fileno(), msgs, 3)
assert n == 3, f"sendmmsg returned {n}"
got = [rx.recv(8) for _ in range(3)]
assert got == [b"p", b"q", b"r"], f"payloads {got}"
rx.close(); tx.close()

print("mmsg semantics checks passed")
