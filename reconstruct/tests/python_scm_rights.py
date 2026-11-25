"""SCM_RIGHTS descriptor passing: send one end of a pipe across a
socketpair and read real bytes through the received descriptor."""
import array
import os
import socket

left, right = socket.socketpair()
read_end, write_end = os.pipe()
try:
    os.write(write_end, b"pipe-bytes")
    payload = array.array("i", [read_end])
    sent = left.sendmsg([b"token"],
                        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, payload)])
    assert sent == 5, sent
    data, ancdata, flags, _ = right.recvmsg(16, socket.CMSG_SPACE(4))
    assert data == b"token", data
    level, ctype, cdata = ancdata[0]
    assert level == socket.SOL_SOCKET, level
    assert ctype == socket.SCM_RIGHTS, ctype
    received = array.array("i")
    received.frombytes(cdata[:4])
    got = os.read(received[0], 64)
    os.close(received[0])
    assert got == b"pipe-bytes", got
    print("scm rights descriptor passing works")
finally:
    for fd in (read_end, write_end):
        os.close(fd)
    left.close()
    right.close()
