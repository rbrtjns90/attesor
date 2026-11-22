"""Run the Linux epoll descriptor and readiness contract through stock CPython."""

import errno
import os
import select
import threading


def test_eventfd():
    event = os.eventfd(2, os.EFD_NONBLOCK | os.EFD_CLOEXEC | os.EFD_SEMAPHORE)
    copy = os.dup(event)
    os.close(event)
    with select.epoll() as readiness:
        readiness.register(copy, select.EPOLLIN)
        assert readiness.poll(0) == [(copy, select.EPOLLIN)]
        assert os.eventfd_read(copy) == os.eventfd_read(copy) == 1
        assert readiness.poll(0) == []
        try:
            os.eventfd_read(copy)
        except BlockingIOError as error:
            assert error.errno == errno.EAGAIN
        else:
            raise AssertionError("empty nonblocking eventfd read succeeded")
        os.eventfd_write(copy, 1)
        assert readiness.poll(0) == [(copy, select.EPOLLIN)]
        assert os.eventfd_read(copy) == 1
    os.close(copy)

    event = os.eventfd(0, os.EFD_NONBLOCK)
    with select.epoll() as readiness:
        readiness.register(event, select.EPOLLOUT)
        assert readiness.poll(0) == [(event, select.EPOLLOUT)]
        os.eventfd_write(event, (1 << 64) - 2)
        assert readiness.poll(0) == []
        try:
            os.eventfd_write(event, 1)
        except BlockingIOError as error:
            assert error.errno == errno.EAGAIN
        else:
            raise AssertionError("saturated eventfd write succeeded")
        assert os.eventfd_read(event) == (1 << 64) - 2
        assert readiness.poll(0) == [(event, select.EPOLLOUT)]
    os.close(event)


def main():
    incoming, outgoing = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    original = select.epoll()
    with select.epoll.fromfd(os.dup(original.fileno())) as readiness:
        assert not os.get_inheritable(original.fileno())
        original.close()
        interest = select.EPOLLIN | select.EPOLLONESHOT
        readiness.register(incoming, interest)
        try:
            readiness.register(incoming, interest)
        except OSError as error:
            assert error.errno == errno.EEXIST
        else:
            raise AssertionError("duplicate epoll registration succeeded")
        assert readiness.poll(0) == []

        writer = threading.Thread(target=lambda: os.write(outgoing, b"X"))
        writer.start()
        assert readiness.poll(3) == [(incoming, select.EPOLLIN)]
        writer.join(3)
        assert not writer.is_alive()
        assert readiness.poll(0) == []
        readiness.modify(incoming, interest)
        assert readiness.poll(0) == [(incoming, select.EPOLLIN)]
        assert os.read(incoming, 1) == b"X"

        readiness.modify(incoming, select.EPOLLIN)
        os.write(outgoing, b"Y")
        assert readiness.poll(0) == [(incoming, select.EPOLLIN)]
        assert readiness.poll(0) == [(incoming, select.EPOLLIN)]
        assert os.read(incoming, 1) == b"Y"
        assert readiness.poll(0) == []

        readiness.unregister(incoming)
        try:
            readiness.modify(incoming, select.EPOLLIN)
        except OSError as error:
            assert error.errno == errno.ENOENT
        else:
            raise AssertionError("modifying a missing registration succeeded")
        readiness.register(incoming, select.EPOLLIN)
        os.close(outgoing)
        assert readiness.poll(1)[0][1] & select.EPOLLHUP
        os.close(incoming)
        assert readiness.poll(0) == []
    test_eventfd()
    print("epoll and eventfd readiness checks passed")


if __name__ == "__main__":
    main()
