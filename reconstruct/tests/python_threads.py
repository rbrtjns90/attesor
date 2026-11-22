"""Exercise normal glibc thread creation, TLS, waits, and joining from CPython."""

import threading
import time


def main():
    worker_count = 6
    started = threading.Barrier(worker_count + 1, timeout=5)
    release = threading.Event()
    guard = threading.Lock()
    local = threading.local()
    results = []

    def worker(index):
        local.index = index
        started.wait()
        if release.wait(5):
            time.sleep(0.002)
            with guard:
                results.append((local.index, threading.get_native_id()))

    workers = [threading.Thread(target=worker, args=(index,)) for index in range(worker_count)]
    for thread in workers:
        thread.start()

    started.wait()
    assert not release.wait(0.002)
    release.set()
    for thread in workers:
        thread.join(5)
    assert all(not thread.is_alive() for thread in workers)
    assert sorted(index for index, _ in results) == list(range(worker_count))
    worker_ids = {tid for _, tid in results}
    assert len(worker_ids) == worker_count
    assert threading.get_native_id() not in worker_ids
    print("six workers joined")


if __name__ == "__main__":
    main()
