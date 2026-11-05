"""Bounded code-only stack snapshots. Raw stack text stays in RAM.

The worker writes faulthandler output to a private socket. The supervisor
exports only installed, root-owned Python file labels and line numbers.
Function names, thread addresses, local values and unknown paths are dropped.
"""
from collections import defaultdict
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import threading
import time

ROOTS = (("/opt/sglang/python/sglang", "sglang"),
         ("/opt/dsv41/lib/python3.12/site-packages/torch", "torch"),
         ("/opt/dsv41/lib/python3.12/site-packages/uvicorn", "uvicorn"),
         ("/opt/dsv41/lib/python3.12/site-packages/zmq", "zmq"),
         ("/usr/lib/python3.12", "python"))
FRAME = re.compile(r'  File "([^"\r\n]+)", line ([0-9]+) in [^\r\n]*')
HEADER = re.compile(r'(Current thread|Thread) 0x[0-9a-fA-F]+.*:')


def code_catalog():
    result = {}
    for directory, label in ROOTS:
        root = Path(directory)
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    continue
                result[str(path)] = label + "/" + path.relative_to(root).as_posix()
            except OSError:
                continue
    return result


class StackSnapshots:
    def __init__(self, directory, ranks, emit, catalog=None):
        self.directory = Path(directory)
        self.ranks = set(ranks)
        self.emit = emit
        self.catalog = code_catalog() if catalog is None else dict(catalog)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.peers = {}
        self.frames = defaultdict(list)
        self.rejected = defaultdict(int)
        self.requested = False
        self.active = False
        self.trace_acks = set()
        self.readers = threading.BoundedSemaphore(max(1, len(self.ranks) * 2))
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.directory / "stacks.sock"))
        os.chmod(self.directory / "stacks.sock", 0o600)
        self.server.listen(8)
        self.server.settimeout(0.1)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self.readers.acquire(blocking=False):
                connection.close()
                continue
            threading.Thread(target=self._read, args=(connection,), daemon=True).start()

    def _read(self, connection):
        key = None
        try:
            connection.settimeout(0.1)
            pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.getuid():
                return
            header = bytearray()
            deadline = time.monotonic() + 2
            while b"\n" not in header and len(header) <= 256 and time.monotonic() < deadline:
                try:
                    data = connection.recv(1)
                except socket.timeout:
                    continue
                if not data:
                    return
                header.extend(data)
            hello = json.loads(header)
            if type(hello) is not dict or set(hello) != {"role", "rank"}:
                return
            if type(hello["role"]) is not str or type(hello["rank"]) is not int:
                return
            key = (hello["role"], hello["rank"])
            if key not in self.ranks:
                return
            path = self.directory / f"{key[0]}-{key[1]}.json"
            if path.stat().st_size > 1024 or json.loads(path.read_text()).get("pid") != pid:
                return
            ready = bytearray()
            while b"\n" not in ready and len(ready) < 16 and time.monotonic() < deadline:
                try:
                    data = connection.recv(1)
                except socket.timeout:
                    continue
                if not data:
                    return
                ready.extend(data)
            if ready != b"ready\n":
                return
            with self.lock:
                if key in self.peers:
                    return
                self.peers[key] = (pid, connection)
            buffer = bytearray()
            total = 0
            thread = -1
            current = False
            while not self.stop.is_set():
                try:
                    data = connection.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                with self.lock:
                    active = self.active
                if not active:
                    continue
                total += len(data)
                if total > 262144:
                    with self.lock:
                        self.rejected[key] += 1
                    continue
                buffer.extend(data)
                while b"\n" in buffer:
                    raw, _, remainder = buffer.partition(b"\n")
                    buffer = bytearray(remainder)
                    if len(raw) > 2048:
                        with self.lock:
                            self.rejected[key] += 1
                        continue
                    line = raw.decode("utf-8", errors="replace")
                    match = HEADER.fullmatch(line)
                    if match:
                        thread += 1
                        current = match[1] == "Current thread"
                        continue
                    match = FRAME.fullmatch(line)
                    if match is None:
                        continue
                    location = self.catalog.get(os.path.normpath(match[1]))
                    number = int(match[2]) if len(match[2]) <= 7 else 0
                    if location is None or not 1 <= number <= 1000000 or thread < 0:
                        with self.lock:
                            self.rejected[key] += 1
                        continue
                    with self.lock:
                        if len(self.frames[key]) < 2048:
                            self.frames[key].append((current, thread, location, number))
                        else:
                            self.rejected[key] += 1
                if len(buffer) > 2048:
                    buffer.clear()
                    with self.lock:
                        self.rejected[key] += 1
        except (OSError, ValueError, TypeError, KeyError):
            pass  # Never format input, peer data or exception text.
        finally:
            if key is not None:
                with self.lock:
                    if self.peers.get(key, (None, None))[1] is connection:
                        del self.peers[key]
            connection.close()
            self.readers.release()

    def _emit(self, *args, **kwargs):
        try:
            self.emit(*args, **kwargs)
        except Exception:
            pass  # A log sink failure must not produce a raw traceback.

    def request(self, known_pids):
        with self.lock:
            if self.requested:
                return
            self.requested = self.active = True
            peers = dict(self.peers)
        for key in sorted(self.ranks):
            peer = peers.get(key)
            if peer is None or known_pids.get(key) != peer[0]:
                continue
            try:
                os.kill(peer[0], signal.SIGUSR2)
                peer[1].send(b"N", socket.MSG_DONTWAIT)
            except OSError:
                pass
        threading.Thread(target=self._finish, daemon=True).start()

    def acknowledge(self, role, rank):
        if type(role) is str and type(rank) is int and (role, rank) in self.ranks:
            with self.lock:
                self.trace_acks.add((role, rank))

    def _finish(self):
        # Do not make shutdown depend on a worker or on CUDA/NCCL cleanup.
        time.sleep(0.8)
        with self.lock:
            self.active = False
            frames = {key: list(value) for key, value in self.frames.items()}
            rejected = dict(self.rejected)
            trace_acks = set(self.trace_acks)
            self.frames.clear()
        for role, rank in sorted(self.ranks):
            rows = frames.get((role, rank), [])
            rows.sort(key=lambda row: not row[0])  # Current thread first.
            for index, (_, thread, location, line) in enumerate(rows[:128]):
                self._emit("stack_frame", role, rank=rank, thread=thread, frame=index,
                          location=location, line=line)
            self._emit("stack_dump_complete" if rows else "stack_dump_unavailable", role,
                      rank=rank, count=min(len(rows), 128),
                      rejected=rejected.get((role, rank), 0) + max(0, len(rows) - 128))
            if (role, rank) not in trace_acks:
                self._emit("nccl_snapshot_unavailable", role, rank=rank, code=1)

    def close(self):
        self.stop.set()
        self.server.close()
        with self.lock:
            for _, connection in self.peers.values():
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
