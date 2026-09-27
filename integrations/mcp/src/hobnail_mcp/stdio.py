"""Bound and validate each wire frame before the MCP library reads any of it."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
import select
import threading

from hobnail.client import parse_json

MAX_INPUT_FRAME = 2_400_000


@dataclass
class InputState:
    error: str | None = None


def pump_frames(source, destination, state, stop, *, limit=MAX_INPUT_FRAME):
    """Forward original bytes only after a complete bounded JSON frame passes.

    The caller owns source; this thread alone closes destination. A nonblocking
    pipe and short select waits permit deterministic shutdown without closing a
    descriptor underneath a blocked reader/writer.
    """
    buffered = bytearray()
    try:
        while not stop.is_set():
            if not select.select([source], [], [], 0.1)[0]:
                continue
            data = os.read(source, 65536)
            if not data:
                if buffered:
                    state.error = "STDIO_TRUNCATED_FRAME"
                return
            buffered.extend(data)
            while b"\n" in buffered:
                newline = buffered.index(b"\n") + 1
                if newline > limit:
                    state.error = "STDIO_FRAME_TOO_LARGE"
                    return
                frame = bytes(buffered[:newline])
                del buffered[:newline]
                try:
                    parse_json(frame.decode("utf-8"))
                except (ValueError, TypeError, UnicodeError, RecursionError):
                    state.error = "STDIO_INVALID_JSON"
                    return
                view = memoryview(frame)
                while view and not stop.is_set():
                    if select.select([], [destination], [], 0.1)[1]:
                        try:
                            view = view[os.write(destination, view):]
                        except BlockingIOError:
                            continue
                if stop.is_set():
                    return
            if len(buffered) >= limit:
                state.error = "STDIO_FRAME_TOO_LARGE"
                return
    except OSError:
        if not stop.is_set():
            state.error = "STDIO_INPUT_FAILURE"
    finally:
        os.close(destination)


@contextmanager
def bounded_stdin():
    """Install a private bounded pipe before the SDK duplicates descriptor zero."""
    source = os.dup(0)
    try:
        reader, writer = os.pipe()
    except BaseException:
        os.close(source)
        raise
    os.set_blocking(writer, False)
    state, stop = InputState(), threading.Event()
    thread = threading.Thread(target=pump_frames, args=(source, writer, state, stop),
                              name="hobnail-bounded-stdio", daemon=True)
    started = False
    try:
        os.dup2(reader, 0)
        os.close(reader)
        reader = None
        thread.start()
        started = True
        yield state
    finally:
        stop.set()
        if started:
            thread.join(timeout=2)
        else:
            os.close(writer)
        if reader is not None:
            os.close(reader)
        os.dup2(source, 0)
        if started and thread.is_alive():
            # Do not recycle a descriptor still used by a live thread.
            state.error = "STDIO_READER_NOT_RETIRED"
        else:
            os.close(source)
